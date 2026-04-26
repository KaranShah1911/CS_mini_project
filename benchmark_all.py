#!/usr/bin/env python3
import ast
import json
import subprocess
import sys
import time
from pathlib import Path

try:
    import psutil
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "-q"])
    import psutil

try:
    import matplotlib.pyplot as plt
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "matplotlib", "-q"])
    import matplotlib.pyplot as plt


def get_static_metrics(script_path):
    """Extract LOC, function count, and cyclomatic proxy from Python file."""
    try:
        with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Non-empty LOC
        lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
        loc = len(lines)
        
        # Parse AST
        tree = ast.parse(content)
        
        # Function count
        func_count = sum(1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))
        
        # Cyclomatic proxy: count decision nodes (If, For, While, ExceptHandler, With) + 1 per function
        decision_count = sum(1 for node in ast.walk(tree) if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)))
        cyclomatic_proxy = decision_count + func_count
        
        return loc, func_count, cyclomatic_proxy
    except Exception as e:
        return 0, 0, 0


def run_benchmark_step(script_path, stdin_input=None, timeout=120):
    """
    Run a single script and measure: wall time, CPU time, peak memory, exit code, stderr.
    Returns: (wall_time, cpu_time, peak_memory_mb, rc, stderr)
    """
    try:
        start_wall = time.time()
        process = subprocess.Popen(
            [sys.executable, script_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )

        proc_obj = psutil.Process(process.pid)
        peak_memory = 0.0
        cpu_start = 0.0
        cpu_last = 0.0

        try:
            ct = proc_obj.cpu_times()
            cpu_start = ct.user + ct.system
            cpu_last = cpu_start
        except Exception:
            pass

        if stdin_input:
            try:
                process.stdin.write(stdin_input)
                process.stdin.flush()
            except Exception:
                pass
        try:
            process.stdin.close()
        except Exception:
            pass

        timed_out = False
        while process.poll() is None:
            if (time.time() - start_wall) > timeout:
                timed_out = True
                process.kill()
                break
            try:
                mem_now = proc_obj.memory_info().rss / (1024 * 1024)
                peak_memory = max(peak_memory, mem_now)
                ct = proc_obj.cpu_times()
                cpu_last = ct.user + ct.system
            except Exception:
                pass
            time.sleep(0.02)

        try:
            _, stderr = process.communicate(timeout=3)
        except Exception:
            stderr = ""

        wall_time = time.time() - start_wall
        try:
            ct = proc_obj.cpu_times()
            cpu_end = ct.user + ct.system
        except Exception:
            cpu_end = cpu_last
        cpu_time = max(0.0, cpu_end - cpu_start)

        rc = -1 if timed_out else process.returncode
        if timed_out:
            stderr = f"TIMEOUT after {timeout}s"

        return wall_time, cpu_time, peak_memory, rc, stderr
    except Exception as e:
        return 0, 0, 0, -1, str(e)


def benchmark_scheme(scheme_name, base_path, steps):
    """
    Benchmark a scheme with given steps.
    steps: list of (script_name, stdin_input)
    Returns: dict with metrics and steps list
    """
    scheme_path = base_path / scheme_name / "Scripts"
    
    # Get static metrics for all Python files
    py_files = list(scheme_path.glob("*.py"))
    total_loc = 0
    total_funcs = 0
    total_cyclomatic = 0
    
    for py_file in py_files:
        loc, funcs, cyclo = get_static_metrics(str(py_file))
        total_loc += loc
        total_funcs += funcs
        total_cyclomatic += cyclo
    
    # Run benchmark steps
    total_wall_time = 0
    total_cpu_time = 0
    peak_memory = 0
    steps_results = []
    
    for script_name, stdin_input in steps:
        script_path = scheme_path / script_name
        wall, cpu, mem, rc, stderr = run_benchmark_step(str(script_path), stdin_input)
        
        total_wall_time += wall
        total_cpu_time += cpu
        peak_memory = max(peak_memory, mem)
        
        step_result = {
            "script": script_name,
            "wall_time_s": round(wall, 4),
            "cpu_time_s": round(cpu, 4),
            "memory_mb": round(mem, 2),
            "rc": rc
        }
        
        if rc != 0:
            step_result["stderr"] = stderr[:200] if stderr else "Unknown error"
        
        steps_results.append(step_result)
    
    # Calculate metrics
    avg_cpu_util = (total_cpu_time / total_wall_time * 100) if total_wall_time > 0 else 0
    throughput = (1.0 / total_wall_time) if total_wall_time > 0 else 0  # KB/s for 1KB payload
    
    return {
        "total_wall_time_s": round(total_wall_time, 4),
        "total_cpu_time_s": round(total_cpu_time, 4),
        "avg_cpu_utilization_pct": round(avg_cpu_util, 2),
        "peak_memory_mb": round(peak_memory, 2),
        "throughput_kbs": round(throughput, 4),
        "static_loc": total_loc,
        "static_functions": total_funcs,
        "static_cyclomatic_proxy": total_cyclomatic,
        "steps": steps_results
    }


def plot_results(results, output_dir):
    """Create benchmark comparison graphs (PNG) from the JSON metrics."""
    schemes = list(results.keys())

    throughput_vals = [results[s]["throughput_kbs"] for s in schemes]
    wall_vals = [results[s]["total_wall_time_s"] for s in schemes]
    cpu_vals = [results[s]["total_cpu_time_s"] for s in schemes]
    mem_vals = [results[s]["peak_memory_mb"] for s in schemes]
    cpu_util_vals = [results[s]["avg_cpu_utilization_pct"] for s in schemes]
    cyclo_vals = [results[s]["static_cyclomatic_proxy"] for s in schemes]
    loc_vals = [results[s]["static_loc"] for s in schemes]
    func_vals = [results[s]["static_functions"] for s in schemes]

    plt.style.use("ggplot")

    def add_labels(ax, bars):
        for bar in bars:
            h = bar.get_height()
            ax.annotate(
                f"{h:.4g}",
                xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8
            )

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle("Hybrid Crypto Benchmark Comparison", fontsize=16, fontweight="bold")

    b1 = axes[0, 0].bar(schemes, throughput_vals, color=["#4E79A7", "#59A14F", "#F28E2B"])
    axes[0, 0].set_title("Speed (Throughput KB/s)")
    axes[0, 0].set_ylabel("KB/s")
    add_labels(axes[0, 0], b1)

    b2 = axes[0, 1].bar(schemes, wall_vals, color=["#4E79A7", "#59A14F", "#F28E2B"])
    axes[0, 1].set_title("Performance (Total Wall Time)")
    axes[0, 1].set_ylabel("Seconds")
    add_labels(axes[0, 1], b2)

    b3 = axes[0, 2].bar(schemes, cpu_vals, color=["#4E79A7", "#59A14F", "#F28E2B"])
    axes[0, 2].set_title("Computation (CPU Time)")
    axes[0, 2].set_ylabel("Seconds")
    add_labels(axes[0, 2], b3)

    b4 = axes[1, 0].bar(schemes, mem_vals, color=["#4E79A7", "#59A14F", "#F28E2B"])
    axes[1, 0].set_title("Memory (Peak MB)")
    axes[1, 0].set_ylabel("MB")
    add_labels(axes[1, 0], b4)

    b5 = axes[1, 1].bar(schemes, cpu_util_vals, color=["#4E79A7", "#59A14F", "#F28E2B"])
    axes[1, 1].set_title("CPU Utilization")
    axes[1, 1].set_ylabel("%")
    add_labels(axes[1, 1], b5)

    width = 0.25
    x = range(len(schemes))
    axes[1, 2].bar([i - width for i in x], cyclo_vals, width=width, label="Cyclomatic Proxy", color="#4E79A7")
    axes[1, 2].bar(x, loc_vals, width=width, label="LOC", color="#59A14F")
    axes[1, 2].bar([i + width for i in x], func_vals, width=width, label="Functions", color="#F28E2B")
    axes[1, 2].set_xticks(list(x))
    axes[1, 2].set_xticklabels(schemes)
    axes[1, 2].set_title("Complexity")
    axes[1, 2].legend(fontsize=8)

    for ax in axes.flat:
        ax.tick_params(axis="x", rotation=15)

    fig.tight_layout(rect=[0, 0.03, 1, 0.95])
    out_path_all = output_dir / "benchmark_comparison.png"
    fig.savefig(out_path_all, dpi=200)
    plt.close(fig)

    # Dedicated runtime chart to make CPU, memory and CPU utilization explicit.
    fig2, axes2 = plt.subplots(1, 3, figsize=(18, 5))
    fig2.suptitle("Runtime Metrics (Detailed)", fontsize=14, fontweight="bold")

    rb1 = axes2[0].bar(schemes, cpu_vals, color=["#4E79A7", "#59A14F", "#F28E2B"])
    axes2[0].set_title("CPU Time (s)")
    add_labels(axes2[0], rb1)

    rb2 = axes2[1].bar(schemes, mem_vals, color=["#4E79A7", "#59A14F", "#F28E2B"])
    axes2[1].set_title("Peak Memory (MB)")
    add_labels(axes2[1], rb2)

    rb3 = axes2[2].bar(schemes, cpu_util_vals, color=["#4E79A7", "#59A14F", "#F28E2B"])
    axes2[2].set_title("CPU Utilization (%)")
    add_labels(axes2[2], rb3)

    for ax in axes2:
        ax.tick_params(axis="x", rotation=15)

    fig2.tight_layout(rect=[0, 0.03, 1, 0.92])
    out_path_runtime = output_dir / "benchmark_runtime_metrics.png"
    fig2.savefig(out_path_runtime, dpi=200)
    plt.close(fig2)

    return out_path_all, out_path_runtime


def main():
    base_path = Path(__file__).resolve().parent
    output_dir = base_path / "benchmark_results"
    output_dir.mkdir(exist_ok=True)
    
    results = {}
    
    # AES-RSA benchmark
    results["AES-RSA"] = benchmark_scheme(
        "AES-RSA",
        base_path,
        [
            ("Key Generation of RSA.py", ""),
            ("AES Encryption.py", "benchpass\n" + "A" * 1024 + "\n"),
            ("Hybrid RSA Encryption.py", "benchpass\n"),
            ("Hybrid RSA Decryption.py", ""),
            ("AES Decryption.py", "")
        ]
    )
    
    # AES-ECC benchmark
    results["AES-ECC"] = benchmark_scheme(
        "AES-ECC",
        base_path,
        [
            ("Step1_ECC_Key_Gen.py", ""),
            ("Step2_Hybrid_Encrypt.py", "A" * 1024 + "\n"),
            ("Step3_Hybrid_Decrypt.py", "")
        ]
    )
    
    # AES-El Gamal benchmark
    results["AES-El Gamal"] = benchmark_scheme(
        "AES-El Gamal",
        base_path,
        [
            ("Step1_Key_Generation.py", ""),
            ("Step2_Hybrid_Encrypt.py", "A" * 1024 + "\n"),
            ("Step3_Hybrid_Decrypt.py", "")
        ]
    )
    
    json_path = output_dir / "benchmark_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    graph_path_all, graph_path_runtime = plot_results(results, output_dir)

    print(f"JSON saved: {json_path}")
    print(f"Graph saved: {graph_path_all}")
    print(f"Runtime graph saved: {graph_path_runtime}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
