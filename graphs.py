
from __future__ import annotations

import matplotlib.pyplot as plt


def plot_success_rates(results_vuln: dict, results_secure: dict) -> None:
    labels = ["Vulnerable", "Secure"]
    values = [results_vuln["success_rate"], results_secure["success_rate"]]

    plt.figure()
    bars = plt.bar(labels, values, color=["#cc4444", "#44aa55"])
    plt.title("Attack Success Rate: Before vs After")
    plt.ylabel("Success Rate (%)")
    plt.ylim(0, 100)
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height + 1,
            f"{height:.1f}%",
            ha="center",
            va="bottom",
        )


def plot_time_vs_keysize(benchmark: dict) -> None:
    sizes = sorted(benchmark.keys())
    keygen_times = [benchmark[s]["keygen_time"] for s in sizes]
    sign_times = [benchmark[s]["sign_time"] for s in sizes]

    plt.figure()
    plt.plot(sizes, keygen_times, marker="o", label="Keygen Time")
    plt.plot(sizes, sign_times, marker="o", label="CRT Sign Time")
    plt.title("Time vs Key Size")
    plt.xlabel("Key Size (bits)")
    plt.ylabel("Time (seconds)")
    plt.xticks(sizes, [str(s) for s in sizes])
    plt.legend()


def plot_confidentiality_integrity(results_vuln: dict, results_secure: dict) -> None:
    categories = ["Confidentiality Broken", "Integrity OK"]
    vuln_values = [
        results_vuln["confidentiality_broken_rate"],
        results_vuln["integrity_rate"],
    ]
    secure_values = [
        results_secure["confidentiality_broken_rate"],
        results_secure["integrity_rate"],
    ]

    x = range(len(categories))
    width = 0.35

    plt.figure()
    plt.bar([i - width / 2 for i in x], vuln_values, width, label="Vulnerable", color="#cc4444")
    plt.bar([i + width / 2 for i in x], secure_values, width, label="Secure", color="#44aa55")
    plt.title("Confidentiality / Integrity Rate Comparison")
    plt.ylabel("Rate (%)")
    plt.xticks(list(x), categories)
    plt.ylim(0, 100)
    plt.legend()


def plot_latency_overhead(results_vuln: dict, results_secure: dict) -> None:
    labels = ["Vulnerable", "Secure"]
    values = [results_vuln["avg_oracle_time"], results_secure["avg_oracle_time"]]

    plt.figure()
    bars = plt.bar(labels, values, color=["#cc4444", "#44aa55"])
    plt.title("Attack vs Prevention Latency Overhead")
    plt.ylabel("Time per Signature (seconds)")
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height + (height * 0.05 if height > 0 else 0.001),
            f"{height:.6f}s",
            ha="center",
            va="bottom",
        )


def plot_all(results_vuln: dict, results_secure: dict, benchmark: dict) -> None:
    plot_success_rates(results_vuln, results_secure)
    plot_time_vs_keysize(benchmark)
    plot_confidentiality_integrity(results_vuln, results_secure)
    plot_latency_overhead(results_vuln, results_secure)
    plt.show()
