
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Literal

from attack import DEFAULT_TRIALS, benchmark_key_sizes, run_trials
from rsa import generate_keypair_with_info
from utils import time_call
import graphs


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CRT Fault Leak in RSA")
        self.root.geometry("1120x760")

        self.priv = None
        self.pub = None
        self.mode = "vulnerable"
        self.results_vulnerable = None
        self.results_secure = None
        self.benchmark_data = None

        self.log_queue: queue.Queue[str] = queue.Queue()

        self._build_ui()
        self.set_mode("vulnerable")
        self.clear_key_details()
        self.clear_pipeline_panel()
        self._start_log_poller()

    def _build_ui(self) -> None:
        # Top control panel
        control_frame = tk.Frame(self.root)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        tk.Label(control_frame, text="Key Size:").pack(side=tk.LEFT, padx=(0, 5))
        self.key_size_var = tk.StringVar(value="1024")
        self.key_size_combo = ttk.Combobox(
            control_frame,
            textvariable=self.key_size_var,
            values=["1024", "2048"],
            state="readonly",
            width=10,
        )
        self.key_size_combo.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_generate = tk.Button(
            control_frame,
            text="Generate Keys / Parameters",
            command=self.on_generate_keys,
        )
        self.btn_generate.pack(side=tk.LEFT, padx=5)

        self.btn_run_attack = tk.Button(
            control_frame,
            text="Run Attack",
            command=self.on_run_attack,
        )
        self.btn_run_attack.pack(side=tk.LEFT, padx=5)

        self.btn_apply_prevention = tk.Button(
            control_frame,
            text="Apply Prevention",
            command=self.on_apply_prevention,
        )
        self.btn_apply_prevention.pack(side=tk.LEFT, padx=5)

        self.btn_show_graphs = tk.Button(
            control_frame,
            text="Show Graphs",
            command=self.on_show_graphs,
        )
        self.btn_show_graphs.pack(side=tk.LEFT, padx=5)

        indicator_frame = tk.Frame(self.root)
        indicator_frame.pack(side=tk.TOP, fill=tk.X, padx=10)

        self.vuln_label = tk.Label(
            indicator_frame,
            text="Vulnerable",
            width=12,
            relief="sunken",
            padx=6,
            pady=4,
        )
        self.vuln_label.pack(side=tk.LEFT, padx=(0, 6))

        self.secure_label = tk.Label(
            indicator_frame,
            text="Secure",
            width=12,
            relief="raised",
            padx=6,
            pady=4,
        )
        self.secure_label.pack(side=tk.LEFT)

        info_frame = tk.Frame(self.root)
        info_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=(8, 10))
        info_frame.grid_columnconfigure(0, weight=1)
        info_frame.grid_columnconfigure(1, weight=1)
        info_frame.grid_columnconfigure(2, weight=1)
        info_frame.grid_rowconfigure(0, weight=1)

        key_frame = ttk.LabelFrame(info_frame, text="Key Details")
        key_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.key_text = tk.Text(key_frame, wrap=tk.WORD, height=14, state="disabled")
        self.key_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        key_scroll = tk.Scrollbar(key_frame, command=self.key_text.yview)
        key_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.key_text.configure(yscrollcommand=key_scroll.set)

        pipeline_frame = ttk.LabelFrame(info_frame, text="Live Attack Pipeline")
        pipeline_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        self.pipeline_text = tk.Text(
            pipeline_frame,
            wrap=tk.WORD,
            height=14,
            state="disabled",
        )
        self.pipeline_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pipeline_scroll = tk.Scrollbar(pipeline_frame, command=self.pipeline_text.yview)
        pipeline_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.pipeline_text.configure(yscrollcommand=pipeline_scroll.set)

        table_frame = ttk.LabelFrame(info_frame, text="Trial Table")
        table_frame.grid(row=0, column=2, sticky="nsew")
        columns = (
            "trial",
            "branch",
            "faulted",
            "gcd_bits",
            "success",
            "integrity",
            "attempts",
        )
        self.trial_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=12,
        )
        self.trial_table.heading("trial", text="Trial")
        self.trial_table.heading("branch", text="Branch")
        self.trial_table.heading("faulted", text="Faulted")
        self.trial_table.heading("gcd_bits", text="GCD Bits")
        self.trial_table.heading("success", text="Success")
        self.trial_table.heading("integrity", text="Integrity")
        self.trial_table.heading("attempts", text="Attempts")
        self.trial_table.column("trial", width=50, anchor="center")
        self.trial_table.column("branch", width=60, anchor="center")
        self.trial_table.column("faulted", width=70, anchor="center")
        self.trial_table.column("gcd_bits", width=70, anchor="center")
        self.trial_table.column("success", width=70, anchor="center")
        self.trial_table.column("integrity", width=70, anchor="center")
        self.trial_table.column("attempts", width=70, anchor="center")
        self.trial_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        table_scroll = tk.Scrollbar(table_frame, command=self.trial_table.yview)
        table_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.trial_table.configure(yscrollcommand=table_scroll.set)

        log_frame = tk.Frame(self.root)
        log_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, state="disabled")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=scrollbar.set)

    def _start_log_poller(self) -> None:
        self.root.after(100, self._process_log_queue)

    def _process_log_queue(self) -> None:
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, msg + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")
        self.root.after(100, self._process_log_queue)

    def log(self, message: str) -> None:
        self.log_queue.put(message)

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.configure(state="disabled")

    def format_bigint(self, value: int | None, line: int = 64) -> str:
        if value is None:
            return "N/A"
        s = str(value)
        return "\n".join(s[i : i + line] for i in range(0, len(s), line))

    def clear_key_details(self) -> None:
        self._set_text(self.key_text, "No key generated yet.")

    def clear_pipeline_panel(self) -> None:
        self._set_text(self.pipeline_text, "No trial data yet.")

    def reset_trial_table(self) -> None:
        for item in self.trial_table.get_children():
            self.trial_table.delete(item)

    def update_key_details(self, info: dict) -> None:
        lines = []
        lines.append("Public exponent e:")
        lines.append(str(info["e"]))
        lines.append("")

        def add_value(label: str, value: int) -> None:
            bits = value.bit_length()
            lines.append(f"{label} (bits={bits}):")
            lines.append(self.format_bigint(value))
            lines.append("")

        add_value("p", info["p"])
        add_value("q", info["q"])
        add_value("n = p*q", info["n"])
        add_value("phi = (p-1)(q-1)", info["phi"])
        add_value("d = e^{-1} mod phi", info["d"])
        add_value("dp = d mod (p-1)", info["dp"])
        add_value("dq = d mod (q-1)", info["dq"])
        add_value("qinv = q^{-1} mod p", info["qinv"])

        lines.append(
            f"Prime search attempts: p={info['p_attempts']}, q={info['q_attempts']}"
        )
        lines.append(f"Keygen rounds: {info['keygen_rounds']}")

        self._set_text(self.key_text, "\n".join(lines).strip())

    def update_pipeline_panel(self, data: dict) -> None:
        lines = []
        lines.append(
            f"Trial {data['trial_index']} | mode={data['mode']} | "
            f"branch={data['fault_branch']} | faulted={data['fault_applied']} | "
            f"integrity_ok={data['integrity_ok']} | attempts={data['attempts_used']}"
        )
        lines.append("")
        lines.append("Step 1: Correct signature s")
        lines.append(self.format_bigint(data["s_correct"]))
        lines.append("")
        lines.append("Step 2: Faulty signature sf")
        lines.append(self.format_bigint(data["s_faulty"]))
        lines.append("")
        lines.append("Step 3: g = gcd(|s - sf|, n)")
        lines.append(self.format_bigint(data["g"]))
        lines.append("")
        lines.append("Step 4: Recovered factor g")
        lines.append(self.format_bigint(data["recovered_factor"]))
        lines.append("")
        lines.append("Step 5: Other factor n/g")
        lines.append(self.format_bigint(data["other_factor"]))

        self._set_text(self.pipeline_text, "\n".join(lines).strip())

    def add_trial_row(self, record) -> None:
        self.trial_table.insert(
            "",
            "end",
            values=(
                record.trial_index,
                record.fault_branch,
                "Yes" if record.fault_applied else "No",
                record.gcd_bits,
                "OK" if record.success else "FAIL",
                "OK" if record.integrity_ok else "FAIL",
                record.attempts_used,
            ),
        )

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        if mode == "vulnerable":
            self.vuln_label.configure(bg="#cc3333", fg="white", relief="sunken")
            self.secure_label.configure(bg="#e0e0e0", fg="#333333", relief="raised")
        else:
            self.vuln_label.configure(bg="#e0e0e0", fg="#333333", relief="raised")
            self.secure_label.configure(bg="#2e9e49", fg="white", relief="sunken")

    def set_buttons_state(self, state: Literal["normal", "disabled"]) -> None:
        self.btn_generate.configure(state=state)
        self.btn_run_attack.configure(state=state)
        self.btn_apply_prevention.configure(state=state)
        self.btn_show_graphs.configure(state=state)

    def on_generate_keys(self) -> None:
        self.set_buttons_state("disabled")
        bits = int(self.key_size_var.get())
        self.log(f"Generating {bits}-bit RSA keypair... this may take a moment.")

        def worker():
            (priv, pub, info), elapsed = time_call(generate_keypair_with_info, bits)
            self.priv = priv
            self.pub = pub
            self.results_vulnerable = None
            self.results_secure = None
            self.log(f"Keygen completed in {elapsed:.3f} seconds.")
            self.log(f"Public modulus size: {pub.n.bit_length()} bits")
            self.log("Key generation steps:")
            self.log("Step 1: Choose public exponent e = 65537")
            self.log(
                "Step 2: Generate probable primes p and q "
                f"({bits // 2} bits each)"
            )
            self.log(
                f"  Prime search attempts: p={info['p_attempts']}, "
                f"q={info['q_attempts']} (keygen rounds={info['keygen_rounds']})"
            )
            self.log(f"  p = {info['p']}")
            self.log(f"  q = {info['q']}")
            self.log("Step 3: Compute n = p*q and phi = (p-1)(q-1)")
            self.log(f"  n = {info['n']}")
            self.log(f"  phi = {info['phi']}")
            self.log("Step 4: Compute private exponent d = e^{-1} mod phi")
            self.log(f"  d = {info['d']}")
            self.log("Step 5: Precompute CRT parameters")
            self.log(f"  dp = d mod (p-1) = {info['dp']}")
            self.log(f"  dq = d mod (q-1) = {info['dq']}")
            self.log(f"  qinv = q^{-1} mod p = {info['qinv']}")
            self.root.after(0, lambda: self.set_mode("vulnerable"))
            self.root.after(0, lambda: self.update_key_details(info))
            self.root.after(0, lambda: self.clear_pipeline_panel())
            self.root.after(0, lambda: self.reset_trial_table())
            self.root.after(0, lambda: self.set_buttons_state("normal"))

        threading.Thread(target=worker, daemon=True).start()

    def on_run_attack(self) -> None:
        if self.priv is None or self.pub is None:
            self.log("No keypair loaded. Click 'Generate Keys / Parameters' first.")
            return
        assert self.pub is not None
        assert self.priv is not None
        pub = self.pub
        priv = self.priv
        key_bits = pub.n.bit_length()

        self.set_buttons_state("disabled")
        self.root.after(0, lambda: self.set_mode("vulnerable"))
        self.log("Running vulnerable CRT fault attack trials...")
        self.log(
            "Attack idea: obtain a correct signature s and a faulty signature sf, "
            "then compute g = gcd(|s - sf|, n) to recover a factor."
        )
        self.log("Detailed step-by-step trace will be shown for trial 1.")
        self.root.after(0, lambda: self.reset_trial_table())
        self.root.after(0, lambda: self.clear_pipeline_panel())

        def worker():
            def trial_hook(record):
                self.root.after(0, lambda rec=record: self.add_trial_row(rec))

            def pipeline_hook(data):
                self.root.after(0, lambda d=data: self.update_pipeline_panel(d))

            results = run_trials(
                num_trials=DEFAULT_TRIALS,
                key_bits=key_bits,
                mode="vulnerable",
                priv=priv,
                pub=pub,
                reuse_key=True,
                progress_hook=self.log,
                trial_hook=trial_hook,
                pipeline_hook=pipeline_hook,
                detail_first=True,
            )
            self.results_vulnerable = results
            self.log(
                f"Vulnerable success rate: {results['success_rate']:.2f}% | "
                f"Integrity OK: {results['integrity_rate']:.2f}%"
            )
            self.log(
                f"Avg oracle time: {results['avg_oracle_time']:.6f}s | "
                f"Avg attack time: {results['avg_attack_time']:.6f}s"
            )
            self.root.after(0, lambda: self.set_buttons_state("normal"))

        threading.Thread(target=worker, daemon=True).start()

    def on_apply_prevention(self) -> None:
        if self.priv is None or self.pub is None:
            self.log("No keypair loaded. Click 'Generate Keys / Parameters' first.")
            return
        assert self.pub is not None
        assert self.priv is not None
        pub = self.pub
        priv = self.priv
        key_bits = pub.n.bit_length()

        self.set_buttons_state("disabled")
        self.root.after(0, lambda: self.set_mode("secure"))
        self.log("Applying prevention (verify + recompute) and rerunning trials...")
        self.log(
            "Mitigation: verify the CRT result before returning. If it fails, "
            "recompute using full exponentiation so no faulty output leaks."
        )
        self.log("Detailed step-by-step trace will be shown for trial 1.")
        self.root.after(0, lambda: self.reset_trial_table())
        self.root.after(0, lambda: self.clear_pipeline_panel())

        def worker():
            def trial_hook(record):
                self.root.after(0, lambda rec=record: self.add_trial_row(rec))

            def pipeline_hook(data):
                self.root.after(0, lambda d=data: self.update_pipeline_panel(d))

            results = run_trials(
                num_trials=DEFAULT_TRIALS,
                key_bits=key_bits,
                mode="secure",
                priv=priv,
                pub=pub,
                reuse_key=True,
                progress_hook=self.log,
                trial_hook=trial_hook,
                pipeline_hook=pipeline_hook,
                detail_first=True,
            )
            self.results_secure = results
            self.log(
                f"Secure success rate: {results['success_rate']:.2f}% | "
                f"Integrity OK: {results['integrity_rate']:.2f}%"
            )
            self.log(
                f"Avg oracle time: {results['avg_oracle_time']:.6f}s | "
                f"Avg attack time: {results['avg_attack_time']:.6f}s"
            )
            self.root.after(0, lambda: self.set_buttons_state("normal"))

        threading.Thread(target=worker, daemon=True).start()

    def on_show_graphs(self) -> None:
        if self.results_vulnerable is None or self.results_secure is None:
            self.log("Run both 'Run Attack' and 'Apply Prevention' before graphs.")
            return
        assert self.results_vulnerable is not None
        assert self.results_secure is not None
        results_vulnerable = self.results_vulnerable
        results_secure = self.results_secure

        self.set_buttons_state("disabled")
        self.log("Benchmarking key sizes for graphs...")

        def worker():
            benchmark = benchmark_key_sizes(samples_per_size=5)
            self.benchmark_data = benchmark

            def show():
                graphs.plot_all(results_vulnerable, results_secure, benchmark)
                self.set_buttons_state("normal")

            self.root.after(0, show)

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
