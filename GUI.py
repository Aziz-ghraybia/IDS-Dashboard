import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading
import json
import csv
try:
    from predict import predicting, LOG_FILE as PRED_LOG_FILE
except Exception:
    # If predict module or models are missing, keep a placeholder. The Live Test button will handle errors.
    predicting = None
    PRED_LOG_FILE = "Logs/detection_log.csv"
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import os

import matplotlib.pyplot as plt

class IDSDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("IDS Monitoring Dashboard")
        self.root.geometry("1400x800")
        self.root.configure(bg="#f0f0f0")
        
        # prefer the persistent detection log produced by `predicting()`
        self.log_file = PRED_LOG_FILE if PRED_LOG_FILE else "Logs/detection_log.csv"
        self.alerts = []
        self.detection_thread = None
        self.running = False
        
        self.setup_styles()
        self.create_layout()
        self.load_data()
        self.start_monitoring()
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Title.TLabel", font=("Arial", 14, "bold"), background="#f0f0f0")
        style.configure("Heading.TLabel", font=("Arial", 11, "bold"), background="#f0f0f0")
        style.configure("TFrame", background="#f0f0f0")
    
    def create_layout(self):
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        title_label = ttk.Label(header_frame, text="🛡️ IDS Monitoring Dashboard", style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        
        self.status_label = ttk.Label(header_frame, text="Status: Monitoring", font=("Arial", 10))
        self.status_label.pack(side=tk.RIGHT)
        
        # Main container with notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tab 1: Dashboard
        self.dashboard_tab = ttk.Frame(notebook)
        notebook.add(self.dashboard_tab, text="Dashboard")
        self.create_dashboard_tab()
        
        # Tab 2: Live Alerts
        self.alerts_tab = ttk.Frame(notebook)
        notebook.add(self.alerts_tab, text="Live Alerts")
        self.create_alerts_tab()
        
        # Tab 3: Statistics
        self.stats_tab = ttk.Frame(notebook)
        notebook.add(self.stats_tab, text="Statistics")
        self.create_stats_tab()
        
        # Tab 4: Logs
        self.logs_tab = ttk.Frame(notebook)
        notebook.add(self.logs_tab, text="Logs")
        self.create_logs_tab()
    
    def create_dashboard_tab(self):
        # Top stats frame
        stats_frame = ttk.Frame(self.dashboard_tab)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.total_alerts_var = tk.StringVar(value="0")
        self.critical_alerts_var = tk.StringVar(value="0")
        self.today_attacks_var = tk.StringVar(value="0")
        
        for label_text, var in [("Total Alerts", self.total_alerts_var),
                                 ("Critical Alerts", self.critical_alerts_var),
                                 ("Today's Attacks", self.today_attacks_var)]:
            card = ttk.LabelFrame(stats_frame, text=label_text, padding=10)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            value_label = ttk.Label(card, text=var.get(), font=("Arial", 20, "bold"))
            value_label.pack()
            # capture `var` in the lambda so each label updates the correct StringVar
            var.trace("w", lambda *args, v=value_label, var=var: v.config(text=var.get()))
            # Add reset button for Critical Alerts card
            if label_text == "Critical Alerts":
                ttk.Button(card, text="Reset", command=lambda: self.critical_alerts_var.set("0")).pack(pady=5)
        
        # Charts + Live Test frame (three-column layout)
        charts_frame = ttk.Frame(self.dashboard_tab)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_charts = ttk.Frame(charts_frame)
        left_charts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.fig_daily = Figure(figsize=(6, 4), dpi=100)
        self.canvas_daily = FigureCanvasTkAgg(self.fig_daily, master=left_charts)
        self.canvas_daily.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # place threat distribution and normal/attack ratio side-by-side
        lower_left = ttk.Frame(left_charts)
        lower_left.pack(fill=tk.BOTH, expand=True)

        self.fig_threat = Figure(figsize=(3, 3), dpi=100)
        self.canvas_threat = FigureCanvasTkAgg(self.fig_threat, master=lower_left)
        self.canvas_threat.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.fig_ratio = Figure(figsize=(3, 3), dpi=100)
        self.canvas_ratio = FigureCanvasTkAgg(self.fig_ratio, master=lower_left)
        self.canvas_ratio.get_tk_widget().pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Live Test / Controls (right column)
        self.live_frame = ttk.LabelFrame(charts_frame, text="Live Test")
        self.live_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=5, pady=5)
        self.create_live_test_ui(self.live_frame)
    
    def create_alerts_tab(self):
        # Alert list with scrollbar
        list_frame = ttk.Frame(self.alerts_tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(list_frame, text="Recent Detections:", style="Heading.TLabel").pack(anchor=tk.W)
        
        self.alerts_text = scrolledtext.ScrolledText(list_frame, height=25, width=160, wrap=tk.WORD)
        self.alerts_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Configure tags for styling
        self.alerts_text.tag_config("critical", foreground="red", font=("Arial", 10, "bold"))
        self.alerts_text.tag_config("warning", foreground="orange", font=("Arial", 10, "bold"))
        self.alerts_text.tag_config("info", foreground="blue", font=("Arial", 9))
    
    def create_stats_tab(self):
        # Weekly and threat type statistics
        stats_frame = ttk.Frame(self.stats_tab)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        left_frame = ttk.Frame(stats_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        ttk.Label(left_frame, text="Weekly Trend:", style="Heading.TLabel").pack(anchor=tk.W)
        self.fig_weekly = Figure(figsize=(6, 4), dpi=100)
        self.canvas_weekly = FigureCanvasTkAgg(self.fig_weekly, master=left_frame)
        self.canvas_weekly.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        right_frame = ttk.Frame(stats_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_frame, text="Attack Types Distribution:", style="Heading.TLabel").pack(anchor=tk.W)
        self.fig_types = Figure(figsize=(6, 4), dpi=100)
        self.canvas_types = FigureCanvasTkAgg(self.fig_types, master=right_frame)
        self.canvas_types.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_logs_tab(self):
        # Logs container
        log_frame = ttk.Frame(self.logs_tab)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Per-sniff summaries (from Logs/sniff_summary.csv)
        summary_frame = ttk.LabelFrame(log_frame, text="Per-Sniff Summaries")
        summary_frame.pack(fill=tk.BOTH, expand=False, pady=5)

        cols = ("TimeStamp", "Packets", "Flows", "Top_RF_Flow", "Top_RF_Prob", "Top_XGB_Flow", "Top_XGB_Prob")
        self.summary_tree = ttk.Treeview(summary_frame, columns=cols, show='headings', height=6)
        for c in cols:
            self.summary_tree.heading(c, text=c)
            self.summary_tree.column(c, width=120, anchor=tk.CENTER)
        vsb = ttk.Scrollbar(summary_frame, orient="vertical", command=self.summary_tree.yview)
        self.summary_tree.configure(yscrollcommand=vsb.set)
        self.summary_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = ttk.Frame(summary_frame)
        btn_frame.pack(fill=tk.X, padx=3, pady=3)
        ttk.Button(btn_frame, text="Refresh Summaries", command=self.load_sniff_summary).pack(side=tk.LEFT, padx=3)

        # Raw logs display (kept below)
        ttk.Label(log_frame, text="Raw Log Data:", style="Heading.TLabel").pack(anchor=tk.W)
        self.logs_text = scrolledtext.ScrolledText(log_frame, height=15, width=160, wrap=tk.WORD, font=("Courier", 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True, pady=5)

    def create_live_test_ui(self, parent):
        # Controls
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        self.run_button = ttk.Button(btn_frame, text="Run Live Test", command=self.on_run_button)
        self.run_button.pack(fill=tk.X, padx=3, pady=3)

        self.last_result_var = tk.StringVar(value="No tests run yet")
        ttk.Label(parent, textvariable=self.last_result_var, wraplength=260).pack(fill=tk.X, padx=5, pady=4)

        summary_frame = ttk.Frame(parent)
        summary_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(summary_frame, text="Last Captured Flows:").grid(row=0, column=0, sticky=tk.W)
        self.last_flows_var = tk.StringVar(value="0")
        ttk.Label(summary_frame, textvariable=self.last_flows_var).grid(row=0, column=1, sticky=tk.E)

        ttk.Label(summary_frame, text="Last Detected Attacks:").grid(row=1, column=0, sticky=tk.W)
        self.last_detected_var = tk.StringVar(value="0")
        ttk.Label(summary_frame, textvariable=self.last_detected_var).grid(row=1, column=1, sticky=tk.E)

        ttk.Label(summary_frame, text="Global Attack Ratio:").grid(row=2, column=0, sticky=tk.W)
        self.last_ratio_var = tk.StringVar(value="0%")
        ttk.Label(summary_frame, textvariable=self.last_ratio_var).grid(row=2, column=1, sticky=tk.E)

        # Threat table
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        cols = ("timestamp", "flow_id", "level", "count", "prob_rf", "prob_xgb")
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings', height=12)
        headings = {"timestamp":"Timestamp", "flow_id":"Flow ID", "level":"Level", "count":"Count", "prob_rf":"Prob RF", "prob_xgb":"Prob XGBoost"}
        for c in cols:
            self.tree.heading(c, text=headings[c], command=lambda _c=c: self.sort_tree(_c, False))
            self.tree.column(c, width=100, anchor=tk.CENTER)
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def sort_tree(self, col, reverse):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        # try numeric sort
        try:
            data.sort(key=lambda t: float(t[0]) if t[0] != '' else float('-inf'), reverse=reverse)
        except Exception:
            data.sort(key=lambda t: t[0].lower() if isinstance(t[0], str) else t[0], reverse=reverse)
        for index, (val, k) in enumerate(data):
            self.tree.move(k, '', index)
        # toggle next time
        self.tree.heading(col, command=lambda: self.sort_tree(col, not reverse))

    def on_run_button(self):
        # Disable button and run predicting() in background
        self.run_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Running test...")
        t = threading.Thread(target=self._run_predict_thread, daemon=True)
        t.start()

    def _run_predict_thread(self):
        result = None
        try:
            result = predicting()
        except Exception as e:
            result = {'error': str(e)}
        # schedule UI update
        self.root.after(100, lambda: self._on_test_complete(result))

    def _on_test_complete(self, result):
        # reload log and refresh displays
        self.load_data()
        self.populate_threat_table()
        # update summary from returned result if available
        try:
            if result and isinstance(result, dict):
                # prefer summary keys returned by predicting()
                flows_val = result.get('Flows') or result.get('Total')
                if flows_val is not None:
                    try:
                        self.last_flows_var.set(str(int(flows_val)))
                    except Exception:
                        self.last_flows_var.set(str(flows_val))
                else:
                    unique_flows = set([a.get('flow_id') for a in self.alerts if a.get('flow_id')])
                    self.last_flows_var.set(str(len(unique_flows)))

                detected = result.get('Detected')
                if detected is None:
                    # try to infer from loaded alerts matching the run timestamp
                    ts = result.get('TimeStamp') or result.get('timestamp') or result.get('Time Stamp')
                    if ts:
                        detected = sum(1 for a in self.alerts if (a.get('timestamp') == ts))
                    else:
                        detected = len(self.alerts)
                self.last_detected_var.set(str(detected))
            else:
                # fallback: estimate from logs
                unique_flows = set([a.get('flow_id') for a in self.alerts if a.get('flow_id')])
                self.last_flows_var.set(str(len(unique_flows)))
                self.last_detected_var.set(str(len(self.alerts)))

            total_captured = int(self.last_flows_var.get()) if str(self.last_flows_var.get()).isdigit() else 0
            detected_count = int(self.last_detected_var.get()) if str(self.last_detected_var.get()).isdigit() else len(self.alerts)
            ratio = (detected_count / total_captured * 100) if total_captured > 0 else 0
            self.last_ratio_var.set(f"{ratio:.1f}%")

            if result and isinstance(result, dict) and result.get('error'):
                self.last_result_var.set("Test completed with error: " + str(result.get('error')))
            else:
                self.last_result_var.set("Last test completed: " + datetime.now().isoformat())
        except Exception:
            self.last_result_var.set("Last test completed")

        self.status_label.config(text="Status: Monitoring")
        self.run_button.config(state=tk.NORMAL)
        # best-effort: compute and save per-sniff summary for the most recent run
        try:
            # find latest run timestamp string in detection CSV
            if Path(self.log_file).exists():
                with open(self.log_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                    if rows:
                        last_ts = rows[-1].get('TimeStamp') or rows[-1].get('timestamp') or rows[-1].get('Time Stamp')
                        if last_ts:
                            self.compute_and_save_summary(last_ts)
        except Exception:
            pass

    def populate_threat_table(self):
        # Clear
        for r in self.tree.get_children():
            self.tree.delete(r)
        # Sort by severity mapping then probability
        def severity_key(level):
            if not level:
                return 0
            l = level.lower()
            if 'danger' in l:
                return 5
            if 'high' in l:
                return 4
            if 'susp' in l or 'suspec' in l or 'suspicious' in l:
                return 3
            if 'low' in l:
                return 2
            if 'attack' in l:
                return 1
            return 0

        rows = list(self.alerts)
        # compute occurrences per flow
        counts = Counter([r.get('flow_id') for r in self.alerts if r.get('flow_id')])
        rows.sort(key=lambda r: (severity_key(r.get('level')), r.get('prob_rf') or 0, r.get('prob_xgb') or 0, counts.get(r.get('flow_id')) or 0), reverse=True)
        for r in rows[:200]:
            fid = r.get('flow_id') or ''
            self.tree.insert('', tk.END, values=(r.get('timestamp') or '', fid, r.get('level') or '', counts.get(fid) or 0, r.get('prob_rf') if r.get('prob_rf') is not None else '', r.get('prob_xgb') if r.get('prob_xgb') is not None else ''))

    def compute_and_save_summary(self, run_timestamp_iso):
        """Compute a per-sniff summary and append it to `Logs/sniff_summary.csv`.
        Summary fields: TimeStamp, Packets, Flows, Top_RF_Flow, Top_RF_Prob, Top_XGB_Flow, Top_XGB_Prob
        """
        try:
            # convert run timestamp to epoch if possible
            run_epoch = None
            try:
                run_epoch = datetime.fromisoformat(run_timestamp_iso).timestamp()
            except Exception:
                try:
                    run_epoch = float(run_timestamp_iso)
                except Exception:
                    run_epoch = None

            # count packets from raw traffic log within a 30s window of run
            packet_count = 0
            raw_path = Path("./Logs/raw_traffic_log.csv")
            if run_epoch and raw_path.exists():
                with open(raw_path, 'r', newline='') as fr:
                    rreader = csv.DictReader(fr)
                    for row in rreader:
                        try:
                            t = float(row.get('timestamp') or row.get('time') or 0)
                        except Exception:
                            continue
                        if abs(t - run_epoch) <= 30:
                            packet_count += 1

            # aggregate flows and find top probabilities from detection log rows matching run timestamp
            flows_count = 0
            top_rf = {'flow': '', 'prob': 0.0}
            top_xgb = {'flow': '', 'prob': 0.0}
            if Path(self.log_file).exists():
                with open(self.log_file, 'r', newline='') as fd:
                    dreader = csv.DictReader(fd)
                    for row in dreader:
                        ts = row.get('TimeStamp') or row.get('timestamp') or row.get('Time Stamp')
                        if not ts or ts != run_timestamp_iso:
                            continue
                        flows_count += 1
                        try:
                            prf = float(row.get('Probability RF') or row.get('Probability_RF') or 0)
                        except Exception:
                            prf = 0.0
                        try:
                            pxg = float(row.get('Probability XGBoost') or row.get('Probability_XGBoost') or 0)
                        except Exception:
                            pxg = 0.0
                        fid = row.get('Flow ID') or row.get('Flow') or ''
                        if prf > top_rf['prob']:
                            top_rf = {'flow': fid, 'prob': prf}
                        if pxg > top_xgb['prob']:
                            top_xgb = {'flow': fid, 'prob': pxg}

            # write summary CSV
            summary_path = Path("./Logs/sniff_summary.csv")
            header = ['TimeStamp', 'Packets', 'Flows', 'Top_RF_Flow', 'Top_RF_Prob', 'Top_XGB_Flow', 'Top_XGB_Prob']
            write_header = not summary_path.exists()
            with open(summary_path, 'a', newline='') as fs:
                writer = csv.DictWriter(fs, fieldnames=header)
                if write_header:
                    writer.writeheader()
                writer.writerow({
                    'TimeStamp': run_timestamp_iso,
                    'Packets': packet_count,
                    'Flows': flows_count,
                    'Top_RF_Flow': top_rf['flow'],
                    'Top_RF_Prob': top_rf['prob'],
                    'Top_XGB_Flow': top_xgb['flow'],
                    'Top_XGB_Prob': top_xgb['prob']
                })
        except Exception:
            return
    
    def load_data(self):
        """Load existing alerts from log file"""
        # Try to read CSV log produced by `predicting()` first
        self.alerts = []
        try:
            if Path(self.log_file).exists():
                with open(self.log_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        # normalize keys to expected names
                        ts = row.get('TimeStamp') or row.get('timestamp') or row.get('Time Stamp') or row.get('timestamp')
                        flow = row.get('Flow ID') or row.get('flow_id') or row.get('Flow') or row.get('FlowID')
                        level = row.get('Level') or row.get('severity') or row.get('level') or 'Low'
                        prf = row.get('Probability RF') or row.get('Probability_RF') or row.get('prob_rf') or ''
                        pxg = row.get('Probability XGBoost') or row.get('Probability_XGBoost') or row.get('prob_xg') or ''
                        try:
                            prf = float(prf) if prf != '' else None
                        except:
                            prf = None
                        try:
                            pxg = float(pxg) if pxg != '' else None
                        except:
                            pxg = None
                        entry = {
                            'timestamp': ts,
                            'flow_id': flow,
                            'level': level,
                            'prob_rf': prf,
                            'prob_xgb': pxg
                        }
                        self.alerts.append(entry)
        except Exception:
            # fallback: empty
            self.alerts = []
        self.update_dashboard()
    
    def start_monitoring(self):
        """Start monitoring thread"""
        self.running = True
        self.detection_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.detection_thread.start()
    
    def monitor_loop(self):
        """Continuous monitoring loop"""
        while self.running:
            self.load_data()
            self.update_dashboard()
            self.update_alerts_display()
            self.update_stats()
            threading.Event().wait(5)  # Update every 5 seconds
    
    def update_dashboard(self):
        """Update dashboard metrics and charts"""
        # totals
        total_detected = len(self.alerts)
        self.total_alerts_var.set(str(total_detected))

        # count only "Dangerous Attack" as critical
        def is_critical(level):
            if not level:
                return False
            return 'dangerous' in level.lower()

        critical_count = sum(1 for a in self.alerts if is_critical(a.get('level')))
        self.critical_alerts_var.set(str(critical_count))

        # attacks today
        today = datetime.now().date()
        today_count = 0
        for a in self.alerts:
            ts = a.get('timestamp')
            if not ts:
                continue
            try:
                d = datetime.fromisoformat(ts).date()
            except Exception:
                try:
                    d = datetime.fromtimestamp(float(ts)).date()
                except Exception:
                    continue
            if d == today:
                today_count += 1
        self.today_attacks_var.set(str(today_count))

        # update plots
        self.plot_daily_attacks()
        self.plot_threat_distribution()
        self.plot_normal_attack_ratio()
    
    def plot_daily_attacks(self):
        """Plot daily attack trend"""
        self.fig_daily.clear()
        ax = self.fig_daily.add_subplot(111)
        
        daily_counts = defaultdict(int)
        for alert in self.alerts:
            ts = alert.get('timestamp')
            if not ts:
                continue
            try:
                date = datetime.fromisoformat(ts).date()
            except Exception:
                try:
                    date = datetime.fromtimestamp(float(ts)).date()
                except Exception:
                    continue
            daily_counts[date] += 1
        
        if daily_counts:
            dates = sorted(daily_counts.keys())[-7:]
            counts = [daily_counts[d] for d in dates]
            ax.bar(range(len(dates)), counts, color="#ff6b6b")
            ax.set_xticks(range(len(dates)))
            ax.set_xticklabels([d.strftime("%m-%d") for d in dates])
        
        ax.set_title("Attacks per Day (Last 7 Days)", fontweight="bold")
        ax.set_ylabel("Count")
        self.fig_daily.tight_layout()
        self.canvas_daily.draw()
    
    def plot_threat_distribution(self):
        """Plot threat type distribution"""
        self.fig_threat.clear()
        ax = self.fig_threat.add_subplot(111)
        # Count by severity/level categories (Dangerous, High, Suspicious, Other)
        threat_counts = defaultdict(int)
        for alert in self.alerts:
            lvl = (alert.get('level') or 'Unknown')
            l = lvl.lower()
            if 'danger' in l:
                key = 'Dangerous Attack'
            elif 'high' in l:
                key = 'High Attack'
            elif 'suspec' in l or 'susp' in l or 'suspicious' in l:
                key = 'Suspicious Behavior'
            elif 'low' in l:
                key = 'Low Attack'
            elif 'attack' in l:
                key = 'Attack'
            else:
                key = 'Other'
            threat_counts[key] += 1
        
        if threat_counts:
            types = list(threat_counts.keys())
            counts = list(threat_counts.values())
            ax.pie(counts, labels=types, autopct="%1.1f%%", colors=["#ff6b6b", "#ffd93d", "#6bcf7f"])
        
        ax.set_title("Threat Distribution", fontweight="bold")
        self.fig_threat.tight_layout()
        self.canvas_threat.draw()

    def plot_normal_attack_ratio(self):
        """Plot global normal vs attack ratio computed by grouping runs by timestamp"""
        self.fig_ratio.clear()
        ax = self.fig_ratio.add_subplot(111)

        # Group rows by timestamp (unique runs). For each run, 'Total' is the total captured flows,
        # and number of rows with the same timestamp is number of detected attacks in that run.
        try:
            totals_by_run = {}
            detected_by_run = defaultdict(int)
            # If alerts were parsed from CSV, they don't include 'Total' directly in our normalized structure,
            # so read the CSV file directly to compute totals grouped by timestamp when possible.
            if Path(self.log_file).exists():
                with open(self.log_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        ts = row.get('TimeStamp') or row.get('TimeStamp') or row.get('timestamp') or row.get('Time Stamp')
                        if not ts:
                            continue
                        try:
                            tot = int(row.get('Total')) if row.get('Total') not in (None, '') else 0
                        except Exception:
                            try:
                                tot = int(float(row.get('Total')))
                            except Exception:
                                tot = 0
                        # record total for that run (if multiple rows present, keep first non-zero)
                        if ts not in totals_by_run or totals_by_run[ts] == 0:
                            totals_by_run[ts] = tot
                        detected_by_run[ts] += 1

            total_flows = sum(totals_by_run.values())
            total_detected = sum(detected_by_run.values())

            # As a fallback, if CSV grouping isn't available, use alerts list: assume each alert is a detection
            if total_flows == 0:
                # estimate using last run totals if available in any alert dict under 'Total'
                total_detected = len(self.alerts)
                # try to get a last run Total from any alert parsed earlier
                last_total = None
                for a in reversed(self.alerts):
                    if 'Total' in a and a['Total']:
                        try:
                            last_total = int(a['Total'])
                            break
                        except Exception:
                            continue
                total_flows = last_total or total_detected or 0

            normal = max(total_flows - total_detected, 0)
            attack = total_detected

            labels = []
            sizes = []
            if normal > 0:
                labels.append('Normal')
                sizes.append(normal)
            if attack > 0:
                labels.append('Attack')
                sizes.append(attack)

            if sizes:
                colors = ['#6bcf7f', '#ff6b6b']
                ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors[:len(sizes)])
                ax.set_title('Normal vs Attack (global)', fontweight='bold')
            else:
                ax.text(0.5, 0.5, 'No data', horizontalalignment='center', verticalalignment='center')
        except Exception:
            ax.text(0.5, 0.5, 'Error', horizontalalignment='center', verticalalignment='center')

        self.fig_ratio.tight_layout()
        self.canvas_ratio.draw()
    
    def update_alerts_display(self):
        """Update live alerts text widget"""
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        # show occurrence counts per flow in the alerts text
        counts = Counter([a.get('flow_id') for a in self.alerts if a.get('flow_id')])
        for alert in sorted(self.alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:50]:
            timestamp = alert.get("timestamp", "N/A")
            level = alert.get("level", "Unknown")
            flow = alert.get("flow_id", "N/A")
            prf = alert.get('prob_rf')
            pxg = alert.get('prob_xgb')
            occ = counts.get(flow) or 0

            line = f"[{timestamp}] Flow: {flow} | Occurrences: {occ} | Level: {level} | RF: {prf if prf is not None else 'N/A'} | XG: {pxg if pxg is not None else 'N/A'}\n"
            tag = "critical" if (level and ('danger' in level.lower() or 'critical' in level.lower())) else "warning" if (level and 'high' in level.lower()) else "info"
            self.alerts_text.insert(tk.END, line, tag)
        
        self.alerts_text.config(state=tk.DISABLED)
    
    def update_stats(self):
        """Update statistics tab"""
        self.plot_weekly_trend()
        self.plot_attack_types()
        self.update_logs_display()
        # refresh per-sniff summaries table
        try:
            self.load_sniff_summary()
        except Exception:
            pass
    
    def plot_weekly_trend(self):
        """Plot weekly trend"""
        self.fig_weekly.clear()
        ax = self.fig_weekly.add_subplot(111)
        
        daily_counts = defaultdict(int)
        for alert in self.alerts:
            ts = alert.get('timestamp')
            if not ts:
                continue
            try:
                date = datetime.fromisoformat(ts).date()
            except Exception:
                try:
                    date = datetime.fromtimestamp(float(ts)).date()
                except Exception:
                    continue
            daily_counts[date] += 1
        
        if daily_counts:
            dates = sorted(daily_counts.keys())[-7:]
            counts = [daily_counts[d] for d in dates]
            ax.plot(range(len(dates)), counts, marker='o', color="#4ecdc4", linewidth=2)
            ax.fill_between(range(len(dates)), counts, alpha=0.3, color="#4ecdc4")
            ax.set_xticks(range(len(dates)))
            ax.set_xticklabels([d.strftime("%a") for d in dates])
        
        ax.set_title("Weekly Attack Trend", fontweight="bold")
        ax.set_ylabel("Attack Count")
        self.fig_weekly.tight_layout()
        self.canvas_weekly.draw()
    
    def plot_attack_types(self):
        """Plot attack types pie chart"""
        self.fig_types.clear()
        ax = self.fig_types.add_subplot(111)
        threat_counts = defaultdict(int)
        for alert in self.alerts:
            lvl = (alert.get('level') or 'Unknown')
            l = lvl.lower()
            if 'danger' in l:
                key = 'Dangerous Attack'
            elif 'high' in l:
                key = 'High Attack'
            elif 'suspec' in l or 'susp' in l or 'suspicious' in l:
                key = 'Suspicious Behavior'
            elif 'low' in l:
                key = 'Low Attack'
            elif 'attack' in l:
                key = 'Attack'
            else:
                key = 'Other'
            threat_counts[key] += 1
        
        if threat_counts:
            types = list(threat_counts.keys())
            counts = list(threat_counts.values())
            colors = ["#ff6b6b", "#ffd93d", "#6bcf7f", "#4ecdc4", "#95a5a6"]
            ax.pie(counts, labels=types, autopct="%1.1f%%", colors=colors[:len(types)])
        
        ax.set_title("Attack Type Distribution", fontweight="bold")
        self.fig_types.tight_layout()
        self.canvas_types.draw()
    
    def update_logs_display(self):
        """Display raw JSON logs"""
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.delete(1.0, tk.END)
        
        log_display = json.dumps(self.alerts[-20:], indent=2)
        self.logs_text.insert(tk.END, log_display)
        self.logs_text.config(state=tk.DISABLED)

    def load_sniff_summary(self):
        """Load per-sniff summaries from Logs/sniff_summary.csv into the summary Treeview"""
        try:
            tree = getattr(self, 'summary_tree', None)
            if tree is None:
                return
            # clear
            for r in tree.get_children():
                tree.delete(r)
            path = Path('./Logs/sniff_summary.csv')
            if not path.exists():
                return
            with open(path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    tree.insert('', tk.END, values=(row.get('TimeStamp') or row.get('TimeStamp') or row.get('timestamp') or '', row.get('Packets') or '', row.get('Flows') or '', row.get('Top_RF_Flow') or '', row.get('Top_RF_Prob') or '', row.get('Top_XGB_Flow') or '', row.get('Top_XGB_Prob') or ''))
        except Exception:
            return
    
    def on_closing(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSDashboard(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()