import os
import math
import pandas as pd
import numpy as np
from datetime import datetime
from tkcalendar import DateEntry

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import MiniBatchKMeans


def perform_clustering(X, n_clusters):
    """
    Perform clustering on feature matrix X
    """
    model = MiniBatchKMeans(
        n_clusters=n_clusters,
        random_state=42,
        batch_size=256,
        n_init=10
    )

    labels = model.fit_predict(X)
    return labels, model


def extract_disk_evidence(base_path):
    """
    Traverse disk/folder and extract forensic metadata
    """
    records = []

    for root, _, files in os.walk(base_path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                stat = os.stat(full_path)
            except Exception:
                continue

            records.append({
                "File_Path": full_path,
                "File_Name": file,
                "Extension": os.path.splitext(file)[1].lower() or ".none",
                "File_Size": stat.st_size,
                "Access_Time": int(stat.st_atime),
                "Modify_Time": int(stat.st_mtime),
                "Create_Time": int(stat.st_ctime)
            })

    return pd.DataFrame(records)

def apply_time_filter(df, start_date=None, end_date=None):
    """
    Filter evidence based on modification time window
    """
    if start_date:
        start_ts = int(datetime.strptime(start_date, "%Y-%m-%d").timestamp())
        df = df[df["Modify_Time"] >= start_ts]

    if end_date:
        end_ts = int(datetime.strptime(end_date, "%Y-%m-%d").timestamp())
        df = df[df["Modify_Time"] <= end_ts]

    return df

def apply_keyword_filter(df, extensions=None):
    """
    Filter suspicious file types quickly
    Example: ['.exe', '.zip', '.docx']
    """
    if not extensions:
        return df

    extensions = [e.lower() for e in extensions]
    return df[df["Extension"].isin(extensions)]

def prepare_forensic_features(df):
    """
    Convert raw forensic metadata into ML features
    """
    df = df.copy()

    # Relative time behavior
    df["Modify_Rel"] = df["Modify_Time"] - df["Modify_Time"].min()
    df["Access_Rel"] = df["Access_Time"] - df["Access_Time"].min()

    # Log scale for file size
    df["Size_Log"] = df["File_Size"].apply(lambda x: math.log(x + 1))

    features = df[["Modify_Rel", "Access_Rel", "Size_Log"]]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)

    return X_scaled, scaler

def forensic_clustering_engine(df):
    """
    Fast clustering + suspicious evidence detection
    """
    X_scaled, scaler = prepare_forensic_features(df)

    # Dynamic cluster count
    k = max(2, int(math.sqrt(len(df))))
    k = min(k, 10)

    model = MiniBatchKMeans(
        n_clusters=k,
        batch_size=256,
        random_state=42
    )

    df["Cluster"] = model.fit_predict(X_scaled)

    # Anomaly score (distance from centroid)
    distances = model.transform(X_scaled)
    df["Anomaly_Score"] = distances.min(axis=1)

    # Threat threshold (top 5%)
    threshold = np.percentile(df["Anomaly_Score"], 95)
    df["Threat_Flag"] = (df["Anomaly_Score"] > threshold).astype(int)

    return df, model

def run_complete_forensic_pipeline(
    disk_path,
    start_date=None,
    end_date=None,
    suspicious_extensions=None
    ):
    """
    End-to-end backend pipeline
    """

    # Step 1: Evidence extraction
    df = extract_disk_evidence(disk_path)

    if df.empty:
        return df

    # Step 2: Time-frame filtering
    df = apply_time_filter(df, start_date, end_date)

    # Step 3: Keyword/extension filtering
    df = apply_keyword_filter(df, suspicious_extensions)

    if df.empty:
        return df

    # Step 4: Fast clustering + detection
    df, model = forensic_clustering_engine(df)

    return df

"""
forensic_gui_prototype.py

A single-file prototype GUI for:
"A Fast Clustering-Based Evidence Extraction System for Digital Forensics"

Features:
- Browse folder (simulates disk image contents)
- Extract metadata (filename, path, ext, size, mtime, ctime, atime)
- Time-window filtering (Start date / End date)
- Optional simple keyword match for text files
- Fast clustering using MiniBatchKMeans
- Display results in GUI table, cluster summary
- Export CSV report

Usage: python forensic_gui_prototype.py
"""

import os
import threading
import time
from datetime import datetime
import math
import csv
import re
import hashlib

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.cluster import MiniBatchKMeans
from sklearn.decomposition import PCA

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# =========================
# Theme Colors
# =========================
'''BG_DARK = "#0f172a"
BG_PANEL = "#1e293b"
FG_TEXT = "#e2e8f0"
ACCENT_BLUE = "#0ea5e9"
ACCENT_GREEN = "#22c55e"
ACCENT_ORANGE = "#f97316"
ACCENT_RED = "#ef4444"
FONT_MAIN = ("Consolas", 11)
FONT_TITLE = ("Consolas", 16, "bold")'''

# optional: file type detection
# try:
#     import magic
#     MAGIC_AVAILABLE = True
# except Exception:
#     MAGIC_AVAILABLE = False

MAGIC_AVAILABLE = False

# ----------------------------
# Utility functions
# ----------------------------
def detect_sensitive_data(file_path):
    patterns = {
        "Aadhaar": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
        "PAN Card": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
    }

    findings = []

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

            for key, pattern in patterns.items():
                if re.search(pattern, content):
                    findings.append(key)
    except:
        pass

    return findings

def get_file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

def human_readable_size(size):
    for unit in ['B','KB','MB','GB','TB']:
        if size < 1024.0:
            return f"{size:3.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def safe_ext(fname):
    _, ext = os.path.splitext(fname)
    return ext.lower() if ext else '.none'

'''def detect_type(path):
    if MAGIC_AVAILABLE:
        try:
            m = magic.from_file(path, mime=True)
            return m
        except Exception:
            return safe_ext(path)
    else:
        return safe_ext(path)'''
        
def detect_type(path):
    return safe_ext(path)
    
# def calculate_suspicion_score(df, start_ts=None, end_ts=None):
#     scores = []
#     reasons = []

#     for _, row in df.iterrows():
#         score = 0
#         reason = []

#         # 1️⃣ Modified in selected time range
#         if start_ts and end_ts:
#             if start_ts <= row['mtime'] <= end_ts:
#                 score += 3
#                 reason.append("Modified in selected time range")

#         # 2️⃣ Suspicious extensions
#         if row['ext'] in ['.exe', '.dll', '.bat', '.ps1', '.zip', '.rar']:
#             score += 3
#             reason.append("Executable or archive file")

#         # 3️⃣ Recently accessed
#         recent_limit = int(time.time()) - (7 * 24 * 60 * 60)
#         if row['atime'] >= recent_limit:
#             score += 2
#             reason.append("Recently accessed")

#         # 4️⃣ Large file size
#         if row['size'] > 10 * 1024 * 1024:
#             score += 1
#             reason.append("Large file size")

#         scores.append(score)
#         reasons.append("; ".join(reason) if reason else "Normal behavior")

#     df['Suspicion_Score'] = scores
#     df['Suspicious'] = df['Suspicion_Score'] >= 5
#     df['Suspicion_Reason'] = reasons

#     return df

def calculate_suspicion_score(df, start_ts=None, end_ts=None):
    scores = []
    reasons = []

    suspicious_keywords = [
        "hack", "attack", "password", "malware",
        "trojan", "virus", "keylogger", "exploit"
    ]

    for _, row in df.iterrows():
        score = 0
        reason = []

        filename = row['name'].lower()

        # 1️⃣ Time-based
        if start_ts and end_ts:
            if start_ts <= row['mtime'] <= end_ts:
                score += 2
                reason.append("Modified in selected time range")

        # 2️⃣ Suspicious extensions
        if row['ext'] in ['.exe', '.dll', '.bat', '.ps1', '.zip', '.rar']:
            score += 3
            reason.append("Executable or archive")

        # 3️⃣ Recently accessed
        recent_limit = int(time.time()) - (7 * 24 * 60 * 60)
        if row['atime'] >= recent_limit:
            score += 2
            reason.append("Recently accessed")

        # 4️⃣ Large file
        if row['size'] > 5 * 1024 * 1024:
            score += 1
            reason.append("Large file")

        # 5️⃣ 🔥 Suspicious filename keywords
        for kw in suspicious_keywords:
            if kw in filename:
                score += 3
                reason.append(f"Keyword detected: {kw}")
                break

        # 6️⃣ 🔥 DOUBLE EXTENSION DETECTION
        if filename.count('.') >= 2:
            score += 3
            reason.append("Double extension detected")
            
        # 8️⃣ Keyword-based detection 🔥🔥🔥
        if 'Keyword_Match' in df.columns and row.get('Keyword_Match'):
            score += 4
            reason.append(f"Keyword match: {row.get('Keyword_Reason')}")
            
        # 🔥 Sensitive Data Detection
        sensitive = detect_sensitive_data(row['path'])
        if sensitive:
            score += 5
            reason.append(f"Sensitive data: {', '.join(sensitive)}")
        
        # Duplicate Files    
        if row.get('Duplicate'):
            score += 2
            reason.append("Duplicate file")

        # 7️⃣ 🔥 LOG FILE CONTENT CHECK
        if row['ext'] == '.log':
            try:
                with open(row['path'], 'r', errors='ignore') as f:
                    content = f.read().lower()
                    for kw in suspicious_keywords:
                        if kw in content:
                            score += 4
                            reason.append(f"Suspicious log content: {kw}")
                            break
            except:
                pass

        scores.append(score)
        reasons.append("; ".join(reason) if reason else "Normal")

    df['Suspicion_Score'] = scores
    df['Suspicious'] = df['Suspicion_Score'] >= 4   # 🔥 LOWERED THRESHOLD

    df['Suspicion_Reason'] = reasons

    return df

# ----------------------------
# Core pipeline functions
# ----------------------------
def list_files_recursive(folder):
    rows = []
    for root, dirs, files in os.walk(folder):
        for fn in files:
            full = os.path.join(root, fn)
            try:
                st = os.stat(full)
            except Exception:
                continue
            rows.append({
                'path': full,
                'name': fn,
                'ext': safe_ext(fn),
                'size': int(st.st_size),
                'mtime': int(st.st_mtime),
                'ctime': int(st.st_ctime),
                'atime': int(st.st_atime)
            })
    return pd.DataFrame(rows)

def filter_by_time(df, start_ts=None, end_ts=None):
    if start_ts is None and end_ts is None:
        return df.copy()
    if start_ts is None:
        start_ts = df['mtime'].min()
    if end_ts is None:
        end_ts = df['mtime'].max()
    return df[(df['mtime'] >= start_ts) & (df['mtime'] <= end_ts)].copy()

DEFAULT_KEYWORDS = [
    "password", "admin", "login", "failed",
    "unauthorized", "malware", "attack",
    "error", "access denied", "root"
]
    
# def keyword_filter(df, keywords):
#     if not keywords:
#         return df

#     keywords = [k.lower().strip() for k in keywords if k.strip()]
#     if not keywords:
#         return df

#     matched_rows = []

#     for _, row in df.iterrows():
#         ext = row['ext'].lower()
#         path = row['path']
#         matched = False

#         for k in keywords:
#             # 1️⃣ EXTENSION-BASED MATCH (FAST)
#             if k.startswith(".") and ext == k:
#                 matched = True
#                 break

#             # 2️⃣ CONTENT-BASED MATCH (TEXT FILES ONLY)
#             if not k.startswith(".") and ext in [
#                 '.txt', '.log', '.csv', '.md', '.json', '.xml'
#             ]:
#                 try:
#                     with open(path, 'r', errors='ignore') as f:
#                         content = f.read().lower()
#                         if k in content:
#                             matched = True
#                             break
#                 except Exception:
#                     pass

#         matched_rows.append(matched)

#     return df[matched_rows]

def keyword_filter(df, keywords):
    if not keywords:
        return df

    keywords = [k.lower().strip() for k in keywords if k.strip()]
    if not keywords:
        return df

    # 🔹 Separate extension & text keywords
    ext_keywords = [k for k in keywords if k.startswith(".")]
    text_keywords = [k for k in keywords if not k.startswith(".")]

    result_df = pd.DataFrame()

    # =========================
    # ✅ EXTENSION FILTER (STRICT)
    # =========================
    if ext_keywords:
        ext_df = df[df['ext'].isin(ext_keywords)]
        result_df = pd.concat([result_df, ext_df])

    # =========================
    # ✅ TEXT FILTER (NAME + CONTENT)
    # =========================
    if text_keywords:
        matched_rows = []

        for _, row in df.iterrows():
            name = row['name'].lower()
            ext = row['ext']
            path = row['path']

            matched = False

            for k in text_keywords:
                # filename match
                if k in name:
                    matched = True
                    break

                # content match (ONLY for text files)
                if ext in ['.txt', '.log', '.csv', '.json', '.xml']:
                    try:
                        with open(path, 'r', errors='ignore') as f:
                            content = f.read().lower()
                            if k in content:
                                matched = True
                                break
                    except:
                        pass

            matched_rows.append(matched)

        text_df = df[matched_rows]
        result_df = pd.concat([result_df, text_df])

    # =========================
    # ✅ FINAL CLEAN
    # =========================
    result_df = result_df.drop_duplicates()

    return result_df


def prepare_features(df, scaler=None, encoder=None, fit=False):
    if df.shape[0] == 0:
        return np.zeros((0, 1)), None, None

    # Relative modification time
    min_m = df['mtime'].min()
    df['mtime_rel'] = df['mtime'] - min_m

    # Log-scaled file size
    df['size_log'] = df['size'].apply(lambda s: math.log(s + 1))

    num = df[['size_log', 'mtime_rel']].values.astype(float)

    if scaler is None:
        scaler = StandardScaler()

    num_scaled = scaler.fit_transform(num) if fit else scaler.transform(num)

    # One-hot encode file extensions (FIXED)
    exts = df[['ext']].fillna('.none')

    if encoder is None:
        encoder = OneHotEncoder(
            sparse_output=False,   # ✅ FIX
            handle_unknown='ignore'
        )

    cat = encoder.fit_transform(exts) if fit else encoder.transform(exts)

    X = np.hstack([num_scaled, cat])
    return X, scaler, encoder

def run_clustering(self):
    if self.df_filtered.shape[0] == 0:
        messagebox.showwarning("No data", "No filtered files to cluster.")
        return

    self.progress['value'] = 5
    self.root.update_idletasks()

    # ---- FEATURE PREPARATION ----
    X, self.scaler, self.encoder = prepare_features(
        self.df_filtered,
        scaler=None,
        encoder=None,
        fit=True
    )

    self.progress['value'] = 40
    self.root.update_idletasks()

    # ---- CLUSTERING ----
    n = max(2, int(math.sqrt(len(X))))
    n = min(n, 10)

    labels, model = run_clustering(X, n_clusters=n)
    self.model = model
    self.df_filtered['cluster'] = labels

    # ---- SUSPICION SCORING (CRITICAL) ----
    start_ts = None
    end_ts = None

    if self.start_entry.get().strip():
        start_ts = int(datetime.strptime(
            self.start_entry.get(), "%Y-%m-%d"
        ).timestamp())

    if self.end_entry.get().strip():
        end_ts = int(datetime.combine(
            datetime.strptime(self.end_entry.get(), "%Y-%m-%d"),
            datetime.max.time()
        ).timestamp())

    self.df_filtered = calculate_suspicion_score(
        self.df_filtered,
        start_ts=start_ts,
        end_ts=end_ts
    )

    # ---- KEEP ONLY SUSPICIOUS FILES ----
    self.df_filtered = self.df_filtered[self.df_filtered['Suspicious'] == True]

    self.progress['value'] = 90
    self.root.update_idletasks()

    # ---- DISPLAY ----
    self.df_filtered['size_hr'] = self.df_filtered['size'].apply(human_readable_size)
    self.df_filtered['mtime_dt'] = self.df_filtered['mtime'].apply(
        lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
    )

    self.update_table(self.df_filtered)
    self.update_summary()

    self.progress['value'] = 100
    messagebox.showinfo(
        "Detection Complete",
        f"Suspicious files detected: {len(self.df_filtered)}"
    )

    
# ----------------------------
# GUI Implementation
# ----------------------------
class ForensicGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Fast Clustering-Based Evidence Extraction (Prototype)")
        self.root.geometry("1000x700")

        # State
        self.df_all = pd.DataFrame()
        self.df_filtered = pd.DataFrame()
        self.scaler = None
        self.encoder = None
        self.model = None

        # Top frame (inputs)
        top = tk.Frame(root)
        top.pack(fill='x', padx=10, pady=8)

        tk.Label(top, text="Select Folder (Evidence):").grid(row=0, column=0, sticky='w')
        self.entry_folder = tk.Entry(top, width=70)
        self.entry_folder.grid(row=0, column=1, padx=6)
        tk.Button(top, text="Browse", command=self.browse_folder).grid(row=0, column=2, padx=6)

        # tk.Label(top, text="Start Date (YYYY-MM-DD) :").grid(row=1, column=0, sticky='w', pady=6)
        # self.start_entry = tk.Entry(top, width=20)
        # self.start_entry.grid(row=1, column=1, sticky='w', padx=6)
        # tk.Label(top, text="End Date (YYYY-MM-DD) :").grid(row=1, column=1, sticky='e', padx=100)
        # self.end_entry = tk.Entry(top, width=20)
        # self.end_entry.grid(row=1, column=2, sticky='w')

        tk.Label(top, text="Start Date :").grid(row=1, column=0, sticky='w', pady=6)

        self.start_entry = DateEntry(
        top,
        width=18,
        date_pattern='yyyy-mm-dd'
        )
        self.start_entry.grid(row=1, column=1, sticky='w', padx=6)

        tk.Label(top, text="End Date :").grid(row=1, column=1, sticky='e', padx=100)

        self.end_entry = DateEntry(
        top,
        width=18,
        date_pattern='yyyy-mm-dd'
        )
        self.end_entry.grid(row=1, column=2, sticky='w')

        # tk.Label(top, text="Keywords (comma-separated, optional) :").grid(row=2, column=0, sticky='w', pady=6)
        # self.kw_entry = tk.Entry(top, width=70)
        # self.kw_entry.grid(row=2, column=1, padx=6)

        tk.Label(top, text="Threat Keywords (e.g. password, admin, attack) :").grid(row=2, column=0, sticky='w', pady=6)

        self.kw_entry = tk.Entry(top, width=70)
        self.kw_entry.grid(row=2, column=1, padx=6)
        
        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(fill='x', padx=10, pady=6)
        tk.Button(btn_frame, text="Load Files", command=self.load_files, bg="#2E86C1", fg="white").pack(side='left', padx=6)
        tk.Button(btn_frame, text="Apply Filters", command=self.apply_filters, bg="#27AE60", fg="white").pack(side='left', padx=6)
        tk.Button(btn_frame, text="Run Clustering", command=self.start_clustering_thread, bg="#D35400", fg="white").pack(side='left', padx=6)
        tk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side='left', padx=6)
        tk.Button(btn_frame, text="Clear", command=self.clear_all).pack(side='left', padx=6)

        # Progress and summary
        status_frame = tk.Frame(root)
        status_frame.pack(fill='x', padx=10, pady=6)
        self.progress = ttk.Progressbar(status_frame, orient="horizontal", length=350, mode="determinate")
        self.progress.pack(side='left', padx=6)
        self.summary_label = tk.Label(status_frame, text="Summary: No data loaded.", anchor='w', justify='left')
        self.summary_label.pack(side='left', padx=12)

        # Results table
        table_frame = tk.Frame(root)
        table_frame.pack(fill='both', expand=True, padx=10, pady=6)
        cols = ("path", "name", "ext", "size", "mtime", "cluster")
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings')
        for c in cols:
            self.tree.heading(c, text=c)
            if c=='path':
                self.tree.column(c, width=380)
            elif c=='name':
                self.tree.column(c, width=180)
            else:
                self.tree.column(c, width=100, anchor='center')
        self.tree.pack(fill='both', expand=True, side='left')
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=vsb.set)

    def browse_folder(self):
        path = filedialog.askdirectory()
        if not path:
            return

        # Warn if user selected a disk image file by mistake
        if path.lower().endswith((".dd", ".img", ".e01")):
            messagebox.showerror(
            "Invalid Selection",
            "Please mount the disk image and select the mounted folder/drive."
            )
            return

        self.entry_folder.delete(0, tk.END)
        self.entry_folder.insert(0, path)


    def load_files(self):
        folder = self.entry_folder.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return
        self.progress['value'] = 0
        self.root.update_idletasks()
        self.df_all = list_files_recursive(folder)
        # 🔥 Duplicate Detection
        self.df_all['hash'] = self.df_all['path'].apply(get_file_hash)
        duplicates = self.df_all[self.df_all.duplicated('hash', keep=False)]
        self.df_all['Duplicate'] = self.df_all['hash'].isin(duplicates['hash'])
        
        # add human readable fields for display
        self.df_all['size_hr'] = self.df_all['size'].apply(human_readable_size)
        self.df_all['mtime_dt'] = self.df_all['mtime'].apply(lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S"))
        self.df_filtered = self.df_all.copy()
        self.update_table(self.df_filtered)
        self.update_summary()
        
    def apply_filters(self):
        if self.df_all.shape[0] == 0:
            messagebox.showwarning("No data", "Load files first.")
            return

        start_txt = self.start_entry.get().strip()
        end_txt = self.end_entry.get().strip()

        start_ts = None
        end_ts = None

        if start_txt != "":
            try:
                start_dt = datetime.strptime(start_txt, "%Y-%m-%d")
                start_ts = int(start_dt.timestamp())
            except ValueError:
                messagebox.showerror(
                "Date Error",
                "Start Date must be in YYYY-MM-DD format"
                )
                return

        if end_txt != "":
            try:
                end_dt = datetime.strptime(end_txt, "%Y-%m-%d")
                end_ts = int(datetime.combine(end_dt, datetime.max.time()).timestamp())
            except ValueError:
                messagebox.showerror(
                "Date Error",
                "End Date must be in YYYY-MM-DD format"
                )
                return

        df = filter_by_time(self.df_all, start_ts, end_ts)
        
        # keywords = []
        # if self.kw_entry.get().strip() != "":
        #     keywords = [k.strip() for k in self.kw_entry.get().split(",")]
        
        # ✅ User keywords
        user_keywords = []
        if self.kw_entry.get().strip() != "":
            user_keywords = [k.strip() for k in self.kw_entry.get().split(",")]

        # ✅ Combine default + user keywords
        #keywords = list(set(DEFAULT_KEYWORDS + user_keywords))
        # ✅ ONLY use user keywords for filtering
        keywords = user_keywords

        # ✅ If you want default keywords, use ONLY when user enters nothing
        if not keywords:
            keywords = DEFAULT_KEYWORDS

        # if keywords:
        #     df = keyword_filter(df, keywords)
        
        if self.kw_entry.get().strip() != "":
            df = keyword_filter(df, keywords)

        self.df_filtered = df
        self.update_table(df)
        self.update_summary()


    def start_clustering_thread(self):
        # run clustering in background to avoid GUI freeze
        t = threading.Thread(target=self.run_clustering)
        t.daemon = True
        t.start()

    # def run_clustering(self):
    #     if self.df_filtered.shape[0] == 0:
    #         messagebox.showwarning("No data", "No filtered files to cluster.")
    #         return
    #     self.progress['value'] = 5
    #     self.root.update_idletasks()
    #     X, self.scaler, self.encoder = prepare_features(self.df_filtered, scaler=None, encoder=None, fit=True)
    #     self.progress['value'] = 40
    #     self.root.update_idletasks()

    #     # choose cluster count heuristically: sqrt(n) or min(10,n)
    #     n = max(1, int(math.sqrt(max(1, X.shape[0]))))
    #     n = min(n, 12)
    #     labels, model = perform_clustering(X, n_clusters=n)
    #     self.model = model
    #     self.df_filtered['cluster'] = labels
    #     self.progress['value'] = 80
    #     self.root.update_idletasks()

    #     # update table
    #     self.df_filtered['size_hr'] = self.df_filtered['size'].apply(human_readable_size)
    #     self.df_filtered['mtime_dt'] = self.df_filtered['mtime'].apply(lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S"))
    #     self.update_table(self.df_filtered)
    #     self.update_summary()
    #     self.progress['value'] = 100
    #     self.root.update_idletasks()
    #     messagebox.showinfo("Clustering Done", f"Clustering finished. Found {len(np.unique(labels))} clusters.")

    def run_clustering(self):
        if self.df_filtered.shape[0] == 0:
            messagebox.showwarning("No data", "No filtered files to cluster.")
            return

        self.progress['value'] = 5
        self.root.update_idletasks()

        # ---- FEATURE PREPARATION ----
        X, self.scaler, self.encoder = prepare_features(
            self.df_filtered,
            scaler=None,
            encoder=None,
            fit=True
        )

        self.progress['value'] = 40
        self.root.update_idletasks()

        # ---- CLUSTERING ----
        n = max(1, int(math.sqrt(max(1, X.shape[0]))))
        n = min(n, 12)

        labels, model = perform_clustering(X, n_clusters=n)
        self.model = model
        self.df_filtered['cluster'] = labels

        # =============================
        # ✅ ADD THIS BLOCK (CRITICAL FIX)
        # =============================
        start_ts = None
        end_ts = None

        if self.start_entry.get().strip():
            start_ts = int(datetime.strptime(
                self.start_entry.get(), "%Y-%m-%d"
            ).timestamp())

        if self.end_entry.get().strip():
            end_ts = int(datetime.combine(
                datetime.strptime(self.end_entry.get(), "%Y-%m-%d"),
                datetime.max.time()
            ).timestamp())

        # ✅ APPLY SUSPICION SCORING
        self.df_filtered = calculate_suspicion_score(
            self.df_filtered,
            start_ts=start_ts,
            end_ts=end_ts
        )

        # ✅ KEEP ONLY SUSPICIOUS FILES
        self.df_filtered = self.df_filtered[
            self.df_filtered['Suspicious'] == True
        ]
        # =============================

        self.progress['value'] = 80
        self.root.update_idletasks()

        # ---- UPDATE TABLE ----
        if self.df_filtered.shape[0] > 0:
            self.df_filtered['size_hr'] = self.df_filtered['size'].apply(human_readable_size)
            self.df_filtered['mtime_dt'] = self.df_filtered['mtime'].apply(
                lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
            )

        self.update_table(self.df_filtered)
        self.update_summary()

        self.progress['value'] = 100
        self.root.update_idletasks()

        messagebox.showinfo(
            "Detection Complete",
            f"Suspicious files detected: {len(self.df_filtered)}"
        )


    def update_table(self, df):
        # clear
        for it in self.tree.get_children():
            self.tree.delete(it)
        # insert rows
        if df.shape[0] == 0:
            return
        display_df = df.copy()
        # ensure cluster column exists
        if 'cluster' not in display_df.columns:
            display_df['cluster'] = -1
        for _, row in display_df.iterrows():
            self.tree.insert('', 'end', values=(row['path'], row['name'], row['ext'], row['size_hr'], row['mtime_dt'], int(row['cluster'])))

    def update_summary(self):
        total = len(self.df_all)
        filtered = len(self.df_filtered)
        clusters = len(self.df_filtered['cluster'].unique()) if 'cluster' in self.df_filtered.columns else 0
        txt = f"Total files: {total}    Filtered: {filtered}    Clusters: {clusters}"
        self.summary_label.config(text=txt)

        
    def export_csv(self):
        if self.df_filtered.shape[0] == 0:
            messagebox.showwarning(
                "No Evidence",
                "No suspicious files detected to export."
            )
            return
        
        if 'Suspicion_Score' not in self.df_filtered.columns:
            messagebox.showerror(
                "Missing Analysis",
                "Suspicion scoring not performed.\nPlease run clustering & analysis first."
            )
            return

        out = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
            title="Save suspicious forensic evidence report"
        )

        if not out:
            return

        df_out = self.df_filtered.copy()

        df_out['size_hr'] = df_out['size'].apply(human_readable_size)
        df_out['mtime_dt'] = df_out['mtime'].apply(
            lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
        )
        df_out['Report_Generated_At'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        df_out = df_out.sort_values(
            by='Suspicion_Score',
            ascending=False
        )

        df_out.to_csv(
            out,
            index=False,
            columns=[
                'path',
                'name',
                'ext',
                'size_hr',
                'mtime_dt',
                'cluster',
                'Suspicion_Score',
                'Suspicion_Reason'
            ]
        )

        messagebox.showinfo(
            "Report Generated",
            "Suspicious evidence report saved successfully."
        )


    def clear_all(self):
        self.entry_folder.delete(0, tk.END)
        self.start_entry.delete(0, tk.END)
        self.end_entry.delete(0, tk.END)
        self.kw_entry.delete(0, tk.END)
        self.df_all = pd.DataFrame()
        self.df_filtered = pd.DataFrame()
        self.update_table(self.df_filtered)
        self.update_summary()
        self.progress['value'] = 0

# ----------------------------
# Run
# ----------------------------
def main():
    root = tk.Tk()
    app = ForensicGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
