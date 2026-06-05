# 🔍 Intelligent Digital Forensic Analysis System

A Python-based Digital Forensic Analysis System that combines **Machine Learning**, **Anomaly Detection**, and **Rule-Based Analysis** to automatically identify suspicious files and assist investigators during digital forensic investigations.

---

## 📖 Overview

Digital forensic investigations often involve analyzing thousands of files to identify potential evidence. Manual analysis is time-consuming and prone to errors. This project automates the process by extracting file metadata, applying machine learning-based clustering, and using forensic rules to detect suspicious files.

The system helps investigators quickly identify files that may require further examination based on factors such as file type, timestamps, file size, keywords, sensitive information, duplicate files, and malware indicators.

---

## ✨ Features

### 📂 File Metadata Extraction

* File Name
* File Path
* File Size
* File Extension
* Creation Time
* Modification Time
* Access Time

### 📅 Time-Based Filtering

* Filter files within a specific date range.
* Focus investigations on relevant time periods.

### 🔎 Threat Keyword Detection

Searches file names and content for suspicious keywords such as:

```text
password
admin
login
unauthorized
malware
attack
access denied
root
confidential
```

### 🤖 Machine Learning-Based Detection

* MiniBatch K-Means Clustering
* Anomaly Detection
* Suspicious File Identification
* Outlier Analysis

### ⚠️ Suspicion Scoring System

Files are evaluated using:

* Suspicious file extensions
* Recent file activity
* File size anomalies
* Threat keywords
* Sensitive data indicators
* Clustering anomalies

### 🪪 Sensitive Data Detection

Detects:

* Aadhaar Numbers
* Email Addresses
* Credit Card Patterns
* Phone Numbers

### 📄 Duplicate File Detection

Uses file hashing to identify duplicate files and reduce redundant evidence.

### 🦠 Malware Indicator Detection

Flags potentially malicious files based on:

* Executable extensions
* Double extensions
* Suspicious naming patterns
* Hidden executable behavior

### 🖥️ Graphical User Interface (GUI)

Built using Tkinter:

* Folder Selection
* Date Filters
* Threat Keyword Filters
* Run Analysis
* Export Results

### 📊 CSV Report Generation

Generate investigation reports containing:

* Suspicious File List
* Suspicion Scores
* Detection Reasons
* Clustering Results

---

## 🏗️ System Architecture

```text
User Input
     │
     ▼
File Extraction Module
     │
     ▼
Preprocessing & Feature Engineering
     │
     ▼
Threat Keyword Filtering
     │
     ▼
Machine Learning Clustering
     │
     ▼
Anomaly Detection
     │
     ▼
Suspicion Scoring Engine
     │
     ▼
Sensitive Data Detection
     │
     ▼
Duplicate File Detection
     │
     ▼
Result Visualization (GUI)
     │
     ▼
CSV Report Generation
```

---

## 🛠️ Technologies Used

* Python
* Pandas
* NumPy
* Scikit-Learn
* Tkinter
* MiniBatch K-Means
* Hashlib
* Regular Expressions (Regex)

---

## 📋 Detection Parameters

| Parameter          | Purpose                            |
| ------------------ | ---------------------------------- |
| File Extension     | Detect risky file types            |
| File Size          | Identify abnormal file sizes       |
| Access Time        | Detect recently accessed files     |
| Modify Time        | Detect recently modified files     |
| Threat Keywords    | Search suspicious terms            |
| Sensitive Data     | Detect Aadhaar, Email, Credit Card |
| Duplicate Files    | Identify repeated files            |
| Anomaly Score      | Detect outlier behavior            |
| Malware Indicators | Flag suspicious executables        |

---

## 🚀 How to Run

### Install Dependencies

```bash
pip install pandas numpy scikit-learn tk python-magic
```

### Run Application

```bash
python forensic_gui_prototype.py
```

---

## 📈 Project Objectives

* Automate digital forensic investigations.
* Reduce manual evidence analysis effort.
* Detect suspicious files using machine learning.
* Improve investigation efficiency.
* Generate forensic investigation reports.
* Identify sensitive information and duplicate files.
* Support cybersecurity and digital forensic research.

---

## 🎯 Applications

* Digital Forensics
* Cybercrime Investigation
* Security Auditing
* Incident Response
* Malware Investigation
* Evidence Collection
* Academic Research

---

## 🔮 Future Enhancements

* AI-Based Threat Detection
* Deep Learning Integration
* Real-Time Monitoring
* Cloud-Based Forensic Analysis
* Advanced Malware Analysis
* Dashboard Visualization
* Memory Forensics Support
* Network Forensics Integration

---

## 👨‍💻 Author

**Yakub Varsee**
B.Tech – Cyber Security & Forensic Engineering

### Patent Holder

**System for Cyber Crime Type Detection, Communication, and Law Section Identification Using IoT**
Indian Patent No. **202521008511**

---

## 📜 License

This project is developed for educational, research, and digital forensic investigation purposes.
