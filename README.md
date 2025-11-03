# 🛡️ Guardian SIEM - Project Report & Setup Guide

**Date:** October 22, 2025  
**Author:** Touhiduzzaman Eshan  

---

## 🎯 Project Goal
To develop a foundational **Security Information and Event Management (SIEM)** system with integrated **AI capabilities** for log analysis, threat detection, and response simulation.

---

## 📊 Current Status
A functional prototype, named **"Guardian SIEM"**, has been successfully developed.  
It integrates:
- Log collection from Windows endpoints  
- Network traffic sniffing  
- Log normalization and correlation  
- Threat intelligence mapping (MITRE ATT&CK, simulated CVEs)  
- Basic risk management  
- **Google Gemini AI** for advanced log analysis  
- Web-based dashboard inspired by Wazuh  

---

## ⚙️ 1. How It Works (Core Components)

The Guardian SIEM system consists of two main Python scripts that work together:

---

### 🖥️ agent.py — The Collector

**Purpose:**  
Runs on any Windows machine you want to monitor (e.g., personal PC or server).  
Its main job is to collect system logs and send them securely to the main SIEM server.

#### 🧩 Core Functions:
- **Log Collection (`fetch_new_events`)**  
  Monitors specified Windows Event Logs (`Security`, `Application`, `System`) in real-time.  

- **Data Extraction (`get_event_details`)**  
  Parses raw logs to extract key details like:
  - Event ID  
  - Timestamp  
  - Username  
  - IP Address  

- **Log Forwarding (`send_logs_in_batches`)**  
  Sends logs securely to the server in small batches to avoid timeouts.  

- **Agent Identity**  
  Each agent sends a unique `AGENT_ID` and `AGENT_NAME`, allowing the server to identify which machine the data came from.  

---

### 🧠 soc_dashboard.py — The Server & Dashboard

**Purpose:**  
Acts as the **central brain** and **user interface** for the entire system.  
It receives logs, processes them, enriches them with threat intelligence, and displays them on the dashboard.

#### ⚙️ Core Components:

- **Log Reception (`/api/logs`)**  
  An API endpoint that listens for incoming logs from all active agents.  

- **Network Sniffing (`packet_handler`)**  
  Collects real-time traffic data (e.g., ICMP, HTTP) from the server’s network interface.  

- **Log Parsing & Enrichment (`parse_and_format_log`)**
  - **Normalize:** Cleans and standardizes log data.  
  - **Enrich:** Adds external intelligence such as:
    - **GeoIP:** Determines the country or city of external IPs.  
    - **DNS Resolution:** Converts IPs to hostnames.  
    - **MITRE ATT&CK Mapping:** Maps Event IDs (e.g., 4625 - Failed Logon → T1110.003).  

- **Database Storage (`add_log_to_db`)**  
  Saves normalized logs into `logs.db` (SQLite).  

- **Statistics (`update_stats_from_log`)**  
  Updates in-memory statistics such as:
  - Total Events  
  - Failed Logins  
  - Active Agents  

  These stats appear live on the dashboard.

---

### ⚡ Correlation Engine (`correlation_engine`)

A background process that runs every 30 seconds to detect multi-stage attacks or suspicious patterns.

#### 🔍 Example Rules:
- **Rule 1:** 3 failed logins + 1 successful login from the same IP =  
  → **Potential Brute Force Success**

- **Rule 2:** New user creation + login within 5 minutes =  
  → **Suspicious New User Activity**

---

## 🤖 AI Analyst (Gemini Powered)

The AI module uses **Google Gemini** to enhance analytical and query capabilities.

#### Modules:
- **`gemini_query_parser`**  
  Converts natural language queries into structured JSON filters.  
  Example:  
  > “Show me failed logins from last hour”  
  → `{"description_like": "Failed Logon", "time_range_str": "1h"}`

- **`process_ai_prompt`**  
  Executes the parsed JSON query on the logs database.

- **`get_gemini_analysis`**  
  Sends recent logs + your query (e.g., “summarize threats”) to Gemini.  
  Returns a summarized analytical report of recent threats or anomalies.

---

## 🌐 Web Dashboard (Flask + HTML/JS)

The web dashboard hosts the GUI for the SIEM system.

### Key Features:
- Real-time statistics display (Total Events, Alerts, Agents)
- Live log stream
- Pop-up alerts for suspicious activity
- List of active agents (updated every 5 minutes)

**Access URL:**  
http://127.0.0.1:5000

---

---

## 🔧 How to Run (Beginner-Friendly Guide)

Follow these steps to set up and run the Guardian SIEM prototype on Windows.

---

### 🧩 Step 1: Prerequisites

| Tool | Purpose | Download |
|------|----------|-----------|
| **Python 3.x** | Core programming environment | [python.org](https://www.python.org) |
| **pip** | Python package installer | Comes with Python |
| **Npcap** | For network packet capture | [npcap.com](https://npcap.com) |
| **Google Gemini API Key** | Enables AI analysis | [Google AI Studio](https://aistudio.google.com) |

✅ During Python installation, check the box: **“Add Python to PATH”**

---

### 📁 Step 2: Project Setup

1. **Create a Project Folder:**  
   Example: F:\SOC_Project

---
   
3. **Add Files:**  
Copy both scripts into your folder:
soc_dashboard.py
agent.py


---

### 🧱 Step 3: Create a Virtual Environment

Open **Command Prompt (as Administrator)** and run:

```bash
cd F:\SOC_Project
python -m venv venv
.\venv\Scripts\activate


### 4. Install Dependencies:

While your `venv` is active, run this single command to install all required libraries:

```cmd
pip install Flask scapy google-generativeai pywin32 requests


### 5. Configure API Key:

1.  Open `soc_dashboard.py` in a text editor (like Notepad).
2.  Find this line (near the top):
    ```python
    GEMINI_API_KEY = "AIzaSyBigGgQ50k6eVuHDT-VRWTVaECg8e-OQUU" 
    ```
    (Note: This appears to be your key, but if it's a placeholder, replace it).
3.  Replace the key with your own Gemini API key if necessary (keep the quotes).
4.  Save and close the file.

### 6. Run the SIEM (Server & Agent):

You need **two** Administrator Command Prompts open at the same time.

**Terminal 1: Run the Server**

1.  Open your **first** Administrator Command Prompt.
2.  Navigate to your folder: `cd F:\SOC_Project`
3.  Activate the environment: `.\venv\Scripts\activate`
4.  Run the server:
    ```cmd
    python soc_dashboard.py
    ```
5.  Keep this terminal open. It will show debug messages.

**Terminal 2: Run the Agent**

1.  Open a **second** Administrator Command Prompt.
2.  Navigate to your folder: `cd F:\SOC_Project`
3.  Activate the environment: `.\venv\Scripts\activate`
4.  Run the agent:
    ```cmd
    python agent.py
    ```
5.  Keep this terminal open. It will show logs as it finds and sends them.

### 7. Access the Dashboard

1.  Open your web browser (like Chrome or Firefox).
2.  Go to the address: `http://127.0.0.1:5000`
3.  You should see the "Guardian SIEM" dashboard. As your agent sends logs, the "Total Events" counter and "Live Log Stream" will update automatically.
