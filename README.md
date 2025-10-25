# Guardian SIEM - Project Report & Setup Guide

**Date:** October 22, 2025

**Project Goal:**  
To develop a foundational **Security Information and Event Management (SIEM)** system with integrated AI capabilities for log analysis, threat detection, and response simulation.

**Current Status:**  
A functional prototype, named **"Guardian SIEM"**, has been successfully developed. It integrates log collection from Windows endpoints, network traffic sniffing, log normalization, correlation, threat intelligence mapping (MITRE ATT&CK, simulated CVEs), basic risk management, and utilizes the **Google Gemini AI** for advanced log analysis via a web-based dashboard inspired by Wazuh.

---

## 1. How It Works (Core Components)

The Guardian SIEM system currently consists of two main Python scripts that work together:

### 🖥️ `agent.py` (The Collector)

**What it does:**  
Runs on any Windows machine you want to monitor (e.g., personal PC, server). Its job is to collect important logs and send them to the main server.

- **Log Collection (`fetch_new_events`):** Monitors Windows Event Logs ("Security", "Application", "System") in real-time.  
- **Data Extraction (`get_event_details`):** Parses raw logs to extract Event ID, timestamp, username, and IP address.  
- **Log Forwarding (`send_logs_in_batches`):** Sends logs securely over the network to `soc_dashboard.py` in batches to prevent timeouts.  
- **Identity:** Sends a unique `AGENT_ID` and `AGENT_NAME` so the server can identify the source machine.

---

### 🧠 `soc_dashboard.py` (The Server & Dashboard)

**What it does:**  
This is the central brain and user interface of the system. It runs on your main server machine.

- **Log Reception (`/api/logs`):** API endpoint that listens for incoming logs from all active agents.  
- **Network Sniffing (`packet_handler`):** Collects its own data by sniffing network traffic (e.g., pings, web connections).  
- **Log Parsing & Enrichment (`parse_and_format_log`):**
  - **Normalizes:** Cleans and standardizes incoming logs.  
  - **Enriches (Threat Intel):**
    - **GeoIP:** Identifies external IP locations (e.g., "Mountain View, USA").  
    - **DNS:** Resolves external IPs to hostnames.  
    - **MITRE ATT&CK:** Maps Event IDs (e.g., 4625 - Failed Logon) to MITRE ATT&CK techniques (e.g., T1110.003).  
- **Database Storage (`add_log_to_db`):** Saves all processed logs in `logs.db` (SQLite).  
- **Statistics (`update_stats_from_log`):** Updates real-time dashboard counters (Total Events, Failed Logins, etc.).  
- **Correlation Engine (`correlation_engine`):**
  - Scans the database every 30 seconds for suspicious multi-log patterns.
  - **Examples:**
    - Rule 1: 3 failed logins + 1 successful login from same IP → *Potential Brute Force Success*  
    - Rule 2: New user created + login within 5 minutes → *Suspicious New User Activity*  

## 🤖 AI Functions

### `process_ai_prompt`
Executes the query on the database based on the parsed JSON command.

### `get_gemini_analysis`
Sends recent logs and open-ended analytical questions (e.g., “summarize threats”) to **Google Gemini AI** for detailed analysis.

---

## 🌐 Web Dashboard (Flask + HTML/JS)

**Purpose:**  
Hosts the web-based user interface and API endpoints for the SIEM system.

**Dashboard Displays:**
- Real-time statistics (Total Events, Alerts, Agents)
- Live log stream
- Pop-up alert notifications
- Active agent list (shows agents active in the last 5 minutes)

---

## 🔧 How to Run (Beginner-Friendly Guide)

Follow these steps to set up and run **Guardian SIEM** on a Windows system.

---

### 1. Prerequisites

- **Python:** Install Python 3.x from [python.org](https://www.python.org).  
  ✅ During installation, check the box **“Add Python to PATH.”**
- **pip:** Comes pre-installed with Python.
- **Npcap:** Required for network sniffing — download and install from [npcap.com](https://npcap.com).
- **Google Gemini API Key:** Obtain it from **Google AI Studio**.

---

### 2. Project Setup

1. **Create Project Folder**  
   Example:
   ```bash
   F:\SOC_Project


### 🤖 AI Analyst (Gemini Powered)

- **`gemini_query_parser`:**  
  Converts natural language queries (e.g., “show me failed logins from last hour”) into JSON commands.  
  Example:  
  ```json
  {"description_like": "Failed Logon", "time_range_str": "1h"}
