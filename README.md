# Guardian SIEM - Project Report & Setup Guide

**Date:** October 22, 2025

**Project Goal:** To develop a foundational Security Information and Event Management (SIEM) system with integrated AI capabilities for log analysis, threat detection, and response simulation.

**Current Status:** A functional prototype, named "Guardian SIEM," has been successfully developed. It integrates log collection from Windows endpoints, network traffic sniffing, log normalization, correlation, threat intelligence mapping (MITRE ATT&CK, simulated CVEs), basic risk management, and utilizes the Google Gemini AI for advanced log analysis via a web-based dashboard inspired by Wazuh.

---

## 1. How It Works (Core Components)

The Guardian SIEM system currently consists of two main Python scripts that work together:

### `agent.py` (The Collector):

* **What it does:** This script runs on any Windows machine you want to monitor (e.g., your personal PC, a server). Its only job is to collect important logs and send them to the main server.
* **Log Collection (`fetch_new_events`):** It monitors specified Windows Event Logs ("Security", "Application", "System") in real-time.
* **Data Extraction (`get_event_details`):** It parses the raw log to pull out key information (Event ID, timestamp, username, IP address).
* **Log Forwarding (`send_logs_in_batches`):** It sends the collected logs securely over the network to the `soc_dashboard.py` server. It sends them in "batches" to avoid network timeouts.
* **Identity:** It sends a unique `AGENT_ID` and `AGENT_NAME` so the server knows which computer the log came from.

### `soc_dashboard.py` (The Server & Dashboard):

* **What it does:** This is the central brain and user interface of the entire system. It runs on your main server machine.
* **Log Reception (`/api/logs`):** It has an API that listens for and receives the logs sent by all active agents.
* **Network Sniffing (`packet_handler`):** It also collects its own data by sniffing network traffic (like pings or website connections) on the server machine itself.
* **Log Parsing & Enrichment (`parse_and_format_log`):** This is a critical step. When a log arrives, this function:
    * **Normalizes:** Cleans up the log and standardizes it.
    * **Enriches (Threat Intel):**
        * **GeoIP:** Checks if any IP address is external. If so, it finds its geographic location (e.g., "Mountain View, USA").
        * **DNS:** Tries to find the hostname for external IPs (e.g., "google-dns.com").
        * **MITRE ATT&CK:** Maps known dangerous Event IDs (like 4625 - Failed Logon) to the official MITRE ATT&CK framework (e.g., T1110.003).
* **Database Storage (`add_log_to_db`):** It stores all processed and enriched logs in an SQLite database file (`logs.db`).
* **Statistics (`update_stats_from_log`):** It updates the in-memory statistics (Total Events, Failed Logins, etc.) with every new log that arrives. This is what makes the dashboard counters update in real-time.
* **Correlation Engine (`correlation_engine`):** A background thread that runs every 30 seconds. It scans the database for suspicious patterns that a single log wouldn't catch. For example:
    * **Rule 1:** 3 failed logins + 1 successful login from the same IP = "Potential Brute Force Success" alert.
    * **Rule 2:** A new user account is created + that user logs in within 5 minutes = "Suspicious New User Activity" alert.
* **AI Analyst (Gemini Powered):**
    * **`gemini_query_parser`:** When you type a query (in any language), this function first sends it to Gemini to understand your intent. Gemini translates "show me failed logins from last hour" into a computer-readable JSON command: `{"description_like": "Failed Logon", "time_range_str": "1h"}`.
    * **`process_ai_prompt`:** This function takes the JSON command from the parser and queries the database for the exact logs you asked for.
    * **`get_gemini_analysis`:** If you ask an open-ended question (like "summarize threats"), this function sends the question plus the 30 most recent logs to Gemini to generate a full, detailed analytical report.
* **Web Dashboard (Flask & HTML/JS):** This hosts the web server and displays the `HTML_TEMPLATE` (your UI). It provides API endpoints that the JavaScript in your browser calls every few seconds to refresh the stats, agent list, and alerts.
* **Pop-up & Agent List:** It shows real-time pop-ups for new alerts and displays all agents that have sent a log in the last 5 minutes.


## 🔧 How to Run (Beginner-Friendly Guide)

Follow these steps carefully to set up and run the Guardian SIEM prototype on a Windows machine.

### 1. Prerequisites:

* **Python:** Ensure you have Python 3.x installed. You can get it from `python.org`. During installation, check the box that says "Add Python to PATH".
* **pip:** Python's package installer, usually included with Python.
* **Npcap:** Required for network sniffing. Download and install it from `npcap.com` (use default settings).
* **Google Gemini API Key:** You must have an API key from Google AI Studio.

### 2. Project Setup:

* **Create Project Folder:** Create a new, empty folder (e.g., `F:\SOC_Project`).
* **Add Files:** Copy your two files, `soc_dashboard.py` and `agent.py`, into this new folder.

### 3. Create Virtual Environment:

This creates a private "bubble" for your project's libraries.

1.  Open **Command Prompt (`cmd`) as Administrator**. (Search for `cmd`, right-click, select "Run as administrator").
2.  Navigate to your project folder:
    ```cmd
    cd F:\SOC_Project
    ```
3.  Create the virtual environment:
    ```cmd
    python -m venv venv
    ```
4.  Activate the virtual environment:
    ```cmd
    .\venv\Scripts\activate
    ```
    Your command prompt line should now start with `(venv)`.

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
