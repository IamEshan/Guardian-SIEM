Guardian SIEM - Project Report & Setup Guide
============================================

**Date:** October 22, 2025

**Project Goal:** To develop a foundational Security Information and Event Management (SIEM) system with integrated AI capabilities for log analysis, threat detection, and response simulation.

**Current Status:** A functional prototype, named "Guardian SIEM," has been successfully developed. It integrates log collection from Windows endpoints, network traffic sniffing, log normalization, correlation, threat intelligence mapping (MITRE ATT&CK, simulated CVEs), basic risk management, and utilizes the Google Gemini AI for advanced log analysis via a web-based dashboard inspired by Wazuh.

1\. How It Works (Core Components)
----------------------------------

The Guardian SIEM system currently consists of two main Python scripts that work together:

1.  **agent.py (The Collector):**
    
    *   **What it does:** This script runs on any Windows machine you want to monitor (e.g., your personal PC, a server). Its only job is to collect important logs and send them to the main server.
        
    *   **Log Collection (fetch\_new\_events):** It monitors specified Windows Event Logs ("Security", "Application", "System") in real-time.
        
    *   **Data Extraction (get\_event\_details):** It parses the raw log to pull out key information (Event ID, timestamp, username, IP address).
        
    *   **Log Forwarding (send\_logs\_in\_batches):** It sends the collected logs securely over the network to the soc\_dashboard.py server. It sends them in "batches" to avoid network timeouts.
        
    *   **Identity:** It sends a unique AGENT\_ID and AGENT\_NAME so the server knows _which_ computer the log came from.
        
2.  **soc\_dashboard.py (The Server & Dashboard):**
    
    *   **What it does:** This is the central brain and user interface of the entire system. It runs on your main server machine.
        
    *   **Log Reception (/api/logs):** It has an API that listens for and receives the logs sent by all active agents.
        
    *   **Network Sniffing (packet\_handler):** It also collects its _own_ data by sniffing network traffic (like pings or website connections) on the server machine itself.
        
    *   **Log Parsing & Enrichment (parse\_and\_format\_log):** This is a critical step. When a log arrives, this function:
        
        *   **Normalizes:** Cleans up the log and standardizes it.
            
        *   **Enriches (Threat Intel):**
            
            *   **GeoIP:** Checks if any IP address is external. If so, it finds its geographic location (e..g., "Mountain View, USA").
                
            *   **DNS:** Tries to find the hostname for external IPs (e.g., "https://www.google.com/search?q=google-dns.com").
                
            *   **MITRE ATT&CK:** Maps known dangerous Event IDs (like 4625 - Failed Logon) to the official MITRE ATT&CK framework (e.g., T1110.003).
                
    *   **Database Storage (add\_log\_to\_db):** It stores all processed and enriched logs in an SQLite database file (logs.db).
        
    *   **Statistics (update\_stats\_from\_log):** It updates the in-memory statistics (Total Events, Failed Logins, etc.) with _every_ new log that arrives. This is what makes the dashboard counters update in real-time.
        
    *   **Correlation Engine (correlation\_engine):** A background thread that runs every 30 seconds. It scans the database for suspicious _patterns_ that a single log wouldn't catch. For example:
        
        *   Rule 1: 3 failed logins + 1 successful login from the same IP = **"Potential Brute Force Success"** alert.
            
        *   Rule 2: A new user account is created + that user logs in within 5 minutes = **"Suspicious New User Activity"** alert.
            
    *   **AI Analyst (Gemini Powered):**
        
        *   gemini\_query\_parser: When you type a query (in any language), this function first sends it to Gemini to understand your _intent_. Gemini translates "show me failed logins from last hour" into a computer-readable JSON command: {"description\_like": "Failed Logon", "time\_range\_str": "1h"}.
            
        *   process\_ai\_prompt: This function takes the JSON command from the parser and queries the database for the _exact_ logs you asked for.
            
        *   get\_gemini\_analysis: If you ask an open-ended question (like "summarize threats"), this function sends the question _plus_ the 30 most recent logs to Gemini to generate a full, detailed analytical report.
            
    *   **Web Dashboard (Flask & HTML/JS):** This hosts the web server and displays the HTML\_TEMPLATE (your UI). It provides API endpoints that the JavaScript in your browser calls every few seconds to refresh the stats, agent list, and alerts.
        
    *   **Pop-up & Agent List:** It shows real-time pop-ups for new alerts and displays all agents that have sent a log in the last 5 minutes.
        

🔧 How to Run (Beginner-Friendly Guide)
---------------------------------------

Follow these steps carefully to set up and run the Guardian SIEM prototype on a Windows machine.

### 1\. Prerequisites:

*   **Python:** Ensure you have Python 3.x installed. You can get it from [python.org](https://www.python.org/). During installation, **check the box that says "Add Python to PATH"**.
    
*   **pip:** Python's package installer, usually included with Python.
    
*   **Npcap:** Required for network sniffing. Download and install it from [npcap.com](https://npcap.com/) (use default settings).
    
*   **Google Gemini API Key:** You must have an API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
    

### 2\. Project Setup:

1.  **Create Project Folder:** Create a new, empty folder (e.g., F:\\SOC\_Project).
    
2.  **Add Files:** Copy your two files, soc\_dashboard.py and agent.py, into this new folder.
    

### 3\. Create Virtual Environment:

This creates a private "bubble" for your project's libraries.

1.  Open **Command Prompt (cmd) as Administrator**. (Search for cmd, right-click, select "Run as administrator").
    
2.  cd F:\\SOC\_Project
    
3.  python -m venv venv
    
4.  .\\venv\\Scripts\\activate
    
5.  Your command prompt line should now start with (venv).
    

### 4\. Install Dependencies:

While your venv is active, run this single command to install all required libraries:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   pip install Flask scapy google-generativeai pywin32 requests   `

### 5\. Configure API Key:

1.  Open soc\_dashboard.py in a text editor (like Notepad).
    
2.  GEMINI\_API\_KEY = "AIzaSyBigGgQ50k6eVuHDT-VRWTVaECg8e-OQUU" _(Note: This appears to be your key, but if it's a placeholder, replace it)._
    
3.  Replace the key with your **own Gemini API key** if necessary (keep the quotes).
    
4.  Save and close the file.
    

### 6\. Run the SIEM (Server & Agent):

You need **two** Administrator Command Prompts open at the same time.

**Terminal 1: Run the Server**

1.  Open your **first** Administrator Command Prompt.
    
2.  Navigate to your folder: cd F:\\SOC\_Project
    
3.  Activate the environment: .\\venv\\Scripts\\activate
    
4.  python soc\_dashboard.py
    
5.  Keep this terminal open. It will show debug messages.
    

**Terminal 2: Run the Agent**

1.  Open a **second** Administrator Command Prompt.
    
2.  Navigate to your folder: cd F:\\SOC\_Project
    
3.  Activate the environment: .\\venv\\Scripts\\activate
    
4.  python agent.py
    
5.  Keep this terminal open. It will show logs as it finds and sends them.
    

### 7\. Access the Dashboard

*   Open your web browser (like Chrome or Firefox).
    
*   Go to the address: http://127.0.0.1:5000
    
*   You should see the "Guardian SIEM" dashboard. As your agent sends logs, the "Total Events" counter and "Live Log Stream" will update automatically.
