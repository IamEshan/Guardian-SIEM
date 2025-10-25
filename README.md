Guardian SIEM (Security Information and Event Management)

A lightweight, AI-powered SIEM solution built with Python, Flask, and Google Gemini for real-time log analysis, threat correlation, and security monitoring.

This project is a foundational SIEM tool designed to collect, analyze, and visualize security events from multiple sources. It leverages the analytical power of Google's Gemini AI to parse natural language queries, analyze threat patterns, and provide actionable insights, all within a clean, Wazuh-inspired web dashboard.

🚀 Key Features

Multi-Agent Log Collection: A lightweight Python agent (agent.py) collects Windows Event Logs (Security, Application, System) from multiple hosts.

Real-time Dashboard: A Flask-based web UI displays incoming logs, key security metrics, and active agent status.

AI Analyst (Gemini Powered):

Natural Language Queries: Ask questions in any language (e.g., "show me failed logins from last hour" or "সন্দেহজনক কার্যকলাপ সারসংক্ষেপ কর").

Automated Analysis: The AI parses user intent to either query the log database or generate a full analytical report on potential threats.

Threat Intelligence Integration:

GeoIP Enrichment: Automatically enriches external IP addresses with geographic location data (City, Country, ISP).

Reverse DNS (Hostname): Resolves external IPs to their hostnames for easier identification.

MITRE ATT&CK Mapping: Maps critical events (like Event ID 4625, 4720) to their corresponding MITRE ATT&CK techniques.

Real-time Event Correlation: A background engine analyzes incoming logs to detect patterns, such as:

Brute Force Success: (e.g., 3+ failed logins followed by a success from the same IP).

Suspicious New User: (e.g., A new user account logs in immediately after creation).

Pop-up Alerting: Generates real-time toast notifications in the dashboard when a new correlated alert is triggered.

Network Monitoring: Includes a basic packet sniffer (using Scapy) to monitor and log network traffic.

⚙️ Technology Stack

Backend: Python 3, Flask

Frontend: HTML, CSS, JavaScript (no frameworks)

Log Collection: pywin32 (for Windows Event Logs), Scapy (for network packets)

Database: SQLite3

AI & Intel:

Google Gemini AI (via google-generativeai)

ip-api.com (for GeoIP)

socket (for Reverse DNS)

📦 Components

soc_dashboard.py (The Server)

The central brain of the operation.

Runs the Flask web server and serves the dashboard UI.

Provides API endpoints (/api/logs, /api/stats, /api/agents, etc.).

Receives logs from all agents and the network sniffer.

Parses, enriches (GeoIP, DNS), and stores logs in the logs.db database.

Runs the background correlation engine.

Communicates with the Google Gemini API to parse queries and generate analysis.

agent.py (The Agent)

A lightweight script to be run on each Windows machine (endpoint) you want to monitor.

Must be run as Administrator to access the Security logs.

Generates a unique, persistent ID (AGENT_ID) for the machine.

Reads new events from "Security", "Application", and "System" logs.

Sends these logs in batches to the soc_dashboard.py server.

🏁 Getting Started

Prerequisites

Python 3.x

Npcap (Required by Scapy for packet sniffing)

A Google Gemini API Key (from Google AI Studio)

Setup & Run

Clone the Repository:

git clone [https://github.com/YourUsername/Guardian-SIEM.git](https://github.com/YourUsername/Guardian-SIEM.git)
cd Guardian-SIEM


Create Virtual Environment & Install Dependencies:

python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt 


(Note: You will need to create a requirements.txt file containing Flask, scapy, google-generativeai, pywin32, and requests)

Configure the Server:

Open soc_dashboard.py.

Find the GEMINI_API_KEY variable and paste your API key.

Run the Server (Terminal 1 - Admin):

Ensure your venv is active.

Run the dashboard:

python soc_dashboard.py


The server will start on http://127.0.0.1:5000.

Configure & Run the Agent (Terminal 2 - Admin):

Open agent.py.

Change the AGENT_NAME variable to a unique name for your computer (e.g., "Dev-Laptop").

(Optional: If your server is on a different PC, change SERVER_URL to the server's IP).

In a new Administrator terminal with the venv active, run the agent:

python agent.py


View the Dashboard:

Open your web browser and go to http://127.0.0.1:5000.

You should see your agent appear in the "Active Agents" list and logs begin to flow into the "Live Log Stream".

🗺️ Future Roadmap

[ ] SOAR Integration: Automatically block malicious IPs on the Windows Firewall.

[ ] UEBA: Profile normal user behavior (logon times, source IPs) and alert on anomalies.

[ ] Honeypot Detection: Alert when a specific "decoy" file or user account is accessed.

[ ] External Threat Intel: Cross-reference IPs/hashes with public threat feeds (e.g., AbuseIPDB).