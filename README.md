Guardian SIEM (Security Information and Event Management)

A lightweight, AI-powered SIEM solution built with Python, Flask, and Google Gemini for real-time log analysis, threat correlation, and security monitoring.

This project is a foundational SIEM tool designed to collect, analyze, and visualize security events from multiple sources. It leverages the analytical power of Google's Gemini AI to parse natural language queries, analyze threat patterns, and provide actionable insights, all within a clean, Wazuh-inspired web dashboard.

🚀 Key Features

Multi-Agent Log Collection: A lightweight Python agent (agent.py) collects Windows Event Logs (Security, Application, System) from multiple hosts.

Real-time Dashboard: A Flask-based web UI displays incoming logs, key security metrics, and active agent status.

Network Sniffing: Captures and analyzes basic network traffic (TCP, UDP, ICMP) on the server.

Log Enrichment (Threat Intel):

GeoIP Location: Automatically enriches external IP addresses with geographic location data (City, Country, ISP).

Reverse DNS (Hostname): Resolves external IPs to their hostnames for easier identification.

MITRE ATT&CK Mapping: Maps known malicious Event IDs (e.g., 4625, 4720) to the MITRE ATT&CK framework.

AI Analyst (Gemini Powered):

Natural Language Queries: Ask questions in any language (e.g., "show me failed logins from last hour" or "সন্দেহজনক কার্যকলাপ সারসংক্ষেপ কর").

Automated Analysis: The AI parses user intent to either query the log database or generate a full analytical report on potential threats.

Real-time Alerting:

Correlation Engine: A background thread analyzes logs to detect patterns (e.g., Brute Force Success, Suspicious New User) and generates correlated alerts.

Pop-up Notifications: Displays real-time pop-up alerts on the dashboard when a new correlated alert is generated.

Agent Management: The dashboard displays a list of all active agents, their last-seen time, and allows filtering logs per-agent.

🛠️ Technologies Used

Backend: Python, Flask

Frontend: HTML, CSS, JavaScript (all within the Flask template)

AI: Google Gemini (via google-generativeai)

Database: SQLite

Log Collection: pywin32 (for Windows Event Logs)

Network Sniffing: scapy

Threat Intel: requests (for ip-api.com), socket (for DNS)

🔧 How to Run

1. Prerequisites

Python 3.x (with pip)

Npcap (for Scapy network sniffing on Windows)

Git (for version control)

A Google Gemini API Key.

2. Setup (Server)

Clone the repository:

git clone [https://github.com/IamEshan/Guardian-SIEM.git](https://github.com/IamEshan/Guardian-SIEM.git)
cd Guardian-SIEM


Create Virtual Environment:

python -m venv venv
.\venv\Scripts\activate


Install Dependencies:

pip install Flask scapy google-generativeai pywin32 requests


Configure API Key:

Open soc_dashboard.py in a text editor.

Find the line GEMINI_API_KEY = "YOUR_GOOGLE_AI_API_KEY" and replace it with your actual Gemini API key.

Run the Server:

You must run this in a terminal with Administrator privileges (for network sniffing).

python soc_dashboard.py


3. Setup (Agent)

Copy the agent.py file to any Windows machine you want to monitor.

Install Python and dependencies on the agent machine: pip install pywin32 requests

Configure the Agent:

Open agent.py in a text editor.

Change AGENT_NAME to a unique name for that machine (e.g., "Domain-Controller" or "Dev-Workstation").

Change SERVER_URL to the IP address of your soc_dashboard.py server (e.g., http://192.168.1.100:5000/api/logs).

Run the Agent:

You must run this in a terminal with Administrator privileges (for reading Security logs).

python agent.py


4. Access the Dashboard

Open your web browser and navigate to the server's address: http://127.0.0.1:5000 (if running on the same machine) or http://[Server-IP]:5000.
