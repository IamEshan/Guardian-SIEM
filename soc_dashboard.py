print("[DEBUG] Stage 1: Script starting, importing libraries...")
import time
import json
import threading
import sqlite3
import re
import subprocess
import os
from datetime import datetime, date, time as dt_time, timedelta
from flask import Flask, render_template_string, request, jsonify, make_response
import traceback # For detailed error logging
import requests # --- Added for GeoIP lookup ---
import queue # --- FIX: Added queue import ---
import socket # --- NEW: Added socket for DNS lookup ---
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    print("[DEBUG] Stage 2: Scapy imported successfully.")
except Exception as e:
    print(f"[FATAL ERROR] An unexpected error occurred while importing Scapy. Is Npcap installed correctly? Error: {e}")
    exit()

try:
    import google.generativeai as genai
    print("[DEBUG] Stage 2.5: Google Gemini library imported successfully.")
except ImportError:
    print("[FATAL ERROR] The Google Gemini library is not installed. Please run 'pip install google-generativeai'")
    exit()

# --- NEW: Import PySNMP libraries ---
try:
    from pysnmp.carrier.asyncore.dgram import udp
    from pysnmp.entity import engine, config
    from pysnmp.entity.rfc3413 import ntfrcv
    from pysnmp.proto.api import v2c
    print("[DEBUG] Stage 2.6: PySNMP imported successfully (for SNMP Traps).")
except ImportError:
    print("[WARNING] The PySNMP library is not installed (pip install pysnmp). SNMP Trap receiver disabled.")
    # We don't exit, as the polling agent and main SIEM can still work
    pass


from collections import Counter
from functools import wraps # For no-cache decorator

# --- Basic Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_ai_secret_key'
DB_NAME = 'logs.db'

# --- Gemini AI Configuration ---
GEMINI_API_KEY = "AIzaSyBigGgQ50k6eVuHDT-VRWTVaECg8e-OQUU"
GEMINI_MODEL_NAME = "gemini-2.5-flash-preview-09-2025" 

if GEMINI_API_KEY != "YOUR_GOOGLE_AI_API_KEY" and GEMINI_API_KEY != "":
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_parser_model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        gemini_analyst_model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        print(f"[DEBUG] Gemini AI Models '{GEMINI_MODEL_NAME}' configured successfully.")
    except Exception as e:
        gemini_parser_model = None; gemini_analyst_model = None
        print(f"\n[WARNING] Failed to configure Gemini AI. Error: {e}\n")
else:
    gemini_parser_model = None; gemini_analyst_model = None
    print("\n[WARNING] Gemini API Key not configured. Advanced AI features disabled.\n")

# --- NEW: AbuseIPDB API Configuration ---
ABUSEIPDB_API_KEY = "0512eb3e1c8747f718013be43e3f8c3a3c13407dcd3987e5d32768daf22d2e3949711735883b9071" # Your API Key
THREAT_INTEL_CACHE = {}
threat_intel_lock = threading.Lock()

# --- In-memory storage ---
stats = {"total_events": 0, "successful_logins": 0, "failed_logins": 0, "app_errors": 0, "correlated_alerts": 0, "event_types": {}}
stats_lock = threading.Lock()
BLOCKED_IPS = set() 
RISK_REGISTER = {
    "R-001": {"description": "Unauthorized access via brute force attacks", "impact": "High", "likelihood": "Medium", "status": "Active", "related_alerts": []},
    "R-002": {"description": "Persistence through new local account creation", "impact": "High", "likelihood": "Low", "status": "Active", "related_alerts": []},
    "R-003": {"description": "Denial of Service through service termination", "impact": "Medium", "likelihood": "Low", "status": "Active", "related_alerts": []},
    "R-004": {"description": "Exploitation of known vulnerabilities (CVEs)", "impact": "High", "likelihood": "Medium", "status": "Active", "related_alerts": []},
    "R-005": {"description": "Credential Access via Credential Manager", "impact": "High", "likelihood": "Low", "status": "Active", "related_alerts": []}, 
}
CORRELATED_ALERTS = []
alert_lock = threading.Lock()
GEOIP_CACHE = {} 
geoip_lock = threading.Lock()
DNS_CACHE = {} 
dns_lock = threading.Lock()
ACTIVE_AGENTS = {} 
agents_lock = threading.Lock()
# --- NEW: Queues for background enrichment ---
geoip_queue = queue.Queue()
dns_queue = queue.Queue()
# --- MODIFICATION: Removed threat_intel_queue (now synchronous) ---
snmp_log_queue = queue.Queue() # --- NEW: Queue for SNMP logs ---


# --- Mappings ---
WIN_EVENT_DESCRIPTIONS = {
    4624: "Successful Logon", 4625: "Failed Logon", 4634: "Logoff",
    4720: "User Account Created", 4722: "User Account Enabled", 4725: "User Account Disabled", 4726: "User Account Deleted",
    4798: "User's local group membership enumerated",
    4627: "Group membership information",
    4672: "Special privileges assigned to new logon",
    5379: "Credential Manager credential read", 
    1000: "App Crash", 1001: "Windows Error Reporting",
    7034: "Service Stop Unexpectedly", 7036: "Service Started", 7040: "Service Start Type Changed",
    6008: "Unexpected Shutdown", 6013: "System Uptime", 0: "Information",
    9001: "MikroTik Health Poll" # --- NEW: SNMP Polling Event ---
}
VULNERABLE_APPS_CVE = { "old_browser.exe": "CVE-2025-1234", "vulnerable_service.exe": "CVE-2025-5678", " risky_app.exe": "CVE-2024-9999" }
MITRE_ATTACK_MAP = {
    "4625": {"id": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    "4720": {"id": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence"},
    "7034": {"id": "T1489", "name": "Service Stop", "tactic": "Impact"},
    "4798": {"id": "T1069.001", "name": "Permission Groups Discovery: Local Groups", "tactic": "Discovery"},
    "5379": {"id": "T1555.004", "name": "Credentials from Password Stores: Windows Credential Manager", "tactic": "Credential Access", "risk_id": "R-005"}, 
    "CORR-BRUTE-SUCCESS": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "risk_id": "R-001"},
    "CORR-NEW-USER-LOGIN": {"id": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence", "risk_id": "R-002"},
}
MITRE_DEFEND_MAP = {
    "T1110.003": {"id": "D3-AL", "name": "Account Locking"},
    "T1136.001": {"id": "D3-AM", "name": "Account Monitoring"},
    "T1489": {"id": "D3-SFC", "name": "Service File-permission Check"},
    "T1110": {"id": "D3-MFA", "name": "Multi-Factor Authentication"},
    "T1069.001": {"id": "D3-PCA", "name": "Process Code Analysis"},
    "T1555.004": {"id": "D3-CH", "name": "Credential Hoarding Mitigation"}, 
}

# --- No-Cache Decorator ---
def nocache(view):
    @wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache_impl

# --- GeoIP, DNS, and Threat Intel Functions ---
def is_internal_ip(ip_address):
    """Checks if an IP is internal/private."""
    if not ip_address or ip_address == '-' or ip_address == '127.0.0.1' or ip_address == '::1':
        return True
    try:
        parts = ip_address.split('.')
        if len(parts) == 4:
            if parts[0] == '10': return True
            if parts[0] == '192' and parts[1] == '168': return True
            if parts[0] == '172' and 16 <= int(parts[1]) <= 31: return True
        return False
    except:
        return False

def get_geoip_data(ip_address):
    """Fetches GeoIP data for a public IP address, using a local cache."""
    if is_internal_ip(ip_address): return "Internal IP"
    with geoip_lock:
        if ip_address in GEOIP_CACHE: return GEOIP_CACHE[ip_address]
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp"
        response = requests.get(url, timeout=2) 
        response.raise_for_status() 
        data = response.json()
        geo_info = f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')} ({data.get('isp', 'N/A')})" if data.get('status') == 'success' else "GeoIP Lookup Failed"
    except Exception as e: geo_info = "GeoIP Error"
    with geoip_lock: GEOIP_CACHE[ip_address] = geo_info
    return geo_info

def get_dns_name(ip_address):
    """Performs a reverse DNS lookup, using a local cache."""
    if is_internal_ip(ip_address): return "Internal IP"
    with dns_lock:
        if ip_address in DNS_CACHE: return DNS_CACHE[ip_address]
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        dns_info = str(hostname)
    except socket.herror: dns_info = "No PTR Record"
    except Exception as e: dns_info = f"DNS Error"
    with dns_lock: DNS_CACHE[ip_address] = dns_info
    return dns_info

# --- NEW: AbuseIPDB Threat Intel Function (Synchronous) ---
def get_threat_intel_data(ip_address):
    """Fetches threat intel from AbuseIPDB, using a local cache."""
    if is_internal_ip(ip_address): return None, 0 # No score for internal IPs
    
    with threat_intel_lock:
        if ip_address in THREAT_INTEL_CACHE:
            return THREAT_INTEL_CACHE[ip_address]

    if not ABUSEIPDB_API_KEY:
        return "API Key Missing", 0

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    
    try:
        print(f"[THREAT INTEL DEBUG] Checking IP: {ip_address}")
        # Synchronous API call
        response = requests.get(url, headers=headers, params=params, timeout=3)
        response.raise_for_status()
        data = response.json().get('data', {})
        
        score = data.get('abuseConfidenceScore', 0)
        if score > 50: # Only report significant scores
            report_count = data.get('totalReports', 0)
            last_report_category = "N/A"
            if data.get('lastReportedAt'):
                    # Attempts to get the first report category for context
                    last_report_category = f"Category {data.get('reports', [{}])[0].get('categories', ['N/A'])[0]}"
            
            threat_info = f"Malicious ({score}%) - {report_count} Reports (Last: {last_report_category})"
        else:
            threat_info = "Not Reported"
            
    except requests.exceptions.Timeout:
        threat_info = "Threat Intel Timeout"; score = 0
    except requests.exceptions.RequestException as e:
        threat_info = f"Threat Intel Error ({e.response.status_code if e.response else 'N/A'})"; score = 0
    except Exception as e:
        threat_info = "Threat Intel Error"; score = 0

    result = (threat_info, score)
    with threat_intel_lock: THREAT_INTEL_CACHE[ip_address] = result
    return result


# --- Database Functions ---
def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); c = conn.cursor()
        c.execute('DROP TABLE IF EXISTS logs')
        c.execute('DROP TABLE IF EXISTS correlated_alerts')
        c.execute('''
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY, timestamp REAL, 
                log_type TEXT, description TEXT, 
                details TEXT, severity TEXT,
                agent_id TEXT, agent_name TEXT
            )
        ''')
        c.execute('CREATE TABLE correlated_alerts (id INTEGER PRIMARY KEY, timestamp REAL, title TEXT, details TEXT, mitre_id TEXT, risk_id TEXT, agent_id TEXT)')
        conn.commit()
        print(f"Database '{DB_NAME}' initialized (tables recreated with agent support).")
    except sqlite3.Error as e: print(f"[DB ERROR] Failed to initialize DB: {e}"); traceback.print_exc()
    finally:
        if conn: conn.close()

def add_log_to_db(log, agent_id, agent_name):
    conn = None; log_id = None
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); c = conn.cursor()
        c.execute("INSERT INTO logs (timestamp, log_type, description, details, severity, agent_id, agent_name) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (log.get('timestamp'), log.get('log_type'), log.get('description'), 
             json.dumps(log.get('details', {})), log.get('severity'),
             agent_id, agent_name))
        log_id = c.lastrowid
        conn.commit()
    except sqlite3.Error as e: print(f"[DB ERROR] Failed to add log: {e}")
    finally:
        if conn: conn.close()
    return log_id

def add_correlated_alert_to_db(alert):
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); c = conn.cursor()
        c.execute("INSERT INTO correlated_alerts (timestamp, title, details, mitre_id, risk_id, agent_id) VALUES (?, ?, ?, ?, ?, ?)",
            (alert['timestamp'], alert['title'], json.dumps(alert['details']), 
             alert.get('mitre_id'), alert.get('risk_id'), alert.get('agent_id')))
        conn.commit()
        with alert_lock:
            CORRELATED_ALERTS.insert(0, alert)
            risk_id = alert.get('risk_id')
            if risk_id and risk_id in RISK_REGISTER:
                if 'related_alerts' not in RISK_REGISTER[risk_id]: RISK_REGISTER[risk_id]['related_alerts'] = []
                if alert['title'] not in RISK_REGISTER[risk_id]['related_alerts']:
                    RISK_REGISTER[risk_id]['related_alerts'].append(alert['title'])
        with stats_lock:
            stats['correlated_alerts'] += 1
            print(f"[STATS DEBUG] Incremented correlated_alerts to {stats['correlated_alerts']}")
    except sqlite3.Error as e: print(f"[DB ERROR] Failed to add alert: {e}")
    finally:
        if conn: conn.close()

def get_time_range_ms(range_str):
    """Calculates start timestamp in milliseconds based on range string."""
    now = datetime.now()
    start_time = None
    if range_str == '1h': start_time = now - timedelta(hours=1)
    elif range_str == '24h': start_time = now - timedelta(days=1)
    elif range_str == '7d': start_time = now - timedelta(days=7)
    elif range_str == 'all': return 0
    else: start_time = now - timedelta(days=1) # Default
    return start_time.timestamp() * 1000 if start_time else 0

def query_db_range(filters={}, limit=50, time_range_str='all'):
    """Queries logs within a specific time range."""
    conn = None; results = []
    start_timestamp_ms = get_time_range_ms(time_range_str)
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); conn.row_factory = sqlite3.Row; c = conn.cursor()
        query = "SELECT * FROM logs"; conditions, params = [], []
        if start_timestamp_ms > 0: conditions.append("timestamp >= ?"); params.append(start_timestamp_ms)
        if filters.get('agent_id'): conditions.append("agent_id = ?"); params.append(filters.get('agent_id'))
        if filters.get('description_like'): conditions.append("description LIKE ?"); params.append(f"%{filters.get('description_like')}%")
        # --- FIX: Correlation key is "Target User" ---
        if filters.get('username'): conditions.append("(details LIKE ?)"); params.extend([f'%"Target User": "%{filters.get("username")}"%'])
        if filters.get('mitre_id'): conditions.append("details LIKE ?"); params.append(f'%"MITRE ATT&CK": "%{filters.get("mitre_id")}%"')
        if filters.get('cve_id'): conditions.append("details LIKE ?"); params.append(f'%"CVE": "{filters.get("cve_id")}"%')
        if conditions: query += " WHERE " + " AND ".join(conditions)
        query += f" ORDER BY timestamp DESC LIMIT {limit}"
        c.execute(query, tuple(params))
        results = [dict(row) for row in c.fetchall()]
        for log in results:
            try: details_str = log.get('details'); log['details'] = json.loads(details_str) if isinstance(details_str, str) else details_str or {}
            except (json.JSONDecodeError, TypeError): log['details'] = {"error": "Could not parse details"}
    except sqlite3.Error as e: print(f"[DB ERROR] Query failed: {e}")
    finally:
        if conn: conn.close()
    return results

def query_db(filters={}, limit=50):
    """Simple query function, defaults to query_db_range with 'all' time."""
    return query_db_range(filters=filters, limit=limit, time_range_str='all')

# --- Correlation Engine ---
def correlation_engine():
    """
    Looks for suspicious patterns in the log database.
    This version is updated to query the normalized 'Source IP' and 'Target User' fields.
    """
    while True:
        time.sleep(30)
        # print("[CORRELATION DEBUG] Running correlation check...") # Verbose
        conn = None
        try:
            conn = sqlite3.connect(DB_NAME, check_same_thread=False); conn.row_factory = sqlite3.Row; c = conn.cursor()
            now_ts = time.time() * 1000
            five_minutes_ago_ts = (datetime.now() - timedelta(minutes=5)).timestamp() * 1000

            # Rule 1: Brute Force Success
            # --- FIX: Use the 'Target User' key which is now normalized by the parser ---
            c.execute("""
                SELECT l_success.details, l_success.agent_id, l_success.agent_name FROM logs l_fail
                JOIN logs l_success ON json_extract(l_fail.details, '$.' || "Source IP") = json_extract(l_success.details, '$.' || "Source IP")
                AND l_fail.agent_id = l_success.agent_id
                WHERE l_fail.description = 'Failed Logon' AND l_success.description = 'Successful Logon'
                AND l_fail.timestamp > ? AND l_success.timestamp > l_fail.timestamp AND l_success.timestamp <= ?
                AND json_extract(l_fail.details, '$.' || "Source IP") IS NOT NULL AND json_extract(l_fail.details, '$.' || "Source IP") != ''
                GROUP BY l_success.agent_id, json_extract(l_success.details, '$.' || "Source IP"), json_extract(l_success.details, '$.' || "Target User")
                HAVING COUNT(DISTINCT l_fail.id) >= 3
            """, (five_minutes_ago_ts, now_ts))
            brute_force_rows = c.fetchall()
            for row in brute_force_rows:
                try: details = json.loads(row['details'])
                except: continue
                src_ip = details.get('Source IP', 'N/A'); target_user = details.get('Target User', 'N/A'); agent_id = row['agent_id']
                alert_id_str = f"brute-force-{agent_id}-{src_ip}-{target_user}-{int(time.time() / 300)}"
                with alert_lock: already_alerted = any(a['details'].get('alert_id') == alert_id_str for a in CORRELATED_ALERTS)
                if not already_alerted:
                    mitre_info = MITRE_ATTACK_MAP.get("CORR-BRUTE-SUCCESS", {})
                    alert = {"timestamp": now_ts, "title": f"Potential Brute Force Success on {row['agent_name']}", "details": { "alert_id": alert_id_str, "description": f"Detected >=3 failed logins then success for '{target_user}' from IP {src_ip} on agent {agent_id}.", "recommendation": f"Investigate '{target_user}'. Block {src_ip}?" }, "mitre_id": mitre_info.get('id'), "risk_id": mitre_info.get('risk_id'), "agent_id": agent_id}
                    print(f"[CORRELATION] New Brute Force Alert: {alert_id_str}")
                    add_correlated_alert_to_db(alert)

            # Rule 2: Suspicious New User Activity
            # --- FIX: Use the 'Target User' key ---
            c.execute("""
                SELECT l_login.details, l_login.agent_id, l_login.agent_name, l_login.timestamp as login_ts FROM logs l_create
                JOIN logs l_login ON json_extract(l_create.details, '$.' || "Target User") = json_extract(l_login.details, '$.' || "Target User")
                AND l_create.agent_id = l_login.agent_id
                WHERE l_create.description = 'User Account Created' AND l_login.description = 'Successful Logon'
                AND l_create.timestamp > ? AND l_login.timestamp > l_create.timestamp AND (l_login.timestamp - l_create.timestamp) < 300000
            """, (five_minutes_ago_ts,))
            new_user_rows = c.fetchall()
            for row in new_user_rows:
                try: details = json.loads(row['details'])
                except: continue
                target_user = details.get('Target User', 'N/A'); src_ip = details.get('Source IP', 'N/A'); agent_id = row['agent_id']
                alert_id_str = f"new-user-login-{agent_id}-{target_user}-{int(time.time() / 300)}"
                with alert_lock: already_alerted = any(a['details'].get('alert_id') == alert_id_str for a in CORRELATED_ALERTS)
                if not already_alerted:
                    mitre_info = MITRE_ATTACK_MAP.get("CORR-NEW-USER-LOGIN", {})
                    alert = {"timestamp": row['login_ts'], "title": f"Suspicious New User Activity on {row['agent_name']}", "details": { "alert_id": alert_id_str, "description": f"New user '{target_user}' on {agent_id} logged in shortly after creation from IP {src_ip}.", "recommendation": f"Verify legitimacy of '{target_user}'." }, "mitre_id": mitre_info.get('id'), "risk_id": mitre_info.get('risk_id'), "agent_id": agent_id}
                    print(f"[CORRELATION] New User Login Alert: {alert_id_str}")
                    add_correlated_alert_to_db(alert)
        except sqlite3.Error as e: print(f"[CORRELATION ERROR] DB error: {e}"); traceback.print_exc()
        except Exception as e: print(f"[CORRELATION ERROR] Unexpected: {e}"); traceback.print_exc()
        finally:
            if conn: conn.close()

# --- AI Agent Logic ---
def get_gemini_analysis(user_prompt, logs):
    if not gemini_analyst_model: return "Gemini AI (Analyst) is not configured."
    formatted_logs = [{"time": datetime.fromtimestamp(log['timestamp']/1000).strftime('%H:%M:%S'), "description": log['description'], "details": log.get('details',{})} for log in logs]
    system_prompt = "You are 'Guardian', a SOC analyst AI. Analyze logs, identify threats, correlate events, mention MITRE ATT&CK techniques, and suggest responses."
    full_prompt = f"User Request: \"{user_prompt}\"\n\nRecent Logs:\n{json.dumps(formatted_logs, indent=2)}"
    try:
        print("[DEBUG] Sending prompt to Gemini API...")
        response = gemini_analyst_model.generate_content([system_prompt, full_prompt], generation_config=genai.types.GenerationConfig(temperature=0.7))
        print("[DEBUG] Received response from Gemini API.")
        if response.candidates and response.candidates[0].content.parts: return response.candidates[0].content.parts[0].text
        elif hasattr(response, 'prompt_feedback') and response.prompt_feedback: block_reason = f"Safety block: {response.prompt_feedback}"; return f"Gemini response blocked. Reason: {block_reason}"
        else: return "Unexpected/empty response from Gemini."
    except Exception as e: print(f"[ERROR] Gemini API call failed: {e}"); return f"Error contacting Gemini: {e}"

def gemini_query_parser(user_prompt):
    if not gemini_parser_model: return {"error": "AI query parser not configured."}
    # --- FIX: Updated prompt to include time_range_str and 'username' (Target User) ---
    system_prompt = """
    You are a query parsing AI. Convert the user's natural language prompt (in any language)
    into a JSON object to query a log database or perform an action.
    
    Valid Actions:
    - "action": "block" | "unblock"
    - "ip_address": string
    
    Valid Query Keys:
    - "description_like": string
    - "username": string (Searches for 'Target User')
    - "mitre_id": string
    - "cve_id": string
    - "time_range_str": "1h" | "24h" | "7d" | "all"
    
    Examples:
    User: "show me failed logins" -> {"description_like": "Failed Logon"}
    User: "failed logins from the last hour" -> {"description_like": "Failed Logon", "time_range_str": "1h"}
    User: "block 1.2.3.4" -> {"action": "block", "ip_address": "1.2.3.4"}
    User: "8.8.8.8 কে ব্লক কর" -> {"action": "block", "ip_address": "8.8.8.8"}
    User: "unblock 1.2.3.4" -> {"action": "unblock", "ip_address": "1.2.3.4"}
    User: "show logs for user 'Admin' in the last 7 days" -> {"username": "Admin", "time_range_str": "7d"}
    
    If the prompt is analytical (e.g., "summarize threats", "what is the risk?"), respond with: ANALYZE
    Respond *only* with the JSON object or "ANALYZE".
    """
    full_prompt = f"User Prompt: \"{user_prompt}\""
    try:
        response = gemini_parser_model.generate_content([system_prompt, full_prompt], generation_config=genai.types.GenerationConfig(temperature=0.0))
        response_text = ""
        if response.candidates and response.candidates[0].content.parts: response_text = response.candidates[0].content.parts[0].text
        elif hasattr(response, 'text'): response_text = response.text
        else: raise Exception("Empty/blocked response")
        response_text = response_text.strip().replace("```json", "").replace("```", "")
        if "ANALYZE" in response_text.upper(): return "ANALYZE"
        try: query_plan = json.loads(response_text); return query_plan if isinstance(query_plan, dict) else "ANALYZE"
        except json.JSONDecodeError: return "ANALYZE"
    except Exception as e: print(f"[ERROR] Gemini Query Parser failed: {e}"); return {"error": f"AI Parser Error: {e}"}

def run_command(command):
    """Executes a shell command and returns success(bool) and output(str)."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, encoding='utf-8')
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[SOAR ERROR] Command failed: {e.stderr}")
        return False, e.stderr
    except Exception as e:
        print(f"[SOAR ERROR] Unexpected error: {e}")
        return False, str(e)

def process_ai_prompt(prompt, agent_id=None):
    query_plan = gemini_query_parser(prompt)
    if isinstance(query_plan, dict) and "error" in query_plan: return {"response": query_plan['error'], "data": None}

    # --- NEW: Handle SOAR Actions ---
    if isinstance(query_plan, dict) and "action" in query_plan:
        action = query_plan.get("action")
        ip = query_plan.get("ip_address")
        
        if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return {"response": f"Invalid IP address provided for action: {ip}", "data": None}

        if action == "block":
            print(f"[SOAR ACTION] Attempting to block IP: {ip}")
            rule_name = f"SIEM_Block_{ip}"
            command = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip}"
            success, output = run_command(command)
            if success:
                BLOCKED_IPS.add(ip)
                return {"response": f"Successfully created firewall rule to block IP: {ip}", "data": None}
            else:
                return {"response": f"Failed to block IP. Error (Run as Admin?): {output}", "data": None}
        
        elif action == "unblock":
            print(f"[SOAR ACTION] Attempting to unblock IP: {ip}")
            rule_name = f"SIEM_Block_{ip}"
            command = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
            success, output = run_command(command)
            if success:
                if ip in BLOCKED_IPS: BLOCKED_IPS.remove(ip)
                return {"response": f"Successfully removed firewall rule for IP: {ip}", "data": None}
            else:
                return {"response": f"Failed to unblock IP. Error (Rule exists?): {output}", "data": None}
    
    # --- Handle ANALYZE and QUERY intents ---
    time_range = 'all' # Default
    if isinstance(query_plan, dict) and 'time_range_str' in query_plan:
        time_range = query_plan.pop('time_range_str') # Extract time range if AI found one
        
    if query_plan == "ANALYZE":
        print(f"[AI DEBUG] Intent 'ANALYZE'. Fetching logs (Agent: {agent_id or 'All'}, Range: {time_range}).")
        filters = {}
        if agent_id: filters['agent_id'] = agent_id
        logs_for_analysis = query_db_range(filters, limit=30, time_range_str=time_range) 
        if not logs_for_analysis: return {"response": f"No recent logs (in {time_range}) for analysis.", "data": None}
        ai_response = get_gemini_analysis(prompt, logs_for_analysis)
        return {"response": ai_response, "data": None}

    if isinstance(query_plan, dict):
        if agent_id: query_plan['agent_id'] = agent_id
        limit = 100
        print(f"[AI DEBUG] Intent 'QUERY'. Executing: {query_plan} (Agent: {agent_id or 'All'}, Range: {time_range})")
        logs = query_db_range(query_plan, limit=limit, time_range_str=time_range) 
        response_text = f"Found {len(logs)} log(s) for your query (Range: {time_range}, Agent: {agent_id or 'All'})."
        return {"response": response_text, "data": logs}

    return {"response": "I couldn't understand that request.", "data": None}


# --- Statistics and Log Parsing ---
def update_stats_from_log(log):
    """Updates the in-memory global stats dictionary based on a new log."""
    if not isinstance(log, dict): return # Safety check
    with stats_lock:
        stats["total_events"] += 1
        category = "Other" # Default category

        event_id = log.get('event_id_internal') # Can be None
        log_type = log.get('log_type', '') # e.g., "Security Event", "Network Traffic"

        # print(f"[STATS DEBUG] Processing log - Type: '{log_type}', Event ID: {event_id}") # Verbose

        if log_type == 'Security Event':
            if event_id == 4625:
                stats["failed_logins"] += 1
                category = "Failed Logon"
                print(f"[STATS DEBUG] Incremented failed_logins to {stats['failed_logins']}")
            elif event_id == 4624:
                stats["successful_logins"] += 1
                category = "Successful Logon"
                # --- *** DEBUG LINE ADDED HERE *** ---
                print(f"[STATS DEBUG] Incremented successful_logins to {stats['successful_logins']}")
            else:
                category = f"Security ({event_id or '?'})"
        elif log_type == 'Application Event':
            if event_id == 1000:
                stats["app_errors"] += 1
                category = "Application Error"
                print(f"[STATS DEBUG] Incremented app_errors to {stats['app_errors']}")
            else:
                category = f"Application ({event_id or '?'})"
        elif log_type == 'System Event':
            category = f"System ({event_id or '?'})"
        elif log_type == 'Network Traffic':
            category = "Network Traffic"
        elif log_type == 'SNMP Poll': 
            category = "SNMP Poll"
        elif log_type == 'SNMP Trap': 
            category = "SNMP Trap"
        elif log_type in ['Unknown Event', 'Other Event', 'Parse Error Event']: # Added Parse Error
            category = f"Other ({event_id or '?'})"
        
        category_str = str(category)
        stats["event_types"][category_str] = stats["event_types"].get(category_str, 0) + 1


# --- ================================================================== ---
# --- `parse_and_format_log` function (with Instant Threat Intel) ---
# --- ================================================================== ---
def parse_and_format_log(log, agent_id="unknown"):
    """
    Parses logs from various sources (new pywin32 agent, sniffer, snmp).
    This is the core of log normalization and synchronous enrichment.
    """
    
    # --- NEW: Logic for 'pywin32' Windows Event Agent ---
    log_channel = log.get('log_channel') # This key is sent by the new agent
    
    if log_channel in ['Security', 'Application', 'System']:
        try:
            event_id = log.get('event_id')
            
            # Use the mapped description if available, otherwise use agent's message
            description = WIN_EVENT_DESCRIPTIONS.get(event_id)
            if not description:
                msg_preview = log.get('message', f"Event ID {event_id}")
                if len(msg_preview) > 70: msg_preview = msg_preview[:70] + "..."
                description = msg_preview

            # The agent's 'data_fields' becomes our base 'details'
            details = log.get('data_fields', {}) 
            details['Event ID'] = event_id
            details['Computer'] = log.get('computer_name', 'N/A')
            details['Source'] = log.get('log_source', log_channel)
            
            # --- Timestamp Conversion ---
            agent_timestamp_str = log.get('timestamp')
            db_timestamp = time.time() * 1000 # Default to now
            if agent_timestamp_str:
                try:
                    # Agent sends ISO string (e.g., "2025-11-02T15:00:00")
                    dt = datetime.fromisoformat(agent_timestamp_str)
                    db_timestamp = dt.timestamp() * 1000
                except Exception as e_ts:
                    print(f"[WARN] Could not parse timestamp '{agent_timestamp_str}': {e_ts}")

            # --- Severity and IP Logic ---
            # Normalize keys for Correlation Engine!
            source_ip = details.get('IpAddress') or details.get('Client Address')
            severity = "WARNING" if event_id in [1000, 4625, 4720, 7034, 5379] else "INFO"

            if source_ip and source_ip != '':
                details['Source IP'] = source_ip # ALWAYS add the normalized key
                if not is_internal_ip(source_ip): # Only enrich non-internal IPs
                    # --- MODIFICATION: Instant Threat Intel ---
                    threat_info, score = get_threat_intel_data(source_ip)
                    if threat_info:
                        details['Threat Intel (Source)'] = threat_info
                        if score > 50 and severity != "CRITICAL": severity = "CRITICAL" # Promote severity
                    # --- End Modification ---
                    
                    # Add to ASYNCHRONOUS enrichment queues (GeoIP/DNS only)
                    geoip_queue.put((-1, source_ip))
                    dns_queue.put((-1, source_ip))
            
            if source_ip in BLOCKED_IPS: severity = "CRITICAL"
            
            # --- Normalize User keys for Correlation ---
            if 'TargetUserName' in details:
                details['Target User'] = details['TargetUserName']
            if 'Account Name' in details:
                # For 4625 (Failed Logon), 'Account Name' is the user
                details['Target User'] = details['Account Name'] 
            
            # --- Enrichment (MITRE/CVE) ---
            event_id_str = str(event_id)
            if event_id is not None and event_id_str in MITRE_ATTACK_MAP: 
                details["MITRE ATT&CK"] = f"{MITRE_ATTACK_MAP[event_id_str]['id']}: {MITRE_ATTACK_MAP[event_id_str]['name']}"
            
            log_message = log.get('message', '').lower()
            for app, cve in VULNERABLE_APPS_CVE.items():
                if app.lower() in json.dumps(details).lower() or app.lower() in log_message: 
                    details["CVE"] = cve
                    
            return {
                "log_type": f"{log_channel} Event", 
                "event_id_internal": event_id, 
                "description": description, 
                "details": details, 
                "timestamp": db_timestamp, # Use the converted timestamp
                "severity": severity
            }
        except Exception as e_parse_win:
            print(f"[PARSE ERROR] Failed to parse Windows log: {e_parse_win}")
            traceback.print_exc()
            # Fallback for failed parsing
            details={'RawMessage': log.get('message','N/A'), 'ParseError': str(e_parse_win)}; 
            event_id=log.get('event_id'); 
            return {"log_type": "Parse Error Event", "event_id_internal": event_id, "description": f"Source: {log_channel}, Event: {event_id}", "details": details, "timestamp": time.time() * 1000, "severity": "WARNING"}

    # --- ==================================================== ---
    # --- OLD LOGIC (for Network Sniffer, SNMP, etc.) ---
    # --- ==================================================== ---

    timestamp_ms = time.time() * 1000 # Use 'now' for these log types
    log_type_source = log.get('log_source')
    primary_type = log_type_source # Get primary type
    
    if primary_type == 'SNMP Polling':
        event_id = log.get('event_id') # 9001
        details = log.get('data_fields', {})
        details['Computer'] = log.get('computer_name', 'N/A')
        severity = "INFO"
        description = WIN_EVENT_DESCRIPTIONS.get(event_id, "SNMP Poll Event")
        return {"log_type": "SNMP Poll", "event_id_internal": event_id, "description": description, "details": details, "timestamp": timestamp_ms, "severity": severity}
    
    if log.get('log_type') == 'snmp_trap':
        primary_type = 'snmp_trap'
    elif not primary_type and log.get('type') == 'network_packet': 
        primary_type = 'Network'
    elif not primary_type: 
        details={}; details['RawMessage']=log.get('message','N/A'); event_id=log.get('event_id'); 
        return {"log_type": "Unknown Event", "event_id_internal": event_id, "description": f"Unknown ID: {event_id}", "details": details, "timestamp": timestamp_ms, "severity": "INFO"}

    original_source_for_details = log_type_source or primary_type

    if primary_type == 'Network':
        source_ip = log.get('source_ip', 'N/A'); severity = 'CRITICAL' if source_ip in BLOCKED_IPS else 'INFO'
        dest_ip = log.get('dest_ip', 'N/A')
        desc = f"Packet from {source_ip}"
        details = {"Source IP": source_ip, "Destination IP": dest_ip, "Protocol": log.get('protocol', 'N/A')}
        
        # --- SYNCHRONOUS ENRICHMENT FOR SOURCE IP ---
        if source_ip and not is_internal_ip(source_ip):
            threat_info, score = get_threat_intel_data(source_ip)
            if threat_info:
                details['Threat Intel (Source)'] = threat_info
                if score > 50 and severity != "CRITICAL": severity = "CRITICAL"
            geoip_queue.put((-1, source_ip)) # Keep asynchronous GeoIP/DNS
            dns_queue.put((-1, source_ip))

        # --- SYNCHRONOUS ENRICHMENT FOR DESTINATION IP ---
        if dest_ip and not is_internal_ip(dest_ip):
            threat_info, score = get_threat_intel_data(dest_ip)
            if threat_info:
                details['Threat Intel (Dest)'] = threat_info
                if score > 50 and severity != "CRITICAL": severity = "CRITICAL"
            geoip_queue.put((-1, dest_ip)) # Keep asynchronous GeoIP/DNS
            dns_queue.put((-1, dest_ip))

        return {"log_type": "Network Traffic", "event_id_internal": None, "description": desc, "severity": severity, "details": details, "timestamp": timestamp_ms}
    
    elif primary_type == 'snmp_trap':
        trap_oid = log.get('trap_oid', 'N/A')
        trap_source_ip = log.get('source_ip', 'N/A')
        description = f"SNMP Trap from {trap_source_ip}"
        details = log.get('details', {})
        details['Source IP'] = trap_source_ip 
        severity = "WARNING" 
        
        if '1.3.6.1.6.3.1.1.5.3' in trap_oid: # linkDown
            description = f"Link Down on {trap_source_ip}"
            severity = "CRITICAL"
        elif '1.3.6.1.6.3.1.1.5.4' in trap_oid: # linkUp
            description = f"Link Up on {trap_source_ip}"
            severity = "INFO"
        elif '1.3.6.1.6.3.1.1.5.1' in trap_oid: # coldStart
            description = f"Device Cold Restart: {trap_source_ip}"
            severity = "CRITICAL"
        
        # --- SYNCHRONOUS ENRICHMENT FOR TRAP SOURCE IP ---
        if trap_source_ip and not is_internal_ip(trap_source_ip):
            threat_info, score = get_threat_intel_data(trap_source_ip)
            if threat_info:
                details['Threat Intel (Source)'] = threat_info
                if score > 50 and severity != "CRITICAL": severity = "CRITICAL"
            geoip_queue.put((-1, trap_source_ip)) # Keep asynchronous GeoIP/DNS
            dns_queue.put((-1, trap_source_ip))

        return {"log_type": "SNMP Trap", "event_id_internal": None, "description": description, "details": details, "timestamp": timestamp_ms, "severity": severity}
        
    else: 
        details={}; details['RawMessage']=log.get('message','N/A'); event_id=log.get('event_id'); 
        return {"log_type": "Other Event", "event_id_internal": event_id, "description": f"Source: {original_source_for_details}, Event: {event_id}", "details": details, "timestamp": timestamp_ms, "severity": "INFO"}


# --- Network Sniffing ---
def packet_handler(packet):
    if IP in packet:
        proto = packet.sprintf("%IP.proto%").upper(); proto_val = proto
        if proto == 'TCP': proto_val = 'TCP'
        elif proto == 'UDP': proto_val = 'UDP'
        elif proto == 'ICMP': proto_val = 'ICMP'
        log_entry = {'type': 'network_packet', 'source_ip': packet[IP].src, 'dest_ip': packet[IP].dst, 'protocol': proto_val}
        
        # --- CRITICAL FIX: Parsing (which includes instant enrichment) happens BEFORE saving/queuing ---
        formatted = parse_and_format_log(log_entry, agent_id="network-sniffer")
        
        if formatted:
            # The formatted log now has the correct 'details' and 'severity' from AbuseIPDB
            log_id = add_log_to_db(formatted, "network-sniffer", "Network Sniffer")
            
            # --- After saving, check if we need to update GeoIP/DNS asynchronously ---
            if log_id:
                if formatted.get('details'):
                    # The details dictionary already contains the Threat Intel data
                    src_ip = formatted['details'].get('Source IP')
                    dst_ip = formatted['details'].get('Destination IP')
                    
                    # Only enqueue GeoIP/DNS as threat intel is already done
                    if src_ip and not is_internal_ip(src_ip):
                        geoip_queue.put((log_id, src_ip))
                        dns_queue.put((log_id, src_ip))
                    if dst_ip and not is_internal_ip(dst_ip):
                        geoip_queue.put((log_id, dst_ip))
                        dns_queue.put((log_id, dst_ip))
                        
            update_stats_from_log(formatted)

def start_sniffing():
    print("Starting network sniffer...");
    try:
        sniff(iface="Wi-Fi", prn=packet_handler, store=0)
    except Exception as e: 
        print(f"[ERROR] Sniffer failed: {e}.")
        print("[ERROR] Could not find interface 'Wi-Fi'. Trying default...")
        try:
            sniff(prn=packet_handler, store=0)
        except Exception as e2:
                print(f"[ERROR] Default sniffer also failed: {e2}.")

# --- Enrichment Worker Thread Functions ---
def geoip_enricher_thread():
    """Worker thread to process IPs from the queue and update the DB."""
    print("[GEOIP WORKER] Starting GeoIP enrichment thread...")
    while True:
        try:
            log_id, ip_address = geoip_queue.get()
            if ip_address is None: break
            
            geo_info = get_geoip_data(ip_address) # API call
            
            if geo_info and geo_info != "Internal IP" and log_id != -1:
                conn = None
                try:
                    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
                    c = conn.cursor()
                    c.execute("SELECT details FROM logs WHERE id = ?", (log_id,))
                    row = c.fetchone()
                    if row:
                        details_dict = json.loads(row[0]) if isinstance(row[0], str) else row[0] or {}
                        
                        if details_dict.get('Source IP') == ip_address: details_dict['Source Geo'] = geo_info
                        elif details_dict.get('Destination IP') == ip_address: details_dict['Destination Geo'] = geo_info
                        
                        c.execute("UPDATE logs SET details = ? WHERE id = ?", (json.dumps(details_dict), log_id))
                        conn.commit()
                except sqlite3.Error as e: print(f"[GEOIP WORKER DB ERROR] {e}")
                finally:
                    if conn: conn.close()
            
            geoip_queue.task_done()
            time.sleep(1.5) # Rate limit
        except queue.Empty:
            time.sleep(5)
        except Exception as e:
            print(f"[GEOIP WORKER ERROR] {e}"); traceback.print_exc()
            if 'log_id' in locals(): geoip_queue.task_done()

def dns_enricher_thread():
    """Worker thread to perform reverse DNS lookups and update the DB."""
    print("[DNS WORKER] Starting DNS enrichment thread...")
    while True:
        try:
            log_id, ip_address = dns_queue.get()
            if ip_address is None: break
            
            dns_name = get_dns_name(ip_address)
            
            if dns_name and dns_name not in ["Internal IP", "No PTR Record", "DNS Error"] and log_id != -1:
                conn = None
                try:
                    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
                    c = conn.cursor()
                    c.execute("SELECT details FROM logs WHERE id = ?", (log_id,))
                    row = c.fetchone()
                    if row:
                        details_dict = json.loads(row[0]) if isinstance(row[0], str) else row[0] or {}
                        
                        if details_dict.get('Source IP') == ip_address: details_dict['Source Hostname'] = dns_name
                        elif details_dict.get('Destination IP') == ip_address: details_dict['Destination Hostname'] = dns_name
                        
                        c.execute("UPDATE logs SET details = ? WHERE id = ?", (json.dumps(details_dict), log_id))
                        conn.commit()
                except sqlite3.Error as e:
                    print(f"[DNS WORKER DB ERROR] {e}")
                finally:
                    if conn: conn.close()
            
            dns_queue.task_done()
        except queue.Empty:
            time.sleep(5)
        except Exception as e:
            print(f"[DNS WORKER ERROR] {e}"); traceback.print_exc()
            if 'log_id' in locals(): dns_queue.task_done()


# --- NEW: SNMP Trap Receiver Thread ---
def snmp_trap_receiver_thread():
    """
    A dedicated thread to listen for SNMP traps on UDP port 162.
    """
    print("[SNMP TRAP] Starting SNMP Trap Receiver on 0.0.0.0:162...")
    
    # Create SNMP engine
    snmpEngine = engine.SnmpEngine()

    # Transport setup
    config.addTransport(
        snmpEngine,
        udp.DOMAIN_NAME + (1,),
        udp.UdpTransport().openServerMode(('0.0.0.0', 162))
    )

    config.addV1System(snmpEngine, 'my-area', 'public') # 'public' community string

    # Callback function for received traps
    def snmp_trap_callback(snmpEngine, stateReference, contextEngineId, contextName,
                           varBinds, cbCtx):
        try:
            transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
            source_ip = transportAddress[0]
            print(f"[SNMP TRAP] Received trap from: {source_ip}")

            trap_details = {}
            trap_oid = "N/A"
            for oid, val in varBinds:
                oid_str = oid.prettyPrint()
                val_str = val.prettyPrint()
                if oid_str == '1.3.6.1.6.3.1.1.4.1.0': # snmpTrapOID.0
                    trap_oid = val_str
                trap_details[oid_str] = val_str

            log_entry = {
                "log_type": "snmp_trap",
                "source_ip": source_ip,
                "agent_id": f"snmp-trap-listener",
                "agent_name": f"SNMP Trap ({source_ip})",
                "trap_oid": trap_oid,
                "details": trap_details
            }
            snmp_log_queue.put(log_entry)

        except Exception as e:
            print(f"[SNMP TRAP ERROR] Error in callback: {e}")
            traceback.print_exc()

    ntfrcv.NotificationReceiver(snmpEngine, snmp_trap_callback)
    snmpEngine.transportDispatcher.jobStarted(1)
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except Exception as e:
        print(f"[SNMP TRAP ERROR] Dispatcher failed: {e}")
        snmpEngine.transportDispatcher.closeDispatcher()
        traceback.print_exc()

# --- NEW: SNMP Log Processor Thread ---
def snmp_log_processor_thread():
    """
    Processes SNMP logs from the queue and adds them to the database.
    """
    print("[SNMP PROCESSOR] Starting SNMP log processor thread...")
    while True:
        try:
            log_entry = snmp_log_queue.get()
            if log_entry is None: break

            agent_id = log_entry.get("agent_id")
            agent_name = log_entry.get("agent_name")

            formatted = parse_and_format_log(log_entry, agent_id=agent_id)
            if formatted:
                add_log_to_db(formatted, agent_id, agent_name)
                update_stats_from_log(formatted)
            
            snmp_log_queue.task_done()
        except queue.Empty:
            time.sleep(1)
        except Exception as e:
            print(f"[SNMP PROCESSOR ERROR] {e}")
            traceback.print_exc()
            if 'log_entry' in locals():
                snmp_log_queue.task_done()


# --- Flask Web Application Routes ---
HTML_TEMPLATE = """
<!DOCTYPE html><html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Guardian SIEM</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root { --bg: #2c3e50; --text: #ecf0f1; --header: #e74c3c; --card-bg: #34495e; --log-bg: #46627f; --input-bg: #5dade2; --nav-bg: #22303f; --accent: #1abc9c; --warn: #f39c12; --crit: #e74c3c; }
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background-color: var(--bg); color: var(--text); font-size: 14px; }
        .dashboard-grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 15px; padding: 15px; }
        h1, h2, h3 { color: var(--header); text-align: center; margin-top: 0; margin-bottom: 15px; }
        h1 { grid-column: 1 / -1; margin-bottom: 0; cursor: pointer; }
        .card { background-color: var(--card-bg); border-radius: 8px; padding: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
        .stats-grid { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
        .stat-card { text-align: center; border-bottom: 3px solid var(--accent); padding-bottom: 10px; }
        .stat-card h3 { font-size: 0.9em; margin-bottom: 5px; color: #bdc3c7; text-transform: uppercase; }
        .stat-card .count { font-size: 2em; font-weight: 600; color: var(--text); }
        .threat-center { grid-column: 1 / 9; }
        .side-panel { grid-column: 9 / -1; display: flex; flex-direction: column; gap: 15px; }
        .log-stream-container, .alert-stream-container, .agent-list-container { max-height: 300px; overflow-y: auto; }
        .log-entry, .alert-entry { padding: 8px; margin-bottom: 6px; background-color: var(--log-bg); border-radius: 4px; font-size: 0.85em; border-left: 4px solid transparent; word-wrap: break-word; }
        .log-entry b, .alert-entry b { color: #bdc3c7; }
        .severity-INFO { border-left-color: #3498db; }
        .severity-WARNING { border-left-color: var(--warn); background-color: #443e37; }
        .severity-CRITICAL { border-left-color: var(--crit); background-color: #5d333f; animation: pulse 1s infinite alternate; }
        .alert-entry { border: 1px solid var(--header); background-color: #3b1f2b; }
        .alert-title { font-weight: bold; color: var(--header); }
        .mitre-link, .cve-link { color: #5dade2; text-decoration: none; font-weight: 500; }
        .log-entry b.geo-location, .log-entry b.hostname { color: var(--accent); }
        .log-entry b.threat-intel { color: var(--warn); font-weight: bold; }
        .risk-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.85em; }
        .risk-table th, .risk-table td { padding: 6px; border: 1px solid #566573; text-align: left; }
        .risk-table th { background-color: #46627f; }
        .agent-container input { width: calc(100% - 70px); padding: 8px; border-radius: 4px; background-color: var(--input-bg); color: #2c3e50; border: none; }
        .agent-container button { width: 60px; padding: 8px; border: none; border-radius: 4px; background-color: var(--accent); color: #2c3e50; cursor: pointer; font-weight: bold; }
        #agent-response-area { margin-top: 10px; padding: 10px; background: var(--log-bg); min-height: 100px; white-space: pre-wrap; border-radius: 4px; font-size: 0.85em; overflow-y: auto; max-height: 200px; }
        .chart-container { position: relative; height: 220px; }
        .agent-list-item { background-color: var(--log-bg); padding: 8px 10px; margin-bottom: 5px; border-radius: 4px; cursor: pointer; transition: background-color 0.2s; border-left: 4px solid var(--accent); }
        .agent-list-item:hover { background-color: #566573; }
        .agent-list-item.offline { border-left-color: var(--crit); opacity: 0.6; }
        #toast-notification { visibility: hidden; min-width: 250px; background-color: var(--header); color: var(--text); text-align: center; border-radius: 5px; padding: 16px; position: fixed; z-index: 100; right: 30px; bottom: 30px; font-size: 1.1em; box-shadow: 0 0 10px rgba(0,0,0,0.5); opacity: 0; transition: visibility 0.5s, opacity 0.5s, transform 0.5s; transform: translateY(100px); }
        #toast-notification.show { visibility: visible; opacity: 1; transform: translateY(0); }
        #toast-notification .close-toast { float: right; margin-left: 15px; color: var(--text); font-weight: bold; cursor: pointer; }
        @keyframes pulse { 0% { background-color: #5d333f; } 100% { background-color: #7d434f; } }
        ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: var(--card-bg); } ::-webkit-scrollbar-thumb { background: #566573; } ::-webkit-scrollbar-thumb:hover { background: #6c7a89; }
    </style>
</head>
<body>
    <div class="dashboard-grid">
        <h1 onclick="filterByAgent(null, 'All Agents')" title="Reset Filters">Guardian SIEM</h1>
        
        <div class="stats-grid card">
            <div class="stat-card"><h3>Total Events</h3><p class="count" id="total-events-count">0</p></div>
            <div class="stat-card"><h3>Successful Logins</h3><p class="count" id="successful-logins-count">0</p></div>
            <div class="stat-card"><h3>Failed Logins</h3><p class="count" id="failed-logins-count">0</p></div>
            <div class="stat-card"><h3>App Errors</h3><p class="count" id="app-errors-count">0</p></div>
            <div class="stat-card"><h3>Correlated Alerts</h3><p class="count" id="correlated-alerts-count">0</p></div>
        </div>

        <div class="threat-center card">
            <h2>Threat & Risk Center</h2>
            <div><h3>Correlated Alerts</h3><div id="correlated-alerts-stream" class="alert-stream-container"><p>No correlated alerts yet.</p></div></div>
            <div style="margin-top:20px;"><h3>Risk Register</h3><table class="risk-table"><thead><tr><th>ID</th><th>Description</th><th>Impact</th><th>Likelihood</th><th>Status</th></tr></thead><tbody id="risk-table-body"></tbody></table></div>
        </div>

        <div class="side-panel">
            <div class="agent-container card">
                <h2>Gemini AI Analyst</h2>
                <div style="display:flex;">
                    <input type="text" id="agent-prompt" placeholder="e.g., block 8.8.8.8">
                    <button onclick="submitPrompt()">Ask</button>
                </div>
                <div id="agent-response-area">Awaiting command...</div>
            </div>
            <div class="card">
                <h2>Active Agents</h2>
                <div id="agent-list" class="agent-list-container">
                    <p>No agents reporting.</p>
                </div>
            </div>
            <div class="card chart-container"><h2>Event Types</h2><canvas id="eventsChart"></canvas></div>
        </div>

         <div class="card" style="grid-column: 1 / 9;">
            <h2>Live Log Stream <span id="log-stream-agent" style="color: var(--accent); font-size: 0.8em;">(All Agents)</span></h2>
            <div id="log-stream" class="log-stream-container"><p>Waiting for logs...</p></div>
         </div>
    </div>
    
    <div id="toast-notification">
        <span class="close-toast" onclick="closeToast()">&times;</span>
        <strong id="toast-title">New Alert</strong>
        <p id="toast-message">A new threat has been detected.</p>
    </div>

    <script>
        let eventsChart;
        let dataUpdateInterval;
        let currentAgentFilter = null;
        let seenAlertIDs = new Set();
        const MITRE_ATTACK_MAP_JS = JSON.parse('{{ mitre_attack_map | tojson | safe }}');
        
        function initializeChart(){
            const ctx=document.getElementById("eventsChart").getContext("2d");
            eventsChart=new Chart(ctx,{type:"doughnut",data:{labels:[],datasets:[{data:[],backgroundColor:["#e74c3c","#f39c12","#3498db","#2ecc71","#9b59b6","#1abc9c", "#7f8c8d"],borderWidth:0}]},options:{responsive:!0,maintainAspectRatio:false,plugins:{legend:{position:"right",labels:{color:"var(--text)",boxWidth:12,padding:10}}}}})}

        function renderLogs(logs, containerId='log-stream') {
            const container = document.getElementById(containerId);
            if (!logs || !Array.isArray(logs)) { console.error("Invalid logs data:", logs); return; }
            const isMainStream = containerId === 'log-stream';

            if (logs.length === 0) {
                 if(isMainStream && container.innerHTML.includes('Waiting')) return;
                 container.innerHTML = `<p>No logs found for this query.</p>`;
                 return;
            }

            if (!isMainStream || container.innerHTML.includes('Waiting for logs...')) {
                container.innerHTML = '';
            }

            const fragment = document.createDocumentFragment();
            logs.forEach(log => {
                const entry = document.createElement('div');
                const severity = log.severity || 'INFO';
                entry.className = `log-entry severity-${severity}`;
                let detailsHtml = '';
                if (log.details && typeof log.details === 'object') {
                    for (const [key, value] of Object.entries(log.details)) {
                        let val_str = value;
                        val_str = typeof val_str === 'string' ? val_str.replace(/</g, "&lt;").replace(/>/g, "&gt;") : val_str;
                        let keyClass = '';
                        if (value && typeof value === 'string') {
                            if (key === "MITRE ATT&CK") { const match = value.match(/^(T\d{4}(\.\d{3})?):\s*(.*)/); if (match) val_str = `<a href="https://attack.mitre.org/techniques/${match[1].replace('.','/')}" target="_blank" class="mitre-link">${value}</a>`; }
                            else if (key === "CVE") { val_str = `<a href="https://nvd.nist.gov/vuln/detail/${value}" target="_blank" class="cve-link">${value}</a>`; }
                        }
                        if (key.includes("Geo") || key.includes("Hostname")) { keyClass = 'class="geo-location"'; }
                        if (key.includes("Threat Intel")) { keyClass = 'class="threat-intel"'; }
                        
                        // --- FIX: Use 'Target User' and 'Source IP' (normalized keys) ---
                        const displayKey = key.replace('UserName',' User').replace('IpAddress', 'IP');
                        if(key !== 'event_id_internal' && val_str !== null && val_str !== undefined && val_str !== '') {
                           detailsHtml += `<b ${keyClass}>${displayKey}:</b> ${val_str}<br>`;
                        }
                    }
                } else { detailsHtml = `<b>Details:</b> ${JSON.stringify(log.details)}<br>`; }
                entry.innerHTML = `<b>${log.description || 'Log Event'}</b> <small>(${new Date(log.timestamp).toLocaleString()})</small><br>${detailsHtml}`;
                if (isMainStream) fragment.prepend(entry); else fragment.appendChild(entry);
            });
            
            if (isMainStream) {
                 container.prepend(fragment);
                 while (container.children.length > 150) { container.removeChild(container.lastChild); }
             } else {
                 container.innerHTML = '';
                 container.appendChild(fragment);
             }
        }

        function renderAlerts(alerts) {
            const container = document.getElementById('correlated-alerts-stream');
             if (!alerts || !Array.isArray(alerts)) { container.innerHTML = '<p>Error loading alerts.</p>'; return; }
            if (alerts.length === 0) { container.innerHTML = '<p>No correlated alerts yet.</p>'; return; }
            container.innerHTML = '';
             const fragment = document.createDocumentFragment();
            alerts.forEach(alert => {
                const entry = document.createElement('div'); entry.className = 'alert-entry';
                const mitre_info = alert.mitre_id && MITRE_ATTACK_MAP_JS && MITRE_ATTACK_MAP_JS[alert.mitre_id] ? MITRE_ATTACK_MAP_JS[alert.mitre_id] : null;
                let mitre_html = '';
                if(mitre_info && mitre_info.id) { mitre_html = `<b>MITRE:</b> <a href="https://attack.mitre.org/techniques/${mitre_info.id.replace('.','/')}" target="_blank" class="mitre-link">${mitre_info.id}</a>`; }
                const risk_html = alert.risk_id ? ` | <b>Risk:</b> ${alert.risk_id}` : '';
                const details = alert.details || {}; const description = details.description || 'N/A'; const recommendation = details.recommendation || 'N/A';
                const alert_unique_id = details.alert_id || alert.title + alert.timestamp;
                if (!seenAlertIDs.has(alert_unique_id)) {
                    seenAlertIDs.add(alert_unique_id);
                    if (Date.now() - alert.timestamp < 60000) {
                        showToast(alert.title, description);
                    }
                }
                entry.innerHTML = `<div class="alert-title">${alert.title || 'Alert'}</div> <small>(${new Date(alert.timestamp).toLocaleString()})</small><p>${description}</p><p><b>Rec:</b> ${recommendation}</p>${mitre_html}${risk_html}`;
                fragment.appendChild(entry);
            });
            container.appendChild(fragment);
            while (container.children.length > 20) { container.removeChild(container.lastChild); }
        }

        function renderRiskRegister(risks) {
            const container = document.getElementById('risk-table-body');
            container.innerHTML = '';
            if (!risks || typeof risks !== 'object') return;
            for (const [id, risk] of Object.entries(risks)) {
                const row = container.insertRow();
                row.innerHTML = `<td>${id}</td><td>${risk.description || ''}</td><td>${risk.impact || ''}</td><td>${risk.likelihood || ''}</td><td>${risk.status || ''}</td>`;
            }
        }
        
        function renderAgentList(agents) {
            const container = document.getElementById('agent-list');
            if (!agents || Object.keys(agents).length === 0) {
                container.innerHTML = '<p>No agents reporting.</p>'; return;
            }
            container.innerHTML = '';
            const fragment = document.createDocumentFragment();
            const now = Date.now();
            for (const [id, agent] of Object.entries(agents)) {
                const entry = document.createElement('div');
                const lastSeen = new Date(agent.last_seen);
                const isOffline = (now - agent.last_seen) > 300000; // 5 minute threshold
                entry.className = `agent-list-item ${isOffline ? 'offline' : ''}`;
                entry.setAttribute('onclick', `filterByAgent('${id}', '${agent.name}')`);
                entry.innerHTML = `<b>${agent.name || id}</b><br><small>${id} - Last seen: ${lastSeen.toLocaleTimeString()}</small>`;
                fragment.appendChild(entry);
            }
            container.appendChild(fragment);
        }
        
        function showToast(title, message) {
            const toast = document.getElementById('toast-notification');
            document.getElementById('toast-title').innerText = title || "New Alert";
            document.getElementById('toast-message').innerText = message || "A new threat has been detected.";
            toast.className = "show";
            setTimeout(() => { toast.className = toast.className.replace("show", ""); }, 5000);
        }
        function closeToast() {
            document.getElementById('toast-notification').className = "";
        }

        function updateAllData() {
             // console.log("Fetching all data..."); // Verbose
             fetch('/api/stats').then(r=>r.json()).then(d=>{
                 if (d && d.stats) {
                     document.getElementById('total-events-count').innerText = d.stats.total_events || 0;
                     document.getElementById('successful-logins-count').innerText = d.stats.successful_logins || 0;
                     document.getElementById('failed-logins-count').innerText = d.stats.failed_logins || 0;
                     document.getElementById('app-errors-count').innerText = d.stats.app_errors || 0;
                     document.getElementById('correlated-alerts-count').innerText = d.stats.correlated_alerts || 0;
                     if(eventsChart && d.chart_data && d.chart_data.labels && d.chart_data.data) {
                         const currentLabels = JSON.stringify(eventsChart.data.labels); const currentData = JSON.stringify(eventsChart.data.datasets[0].data);
                         const newLabels = JSON.stringify(d.chart_data.labels); const newData = JSON.stringify(d.chart_data.data);
                         if (currentLabels !== newLabels || currentData !== newData) {
                             eventsChart.data.labels = d.chart_data.labels; eventsChart.data.datasets[0].data = d.chart_data.data; eventsChart.update();
                         }
                     }
                 }
             }).catch(e => console.error("Error fetching stats:", e));
             
             let alertUrl = `/api/correlated_alerts`;
             if (currentAgentFilter) alertUrl += `?agent_id=${currentAgentFilter}`;
             fetch(alertUrl).then(r=>r.json()).then(d=>renderAlerts(d)).catch(e => console.error("Error fetching alerts:", e));
             
             fetch('/api/risk_register').then(r=>r.json()).then(d=>renderRiskRegister(d)).catch(e => console.error("Error fetching risk register:", e));
             fetch('/api/agents').then(r=>r.json()).then(d=>renderAgentList(d)).catch(e => console.error("Error fetching agents:", e));
        }
        
        function fetchLogs(agentId = null) {
            let url = `/api/latest_logs`;
            if (agentId) {
                url += `?agent_id=${agentId}`;
            }
            fetch(url).then(r => r.json()).then(d => renderLogs(d)).catch(e => console.error("Error fetching logs:", e));
        }
        
        function filterByAgent(agentId, agentName = 'All Agents') {
            currentAgentFilter = agentId;
            document.getElementById('log-stream-agent').innerText = `(${agentName})`;
            document.getElementById('log-stream').innerHTML = '<p>Loading logs...</p>';
            fetchLogs(currentAgentFilter);
            
            let alertUrl = `/api/correlated_alerts`;
             if (currentAgentFilter) alertUrl += `?agent_id=${currentAgentFilter}`;
             fetch(alertUrl).then(r=>r.json()).then(d=>renderAlerts(d)).catch(e => console.error("Error fetching alerts:", e));
        }
        
        function submitPrompt() {
            const promptInput = document.getElementById('agent-prompt'); const prompt = promptInput.value;
            const responseArea = document.getElementById('agent-response-area');
            if (!prompt) return;
            responseArea.innerText = 'Analyzing with Gemini...';
            
            fetch('/api/agent', { 
                method: 'POST', 
                headers: {'Content-Type': 'application/json'}, 
                body: JSON.stringify({
                    prompt: prompt, 
                    agent_id: currentAgentFilter
                })
            })
            .then(response => { if (!response.ok) { return response.text().then(text => { throw new Error(`HTTP ${response.status}: ${text || response.statusText}`); }); } return response.json(); })
            .then(data => {
                responseArea.innerText = data.response;
                if (data.data && Array.isArray(data.data)) {
                    renderLogs(data.data, 'log-stream');
                    document.getElementById('log-stream-agent').innerText = `(AI Query Results)`;
                }
            })
            .catch(error => { console.error('AI Agent Error:', error); responseArea.innerText = 'Error: ' + error; });
            promptInput.value = '';
        }

        window.onload = () => {
            initializeChart();
            updateAllData(); // Initial fetch
            fetchLogs(currentAgentFilter); // Initial log fetch
            
            if(dataUpdateInterval) clearInterval(dataUpdateInterval);
            dataUpdateInterval = setInterval(updateAllData, 8000); 

            setInterval(() => {
                 const responseArea = document.getElementById('agent-response-area');
                 if(responseArea.innerText.includes('Awaiting command') || (responseArea.innerText.startsWith('Found') && responseArea.innerText.includes('logs'))) {
                     fetchLogs(currentAgentFilter);
                 }
             }, 15000); 

            document.getElementById('agent-prompt').addEventListener('keyup', e => { if (e.key === 'Enter') submitPrompt(); });
        };
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    try:
        return render_template_string(HTML_TEMPLATE, mitre_attack_map=MITRE_ATTACK_MAP)
    except Exception as e:
        print(f"[ERROR] Index route: {e}"); traceback.print_exc()
        return "<h1>Internal Server Error</h1>", 500

@app.route('/api/agent', methods=['POST'])
@nocache
def handle_agent_prompt():
    prompt = request.json.get('prompt')
    agent_id = request.json.get('agent_id')
    if not prompt: return jsonify({"response": "No prompt.", "data": None}), 400
    try:
        result = process_ai_prompt(prompt, agent_id=agent_id) 
        return jsonify(result)
    except Exception as e: print(f"[ERROR] Agent prompt: {e}"); traceback.print_exc(); return jsonify({"response": f"Error: {e}", "data": None}), 500

@app.route('/api/logs', methods=['POST'])
@nocache
def receive_logs():
    try:
        data = request.json
        if not data or 'agent_id' not in data or 'logs' not in data:
            print(f"[RECV ERROR] Invalid log payload structure: {data}")
            return jsonify({"status": "error", "message": "Invalid payload structure"}), 400

        agent_id = data.get('agent_id')
        agent_name = data.get('agent_name', agent_id)
        logs_data = data.get('logs', [])
        
        with agents_lock:
            ACTIVE_AGENTS[agent_id] = {"name": agent_name, "last_seen": time.time() * 1000}
            # print(f"[AGENT DEBUG] Heartbeat from {agent_name} ({agent_id})") # Verbose

        if not isinstance(logs_data, list): logs_data = [logs_data]
        count = 0
        for log in logs_data:
            if not isinstance(log, dict): continue
            
            # --- MODIFICATION: Parsing (and instant enrichment) happens FIRST ---
            formatted = parse_and_format_log(log, agent_id=agent_id)
            
            if formatted:
                log_id = add_log_to_db(formatted, agent_id, agent_name)
                # --- After saving, queue for GeoIP/DNS asynchronously ---
                if log_id: 
                    if formatted.get('details'):
                        src_ip = formatted['details'].get('Source IP')
                        
                        # Only enqueue GeoIP/DNS as threat intel is already done
                        if src_ip and not is_internal_ip(src_ip):
                            geoip_queue.put((log_id, src_ip))
                            dns_queue.put((log_id, src_ip))
                            
                update_stats_from_log(formatted)
                count += 1
        return jsonify({"status": "success", "processed": count})
    except json.JSONDecodeError: return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    except Exception as e: print(f"[RECV ERR] {e}"); traceback.print_exc(); return jsonify({"status": "error", "message": f"{e}"}), 500

@app.route('/api/agents')
@nocache
def get_active_agents():
    with agents_lock:
        now = time.time() * 1000
        active_agents_filtered = {
            id: agent for id, agent in ACTIVE_AGENTS.items()
            if (now - agent.get('last_seen', 0)) < 300000 # 5 minutes
        }
        return jsonify(active_agents_filtered)

@app.route('/api/latest_logs')
@nocache
def get_latest_logs():
    agent_id = request.args.get('agent_id', None)
    filters = {}
    if agent_id: filters['agent_id'] = agent_id
    try:
        logs = query_db(filters, limit=150) # Use simple query_db
        return jsonify(logs)
    except Exception as e: print(f"[ERR] Latest logs: {e}"); traceback.print_exc(); return jsonify({"error": f"{e}"}), 500

@app.route('/api/correlated_alerts')
@nocache
def get_correlated_alerts():
    agent_id = request.args.get('agent_id', None)
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); conn.row_factory = sqlite3.Row; c = conn.cursor()
        query = "SELECT * FROM correlated_alerts"; conditions, params = [], []
        if agent_id: conditions.append("agent_id = ?"); params.append(agent_id)
        if conditions: query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp DESC LIMIT 20"
        
        c.execute(query, tuple(params))
        alerts = [dict(row) for row in c.fetchall()]
        conn.close()
        for alert in alerts:
            if isinstance(alert.get('details'), str):
                alert['details'] = json.loads(alert['details'])
        return jsonify(alerts)
    except Exception as e: print(f"[ERR] Correlated alerts: {e}"); traceback.print_exc(); return jsonify({"error": f"{e}"}), 500


@app.route('/api/risk_register')
@nocache
def get_risk_register():
    try: return jsonify(RISK_REGISTER.copy())
    except Exception as e: print(f"[ERR] Risk register: {e}"); traceback.print_exc(); return jsonify({"error": f"{e}"}), 500

@app.route('/api/stats')
@nocache
def get_stats():
    try:
        with stats_lock:
            current_stats = stats.copy()
            current_event_types = stats.get("event_types", {}).copy()
            labels = list(current_event_types.keys())
            data = list(current_event_types.values())
            
            conn = None
            try:
                conn = sqlite3.connect(DB_NAME, check_same_thread=False); c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM correlated_alerts")
                alert_count_result = c.fetchone()
                # --- FIX: Read count from DB, not in-memory ---
                current_stats['correlated_alerts'] = alert_count_result[0] if alert_count_result else 0
            except Exception as e_alert_count: print(f"[STATS ERROR] Could not count alerts: {e_alert_count}")
            finally:
                if conn: conn.close()
            
            # print(f"[API STATS DEBUG] Sending stats: {current_stats}") # Verbose
            return jsonify({"stats": current_stats, "chart_data": {"labels": labels, "data": data}})
    except Exception as e:
        print(f"[ERROR] Exception in get_stats: {e}"); traceback.print_exc()
        return jsonify({"stats": {"total_events": 0, "successful_logins": 0, "failed_logins": 0, "app_errors": 0, "correlated_alerts": 0},
                        "chart_data": {"labels": [], "data": []}}), 500


if __name__ == '__main__':
    print("[DEBUG] Stage 3: Initializing database...")
    init_db()
    print("[DEBUG] Stage 4: Starting background threads...")
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=correlation_engine, daemon=True).start()
    threading.Thread(target=geoip_enricher_thread, daemon=True).start() 
    threading.Thread(target=dns_enricher_thread, daemon=True).start()
    # --- MODIFICATION: Removed threat_intel_enricher_thread (now synchronous) ---
    if 'ntfrcv' in globals():
        threading.Thread(target=snmp_trap_receiver_thread, daemon=True).start()
        threading.Thread(target=snmp_log_processor_thread, daemon=True).start()
    else:
        print("[WARNING] PySNMP not found. SNMP Trap Receiver thread NOT started.")
        
    print("[DEBUG] Stage 5: Starting Flask web server...")
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)