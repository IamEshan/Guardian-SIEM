
# ইউজার অথেন্টিকেশনের জন্য
from werkzeug.security import generate_password_hash, check_password_hash 
from flask import Flask, render_template, request, jsonify, make_response, redirect, url_for, abort # abort যোগ করতে পারেন
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# redirect এবং url_for যোগ করা হয়েছে 👆
import time
import json
import threading
import sqlite3
import re
import subprocess
import os
from datetime import datetime, date, time as dt_time, timedelta
from flask import Flask, render_template, request, jsonify, make_response
import traceback # For detailed error logging
import requests 
import queue 
import socket 
import sys # For SOAR Admin check in process_ai_prompt
import io
from reportlab.pdfgen import canvas
#from reportlab.lib.pagesizes import letter
from reportlab.lib.pagesizes import A4 # <-- FIX: A4 সাইজ ইমপোর্ট করুন
from flask import make_response
from google import genai
# --- Import dotenv for secure config ---
try:
    from dotenv import load_dotenv
    load_dotenv() 
    print("[DEBUG] Stage 2: .env configuration loaded successfully.")
except ImportError:
    print("[FATAL ERROR] python-dotenv not installed. Please run 'pip install python-dotenv'")
    exit()

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    print("[DEBUG] Stage 2.1: Scapy imported successfully.")
except Exception as e:
    print(f"[FATAL ERROR] An unexpected error occurred while importing Scapy. Is Npcap installed correctly? Error: {e}")
    exit()

try:
    import google.generativeai as genai
    print("[DEBUG] Stage 2.2: Google Gemini library imported successfully.")
except ImportError:
    print("[FATAL ERROR] The Google Gemini library is not installed. Please run 'pip install google-generativeai'")
    exit()
    
# --- Import PySNMP libraries ---
try:
    from pysnmp.carrier.asyncore.dgram import udp
    from pysnmp.entity import engine, config
    from pysnmp.entity.rfc3413 import ntfrcv
    from pysnmp.proto.api import v2c
    print("[DEBUG] Stage 2.3: PySNMP imported successfully (for SNMP Traps).")
except ImportError:
    print("[WARNING] The PySNMP library is not installed (pip install pysnmp). SNMP Trap receiver disabled.")
    pass
    
from collections import Counter
from functools import wraps 

# --- Basic Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_ai_secret_key') 
DB_NAME = 'logs.db'
USER_DB_NAME = 'users.db'

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app) # Flask অ্যাপের সাথে LoginManager ইনিশিয়ালাইজ করা
login_manager.login_view = 'login' # লগইন না করা থাকলে এই রুটে রিডাইরেক্ট হবে।


# soc_dashboard.py - Flask-Login Setup এর পরে

class User(UserMixin):
    """
    ইউজার অবজেক্ট ম্যানেজ করার জন্য ক্লাস। 
    এটি Flask-Login-এর জন্য প্রয়োজনীয় id, username, এবং role ধারণ করে।
    """
    def __init__(self, id, username, role):
        # মনে রাখবেন: Flask-Login-এর জন্য আইডি সবসময় স্ট্রিং হতে হবে
        self.id = str(id) 
        self.username = username
        self.role = role
        
        
@login_manager.user_loader
def load_user(user_id):
    """
    ইউজার সেশন রিকোয়েস্টের সময় ডাটাবেস থেকে ইউজারকে লোড করে।
    """
    # ডাটাবেস সংযোগ
    conn = sqlite3.connect(USER_DB_NAME, check_same_thread=False)
    c = conn.cursor()
    
    # ID দ্বারা ইউজারকে খোঁজা হচ্ছে
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        # User(id, username, role)
        # ডাটাবেস থেকে পাওয়া তথ্য দিয়ে User অবজেক্ট তৈরি ও রিটার্ন
        return User(user_data[0], user_data[1], user_data[2])
    return None


def role_required(allowed_roles):
    """নির্দিষ্ট ইউজার রোলগুলির জন্য অ্যাক্সেস সীমাবদ্ধ করে।"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401) # Unauthorized - লগইন করা নেই
            
            # T3 হলো Admin, তাই তারা সব অ্যাক্সেস করতে পারবে, যদি না অন্যথায় বলা হয়
            if current_user.role == 't3':
                 pass # T3-কে বাইপাস অ্যাক্সেস দেওয়া হলো
            elif current_user.role not in allowed_roles:
                print(f"[RBAC BLOCK] User {current_user.username} (Role: {current_user.role}) attempted to access {request.path}")
                abort(403) # Forbidden - অনুমোদিত নয়
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- Gemini AI Configuration ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "") 
GEMINI_MODEL_NAME = "gemini-2.5-flash" 

if GEMINI_API_KEY:
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

# --- AbuseIPDB API Configuration ---
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
THREAT_INTEL_CACHE = {}
threat_intel_lock = threading.Lock()

# --- Geolocation Risk Configuration (Read and parse CSV string) ---
HIGH_RISK_COUNTRIES_STR = os.getenv("HIGH_RISK_COUNTRIES", "China,Russia,North Korea,Iran,Vietnam")
HIGH_RISK_COUNTRIES = [country.strip() for country in HIGH_RISK_COUNTRIES_STR.split(',') if country.strip()]
# --- NEW: Discord Webhook Configuration ---
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")


# --- In-memory storage and Locks ---
stats = {"total_events": 0, "successful_logins": 0, "failed_logins": 0, "app_errors": 0, "correlated_alerts": 0, "event_types": {}}
stats_lock = threading.Lock()
BLOCKED_IPS = set() 

# --- NEW: UEBA & Asset Configuration (R-011) ---
CRITICAL_USERS = {"Admin", "FinanceMgr", "DBAdmin", "HP"} # High-Value Users to monitor
CRITICAL_ASSETS = {"192.168.1.10", "127.0.0.1"} # Critical internal IPs (Added 127.0.0.1 for local testing)
# --- END NEW CONFIG ---

RISK_REGISTER = {
    "R-001": {"description": "Unauthorized access via brute force attacks", "impact": "High", "likelihood": "Medium", "status": "Active", "related_alerts": []},
    "R-002": {"description": "Persistence through new local account creation", "impact": "High", "likelihood": "Low", "status": "Active", "related_alerts": []},
    "R-003": {"description": "Denial of Service through service termination", "impact": "Medium", "likelihood": "Low", "status": "Active", "related_alerts": []},
    "R-004": {"description": "Exploitation of known vulnerabilities (CVEs)", "impact": "High", "likelihood": "Medium", "status": "Active", "related_alerts": []},
    "R-005": {"description": "Credential Access via Credential Manager", "impact": "High", "likelihood": "Low", "status": "Active", "related_alerts": []}, 
    "R-006": {"description": "Successful logon from a high-risk geo-location", "impact": "Critical", "likelihood": "Medium", "status": "Active", "related_alerts": []},
    # --- NEW R-011 ENTRY ---
    "R-011": {"description": "Suspicious Activity during High-Value Session (Trust Drop)", "impact": "Critical", "likelihood": "Medium", "status": "Active", "related_alerts": []},
    # --- NEW R-012 ENTRY (PQCM) ---
    "R-012": {"description": "Use of Weak/Non-Quantum Safe Cryptography", "impact": "High", "likelihood": "Low", "status": "Active", "related_alerts": []},
}
CORRELATED_ALERTS = []
alert_lock = threading.Lock()
GEOIP_CACHE = {} 
geoip_lock = threading.Lock()
DNS_CACHE = {} 
dns_lock = threading.Lock()
ACTIVE_AGENTS = {} 
ACTIVE_SESSIONS = {} 
session_lock = threading.Lock()
agents_lock = threading.Lock()

dns_queue = queue.Queue()
snmp_log_queue = queue.Queue() 

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
    6008: "Unexpected Shutdown", 6013: "System Uptime", 
    5058: "Key File Operation (Possible Crypto)", # Windows Crypto Event ID example (PQCM)
    5061: "Cryptographic Operation Status",       # Windows Crypto Event ID example (PQCM)
    9001: "MikroTik Health Poll",
    0: "Information",
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
    "CORR-GEO-RISK-LOGIN": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access/Persistence", "risk_id": "R-006"},
    # --- NEW: SESSiON TRUST SCORING (R-011) ---
    "CORR-TRUST-SCORE": {"id": "T1537", "name": "Abuse Elevation Control", "tactic": "Privilege Escalation", "risk_id": "R-011"},
    # --- NEW: PQCM (R-012) ---
    "5058_WEAK": {"id": "T1574.008", "name": "Execution Guardrails", "tactic": "Defense Evasion", "risk_id": "R-012"},
}
MITRE_DEFEND_MAP = {
    "T1110.003": {"id": "D3-AL", "name": "Account Locking"},
    "T1136.001": {"id": "D3-AM", "name": "Account Monitoring"},
    "T1489": {"id": "D3-SFC", "name": "Service File-permission Check"},
    "T1110": {"id": "D3-MFA", "name": "Multi-Factor Authentication"},
    "T1069.001": {"id": "D3-PCA", "name": "Process Code Analysis"},
    "T1555.004": {"id": "D3-CH", "name": "Credential Hoarding Mitigation"}, 
}

# --- No-Cache Decorator (Unchanged) ---
def nocache(view):
    @wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache_impl

# --- GeoIP, DNS, and Threat Intel Functions (Unchanged) ---
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
        
# --- Privilege Check Utility (Necessary for SOAR actions) ---
def is_running_as_admin():
    """Checks if the Python process is running with administrator/root privileges."""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/macOS
            return os.geteuid() == 0
    except (ImportError, AttributeError):
        return False
    
def get_geoip_data(ip_address):
    """
    Fetches GeoIP data for a public IP address, using a local cache.
    Returns: (geo_info_string, country_name)
    """
    if is_internal_ip(ip_address): return "Internal IP", None
    
    with geoip_lock:
        if ip_address in GEOIP_CACHE: 
            return GEOIP_CACHE[ip_address]
    
    geo_info = "GeoIP Lookup Failed"
    country_name = None
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp"
        response = requests.get(url, timeout=2) 
        response.raise_for_status() 
        data = response.json()
        if data.get('status') == 'success':
            country_name = data.get('country')
            geo_info = f"{data.get('city', 'N/A')}, {country_name} ({data.get('isp', 'N/A')})" 
        else:
            geo_info = f"GeoIP Lookup Failed: {data.get('message', 'N/A')}"
    except Exception as e: 
        geo_info = "GeoIP Error"
    
    result = (geo_info, country_name)
    with geoip_lock: 
        GEOIP_CACHE[ip_address] = result
    return result

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

def get_dns_name_with_retry(ip_address, max_retries=3):
    """Performs reverse DNS lookup with retry logic."""
    if is_internal_ip(ip_address):
        return "Internal IP"
    
    for attempt in range(max_retries):
        try:
            with dns_lock:
                 if ip_address in DNS_CACHE: return DNS_CACHE[ip_address]
                 
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            dns_info = str(hostname)
            
            # Update cache on success
            with dns_lock: DNS_CACHE[ip_address] = dns_info
            return dns_info
            
        except socket.herror:
            dns_info = "No PTR Record"
            with dns_lock: DNS_CACHE[ip_address] = dns_info
            return dns_info
        
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                dns_info = f"DNS Error (Retries Failed)"
                with dns_lock: DNS_CACHE[ip_address] = dns_info
                return dns_info

    return f"DNS Error (Failed)"

def get_threat_intel_data(ip_address):
    """Fetches threat intel from AbuseIPDB, using a local cache."""
    if is_internal_ip(ip_address): return None, 0 
    
    with threat_intel_lock:
        if ip_address in THREAT_INTEL_CACHE:
            return THREAT_INTEL_CACHE[ip_address]

    if not ABUSEIPDB_API_KEY:
        return "API Key Missing", 0

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=3)
        response.raise_for_status()
        data = response.json().get('data', {})
        
        score = data.get('abuseConfidenceScore', 0)
        if score > 50: 
            report_count = data.get('totalReports', 0)
            last_report_category = "N/A"
            if data.get('lastReportedAt'):
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

# --- NEW: External Notification Function (Unchanged) ---
def send_discord_notification(alert):
    """Sends a formatted notification message to a Discord webhook."""
    webhook_url = DISCORD_WEBHOOK_URL
    if not webhook_url:
        return

    # Extracting necessary data
    title = alert['title']
    description = alert['details'].get('description', 'N/A')
    recommendation = alert['details'].get('recommendation', 'N/A')
    ai_context = alert['details'].get('AI Context', {}) 
    
    agent_id = alert['agent_id']
    mitre_id = alert.get('mitre_id', 'N/A')
    risk_id = alert.get('risk_id', 'N/A')
    timestamp_iso = datetime.fromtimestamp(alert['timestamp']/1000).isoformat()
    
    # Define color based on Risk ID/Impact (FF0000 Red for Critical, FFA500 Orange for High)
    color = 15548997 
    impact = RISK_REGISTER.get(risk_id, {}).get('impact', 'N/A')
    if impact == 'High': color = 16757657 
    elif impact == 'Medium': color = 15105570 

    # Discord Embed Structure
    data = {
        "embeds": [
            {
                "title": f"🚨 {title}",
                "description": f"**Risk ID:** {risk_id} | **Impact:** {impact} | **Agent:** {agent_id}\n\n{description}",
                "color": color,
                "fields": [
                    # AI Context Fields
                    {"name": "AI Remediation Summary", "value": ai_context.get('Remediation Summary', 'N/A'), "inline": False},
                    {"name": "Predicted Next Action", "value": ai_context.get('Predicted Next Action', 'N/A'), "inline": True},
                    {"name": "Affected Likelihood (AI)", "value": ai_context.get('Affected Systems Likelihood', 'N/A'), "inline": True},
                    {"name": "MITRE ATT&CK", "value": mitre_id, "inline": True},
                    {"name": "Full Recommended Action", "value": recommendation, "inline": False},
                ],
                "timestamp": timestamp_iso
            }
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=data, timeout=5)
        response.raise_for_status() 
        print(f"[DISCORD] Successfully sent alert for {risk_id}.")
    except requests.exceptions.RequestException as e:
        pass
    except Exception as e:
        print(f"[DISCORD ERROR] Unexpected error sending alert: {e}")

# --- Database Functions (Modified for AI/STS/PQCM) ---
def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); c = conn.cursor()
        
        # 1. DROP old tables 
        c.execute('DROP TABLE IF EXISTS logs')
        c.execute('DROP TABLE IF EXISTS correlated_alerts')
        c.execute('DROP TABLE IF EXISTS incident_tickets') # <-- Added for clean schema update
        
        # 2. CREATE logs table (Standard)
        c.execute('''
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY, timestamp REAL, 
                log_type TEXT, description TEXT, 
                details TEXT, severity TEXT,
                agent_id TEXT, agent_name TEXT
            )
        ''')
        
        # 3. CREATE correlated_alerts table (Base Alerts)
        c.execute('''
            CREATE TABLE correlated_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                title TEXT,
                details TEXT,
                mitre_id TEXT,
                risk_id TEXT,
                agent_id TEXT,
                status TEXT DEFAULT 'Pending',
                urgency TEXT DEFAULT 'Low' 
            )
        ''')

        # 4. CREATE incident_tickets table (T1 to T2 Escalation - CORRECTED)
        c.execute('''
            CREATE TABLE incident_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL, 
                title TEXT,
                created_by TEXT, 
                assigned_to TEXT, 
                status TEXT DEFAULT 'OPEN', 
                priority TEXT DEFAULT 'Medium',
                creation_timestamp REAL,
                resolution_timestamp REAL,  -- <--- এটিই ছিল মিসিং কলাম
                details TEXT, 
                FOREIGN KEY (alert_id) REFERENCES correlated_alerts(id)
            )
        ''') # <--- এখানে resolution_timestamp যোগ করা হলো
        
        conn.commit()
        print(f"Database '{DB_NAME}' initialized (tables recreated with Triage and Incident Ticket support).")
        
    except sqlite3.Error as e: 
        print(f"[DB ERROR] Failed to initialize DB: {e}"); 
    finally:
        if conn: conn.close()


def init_user_db():
    """ইউজার ম্যানেজমেন্টের জন্য নতুন ডাটাবেস তৈরি করে এবং প্রাথমিক ইউজার তৈরি করে।"""
    conn = None
    try:
        # 1. ডাটাবেসের সাথে কানেক্ট করুন
        # USER_DB_NAME কনফিগারেশন থেকে 'users.db' ব্যবহার করবে
        conn = sqlite3.connect(USER_DB_NAME, check_same_thread=False)
        c = conn.cursor()
        
        # 2. 'users' টেবিল তৈরি করুন (যদি না থাকে)
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        conn.commit()
        print(f"[DEBUG] Database '{USER_DB_NAME}' initialized for users.")
        
        # 3. প্রাথমিক ইউজার তৈরি করুন (যদি টেবিলটি খালি থাকে)
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            print("[SETUP] Creating default users...")
            
            # NOTE: generate_password_hash অবশ্যই ফাইলের উপরে import করা থাকতে হবে।
            # মেথড: pbkdf2:sha256 (কারণ argon2 ত্রুটি দিচ্ছিল)
            hashed_t1 = generate_password_hash("t1pass", method='pbkdf2:sha256')
            hashed_t2 = generate_password_hash("t2pass", method='pbkdf2:sha256')
            hashed_t3 = generate_password_hash("t3pass", method='pbkdf2:sha256')

            # ডাটাবেসে ইউজারদের যুক্ত করুন (t1analyst, t2senior, t3admin)
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                      ('t1analyst', hashed_t1, 't1'))
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                      ('t2senior', hashed_t2, 't2'))
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                      ('t3admin', hashed_t3, 't3'))
            conn.commit()
            print("[SETUP] Default users (t1analyst, t2senior, t3admin) created (Password: t1pass, t2pass, t3pass).")
            
    except sqlite3.Error as e:
        print(f"[DB ERROR] Failed to initialize user DB: {e}")
    finally:
        # সংযোগ স্থাপন হয়ে থাকলে, তা বন্ধ করুন
        if conn: conn.close()


# --- Database Maintenance Functions ---
def prune_old_logs(days=30):
    """Deletes logs older than the specified number of days."""
    conn = None
    try:
        # Calculate the timestamp threshold (in milliseconds)
        threshold_ms = (datetime.now() - timedelta(days=days)).timestamp() * 1000
        
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); c = conn.cursor()
        
        # Delete old logs from the main logs table
        c.execute("DELETE FROM logs WHERE timestamp < ?", (threshold_ms,))
        deleted_log_count = c.rowcount
        
        # OPTIONAL: Delete old correlated alerts (e.g., alerts older than 90 days)
        threshold_alerts_ms = (datetime.now() - timedelta(days=90)).timestamp() * 1000
        c.execute("DELETE FROM correlated_alerts WHERE timestamp < ?", (threshold_alerts_ms,))
        deleted_alert_count = c.rowcount

        conn.commit()
        print(f"[DB PRUNING] Successfully deleted {deleted_log_count} old logs and {deleted_alert_count} old alerts.")
        
    except sqlite3.Error as e: 
        print(f"[DB PRUNING ERROR] Failed to prune database: {e}")
        traceback.print_exc()
    finally:
        if conn: conn.close()


def database_cleanup_thread(interval_hours=24):
    """Runs the pruning function periodically."""
    print(f"[DB CLEANUP] Starting periodic database cleanup thread (Interval: {interval_hours} hours).")
    # Run once at startup (after initialization) and then wait
    time.sleep(60) # Wait a minute after startup to allow logs to start flowing
    
    while True:
        try:
            prune_old_logs(days=30)
        except Exception as e:
            print(f"[DB CLEANUP ERROR] Unhandled error in cleanup thread: {e}")
        
        # Wait for the specified interval (convert hours to seconds)
        time.sleep(interval_hours * 3600)

# --- END Database Maintenance Functions ---


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

def track_and_score_session(log):
    """
    Tracks session activity for critical users and triggers R-011 if high-speed activity (trust drop) is detected.
    """
    
    # 1. Extract necessary data
    target_user = log.get('details', {}).get('Target User')
    source_ip = log.get('details', {}).get('Source IP')
    
    # Use Agent Name as fallback for target user if log details are sparse
    if not target_user:
        target_user = log.get('agent_name', 'UNKNOWN_USER')

    # Only track activity for pre-defined CRITICAL_USERS
    if not target_user or target_user not in CRITICAL_USERS:
        return
        
    current_ts = time.time() * 1000
    
    # Create a unique session key based on User, IP, and a time window (e.g., 1 hour window)
    session_key = f"{target_user}-{source_ip}-{int(current_ts / 3600000)}" 

    with session_lock:
        if session_key not in ACTIVE_SESSIONS:
            # First activity detected for this user/ip in this time window
            ACTIVE_SESSIONS[session_key] = {
                'user': target_user, 
                'start_ts': current_ts, 
                'actions': 1, 
                'last_action_ts': current_ts,
                'trust_violations': 0
            }
            return
        
        session = ACTIVE_SESSIONS[session_key]
        time_elapsed_s = (current_ts - session['last_action_ts']) / 1000
        
        session['actions'] += 1
        session['last_action_ts'] = current_ts

        # 2. Score Logic: Check for High-Speed Activity (e.g., more than 1 action per second)
        if time_elapsed_s < 1.0 and time_elapsed_s > 0: 
            session['trust_violations'] += 1 
            
        # 3. Correlation Trigger (R-011)
        if session['trust_violations'] >= 3 and (current_ts - session['start_ts']) < 300000: # 3 violations within 5 minutes
            
            # Check if alert already exists to prevent flood
            alert_id_str = f"trust-drop-{target_user}-{int(current_ts / 300000)}"
            with alert_lock: already_alerted = any(a['details'].get('alert_id') == alert_id_str for a in CORRELATED_ALERTS)
            
            if not already_alerted:
                mitre_info = MITRE_ATTACK_MAP.get("CORR-TRUST-SCORE", {})
                
                alert = {
                    "timestamp": current_ts, 
                    "title": f"CRITICAL: Trust Score Drop for {target_user}", 
                    "details": { 
                        "alert_id": alert_id_str,
                        "description": f"High-value user '{target_user}' exhibited suspicious high-speed activity ({session['trust_violations']} violations in 5 mins). Possible internal compromise.", 
                        "recommendation": "IMMEDIATELY suspend user session and validate identity." 
                    }, 
                    "mitre_id": mitre_info.get('id'), 
                    "risk_id": mitre_info.get('risk_id'), 
                    "agent_id": log.get('agent_id')
                }
                
                add_correlated_alert_to_db(alert)
                session['trust_violations'] = 0 # Reset counter after alert


def add_correlated_alert_to_db(alert):
    conn = None
    ai_context = None 
    
    try:
        risk_id = alert.get('risk_id')
        impact = RISK_REGISTER.get(risk_id, {}).get('impact')
        
        # --- NEW: Set Initial Triage Status and Urgency ---
        alert['status'] = alert.get('status', 'Pending') 
        alert['urgency'] = alert.get('urgency', 'Low')
        
        # CRITICAL button logic: If title includes CRITICAL, set urgency to High/Urgent
        if "CRITICAL" in alert.get('title', ''):
             alert['urgency'] = 'High'
        # --- END NEW Triage Status ---


        # --- 1. AI CONTEXT GENERATION ---
        if impact == 'Critical' or impact == 'High':
            
            try:
                print(f"[ALERT CONTEXT] Fetching AI context for {risk_id} ({impact})...")
                ai_context = get_gemini_alert_context(alert)
                
            except Exception as ai_e:
                error_name = ai_e.__class__.__name__
                # If AI call fails, initialize context with ALL expected fields
                ai_context = {
                    "Remediation Summary": f"AI Context Failed: {error_name}",
                    "Affected Systems Likelihood": "N/A",
                    "Predicted Next Action": "N/A"
                }
                print(f"[AI ISOLATION ERROR] AI call failed during enrichment: {ai_e}")

            # --- 2. MERGE CONTEXT AND UPDATE RECOMMENDATION ---
            if 'details' not in alert: alert['details'] = {}
            
            if ai_context:
                alert['details']['AI Context'] = ai_context
                
                # Extract AI values (safely retrieve string values)
                predicted_action = str(ai_context.get('Predicted Next Action', 'N/A'))
                ai_summary = str(ai_context.get('Remediation Summary', 'N/A'))
                
                # --- CRITICAL FIX: Merge Predicted Next Action into top-level details ---
                alert['details']['Predicted Next Action'] = predicted_action 
                
                # Update the main 'recommendation' field for combined output (Rec: field content)
                original_recommendation = alert['details'].get('recommendation', 'Investigate and isolate.')
                
                if "AI Context Failed" not in ai_summary and predicted_action != 'N/A':
                    # SUCCESS case: Combine prediction and summary
                    alert['details']['recommendation'] = f"PREDICT: {predicted_action} | SUGGEST: {ai_summary}"
                else:
                    # FAILURE case: Show the error type along with original Rec
                    failure_detail = ai_summary.split(':')[-1].strip() if ':' in ai_summary else ai_summary
                    alert['details']['recommendation'] = f"(AI Failed: {failure_detail}) | Original: {original_recommendation}"
        
        # --- 3. DB Insertion (MODIFIED TO INCLUDE TRIAGE COLUMNS) ---
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); c = conn.cursor()
        
        # NOTE: Using explicit column names to ensure Triage columns are included
        c.execute("""
            INSERT INTO correlated_alerts (
                timestamp, title, details, mitre_id, risk_id, agent_id, status, urgency
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert['timestamp'], 
            alert['title'], 
            json.dumps(alert['details']), 
            alert.get('mitre_id'), 
            alert.get('risk_id'), 
            alert.get('agent_id'),
            alert['status'],   # <--- NEW
            alert['urgency']   # <--- NEW
        ))
        conn.commit()

        # --- 4. Notification Logic (Unchanged) ---
        if impact == 'Critical' or impact == 'High':
             threading.Thread(target=send_discord_notification, args=(alert,), daemon=True).start()
             print(f"[ALERT NOTIFICATION] Triggering Discord for {risk_id} ({impact}).")

        # --- 5. In-memory update (COMPLETED LOGIC) ---
        with alert_lock:
            CORRELATED_ALERTS.insert(0, alert)
            if risk_id and risk_id in RISK_REGISTER:
                if 'related_alerts' not in RISK_REGISTER[risk_id]: RISK_REGISTER[risk_id]['related_alerts'] = []
                if alert['title'] not in RISK_REGISTER[risk_id]['related_alerts']:
                    RISK_REGISTER[risk_id]['related_alerts'].append(alert['title'])
        
        with stats_lock:
            stats['correlated_alerts'] += 1
            print(f"[STATS DEBUG] Incremented correlated_alerts to {stats['correlated_alerts']}")

    except sqlite3.Error as e: print(f"[DB ERROR] Failed to add alert: {e}")
    except Exception as e: print(f"[DB/CRITICAL ERROR] Unhandled error in alert processing: {e}"); traceback.print_exc()
    finally:
        if conn: conn.close()


def track_and_score_session(log):
    """
    Tracks session activity for critical users and triggers R-011 if high-speed activity (trust drop) is detected.
    """
    
    # 1. Extract necessary data
    target_user = log.get('details', {}).get('Target User')
    source_ip = log.get('details', {}).get('Source IP')
    
    # Only track activity for pre-defined CRITICAL_USERS
    if not target_user or target_user not in CRITICAL_USERS:
        return
        
    current_ts = time.time() * 1000
    
    # Create a unique session key based on User, IP, and a time window (e.g., 1 hour window)
    session_key = f"{target_user}-{source_ip}-{int(current_ts / 3600000)}" 

    with session_lock:
        if session_key not in ACTIVE_SESSIONS:
            # First activity detected for this user/ip in this time window
            ACTIVE_SESSIONS[session_key] = {
                'user': target_user, 
                'start_ts': current_ts, 
                'actions': 1, 
                'last_action_ts': current_ts,
                'trust_violations': 0
            }
            return
        
        session = ACTIVE_SESSIONS[session_key]
        time_elapsed_s = (current_ts - session['last_action_ts']) / 1000
        
        session['actions'] += 1
        session['last_action_ts'] = current_ts

        # 2. Score Logic: Check for High-Speed Activity (e.g., more than 1 action per second)
        # This simulates fast data fetching or rapid command execution (UEBA anomaly).
        if time_elapsed_s < 1.0 and time_elapsed_s > 0: 
            session['trust_violations'] += 1 
            
        # 3. Correlation Trigger (R-011)
        if session['trust_violations'] >= 3 and (current_ts - session['start_ts']) < 300000: # 3 violations within 5 minutes
            
            # Check if alert already exists to prevent flood
            alert_id_str = f"trust-drop-{target_user}-{int(current_ts / 300000)}"
            with alert_lock: already_alerted = any(a['details'].get('alert_id') == alert_id_str for a in CORRELATED_ALERTS)
            
            if not already_alerted:
                mitre_info = MITRE_ATTACK_MAP.get("CORR-TRUST-SCORE", {})
                
                # --- CORRECTED DICTIONARY DEFINITION STARTING HERE ---
                alert = {
                    "timestamp": current_ts, 
                    "title": f"CRITICAL: Trust Score Drop for {target_user}", 
                    "details": { 
                        "alert_id": alert_id_str,
                        "description": f"High-value user '{target_user}' exhibited suspicious high-speed activity ({session['trust_violations']} violations in 5 mins). Possible internal compromise.", 
                        "recommendation": "IMMEDIATELY suspend user session and validate identity." 
                    }, 
                    "mitre_id": mitre_info.get('id'), 
                    "risk_id": mitre_info.get('risk_id'), 
                    "agent_id": log.get('agent_id')
                }
                # --- CORRECTED DICTIONARY DEFINITION ENDING HERE ---
                
                # add_correlated_alert_to_db will handle AI context and Discord notification
                add_correlated_alert_to_db(alert)
                session['trust_violations'] = 0 # Reset counter after alert
def get_time_range_ms(range_str):
    """Calculates start timestamp in milliseconds based on range string."""
    now = datetime.now()
    start_time = None
    if range_str == '1h': start_time = now - timedelta(hours=1)
    elif range_str == '24h': start_time = now - timedelta(days=1)
    elif range_str == '7d': start_time = now - timedelta(days=7)
    elif range_str == 'all': return 0
    else: start_time = now - timedelta(days=1) 
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

# --- Correlation Engine (Unchanged) ---
def correlation_engine():
    """
    Looks for suspicious patterns in the log database, including brute force and Geo-Risk logons.
    """
    while True:
        try:
            time.sleep(30)
            conn = None
            
            conn = sqlite3.connect(DB_NAME, check_same_thread=False); conn.row_factory = sqlite3.Row; c = conn.cursor()
            now_ts = time.time() * 1000
            five_minutes_ago_ts = (datetime.now() - timedelta(minutes=5)).timestamp() * 1000
            one_hour_ago_ts = (datetime.now() - timedelta(hours=1)).timestamp() * 1000

            # Rule 1: Brute Force Success
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

            # Rule 3: High-Risk Geolocation Logon
            c.execute("""
                SELECT details, agent_id, agent_name, id, timestamp FROM logs
                WHERE description = 'Successful Logon' 
                AND details LIKE ? 
                AND timestamp > ?
            """, (f'%\"CORR_GEO_RISK\": \"TRUE\"%', one_hour_ago_ts))
            geo_risk_rows = c.fetchall()
            
            for row in geo_risk_rows:
                try: details = json.loads(row['details'])
                except: continue
                
                src_ip = details.get('Source IP', 'N/A')
                geo_risk_info = details.get('Geolocation Risk', 'N/A')
                target_user = details.get('Target User', 'N/A')
                agent_id = row['agent_id']
                
                alert_id_str = f"geo-risk-login-{agent_id}-{src_ip}-{target_user}-{int(row['timestamp'] / 3600000)}"
                with alert_lock: already_alerted = any(a['details'].get('alert_id') == alert_id_str for a in CORRELATED_ALERTS)
                
                if not already_alerted:
                    mitre_info = MITRE_ATTACK_MAP.get("CORR-GEO-RISK-LOGIN", {})
                    alert = {
                        "timestamp": row['timestamp'], 
                        "title": f"CRITICAL: High-Risk Geo Logon on {row['agent_name']}", 
                        "details": { 
                            "alert_id": alert_id_str, 
                            "description": f"Successful login by '{target_user}' from a high-risk geo-location. {geo_risk_info}", 
                            "recommendation": f"Immediate investigation of user session and enforce Geo-Fencing policy. Block {src_ip} via SOAR." 
                        }, 
                        "mitre_id": mitre_info.get('id'), 
                        "risk_id": mitre_info.get('risk_id'), 
                        "agent_id": agent_id
                    }
                    print(f"[CORRELATION] New Geo-Risk Alert: {alert_id_str}")
                    add_correlated_alert_to_db(alert)

        except sqlite3.Error as e: print(f"[CORRELATION ERROR] DB error: {e}"); traceback.print_exc()
        except Exception as e: print(f"[CORRELATION ERROR] Unexpected: {e}"); traceback.print_exc()
        finally:
            if conn: conn.close()

# --- AI Agent Logic (Unchanged) ---
def get_gemini_analysis(user_prompt, logs):
    if not gemini_analyst_model: return "Gemini AI (Analyst) is not configured."
    formatted_logs = [{"time": datetime.fromtimestamp(log['timestamp']/1000).strftime('%H:%M:%S'), "description": log['description'], "details": log.get('details',{})} for log in logs]
    system_prompt = "You are 'Guardian', a SOC analyst AI. Analyze logs, identify threats, correlate events, mention MITRE ATT&CK techniques, and suggest responses."
    full_prompt = f"User Request: \"{user_prompt}\"\n\nRecent Logs:\n{json.dumps(formatted_logs, indent=2)}"
    try:
        response = gemini_analyst_model.generate_content([system_prompt, full_prompt], generation_config=genai.types.GenerationConfig(temperature=0.7))
        if response.candidates and response.candidates[0].content.parts: return response.candidates[0].content.parts[0].text
        elif hasattr(response, 'prompt_feedback') and response.prompt_feedback: block_reason = f"Safety block: {response.prompt_feedback}"; return f"Gemini response blocked. Reason: {block_reason}"
        else: return "Unexpected/empty response from Gemini."
    except Exception as e: print(f"[ERROR] Gemini API call failed: {e}"); return f"Error contacting Gemini: {e}"


# [New Function: Add this right after the existing get_gemini_analysis function]

# [soc_dashboard.py - Replace the existing get_gemini_alert_context function entirely]

# [soc_dashboard.py - Replace the existing get_gemini_alert_context function entirely]

# [soc_dashboard.py - Inside the get_gemini_alert_context function]

def get_gemini_alert_context(alert):
    """
    Analyzes a high-severity alert using Gemini and returns a structured AI context
    including immediate remediation and the predicted next attack step (CACP).
    """
    if not gemini_analyst_model: return {"Remediation Summary": "AI not configured.", "Affected Systems Likelihood": "N/A", "Predicted Next Action": "N/A"}
    
    # Prepare structured data for the model (rest of the context setup remains the same)
    title = alert.get('title', 'Unknown Alert')
    details = alert.get('details', {})
    mitre_id = alert.get('mitre_id', 'N/A')
    risk_id = alert.get('risk_id', 'N/A')
    
    alert_context = {
        "Alert Title": title,
        "Risk ID": risk_id,
        "MITRE ATT&CK": mitre_id,
        "Agent ID": alert.get('agent_id'),
        "Source IP": details.get('Source IP', 'N/A'),
        "Target User": details.get('Target User', 'N/A'),
        "Geolocation Risk": details.get('Geolocation Risk', 'N/A'),
        "Current Time": datetime.now().isoformat()
    }
    
    system_prompt = """
    You are 'Cognitive Attack Path Predictor (CACP)'. You MUST analyze the high-severity alert and generate a structured JSON prediction for the SOC analyst. Your prediction must include the immediate remediation, system likelihood, and the single most probable next step in the attack chain (use MITRE ID, e.g., T1053.005).
    You MUST respond ONLY with a JSON object that strictly adheres to the schema.
    """
    
    full_prompt = f"Analyze this high-severity alert context and provide the JSON summary:\n{json.dumps(alert_context, indent=2)}"
    
    try:
        # 1. Define the JSON Schema (for stability)
        json_schema = {
            "type": "object",
            "properties": {
                "Remediation Summary": {"type": "string", "description": "A very brief, immediate action plan. Max 2 sentences."},
                "Affected Systems Likelihood": {"type": "string", "enum": ["High", "Medium", "Low", "N/A"]},
                "Predicted Next Action": {"type": "string", "description": "The single most probable next MITRE ATT&CK ID (e.g., T1053.005) the attacker will attempt."}
            },
            "required": ["Remediation Summary", "Affected Systems Likelihood", "Predicted Next Action"]
        }
        
        # 2. Call API (using GenerationConfig fix)
        response = gemini_analyst_model.generate_content(
            contents=[system_prompt, full_prompt], 
            config=genai.types.GenerationConfig( 
                response_mime_type="application/json",
                response_schema=json_schema
            )
        )
        
        # --- CRITICAL FIX: Direct Access and Robust Parsing ---
        # Get text from the nested structure (most reliable source for JSON)
        if response.candidates and response.candidates[0].content.parts:
            response_text = response.candidates[0].content.parts[0].text
        else:
            # Fallback (This may be the source of the TypeError if it's None)
            response_text = getattr(response, 'text', None) 
        
        if not response_text or not isinstance(response_text, str):
            # If the response is truly None or not a string, raise a specific error
            raise Exception(f"Empty or non-string response received. Check API Key or Network.")
            
        # Use Regex to isolate the JSON content ({...}) from any markdown or text wrapper
        match = re.search(r'\{.*\}', response_text.strip(), re.DOTALL)
        
        if match:
            clean_json_str = match.group(0).strip()
            context_data = json.loads(clean_json_str)
            return context_data
        else:
            raise json.JSONDecodeError("Could not isolate JSON body in AI response.", response_text, 0)
        
    except Exception as e: 
        print(f"[AI CONTEXT ERROR] Gemini API call failed: {e.__class__.__name__}: {e}")
        # Return error with ALL expected fields initialized
        return {"Remediation Summary": f"AI Context Error: {e.__class__.__name__}", "Affected Systems Likelihood": "N/A", "Predicted Next Action": "N/A"}

def gemini_query_parser(user_prompt):
    if not gemini_parser_model: return {"error": "AI query parser not configured."}
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

# [soc_dashboard.py - Replace the existing process_ai_prompt function entirely]

def process_ai_prompt(prompt, agent_id=None):
    query_plan = gemini_query_parser(prompt)
    if isinstance(query_plan, dict) and "error" in query_plan: return {"response": query_plan['error'], "data": None}

    # --- NEW: Handle SOAR Actions (with Admin Check) ---
    if isinstance(query_plan, dict) and "action" in query_plan:
        action = query_plan.get("action")
        ip = query_plan.get("ip_address")
        
        # Check Admin Privileges for SOAR actions
        if not is_running_as_admin():
            return {"response": f"SOAR FAILED: Cannot execute '{action}' action. The Flask server must be run as an **Administrator/Root**.", "data": None}
        
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
                return {"response": f"Failed to block IP. Error: {output}", "data": None}
            
        elif action == "unblock":
            print(f"[SOAR ACTION] Attempting to unblock IP: {ip}")
            rule_name = f"SIEM_Block_{ip}"
            command = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
            success, output = run_command(command)
            if success:
                if ip in BLOCKED_IPS: BLOCKED_IPS.remove(ip)
                return {"response": f"Successfully removed firewall rule for IP: {ip}", "data": None}
            else:
                return {"response": f"Failed to unblock IP. Error: {output}", "data": None}
    
    # --- Handle ANALYZE and QUERY intents (Unchanged) ---
    time_range = 'all' 
    if isinstance(query_plan, dict) and 'time_range_str' in query_plan:
        time_range = query_plan.pop('time_range_str') 
        
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


# --- Statistics and Log Parsing (Unchanged) ---
def update_stats_from_log(log):
    """Updates the in-memory global stats dictionary based on a new log."""
    if not isinstance(log, dict): return 
    with stats_lock:
        stats["total_events"] += 1
        category = "Other" 

        event_id = log.get('event_id_internal') 
        log_type = log.get('log_type', '') 

        if log_type == 'Security Event':
            if event_id == 4625:
                stats["failed_logins"] += 1
                category = "Failed Logon"
            elif event_id == 4624:
                stats["successful_logins"] += 1
                category = "Successful Logon"
            else:
                category = f"Security ({event_id or '?'})"
        elif log_type == 'Application Event':
            if event_id == 1000:
                stats["app_errors"] += 1
                category = "Application Error"
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
        elif log_type in ['Unknown Event', 'Other Event', 'Parse Error Event']: 
            category = f"Other ({event_id or '?'})"
        
        category_str = str(category)
        stats["event_types"][category_str] = stats["event_types"].get(category_str, 0) + 1


# --- `parse_and_format_log` function (Unchanged) ---
# [soc_dashboard.py - Replace the existing def parse_and_format_log(log, agent_id="unknown"): function entirely]

# [soc_dashboard.py - Replace the existing def parse_and_format_log(...) function entirely]

def parse_and_format_log(log, agent_id="unknown"):
    """
    Parses logs from various sources, applying synchronous GeoIP and Threat Intel enrichment.
    """
    
    log_channel = log.get('log_channel') 
    
    if log_channel in ['Security', 'Application', 'System']:
        try:
            event_id = log.get('event_id')
            
            description = WIN_EVENT_DESCRIPTIONS.get(event_id)
            if not description:
                msg_preview = log.get('message', f"Event ID {event_id}")
                if len(msg_preview) > 70: msg_preview = msg_preview[:70] + "..."
                description = msg_preview

            # --- CRITICAL FIX START: Ensure 'details' is a mutable dictionary ---
            # If the log sender (agent or test script) didn't send 'data_fields' as a dict, fix it.
            details = log.get('data_fields') 
            if not isinstance(details, dict) or details is None:
                 details = {} 
            # --- CRITICAL FIX END ---

            details['Event ID'] = event_id
            details['Computer'] = log.get('computer_name', 'N/A')
            details['Source'] = log.get('log_source', log_channel)
            
            # --- Timestamp Conversion ---
            agent_timestamp_str = log.get('timestamp')
            db_timestamp = time.time() * 1000 
            if agent_timestamp_str:
                try:
                    dt = datetime.fromisoformat(agent_timestamp_str)
                    db_timestamp = dt.timestamp() * 1000
                except Exception as e_ts:
                    print(f"[WARN] Could not parse timestamp '{agent_timestamp_str}': {e_ts}")

            # --- Severity and IP Logic ---
            source_ip = details.get('IpAddress') or details.get('Client Address')
            severity = "WARNING" if event_id in [1000, 4625, 4720, 7034, 5379] else "INFO"

            if source_ip and source_ip != '':
                details['Source IP'] = source_ip 
                if not is_internal_ip(source_ip): 
                    
                    # --- Instant GeoIP Lookup for Risk Check (Synchronous) ---
                    geo_info_str, country = get_geoip_data(source_ip)
                    details['Source Geo'] = geo_info_str 
                    
                    if country and country in HIGH_RISK_COUNTRIES and event_id == 4624:
                        severity = "CRITICAL"
                        details["Geolocation Risk"] = f"HIGH - Successful Logon from {country}"
                        details["CORR_GEO_RISK"] = "TRUE" 
                    
                    # --- Instant Threat Intel (Synchronous) ---
                    threat_info, score = get_threat_intel_data(source_ip)
                    if threat_info:
                        details['Threat Intel (Source)'] = threat_info
                        if score > 50 and severity != "CRITICAL": severity = "CRITICAL" 
                    
                    dns_queue.put((-1, source_ip)) 
            
            if source_ip in BLOCKED_IPS: severity = "CRITICAL"
            
            # --- Normalize User keys for Correlation ---
            if 'TargetUserName' in details:
                details['Target User'] = details['TargetUserName']
            if 'Account Name' in details:
                details['Target User'] = details['Account Name'] 
            
            # --- Enrichment (MITRE/CVE) ---
            event_id_str = str(event_id)
            if event_id is not None and event_id_str in MITRE_ATTACK_MAP: 
                details["MITRE ATT&CK"] = f"{MITRE_ATTACK_MAP[event_id_str]['id']}: {MITRE_ATTACK_MAP[event_id_str]['name']}"
            
            # --- NEW: PQCM (R-012) - Weak Cryptography Check ---
            details_str = json.dumps(details).upper()
            
            if event_id in [5058, 5061]:
                if 'SHA1' in details_str or 'MD5' in details_str or 'RSA/1024' in details_str:
                    
                    # R-012 Trigger Logic: Promote Severity and Tag Risk
                    details["CRYPTO_VULNERABILITY"] = "WEAK_ALGORITHM_DETECTED"
                    
                    # Promote severity to CRITICAL (matching the High impact of R-012)
                    severity = "CRITICAL" 
                    
                    # Apply MITRE mapping for R-012
                    mitre_info = MITRE_ATTACK_MAP.get("5058_WEAK", {})
                    if mitre_info:
                        details["MITRE ATT&CK"] = f"{mitre_info['id']}: {mitre_info['name']}"
                        details["RISK_R-012_FLAG"] = "TRUE" # Flag for future correlation rules
            # --- End PQCM Check ---
            
            log_message = log.get('message', '').lower()
            for app, cve in VULNERABLE_APPS_CVE.items():
                if app.lower() in json.dumps(details).lower() or app.lower() in log_message: 
                    details["CVE"] = cve
                    
            return {
                "log_type": f"{log_channel} Event", 
                "event_id_internal": event_id, 
                "description": description, 
                "details": details, 
                "timestamp": db_timestamp, 
                "severity": severity
            }
        except Exception as e_parse_win:
            print(f"[PARSE ERROR] Failed to parse Windows log: {e_parse_win}")
            traceback.print_exc()
            details={'RawMessage': log.get('message','N/A'), 'ParseError': str(e_parse_win)}; 
            event_id=log.get('event_id'); 
            return {"log_type": "Parse Error Event", "event_id_internal": event_id, "description": f"Source: {log_channel}, Event: {event_id}", "details": details, "timestamp": time.time() * 1000, "severity": "WARNING"}

    # --- OLD LOGIC (for Network Sniffer, SNMP, etc.) ---
    
    timestamp_ms = time.time() * 1000 
    log_type_source = log.get('log_source')
    primary_type = log_type_source 
    
    if primary_type == 'SNMP Polling':
        event_id = log.get('event_id') 
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
        return {"log_type": "Unknown Event", "event_id_internal": event_id, "description": f"Source: {original_source_for_details}, Event: {event_id}", "details": details, "timestamp": timestamp_ms, "severity": "INFO"}

    original_source_for_details = log_type_source or primary_type

    if primary_type == 'Network':
        source_ip = log.get('source_ip', 'N/A'); severity = 'CRITICAL' if source_ip in BLOCKED_IPS else 'INFO'
        dest_ip = log.get('dest_ip', 'N/A')
        desc = f"Packet from {source_ip}"
        details = {"Source IP": source_ip, "Destination IP": dest_ip, "Protocol": log.get('protocol', 'N/A')}
        
        # --- SYNCHRONOUS ENRICHMENT FOR SOURCE IP ---
        if source_ip and not is_internal_ip(source_ip):
            # Threat Intel
            threat_info, score = get_threat_intel_data(source_ip)
            if threat_info:
                details['Threat Intel (Source)'] = threat_info
                if score > 50 and severity != "CRITICAL": severity = "CRITICAL"
            
            # --- Instant GeoIP Lookup for Source IP (Synchronous) ---
            geo_info_str, country = get_geoip_data(source_ip)
            details['Source Geo'] = geo_info_str 
            if country and country in HIGH_RISK_COUNTRIES: 
                severity = "CRITICAL"
                details["Geolocation Risk"] = f"HIGH - Traffic from {country}"
                details["CORR_GEO_RISK"] = "TRUE" 
            
            dns_queue.put((-1, source_ip)) 

        # --- SYNCHRONOUS ENRICHMENT FOR DESTINATION IP ---
        if dest_ip and not is_internal_ip(dest_ip):
            # Threat Intel
            threat_info, score = get_threat_intel_data(dest_ip)
            if threat_info:
                details['Threat Intel (Dest)'] = threat_info
                if score > 50 and severity != "CRITICAL": severity = "CRITICAL"
                
            # --- Instant GeoIP Lookup for Destination IP (Synchronous) ---
            geo_info_str, country = get_geoip_data(dest_ip)
            details['Destination Geo'] = geo_info_str 
            
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
            # Threat Intel
            threat_info, score = get_threat_intel_data(trap_source_ip)
            if threat_info:
                details['Threat Intel (Source)'] = threat_info
                if score > 50 and severity != "CRITICAL": severity = "CRITICAL"
                
            # --- Instant GeoIP Lookup for Source IP (Synchronous) ---
            geo_info_str, country = get_geoip_data(trap_source_ip)
            details['Source Geo'] = geo_info_str 
            if country and country in HIGH_RISK_COUNTRIES: 
                severity = "CRITICAL"
                details["Geolocation Risk"] = f"HIGH - Trap from {country}"
                details["CORR_GEO_RISK"] = "TRUE" 
            
            dns_queue.put((-1, trap_source_ip))

        return {"log_type": "SNMP Trap", "event_id_internal": None, "description": description, "details": details, "timestamp": timestamp_ms, "severity": severity}
        
    else: 
        details={}; details['RawMessage']=log.get('message','N/A'); event_id=log.get('event_id'); 
        return {"log_type": "Other Event", "event_id_internal": event_id, "description": f"Source: {original_source_for_details}, Event: {event_id}", "details": details, "timestamp": timestamp_ms, "severity": "INFO"}
# --- Network Sniffing (Unchanged) ---
# [soc_dashboard.py - Replace the existing def packet_handler(packet): function entirely]

def packet_handler(packet):
    if IP in packet:
        proto = packet.sprintf("%IP.proto%").upper(); proto_val = proto
        if proto == 'TCP': proto_val = 'TCP'
        elif proto == 'UDP': proto_val = 'UDP'
        elif proto == 'ICMP': proto_val = 'ICMP'
        log_entry = {'type': 'network_packet', 'source_ip': packet[IP].src, 'dest_ip': packet[IP].dst, 'protocol': proto_val}
        
        formatted = parse_and_format_log(log_entry, agent_id="network-sniffer")
        
        if formatted:
            log_id = add_log_to_db(formatted, "network-sniffer", "Network Sniffer")
            
            # --- NEW: Call Session Tracking/Scoring for Network Data (STS) ---
            track_and_score_session(formatted)
            # --- END NEW ---
            
            if log_id:
                if formatted.get('details'):
                    src_ip = formatted['details'].get('Source IP')
                    dst_ip = formatted['details'].get('Destination IP')
                    
                    if src_ip and not is_internal_ip(src_ip):
                        dns_queue.put((log_id, src_ip))
                    if dst_ip and not is_internal_ip(dst_ip):
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

# --- Enrichment Worker Thread Functions (Unchanged) ---
def geoip_enricher_thread():
    """GeoIP worker is now mostly a placeholder for future use, as primary GeoIP is synchronous."""
    print("[GEOIP WORKER] Starting GeoIP enrichment thread (Idling)...")
    while True:
        try:
            time.sleep(10) 
        except Exception as e:
            print(f"[GEOIP WORKER ERROR] {e}"); traceback.print_exc()
            time.sleep(5)

def dns_enricher_thread():
    """Worker thread to perform reverse DNS lookups and update the DB."""
    print("[DNS WORKER] Starting DNS enrichment thread...")
    while True:
        try:
            log_id, ip_address = dns_queue.get(timeout=5)
            if ip_address is None: break
            
            # --- MODIFIED: Use the robust retry function ---
            dns_name = get_dns_name_with_retry(ip_address) 
            
            # Check if we got a valid hostname before updating the DB
            if dns_name and dns_name not in ["Internal IP", "No PTR Record", "DNS Error (Retries Failed)"] and log_id != -1:
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
            continue
        except Exception as e:
            print(f"[DNS WORKER ERROR] {e}"); traceback.print_exc()
            if 'log_id' in locals(): dns_queue.task_done()

# --- SNMP Trap Receiver/Processor (Unchanged) ---
def snmp_trap_receiver_thread():
    """A dedicated thread to listen for SNMP traps on UDP port 162."""
    print("[SNMP TRAP] Starting SNMP Trap Receiver on 0.0.0.0:162...")
    
    snmpEngine = engine.SnmpEngine()

    try:
        config.addTransport(
            snmpEngine,
            udp.DOMAIN_NAME + (1,),
            udp.UdpTransport().openServerMode(('0.0.0.0', 162))
        )
    except Exception as e:
        print(f"[FATAL SNMP ERROR] Could not bind to UDP port 162. Check permissions (e.g., run as root/admin). Error: {e}")
        return 

    config.addV1System(snmpEngine, 'my-area', 'public') 

    def snmp_trap_callback(snmpEngine, stateReference, contextEngineId, contextName,
                           varBinds, cbCtx):
        try:
            transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
            source_ip = transportAddress[0]

            trap_details = {}
            trap_oid = "N/A"
            for oid, val in varBinds:
                oid_str = oid.prettyPrint()
                val_str = val.prettyPrint()
                if oid_str == '1.3.6.1.6.3.1.1.4.1.0': 
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

def snmp_log_processor_thread():
    """Processes SNMP logs from the queue and adds them to the database."""
    print("[SNMP PROCESSOR] Starting SNMP log processor thread...")
    while True:
        try:
            log_entry = snmp_log_queue.get(timeout=1)
            if log_entry is None: break

            agent_id = log_entry.get("agent_id")
            agent_name = log_entry.get("agent_name")

            formatted = parse_and_format_log(log_entry, agent_id=agent_id) 
            if formatted:
                add_log_to_db(formatted, agent_id, agent_name)
                update_stats_from_log(formatted)
            
            snmp_log_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[SNMP PROCESSOR ERROR] {e}")
            traceback.print_exc()
            if 'log_entry' in locals():
                snmp_log_queue.task_done()


# ----------------------------------------------------------------------
# --- Flask Web Application Routes (MODIFIED for File Templating) ---
# ----------------------------------------------------------------------

# soc_dashboard.py - [Unified Flask Routes]

# --- 1. Login, Index, Dashboard & Logout Routes ---




@app.route('/')
def index():
    """
    হোমপেজ, যা ইউজার লগইন না করা থাকলে সরাসরি /login রুটে নিয়ে যায়।
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    # এখন শুধু ইউনিভার্সাল '/login' রুটে রিডাইরেক্ট করা হচ্ছে
    return redirect(url_for('login')) 





@app.route('/login', methods=['GET', 'POST']) # <--- URL থেকে <tier> অংশটি সরিয়ে দেওয়া হয়েছে
def login(): # <--- ফাংশন আর্গুমেন্ট থেকে tier সরিয়ে দেওয়া হয়েছে
    """
    ইউজারনেম এবং পাসওয়ার্ডের মাধ্যমে স্বয়ংক্রিয়ভাবে রোল নির্ধারণ ও লগইন করে।
    """
    
    # 1. ইউজার ইতিমধ্যে লগইন করা থাকলে ড্যাশবোর্ডে পাঠান
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # 2. POST রিকোয়েস্ট (লগইন চেষ্টা)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(USER_DB_NAME)
        c = conn.cursor()
        # ডাটাবেস থেকে ইউজার ডেটা Fetch করা হচ্ছে
        c.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        conn.close()

        if user_data:
            # check_password_hash ব্যবহার করে পাসওয়ার্ড ভেরিফাই করা হচ্ছে
            if check_password_hash(user_data[2], password):
                user = User(user_data[0], user_data[1], user_data[3])
                
                # *** রোলটি স্বয়ংক্রিয়ভাবে নির্ধারিত হলো এবং কোনো চেকিং দরকার নেই ***
                login_user(user) # Flask-Login সেশন শুরু
                return redirect(url_for('dashboard'))
            
        # ব্যর্থ হলে পুনরায় লগইন পেজ দেখান
        # NOTE: tier আর্গুমেন্টটি এখন আর দরকার নেই
        return render_template('login.html', error="❌ Invalid Credentials")

    # 3. GET রিকোয়েস্ট হলে লগইন টেমপ্লেট দেখান
    return render_template('login.html', error=None)


# soc_dashboard.py ফাইলের মধ্যে যোগ করুন

@app.route('/live_logs_window') # <--- ছবির URL এর সাথে ম্যাচ করার জন্য
@login_required 
def live_log_stream_window(): # <--- ফাংশনটির নাম পরিবর্তন করা হলো
    """লাইভ লগ স্ট্রিম পেজটিকে নতুন উইন্ডোতে রেন্ডার করে।"""
    # NOTE: live_logs.html ফাইলটি আপনার templates ফোল্ডারে থাকতে হবে।
    return render_template('live_logs.html', user_role=current_user.role)


@app.route('/full_ticket_history')
@login_required 
@role_required(['t1', 't2', 't3']) # T1/T2/T3 সবার জন্য অ্যাক্সেস খোলা হলো
def full_ticket_history_page():
    """সম্পূর্ণ টিকিট ট্র্যাকিং পেজটি রেন্ডার করে।"""
    # NOTE: ticket_history.html ফাইলটি আপনার templates ফোল্ডারে থাকতে হবে।
    return render_template('ticket_history.html', user_role=current_user.role)



@app.route('/dashboard')
@login_required 
def dashboard():
    # 1. NEW: Python-এ কলাম সাইজ গণনা করুন (Threat Center Grid Column Definition)
    # T2/T3 role হলে, Threat Center কলাম 1 থেকে 10 পর্যন্ত হবে (টিকিট Queue এর জন্য 10-12 ফাঁকা থাকবে)
    # T1 role হলে, Threat Center কলাম 1 থেকে শেষ পর্যন্ত (-1) হবে।
    threat_center_cols_variable = '1 / 10' if current_user.role in ['t2', 't3'] else '1 / -1'
    
    return render_template(
        'dashboard.html', 
        user_role=current_user.role, 
        mitre_attack_map=MITRE_ATTACK_MAP,
        # নতুন ভেরিয়েবলটি HTML এ পাস করা হলো:
        threat_center_cols_variable=threat_center_cols_variable 
    )

@app.route('/logout')
@login_required 
def logout():
    """ইউজারকে সেশন থেকে লগআউট করে।"""
    logout_user()
    return redirect(url_for('index'))


# ----------------------------------------------------------------------
# --- 2. RBAC PROTECTED API ROUTES ---
# ----------------------------------------------------------------------

# --- 2.1. AI Agent / Process Prompt (T2, T3 Only) ---
# NOTE: এটি handle_agent_prompt-এর FINAL সংজ্ঞা, কোনো ডুপ্লিকেট রাখবেন না।
@app.route('/api/agent', methods=['POST'])
@nocache
@role_required(['t2', 't3']) 
def handle_agent_prompt():
    prompt = request.json.get('prompt')
    agent_id = request.json.get('agent_id')
    
    if not prompt: 
        return jsonify({"response": "No prompt.", "data": None}), 400
    
    try:
        result = process_ai_prompt(prompt, agent_id=agent_id) 
        return jsonify(result)
        
    except Exception as e: 
        print(f"[ERROR] Agent prompt: {e}")
        traceback.print_exc()
        return jsonify({"response": f"Error: {e}", "data": None}), 500


# soc_dashboard.py (সম্পূর্ণ get_all_incident_tickets ফাংশন)

@app.route('/api/all_tickets', methods=['GET'])
@role_required(['t1', 't2', 't3'])
@nocache
def get_all_incident_tickets():
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        conn.row_factory = sqlite3.Row 
        c = conn.cursor()
        
        query = "SELECT * FROM incident_tickets WHERE 1=1"
        params = []
        
        start_ts = request.args.get('start_ts', None)
        end_ts = request.args.get('end_ts', None)
        
        if start_ts:
            query += " AND creation_timestamp >= ?"
            params.append(start_ts)
        
        if end_ts:
            query += " AND creation_timestamp <= ?"
            params.append(end_ts)
            
        query += " ORDER BY creation_timestamp DESC"
        
        c.execute(query, tuple(params))
        tickets = [dict(row) for row in c.fetchall()]
        
        # --- এক্সট্র্যাকশন লজিক শুরু ---
        for ticket in tickets:
            details_dict = {}
            
            # 1. JSON details parsing
            # টিকিট ডিটেইলস Parse করা
            if isinstance(ticket.get('details'), str):
                try: 
                    details_dict = json.loads(ticket['details'])
                except json.JSONDecodeError: 
                    pass 
            elif isinstance(ticket.get('details'), dict):
                details_dict = ticket['details']
            
            # 2. Agent ID এক্সট্র্যাক্ট করা (শক্তিশালী ফলব্যাক সহ)
            # এটি নিশ্চিত করে যে Agent ID মূল Alert Details (details_dict) অথবা
            # Correlated Alert-এর টপ লেভেল agent_id থেকে আসবে।
            agent_id = details_dict.get('agent_id') or details_dict.get('Agent ID') or 'N/A'
            
            # যদি details_dict টি Correlated Alert এর মূল Details হয়, তাহলে Agent ID সেখানে থাকতে পারে
            if agent_id == 'N/A' and 'agent_id' in details_dict:
                agent_id = details_dict['agent_id']
                
            ticket['agent_id_for_display'] = agent_id
            
            # 3. Details Preview তৈরি করা
            description = details_dict.get('description', 'N/A')
            source_ip = details_dict.get('Source IP', 'N/A')
            target_user = details_dict.get('Target User', 'N/A')
            predicted_action = details_dict.get('Predicted Next Action', 'N/A')

            preview_parts = []
            
            # Alert Title (Ticket Title থেকে সংক্ষেপ করা)
            if ticket.get('title'):
                title_preview = ticket['title'].split(':')[1].strip() if ':' in ticket['title'] else ticket['title']
                preview_parts.append(f"Title: {title_preview}")
                
            # গুরুত্বপূর্ণ ডিটেইলস যোগ করা
            if source_ip != 'N/A': preview_parts.append(f"IP: {source_ip}")
            if target_user != 'N/A': preview_parts.append(f"User: {target_user}")
            if predicted_action != 'N/A': preview_parts.append(f"AI Next: {predicted_action}")
            
            ticket['details_preview_text'] = " | ".join(preview_parts) if preview_parts else "No detailed context available."
            
            # 4. Timestamp formatting (আগের মতোই থাকবে)
            if ticket.get('creation_timestamp'):
                 ticket['creation_date'] = datetime.fromtimestamp(ticket['creation_timestamp'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
            if ticket.get('resolution_timestamp'):
                 ticket['resolution_date'] = datetime.fromtimestamp(ticket['resolution_timestamp'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
            else:
                 ticket['resolution_date'] = 'N/A'
            
            # মূল details ডিকশনারি সংরক্ষণ করা
            ticket['details'] = details_dict
        
        # --- এক্সট্র্যাকশন লজিক শেষ ---

        return jsonify(tickets)
    except Exception as e:
        print(f"[FULL TICKET TRACKER CRITICAL ERROR] Failed to fetch all tickets: {e}")
        # DEBUG: যদি কোনো ত্রুটি হয়, Agent ID এবং Details Preview সহ একটি ত্রুটি বার্তা দেখানো হবে।
        traceback.print_exc()
        return jsonify({"error": f"Failed to fetch tickets: {e.__class__.__name__}"}), 500
    finally:
        if conn: conn.close()



# soc_dashboard.py - get_ai_investigation_suggestion ফাংশন (FINAL FIX)

@app.route('/api/get_ai_suggestion', methods=['POST'])
@role_required(['t2', 't3'])
@nocache
def get_ai_investigation_suggestion():
    # 1. AI কনফিগারেশন চেক
    if not gemini_analyst_model:
        return jsonify({"status": "warning", "suggestion": "AI is offline (Gemini not configured). Cannot generate plan."}), 200

    data = request.get_json()
    ticket_id = data.get('ticket_id')
    
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME); conn.row_factory = sqlite3.Row; c = conn.cursor()
        
        c.execute("SELECT t.title, t.details, t.alert_id FROM incident_tickets t WHERE t.id = ?", (ticket_id,))
        ticket_row = c.fetchone()
        
        if not ticket_row:
            return jsonify({"status": "error", "suggestion": "Ticket not found."}), 404
        
        ticket = dict(ticket_row)
        
        # --- CRITICAL FIX: Robust JSON Parsing and Error Handling ---
        details_raw = ticket.get('details')
        if not details_raw or not isinstance(details_raw, str):
             details = {"error": "Original alert details are missing or corrupt."}
        else:
             try:
                 details = json.loads(details_raw)
             except (json.JSONDecodeError, TypeError) as json_err:
                 # এই TypeError বা JSONDecodeError টিই আপনার রিপোর্টটিকে ভেঙ্গে দিচ্ছিল
                 details = {"Parse Error": f"Failed to decode alert details: {json_err.__class__.__name__}"}
        # -------------------------------------------
        
        # 2. Gemini AI কে জিজ্ঞাসা করুন
        system_prompt = "You are a Tier 2 SOC AI Investigator. Provide a human-readable, step-by-step mitigation and investigation plan (max 4 steps) based on the alert details. Use Markdown formatting for clarity."
        
        full_prompt = f"Ticket ID: {ticket_id}\nTitle: {ticket['title']}\nOriginal Alert Details: {json.dumps(details, indent=2)}"
        
        # API কল
        ai_response = gemini_analyst_model.generate_content([system_prompt, full_prompt]).text
        
        return jsonify({"status": "success", "suggestion": ai_response}), 200
        
    except Exception as e:
        print(f"[AI INVESTIGATION CRITICAL ERROR] Ticket ID {ticket_id}. Error: {e}")
        return jsonify({"status": "error", "suggestion": f"AI System Error: {e.__class__.__name__}"}), 500
    finally:
        if conn: conn.close()


# --- 2.2. Alert Triage / Status Update (T1, T2, T3) ---
@app.route('/api/update_alert_status', methods=['POST'])
@nocache
@role_required(['t1', 't2', 't3']) 
def update_alert_status():
    
    data = request.get_json()
    alert_id = data.get('id')
    new_status = data.get('status')
    new_urgency = data.get('urgency') # এই লাইন পর্যন্ত আপনার কাছে ছিল

    # --- DB Update Logic (এই লজিকটি যোগ করুন) ---
    if not alert_id:
        return jsonify({"status": "error", "message": "Alert ID is required."}), 400

    conn = None
    try:
        # DB_NAME হলো 'logs.db' যা আপনার alert গুলি ধরে রাখে
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        updates = []
        params = []

        if new_status and new_status in ['Solved', 'Pending', 'Dismissed']:
            updates.append("status = ?")
            params.append(new_status)
            
        if new_urgency and new_urgency in ['Low', 'Medium', 'High', 'Urgent']:
            updates.append("urgency = ?")
            params.append(new_urgency)

        if not updates:
            return jsonify({"status": "error", "message": "No valid status or urgency update provided."}), 400
            
        # SQL কোয়েরি তৈরি করা হচ্ছে
        set_clause = ", ".join(updates)
        query = f"UPDATE correlated_alerts SET {set_clause} WHERE id = ?"
        params.append(alert_id)
        
        c.execute(query, params)
        conn.commit()
        
        # কোনো রো আপডেট হয়েছে কিনা তা চেক করা
        if c.rowcount == 0:
            return jsonify({"status": "warning", "message": f"Alert ID {alert_id} not found."}), 404

        print(f"[TRIAGE] Alert ID {alert_id} updated. Status: {new_status}, Urgency: {new_urgency}")
        return jsonify({"status": "success", "message": "Alert status updated."})

    except Exception as e:
        print(f"[DB ERROR] Failed to update alert status: {e}")
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500
    finally:
        if conn:
            conn.close()


# soc_dashboard.py - [API ROUTES] সেকশনের মধ্যে বসান

@app.route('/api/escalate_alert', methods=['POST'])
@role_required(['t1', 't3']) # T1 এবং T3 (Admin) টিকিট তৈরি করতে পারবে
@nocache
def create_incident_ticket():
    data = request.get_json()
    alert_id = data.get('alert_id')
    
    if not alert_id:
        return jsonify({"status": "error", "message": "Alert ID is required for escalation."}), 400

    conn = None
    try:
        # DB_NAME হলো 'logs.db'
        conn = sqlite3.connect(DB_NAME); c = conn.cursor()
        
        # 1. মূল অ্যালার্ট ডেটা Fetch করুন
        # correlated_alerts টেবিল থেকে তথ্য নিচ্ছি
        c.execute("SELECT title, details, risk_id, agent_id FROM correlated_alerts WHERE id = ?", (alert_id,))
        alert_row = c.fetchone()
        if not alert_row:
            return jsonify({"status": "error", "message": f"Alert ID {alert_id} not found."}), 404
            
        title, details_json, risk_id, agent_id = alert_row
        
        # 2. নতুন টিকেট তৈরি করে incident_tickets টেবিলে ইনসার্ট করুন
        ticket_title = f"[ESCALATED] {risk_id}: {title}"
        current_ts = time.time() * 1000
        
        c.execute("""
            INSERT INTO incident_tickets (
                alert_id, title, created_by, assigned_to, 
                priority, status, creation_timestamp, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id, 
            ticket_title, 
            current_user.username, 
            'UNASSIGNED', 
            'High', 
            'OPEN', 
            current_ts, 
            details_json
        ))
        
        ticket_id = c.lastrowid
        
        # 3. মূল অ্যালার্টের status আপডেট করুন (T1 ট্রায়েজ সম্পন্ন করেছে)
        c.execute("UPDATE correlated_alerts SET status = ?, urgency = ? WHERE id = ?", 
                  ('Escalated', 'High', alert_id))
        
        conn.commit()
        
        print(f"[ESCALATION] New Ticket {ticket_id} created by {current_user.username} for Alert {alert_id}")
        
        return jsonify({"status": "success", "message": f"Incident Ticket {ticket_id} created and escalated.", "ticket_id": ticket_id})

    except Exception as e:
        print(f"[TICKET ERROR] Failed to create ticket: {e}")
        # traceback.print_exc() 
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500
    finally:
        if conn: conn.close()

@app.route('/api/my_tickets', methods=['GET'])
@role_required(['t2', 't3']) # <-- RBAC: শুধুমাত্র T2 এবং T3 টিকিট দেখতে পারবে
@nocache
def get_my_escalated_tickets():
    """
    T2/T3 ইউজারদের জন্য OPEN বা IN_PROGRESS স্ট্যাটাসে থাকা টিকিটগুলি ফেচ করে।
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        conn.row_factory = sqlite3.Row # ডেটা ডিকশনারি আকারে পেতে
        c = conn.cursor()
        
        # T2 ব্যবহারকারী শুধুমাত্র OPEN/IN_PROGRESS স্ট্যাটাসের টিকিট দেখবে (যা তাদের কাজ)
        query = """
            SELECT * FROM incident_tickets 
            WHERE status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE') 
            ORDER BY creation_timestamp DESC LIMIT 20
        """
        
        c.execute(query)
        tickets = [dict(row) for row in c.fetchall()]
        
        # ডিটেইলস কলামের JSON স্ট্রিং-কে আবার Python ডিকশনারিতে কনভার্ট করা
        for ticket in tickets:
            if isinstance(ticket.get('details'), str):
                try:
                    ticket['details'] = json.loads(ticket['details'])
                except json.JSONDecodeError:
                    # যদি JSON parsing এ সমস্যা হয়, তবে স্ট্রিং হিসেবেই রাখব
                    pass 
        
        return jsonify(tickets)
    except Exception as e:
        print(f"[TICKET ERROR] Failed to fetch tickets: {e}")
        return jsonify({"error": f"Failed to fetch tickets: {e}"}), 500
    finally:
        if conn: conn.close()


# --- 2.3. Admin Risk Control (T3 Only) ---
@app.route('/api/admin/risk_control', methods=['POST'])
@nocache
@role_required(['t3']) 
def admin_risk_control():
    """T3 ইউজারদের জন্য রিস্ক রেজিস্টার বা SOAR সেটিংস পরিবর্তন করার ডামি রুট।"""
    return jsonify({"status": "success", "message": "Access Granted to T3 (Admin)."})
    
# NOTE: আপনার অন্যান্য API রুটগুলি (যেমন /api/logs, /api/stats) এই সেকশনের ঠিক পরে থাকবে।

# [soc_dashboard.py - Add this new Flask route near other utility functions]

# [soc_dashboard.py - Add this new Flask route]
# soc_dashboard.py - update_ticket_status() ফাংশন

# soc_dashboard.py - update_ticket_status() ফাংশন

@app.route('/api/update_ticket_status', methods=['POST'])
@role_required(['t2', 't3']) 
@nocache
def update_ticket_status():
    data = request.get_json()
    ticket_id = data.get('ticket_id')
    new_status = data.get('new_status')
    assigned_to = data.get('assigned_to', current_user.username) 

    if not ticket_id or not new_status:
        return jsonify({"status": "error", "message": "Ticket ID and new status are required."}), 400

    VALID_STATUSES = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'CLOSED']
    if new_status not in VALID_STATUSES:
        return jsonify({"status": "error", "message": f"Invalid status: {new_status}"}), 400

    conn = None
    try:
        conn = sqlite3.connect(DB_NAME); c = conn.cursor()
        current_ts = time.time() * 1000

        # যদি RESOLVED, FALSE_POSITIVE বা CLOSED হয়, resolution_timestamp যোগ করুন
        if new_status in ['RESOLVED', 'FALSE_POSITIVE', 'CLOSED']:
            
            # 1. incident_tickets টেবিল আপডেট করুন
            c.execute("""
                UPDATE incident_tickets 
                SET status = ?, assigned_to = ?, resolution_timestamp = ?
                WHERE id = ?
            """, (new_status, assigned_to, current_ts, ticket_id))

            # --- NEW LOGIC START: Correlated Alert স্ট্যাটাস আপডেট করুন ---
            # 2. সংশ্লিষ্ট Correlated Alert ID খুঁজে বের করুন
            c.execute("SELECT alert_id FROM incident_tickets WHERE id = ?", (ticket_id,))
            alert_id_row = c.fetchone()
            
            if alert_id_row:
                alert_id = alert_id_row[0]
                
                # 3. Correlated Alert-এর স্ট্যাটাস 'Solved' করে দিন
                # এটি নিশ্চিত করে যে অ্যালার্টটি ড্যাশবোর্ডের "Threat Center" থেকে সরে যাবে
                c.execute("UPDATE correlated_alerts SET status = 'Solved' WHERE id = ?", (alert_id,))
                print(f"[STATUS SYNC] Alert ID {alert_id} status updated to 'Solved' after Ticket {ticket_id} change to {new_status}.")
            # --- NEW LOGIC END ---

        else:
            # অন্যথায়, শুধু স্ট্যাটাস আপডেট করুন (resolution_timestamp NULL করে দিন)
             c.execute("""
                UPDATE incident_tickets 
                SET status = ?, assigned_to = ?, resolution_timestamp = NULL
                WHERE id = ?
            """, (new_status, assigned_to, ticket_id))

        if c.rowcount == 0:
            return jsonify({"status": "error", "message": f"Ticket {ticket_id} not found."}), 404

        conn.commit()
        
        return jsonify({"status": "success", "message": f"Ticket {ticket_id} status updated to {new_status}."})

    except Exception as e:
        # বিশদ ত্রুটি লগিং: এটি ফেইলরের মূল কারণ চিহ্নিত করতে সাহায্য করবে
        print(f"[TICKET UPDATE CRITICAL ERROR] Ticket {ticket_id} failed to update. Error: {e}")
        return jsonify({"status": "error", "message": f"Server error occurred. Check server console."}), 500
    finally:
        if conn: conn.close()

# soc_dashboard.py - generate_incident_report() ফাংশন

# soc_dashboard.py - generate_incident_report() ফাংশন

# soc_dashboard.py - generate_incident_report() ফাংশন

from reportlab.lib.pagesizes import A4 # <-- নিশ্চিত করুন এটি A4 ইমপোর্ট করছে

@app.route('/api/generate_report/<int:ticket_id>', methods=['GET'])
@role_required(['t2', 't3'])
@nocache
def generate_incident_report(ticket_id):
    conn = None
    try:
        # ... (ডাটাবেস ফেচিং লজিক অপরিবর্তিত) ...
        conn = sqlite3.connect(DB_NAME); conn.row_factory = sqlite3.Row; c = conn.cursor()
        c.execute("SELECT * FROM incident_tickets WHERE id = ? AND status IN ('RESOLVED', 'FALSE_POSITIVE', 'CLOSED')", (ticket_id,))
        ticket_row = c.fetchone()
        
        if not ticket_row:
            return jsonify({"status": "error", "message": "Ticket not found or not yet resolved/closed."}), 404
        
        ticket = dict(ticket_row) 
        res_timestamp = ticket.get('resolution_timestamp')
        details = json.loads(ticket.get('details', '{}')) 
        
        try:
            res_date_str = datetime.fromtimestamp(res_timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S') 
        except (TypeError, ValueError):
            res_date_str = 'N/A'
            
        # LIVE AI PLAN GENERATION (Assuming this runs successfully)
        if not gemini_analyst_model:
             ai_plan_text = "ERROR: AI not configured. Could not generate the investigation plan."
        else:
             system_prompt = "You are a Tier 2 SOC AI Investigator. Provide a human-readable, step-by-step mitigation and investigation plan (max 4 steps) based on the alert details. Use clear steps and Rationale/Action headers."
             full_prompt = f"Ticket ID: {ticket_id}\nTitle: {ticket['title']}\nOriginal Alert Details: {json.dumps(details, indent=2)}"
             ai_response = gemini_analyst_model.generate_content([system_prompt, full_prompt])
             ai_plan_text = ai_response.text

        
        # --- PDF রিপোর্ট তৈরি (reportlab ব্যবহার করে) ---
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4) 
        p.setTitle(f"Incident Report TKT #{ticket['id']}")
        
        y_pos = 750
        LEFT_MARGIN = 60 # সঠিক বাম মার্জিন
        
        # --- 1. Header and Metadata (Base Position 750) ---
        p.setFont('Helvetica-Bold', 16)
        p.setFillColorRGB(0.8, 0.2, 0.2)
        p.drawString(LEFT_MARGIN, y_pos, f"GUARDIAN SIEM FINAL INCIDENT REPORT")
        p.setFillColorRGB(0, 0, 0)
        y_pos -= 30

        p.setFont('Helvetica-Bold', 12)
        p.drawString(LEFT_MARGIN, y_pos, f"INCIDENT: {ticket['title']}")
        y_pos -= 15
        p.drawString(LEFT_MARGIN, y_pos, f"Ticket ID: #{ticket['id']} | Status: {ticket['status']}")
        y_pos -= 15
        p.drawString(LEFT_MARGIN, y_pos, f"Resolved By (T2): {ticket['assigned_to']} | Date: {res_date_str}")
        y_pos -= 35

        # --- 2. AI INVESTIGATION PLAN (Core Body) ---
        p.setFont('Helvetica-Bold', 14)
        p.drawString(LEFT_MARGIN, y_pos, "AI GENERATED MITIGATION AND INVESTIGATION PLAN")
        p.line(LEFT_MARGIN, y_pos - 3, 550, y_pos - 3) # লাইন প্রশস্ত করা হলো
        y_pos -= 20
        
        # AI Plan Printing (Start from here, handling text wrapping manually)
        plan_lines = ai_plan_text.strip().split('\n')
        
        for line in plan_lines:
            if y_pos < 50: p.showPage(); y_pos = 750
            
            clean_line = line.replace('**', '').replace('*', '').strip()
            indent = LEFT_MARGIN 
            
            # Indentation Logic
            if line.startswith('###'): # Main Heading
                p.setFont('Helvetica-Bold', 11); indent = LEFT_MARGIN
            elif line.strip().startswith('Step'): # Step Heading
                p.setFont('Helvetica-Bold', 10); indent = LEFT_MARGIN + 5
            elif line.strip().startswith('Action:') or line.strip().startswith('Rationale:'): # Sub-point
                p.setFont('Helvetica', 9); indent = LEFT_MARGIN + 15
            else: 
                p.setFont('Helvetica', 9); indent = LEFT_MARGIN + 25

            # Text Splitting for long lines (Simple truncation)
            MAX_CHARS_PER_LINE = 100
            
            if len(clean_line) > MAX_CHARS_PER_LINE:
                # If line is too long, it will be truncated to avoid clipping.
                p.drawString(indent, y_pos, clean_line[:MAX_CHARS_PER_LINE] + "...")
            else:
                p.drawString(indent, y_pos, clean_line)
                
            y_pos -= 12 # Line spacing for next item

        # --- 3. FINAL CONCLUSION ---
        y_pos -= 30
        p.setFont('Helvetica-Bold', 12)
        p.drawString(LEFT_MARGIN, y_pos, "T2 ANALYST FINAL CONCLUSION")
        p.line(LEFT_MARGIN, y_pos - 3, 550, y_pos - 3)
        y_pos -= 20
        p.setFont('Helvetica', 10)
        p.drawString(LEFT_MARGIN, y_pos, f"The incident was resolved according to the AI-generated containment steps.")
        y_pos -= 15
        p.drawString(LEFT_MARGIN, y_pos, f"TICKET CLOSED: {ticket['status']}")


        p.showPage()
        p.save()
        buffer.seek(0)

        # Response তৈরি ও ফাইল ডাউনলোড
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f"attachment; filename=Incident_Report_TKT{ticket_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
        return response

    except Exception as e:
        print(f"[REPORT CRITICAL ERROR] Ticket ID {ticket_id}. Full Error: {e}")
        return jsonify({"status": "error", "message": f"Error generating report: {e}. Check server console."}), 500
    finally:
        if conn: conn.close()



# soc_dashboard.py - অন্যান্য API রুটের সাথে যোগ করুন

@app.route('/api/analyst_metrics', methods=['GET'])
@role_required(['t2', 't3'])
@nocache
def get_analyst_metrics():
    # বর্তমান ইউজারের নাম
    current_user_name = current_user.username
    
    # ডেট রেঞ্জ ফিল্টার (Frontend থেকে আসতে পারে)
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # ডেটস্ট্যাম্পকে মিলিসেকেন্ডে কনভার্ট করুন
    start_ts = 0
    end_ts = time.time() * 1000 # বর্তমান সময় (ডিফল্ট)
    
    if start_date_str:
        try:
            start_dt = datetime.strptime(start_date_str, '%Y-%m-%d')
            start_ts = start_dt.timestamp() * 1000
        except ValueError:
            pass
            
    if end_date_str:
        try:
            # দিনের শেষে টাইমস্ট্যাম্প নিতে হবে
            end_dt = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)
            end_ts = end_dt.timestamp() * 1000
        except ValueError:
            pass

    conn = None
    try:
        conn = sqlite3.connect(DB_NAME); c = conn.cursor()
        
        # 1. T2/T3 এর জন্য স্ট্যাটাস অনুযায়ী কাউন্ট
        query = """
            SELECT status, COUNT(id) as count
            FROM incident_tickets
            WHERE assigned_to = ?
              AND creation_timestamp >= ? 
              AND creation_timestamp <= ?
            GROUP BY status
        """
        
        c.execute(query, (current_user_name, start_ts, end_ts))
        ticket_counts = dict(c.fetchall())
        
        # 2. মোট অসমাপ্ত (OPEN/IN_PROGRESS) টিকিট
        query_open = """
            SELECT COUNT(id)
            FROM incident_tickets
            WHERE status IN ('OPEN', 'IN_PROGRESS')
        """
        c.execute(query_open)
        total_pending = c.fetchone()[0]
        
        metrics = {
            "user_resolved": ticket_counts.get('RESOLVED', 0) + ticket_counts.get('FALSE_POSITIVE', 0),
            "user_closed": ticket_counts.get('CLOSED', 0),
            "user_in_progress": ticket_counts.get('IN_PROGRESS', 0),
            "user_assigned": sum(ticket_counts.values()),
            "total_pending_system": total_pending,
            "username": current_user_name,
            "date_range": f"{start_date_str or 'All Time'} to {end_date_str or 'Today'}"
        }
        
        return jsonify(metrics)
        
    except Exception as e:
        print(f"[METRICS ERROR] Failed to fetch metrics: {e}")
        return jsonify({"error": str(e), "user_resolved": 0, "total_pending_system": 0}), 500
    finally:
        if conn: conn.close()


@app.route('/api/test_pqcm_alert', methods=['GET'])
@nocache
def trigger_pqcm_test():
    """Manually simulates a Weak Cryptography event (R-012) for direct testing."""
    
    # Check 1: Ensure AI model is available for context enrichment
    if not gemini_analyst_model: 
        return jsonify({"status": "error", "message": "Gemini AI not configured. Cannot proceed with alert test."}), 400
        
    # 2. Define the Malicious Log Data (Injected directly with Weak Algorithm)
    test_log = {
        "log_channel": "Security",
        "event_id": 5058, 
        "timestamp": datetime.utcnow().isoformat(), # Use current time for the log
        "log_source": "WinCryptoAPI",
        "data_fields": {
            "Target User": "DBAdmin",
            "Source IP": "10.10.10.10", # Non-local IP for better GeoIP test simulation
            "AlgorithmName": "Weak Hashing Method SHA1", # The trigger keyword
            "KeyLength": "1024"
        }
    }
    
    # 3. Format and add to DB (forcing the parsing function to run the R-012 check)
    try:
        # The log data must be formatted to trigger the R-012 check in parse_and_format_log
        formatted = parse_and_format_log(test_log, agent_id="PQCM-MANUAL")
        
        # Check if the log was successfully promoted to CRITICAL
        if formatted and formatted.get('severity') == "CRITICAL":
            
            # Create the final correlated alert structure
            alert = {
                "timestamp": formatted['timestamp'],
                "title": f"CRITICAL: Test Weak Cryptography (R-012)",
                "details": formatted['details'], # Use enriched details (containing PQCM flags)
                "mitre_id": MITRE_ATTACK_MAP["5058_WEAK"]["id"],
                "risk_id": "R-012",
                "agent_id": "PQCM-MANUAL"
            }
            
            add_correlated_alert_to_db(alert)
            return jsonify({"status": "SUCCESS", "message": "PQCM R-012 Alert triggered. Check dashboard and Discord."})
        
        return jsonify({"status": "FAILED", "message": "Log processed but R-012 criteria not met (Log was not Critical/SHA1 not detected)."}), 200
        
    except Exception as e:
        print(f"[PQCM TEST CRASH] {e}")
        traceback.print_exc()
        return jsonify({"status": "CRASHED", "message": f"Test failed due to internal error: {e}"}), 500


@app.route('/api/logs', methods=['POST'])
@nocache
# [soc_dashboard.py - Replace the existing def receive_logs(): function entirely]

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

        if not isinstance(logs_data, list): logs_data = [logs_data]
        count = 0
        for log in logs_data:
            if not isinstance(log, dict): continue
            
            formatted = parse_and_format_log(log, agent_id=agent_id)
            
            if formatted:
                log_id = add_log_to_db(formatted, agent_id, agent_name)
                
                # --- NEW: Call Session Tracking/Scoring for Windows Events (STS) ---
                if formatted.get('log_type') in ['Security Event', 'Application Event']:
                    track_and_score_session(formatted)
                # --- END NEW ---
                
                if log_id: 
                    if formatted.get('details'):
                        src_ip = formatted['details'].get('Source IP')
                        
                        if src_ip and not is_internal_ip(src_ip):
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
            if (now - agent.get('last_seen', 0)) < 300000 
        }
        return jsonify(active_agents_filtered)

@app.route('/api/latest_logs')
@nocache
def get_latest_logs():
    agent_id = request.args.get('agent_id', None)
    filters = {}
    if agent_id: filters['agent_id'] = agent_id
    try:
        logs = query_db(filters, limit=150) 
        return jsonify(logs)
    except Exception as e: print(f"[ERR] Latest logs: {e}"); traceback.print_exc(); return jsonify({"error": f"{e}"}), 500

# [soc_dashboard.py - Replace the existing get_correlated_alerts function entirely]

@app.route('/api/correlated_alerts')
@nocache
def get_correlated_alerts():
    agent_id = request.args.get('agent_id', None)
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False); conn.row_factory = sqlite3.Row; c = conn.cursor()
        
        # --- NOTE: Removed unnecessary LIMIT 20 to use dynamic filter ---
        query = "SELECT id, timestamp, title, details, mitre_id, risk_id, agent_id, status, urgency FROM correlated_alerts"
        conditions, params = [], []
        
        # --- NEW FILTER START: শুধুমাত্র Solved এবং Dismissed নয়, এমন অ্যালার্টগুলো দেখান ---
        # এই ফিল্টার নিশ্চিত করে যে টিকেট বন্ধ হওয়ার পর অ্যালার্টটি স্লাইড থেকে সরে যাবে
        conditions.append("status NOT IN ('Solved', 'Dismissed')") 
        # --- NEW FILTER END ---

        if agent_id: conditions.append("agent_id = ?"); params.append(agent_id)
        
        if conditions: 
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC LIMIT 20" # শেষ ২০টি অ্যাক্টিভ অ্যালার্ট দেখান
        
        c.execute(query, tuple(params))
        alerts = [dict(row) for row in c.fetchall()]
        conn.close()
        
        for alert in alerts:
            if isinstance(alert.get('details'), str):
                alert['details'] = json.loads(alert['details'])
        
        return jsonify(alerts)
    
    except Exception as e: 
        print(f"[ERR] Correlated alerts: {e}"); 
        traceback.print_exc(); 
        return jsonify({"error": f"{e}"}), 500





@app.route('/api/risk_register')
@nocache
def get_risk_register():
    try: return jsonify(RISK_REGISTER.copy())
    except Exception as e: print(f"[ERR] Risk register: {e}"); traceback.print_exc(); return jsonify({"error": f"{e}"}), 500

@app.route('/api/stats')
@nocache
def get_stats():
    try:
        now_ts = time.time() * 1000
        five_minutes_ago_ts = (datetime.now() - timedelta(minutes=5)).timestamp() * 1000
        
        conn = None
        current_stats = {}
        chart_event_counts = {}

        try:
            conn = sqlite3.connect(DB_NAME, check_same_thread=False); c = conn.cursor()
            
            # --- 1. Global Counters (Reading from in-memory stats) ---
            with stats_lock:
                current_stats = stats.copy()
            
            # --- 2. Real-time Chart Data (COUNT by log_type in last 5 minutes) ---
            # This query calculates the count of events grouped by log_type in the last 5 minutes.
            c.execute("""
                SELECT log_type, COUNT(*) 
                FROM logs 
                WHERE timestamp >= ? 
                GROUP BY log_type
            """, (five_minutes_ago_ts,))
            
            chart_data_rows = c.fetchall()
            
            for log_type, count in chart_data_rows:
                chart_event_counts[log_type] = count
                
            # --- 3. Update Correlated Alerts Count (Reading from DB) ---
            c.execute("SELECT COUNT(*) FROM correlated_alerts")
            alert_count_result = c.fetchone()
            current_stats['correlated_alerts'] = alert_count_result[0] if alert_count_result else 0
            
        except Exception as e_db_count: 
            print(f"[STATS ERROR] Could not perform real-time counting: {e_db_count}")
            chart_event_counts = {} # Reset to empty on error
            
        finally:
            if conn: conn.close()
            
        # Prepare data for the Chart.js JSON response
        labels = list(chart_event_counts.keys())
        data = list(chart_event_counts.values())
        
        print(f"[STATS DEBUG] Chart Data (Last 5 min): {chart_event_counts}")
        
        return jsonify({"stats": current_stats, "chart_data": {"labels": labels, "data": data}})
        
    except Exception as e:
        print(f"[ERROR] Exception in get_stats: {e}"); traceback.print_exc()
        return jsonify({"stats": {"total_events": 0, "successful_logins": 0, "failed_logins": 0, "app_errors": 0, "correlated_alerts": 0},
                         "chart_data": {"labels": [], "data": []}}), 500


if __name__ == '__main__':
    print("[DEBUG] Stage 3: Initializing database...")
    init_db()
    init_user_db()
    print("[DEBUG] Stage 4: Starting background threads...")
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=correlation_engine, daemon=True).start()
    threading.Thread(target=geoip_enricher_thread, daemon=True).start()
    threading.Thread(target=dns_enricher_thread, daemon=True).start()
    threading.Thread(target=database_cleanup_thread, args=(24,), daemon=True).start() # Runs every 24 hours
    
    if 'ntfrcv' in globals():
        threading.Thread(target=snmp_trap_receiver_thread, daemon=True).start()
        threading.Thread(target=snmp_log_processor_thread, daemon=True).start()
    else:
        print("[WARNING] PySNMP not found. SNMP Trap Receiver thread NOT started.")
        
    print("[DEBUG] Stage 5: Starting Flask web server...")
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)