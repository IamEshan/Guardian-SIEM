import requests
import time
import socket
import platform
# --- FIX: Import pysnmp components explicitly ---
from pysnmp.hlapi import (getCmd, SnmpEngine, CommunityData, UdpTransportTarget, 
                          ContextData, ObjectType, ObjectIdentity)

# --- Configuration ---
MIKROTIK_ROUTER_IP = "192.168.1.204" # এটি আপনার MikroTik CHR VM-এর আইপি

SNMP_COMMUNITY = "public" # যে Community String আপনি রাউটারে সেট করেছেন
# --- FIX: Increased poll interval to 20s to avoid rate-limiting ---
POLL_INTERVAL = 20 # প্রতি ২০ সেকেন্ডে পোল করবে

# --- SIEM Server Configuration ---
SIEM_SERVER_URL = "http://127.0.0.1:5000/api/logs"
AGENT_ID = f"snmp-agent-{socket.gethostname()}"
AGENT_NAME = f"MikroTik Router ({MIKROTIK_ROUTER_IP})"

# --- SNMP OIDs (MikroTik/Standard OIDs) ---
INTERFACE_INDEX = "2" # "1" হলো ether1, "2" হলো ether2. (ether2 is usually WAN)

OID_UPTIME = "1.3.6.1.2.1.1.3.0"  # sysUpTime
OID_IF_DESCR = f"1.3.6.1.2.1.2.2.1.2.{INTERFACE_INDEX}" # Interface Description (e.g., ether2)
OID_IF_IN_OCTETS = f"1.3.6.1.2.1.2.2.1.10.{INTERFACE_INDEX}" # Interface In-Bytes
OID_IF_OUT_OCTETS = f"1.3.6.1.2.1.2.2.1.16.{INTERFACE_INDEX}" # Interface Out-Bytes

def get_snmp_data(oid):
    """
    MikroTik রাউটার থেকে একটি নির্দিষ্ট OID-এর ডেটা পোল (pull) করে।
    """
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(SNMP_COMMUNITY, mpModel=0),
                   UdpTransportTarget((MIKROTIK_ROUTER_IP, 161), timeout=2, retries=1), # Increased timeout
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)))
        )

        if errorIndication:
            print(f"[ERROR] SNMP poll failed for {oid}: {errorIndication}")
            return f"Error: {errorIndication}"
        elif errorStatus:
            print(f"[ERROR] SNMP poll failed for {oid}: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
            return f"Error: {errorStatus.prettyPrint()}"
        else:
            return str(varBinds[0][1]) # ডেটা-টিকে স্ট্রিং হিসেবে রিটার্ন করুন
            
    except Exception as e:
        print(f"[ERROR] SNMP Exception for {oid}: {e}")
        return f"Exception: {e}"

def send_logs_to_server(logs):
    """
    সংগ্রহ করা লগগুলো SIEM সার্ভারে পাঠায়।
    """
    try:
        payload = {
            "agent_id": AGENT_ID,
            "agent_name": AGENT_NAME,
            "logs": logs
        }
        response = requests.post(SIEM_SERVER_URL, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"Successfully sent 1 log(s) to SIEM server.")
        else:
            print(f"Failed to send logs. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.ConnectionError:
        print(f"Connection refused. Is the SIEM server (soc_dashboard.py) running at {SIEM_SERVER_URL}?")
    except requests.exceptions.Timeout:
        print("Connection timed out while trying to send logs.")
    except Exception as e:
        print(f"An error occurred while sending logs: {e}")

def main():
    print(f"--- Guardian SNMP Agent for MikroTik ---")
    print(f"Agent ID: {AGENT_ID}")
    print(f"Target Router: {MIKROTIK_ROUTER_IP}")
    print(f"SIEM Server: {SIEM_SERVER_URL}")
    print(f"Polling every {POLL_INTERVAL} seconds...")
    print("Press CTRL+C to stop.")
    
    interface_name = get_snmp_data(OID_IF_DESCR)
    if "Error" in interface_name:
        print(f"[WARNING] Could not get interface name for index {INTERFACE_INDEX}. Defaulting to 'if{INTERFACE_INDEX}'.")
        interface_name = f"if{INTERFACE_INDEX}"
        
    print(f"Monitoring Interface: {interface_name} (Index: {INTERFACE_INDEX})")

    while True:
        try:
            start_time = time.time()
            
            # রাউটার থেকে ডেটা সংগ্রহ করুন
            uptime = get_snmp_data(OID_UPTIME)
            
            # --- FIX: রাউটারের ফ্লাড ডিটেকশন এড়ানোর জন্য ১ সেকেন্ড বিরতি ---
            time.sleep(1) 
            
            traffic_in = get_snmp_data(OID_IF_IN_OCTETS)
            
            # --- FIX: রাউটারের ফ্লাড ডিটেকশন এড়ানোর জন্য ১ সেকেন্ড বিরতি ---
            time.sleep(1) 
            
            traffic_out = get_snmp_data(OID_IF_OUT_OCTETS)

            # একটি লগ প্যাকেট তৈরি করুন
            log_entry = {
                "log_source": "SNMP Polling",
                "log_channel": "Network", # এটি parse_and_format_log ফাংশনে ব্যবহৃত হয় না
                "event_id": 9001, # একটি কাস্টম ইভেন্ট আইডি
                "computer_name": MIKROTIK_ROUTER_IP,
                "message": f"MikroTik Health Poll: Uptime={uptime}, In={traffic_in}, Out={traffic_out}",
                "data_fields": {
                    "Uptime": uptime,
                    f"{interface_name}_Traffic_IN (Bytes)": traffic_in,
                    f"{interface_name}_Traffic_OUT (Bytes)": traffic_out,
                    "Source IP": MIKROTIK_ROUTER_IP 
                }
            }
            
            # সার্ভারে লগ পাঠান
            send_logs_to_server([log_entry])
            
            # --- FIX: Calculate sleep time correctly ---
            elapsed_time = time.time() - start_time
            sleep_time = max(0, POLL_INTERVAL - elapsed_time)
            time.sleep(sleep_time)

        except KeyboardInterrupt:
            print("\nStopping SNMP agent...")
            break
        except Exception as e:
            print(f"Main loop error: {e}")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

