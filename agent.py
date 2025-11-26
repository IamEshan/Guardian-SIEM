import time
import requests
import json
import win32evtlog 
import win32evtlogutil
import traceback 
import os 
import ctypes 
import threading
from datetime import datetime
import pywintypes 
import uuid 
import sys 

# --- Configuration ---
# Generate a unique ID based on the machine's MAC address
AGENT_ID = f"agent-mac-{str(uuid.getnode())}" 
AGENT_NAME = "My-Desktop-PC" 
SERVER_URL = "http://127.0.0.1:5000/api/logs"
LOG_SOURCES_TO_MONITOR = ["Security", "Application", "System"]
POLL_INTERVAL = 10
REQUEST_TIMEOUT = 30
LOG_BATCH_SIZE = 200

# This will be populated by initialize_last_records()
last_record_numbers = {source: 0 for source in LOG_SOURCES_TO_MONITOR}

# --- Constants ---
ERROR_INVALID_HANDLE = 6
ERROR_NO_MORE_ITEMS = 18
ERROR_INVALID_PARAMETER = 87
RPC_S_SERVER_UNAVAILABLE = 1722

# --- NEW: Session Trust Tracking STATE (Minimalist version for agent) ---
CRITICAL_USERS = {"Admin", "FinanceMgr", "DBAdmin", "HP"} 
ACTIVE_SESSIONS = {} 
session_lock = threading.Lock() 

# ----------------------------------------------------------------------
# Core Event Processing Functions
# ----------------------------------------------------------------------

def get_event_details(event):
    """Extracts relevant details from a PyEventLogRecord object."""
    details = {}
    record_num = getattr(event, 'RecordNumber', 'N/A')
    log_type = getattr(event, 'LogFile', 'Unknown')
    try:
        # Event ID and System Info
        event_id = event.EventID & 0xFFFF
        computer_name = str(event.ComputerName)
        log_source_name = str(event.SourceName)
        
        # Timestamp conversion
        try:
            timestamp = event.TimeGenerated.isoformat()
        except ValueError:
            timestamp = datetime.utcnow().isoformat() + "Z (fallback)"

        # Message Formatting
        try:
            message = win32evtlogutil.SafeFormatMessage(event, log_source_name)
            message = ' '.join(message.split())
        except pywintypes.error as msg_err:
             message = f"Event ID {event_id} (Message formatting failed: WinError {msg_err.winerror})"
             if event.StringInserts: message += " - Data available"
        except Exception as e_msg_fmt:
            message = f"Event ID {event_id} (Unexpected error formatting message)"
            print(f"[{log_type}] Error formatting message for record {record_num}: {e_msg_fmt}")

        # Data Field Extraction (Normalization)
        data_fields = {}
        if event.StringInserts:
            strings = [str(s).strip() if s is not None else '' for s in event.StringInserts]
            
            # --- CRITICAL LOGON FIX: Ensure correct indexing for common events ---
            if event_id == 4624: # Successful Logon
                data_fields['SubjectUserName'] = strings[1] if len(strings) > 1 else 'N/A'
                data_fields['TargetUserName'] = strings[5] if len(strings) > 5 else 'N/A' # <--- USERNAME
                data_fields['Logon Type'] = strings[8] if len(strings) > 8 else 'N/A'
                data_fields['IpAddress'] = strings[18] if len(strings) > 18 else 'N/A'
            elif event_id == 4625: # Failed Logon
                 data_fields['Account Name'] = strings[5] if len(strings) > 5 else 'N/A'
                 data_fields['Failure Reason'] = strings[9] if len(strings) > 9 else 'N/A'
                 data_fields['Status Code'] = strings[7] if len(strings) > 7 else 'N/A'
                 data_fields['IpAddress'] = strings[19] if len(strings) > 19 else 'N/A'
            elif event_id == 4720: # User Created
                 data_fields['TargetUserName'] = strings[0] if len(strings) > 0 else 'N/A'
                 data_fields['SubjectUserName'] = strings[4] if len(strings) > 4 else 'N/A'
            else: # Generic fallback
                for i, field_val in enumerate(strings):
                    if len(field_val) > 500: field_val = field_val[:500] + "..."
                    data_fields[f'Field_{i+1}'] = field_val

        return {
            "record_number": record_num,
            "computer_name": computer_name,
            "event_id": event_id,
            "timestamp": timestamp,
            "message": message,
            "log_source": log_source_name,
            "data_fields": data_fields
        }
    except Exception as e:
        print(f"Error processing event record {record_num}: {e}")
        traceback.print_exc()
        return None

# ----------------------------------------------------------------------
# Robust Log Reading and Re-Sync Functions
# ----------------------------------------------------------------------

def get_newest_record_num(handle, log_type):
    """
    Safely gets the record number of the absolute newest event in the log.
    (Most reliable method: Oldest + Total - 1)
    """
    try:
        total = win32evtlog.GetNumberOfEventLogRecords(handle)
        if total == 0:
            return 0 
        oldest = win32evtlog.GetOldestEventLogRecord(handle)
        return (oldest + total - 1)
    except Exception as e:
        print(f"[{log_type}] Error in get_newest_record_num: {e}")
        return 0 

def initialize_last_records():
    """Reads the current record number in each log to start monitoring from the end."""
    print("Initializing start positions for log monitors...")
    print(f"--- This Agent ID: {AGENT_ID} (Name: {AGENT_NAME}) ---")
    for source in LOG_SOURCES_TO_MONITOR:
        handle = None
        start_record = 0
        try:
            handle = win32evtlog.OpenEventLog(None, source)
            start_record = get_newest_record_num(handle, source)
        except Exception as e_init_open:
            print(f"Could not open/read '{source}' during init: {e_init_open}. Starting from record 0.")
            start_record = 0 
        finally:
             if handle:
                 try: win32evtlog.CloseEventLog(handle)
                 except: pass

        last_record_numbers[source] = start_record
        print(f"[{source}] Initialized. Will start reading *after* record number: {start_record}")


def fetch_new_events(server, log_type, last_record_number):
    """
    Reads new events reliably by ensuring the handle is always valid and 
    automatically re-syncing if the log is cleared.
    """
    handle = None
    events_read_list = []
    highest_record_read = last_record_number
    log_was_cleared = False
    
    try:
        # --- 1. Open new handle every cycle (FIX for 'Invalid Handle') ---
        handle = win32evtlog.OpenEventLog(server, log_type)
        
        # --- 2. Check current status and re-sync if needed ---
        newest_available_record = get_newest_record_num(handle, log_type)
        oldest_available_record = win32evtlog.GetOldestEventLogRecord(handle)
        
        if newest_available_record <= last_record_number:
            # No new logs or log is empty
            return [], last_record_number 

        if last_record_number < oldest_available_record:
            # Log was cleared OR wrapped and our last record number is now gone!
            log_was_cleared = True
            last_record_number = oldest_available_record - 1 # Reset to start reading from oldest
            print(f"[{log_type}] Log reset/wrapped detected. Re-syncing from record {oldest_available_record}.")

        # --- 3. Start reading from the calculated position ---
        flags_seek = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
        read_from_record = last_record_number + 1
        events = None
        
        try:
            events = win32evtlog.ReadEventLog(handle, flags_seek, read_from_record)
        except win32evtlog.error as e_seek:
            # Catch expected errors during seek after a clear/wrap (like 87 or 18)
            if e_seek.winerror == ERROR_INVALID_PARAMETER or e_seek.winerror == ERROR_NO_MORE_ITEMS:
                 print(f"[{log_type}] Seek failed after re-sync. Log likely cleared again. Skipping cycle.")
                 return [], newest_available_record 
            else:
                 raise e_seek 
        
        # --- 4. Process the batch of events ---
        while events:
            for event in events:
                record_num = event.RecordNumber
                
                processed = get_event_details(event)
                if processed:
                    events_read_list.append(processed)
                    highest_record_read = max(highest_record_read, record_num)

            # Read the next batch (SEQUENTIAL_READ)
            try:
                flags_cont = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(handle, flags_cont, 0)
            except win32evtlog.error as e_cont:
                if e_cont.winerror == ERROR_NO_MORE_ITEMS:
                    events = [] 
                else:
                    print(f"[{log_type}] Error continuing sequential read: {e_cont}. Stopping cycle.")
                    events = []
        
        # Update the position if new logs were read or if a clear/wrap happened
        if log_was_cleared or highest_record_read > last_record_number:
            return events_read_list, highest_record_read 
        
        return events_read_list, last_record_number

    except pywintypes.error as e_invalid_handle:
        # Catch Invalid Handle error (Error 6) and other pywintypes errors
        print(f"[{log_type}] CRITICAL Error in fetch_new_events: WinError {e_invalid_handle.winerror} - {e_invalid_handle.strerror}")
        return [], last_record_number 
        
    except Exception as e_outer:
        print(f"[{log_type}] CRITICAL UNHANDLED Error in fetch_new_events: {e_outer}")
        traceback.print_exc()
        return [], last_record_number
    finally:
        if handle:
            try:
                win32evtlog.CloseEventLog(handle)
            except:
                pass # Ignore if close fails

# ----------------------------------------------------------------------
# Log Sending Functions
# ----------------------------------------------------------------------

def send_logs_in_batches(logs, log_type):
    """Sends logs in batches to avoid overwhelming the server or hitting timeouts."""
    total_sent = 0
    batch_success = True 
    for i in range(0, len(logs), LOG_BATCH_SIZE):
        batch = logs[i:i + LOG_BATCH_SIZE]
        if not send_logs_to_server(batch, log_type):
            print(f"[{log_type}] Failed to send batch starting at index {i}. Stopping send.")
            batch_success = False
            break
        total_sent += len(batch)
    return batch_success


def send_logs_to_server(logs_batch, log_type):
    """Sends a single batch of log events to the central server."""
    if not logs_batch: return True

    try:
        payload = {
            "agent_id": AGENT_ID,
            "agent_name": AGENT_NAME,
            "logs": []
        }
        
        for log_entry in logs_batch:
             log_entry['log_channel'] = log_type
             payload["logs"].append(log_entry)

        headers = {'Content-Type': 'application/json'}
        response = requests.post(SERVER_URL, data=json.dumps(payload), headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            return True
        else:
            try: error_detail = response.json()
            except: error_detail = response.text
            print(f"[{log_type}] Failed to send batch. Server responded with {response.status_code}: {error_detail}")
            return False

    except requests.exceptions.Timeout:
         print(f"[{log_type}] Connection to server {SERVER_URL} timed out sending batch.")
         return False
    except requests.exceptions.RequestException as e:
         print(f"[{log_type}] Could not connect to server sending batch. Error: {e}")
         return False
    except Exception as e:
         print(f"[{log_type}] UNEXPECTED error sending batch: {e}")
         traceback.print_exc()
         return False

# ----------------------------------------------------------------------
# Main Monitoring Loop
# ----------------------------------------------------------------------

def monitor_log(log_type):
    """Monitors a single log source continuously."""
    print(f"Starting monitor for '{log_type}' log...")
    while True:
        try:
            last_record_before_fetch = last_record_numbers[log_type]
            new_logs, highest_record_read_this_cycle = fetch_new_events(None, log_type, last_record_before_fetch)

            if highest_record_read_this_cycle > last_record_before_fetch:
                send_success = True
                if new_logs:
                    print(f"[{log_type}] Found {len(new_logs)} new logs (up to record {highest_record_read_this_cycle}). Sending...") 
                    send_success = send_logs_in_batches(new_logs, log_type)

                if send_success:
                    last_record_numbers[log_type] = highest_record_read_this_cycle
                else:
                    print(f"[{log_type}] Send failed, maintaining last record {last_record_before_fetch} for retry.")
            
            time.sleep(POLL_INTERVAL)

        except Exception as e:
            print(f"[{log_type}] UNEXPECTED ERROR in monitor loop (Outer): {e}")
            traceback.print_exc()
            time.sleep(POLL_INTERVAL * 3) 


def main():
    """
    Main function to start monitoring threads for each log source.
    """
    print("Starting Windows Log Agent...")
    print(f"Sending data to {SERVER_URL}")

    initialize_last_records()

    threads = []
    for source in LOG_SOURCES_TO_MONITOR:
        thread = threading.Thread(target=monitor_log, args=(source,), name=f"Monitor-{source}", daemon=True)
        threads.append(thread)
        thread.start()

    try:
        while True:
            # Check thread status every minute
            time.sleep(60) 

    except KeyboardInterrupt:
        print("\nCtrl+C detected. Agent shutting down gracefully.")
    except Exception as e:
         print(f"\nCRITICAL ERROR in main loop: {e}")
         traceback.print_exc()
    finally:
        print("Agent shutdown complete.")
        sys.exit(0)


if __name__ == "__main__":
    is_admin = False 
    try:
        # Check for admin privileges on Windows
        if sys.platform.startswith('win'):
            # CORRECTED: IsUserAnAdmin is the correct function name
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0 
        else:
            # Check for root on Linux/macOS (less relevant for win32evtlog)
            is_admin = os.getuid() == 0
    except Exception:
        # Default fallback, proceed to main and rely on the win32evtlog to fail clearly
        is_admin = True 
    
    if not is_admin:
        print("\n" + "="*60)
        print("ERROR: Administrator Privileges Required")
        print("This agent needs to run as an Administrator/Root to access Event Logs.")
        print("Please close this window and re-launch the script using 'Run as administrator'.")
        print("="*60 + "\n")
        if sys.platform.startswith('win'):
            input("Press Enter to exit...")
    else:
        main()