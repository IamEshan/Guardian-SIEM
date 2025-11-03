import time
import requests
import json
import win32evtlog # Requires pywin32
import win32evtlogutil
import traceback # For detailed error logging
import os # Added for admin check
import ctypes # Added for admin check
import threading
from datetime import datetime
import pywintypes # Import pywintypes to catch specific exceptions
import uuid 

# --- Configuration ---
AGENT_ID = f"agent-mac-{str(uuid.getnode())}" 
AGENT_NAME = "My-Desktop-PC" # You can still customize this name
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


def get_event_details(event):
    """Extracts relevant details from a PyEventLogRecord object."""
    details = {}
    record_num = getattr(event, 'RecordNumber', 'N/A')
    log_type = getattr(event, 'LogFile', 'Unknown')
    try:
        event_id = event.EventID & 0xFFFF
        computer_name = str(event.ComputerName)
        try:
            timestamp = event.TimeGenerated.isoformat()
        except ValueError:
            timestamp = datetime.utcnow().isoformat() + "Z (fallback)"
        log_source_name = str(event.SourceName)

        try:
            message = win32evtlogutil.SafeFormatMessage(event, log_source_name)
            message = ' '.join(message.split())
        except pywintypes.error as msg_err:
             message = f"Event ID {event_id} (Message formatting failed)"
             if event.StringInserts: message += " - Data available"
        except Exception as e_msg_fmt:
            message = f"Event ID {event_id} (Unexpected error formatting message)"
            print(f"[{log_type}] Error formatting message for record {record_num}: {e_msg_fmt}")

        data_fields = {}
        if event.StringInserts:
            strings = [str(s).strip() if s is not None else '' for s in event.StringInserts]
            if event_id == 4624: # Successful Logon
                data_fields['SubjectUserName'] = strings[1] if len(strings) > 1 else 'N/A'
                data_fields['TargetUserName'] = strings[5] if len(strings) > 5 else 'N/A'
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
                    display_val = field_val
                    if len(display_val) > 500: display_val = display_val[:500] + "..."
                    data_fields[f'Field_{i+1}'] = display_val

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

# --- ================================================================== ---
# --- *** NEW ROBUST FUNCTIONS TO HANDLE LOG CLEARS/WRAPS *** ---
# --- ================================================================== ---

def get_newest_record_num(handle, log_type):
    """
    Safely gets the record number of the absolute newest event in the log.
    """
    try:
        # Use BACKWARDS_READ | SEQUENTIAL_READ and offset 0 to get the single newest event
        flags_newest = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags_newest, 0)
        if events:
            return events[0].RecordNumber
    except Exception as e:
        print(f"[{log_type}] Warning: Could not get newest record num via backwards read: {e}")
    
    # Fallback: get total count and oldest record
    try:
        total = win32evtlog.GetNumberOfEventLogRecords(handle)
        oldest = win32evtlog.GetOldestEventLogRecord(handle)
        if total > 0:
            return (oldest + total - 1)
        else:
            return 0 # Log is empty
    except Exception as e_fallback:
        print(f"[{log_type}] Error in fallback get_newest_record_num: {e_fallback}")
        return 0 # Absolute fallback

def initialize_last_records():
    """Reads the current number of records in each log to start monitoring from the end."""
    print("Initializing start positions for log monitors...")
    print(f"--- This Agent ID: {AGENT_ID} (Name: {AGENT_NAME}) ---")
    for source in LOG_SOURCES_TO_MONITOR:
        handle = None
        start_record = 0
        try:
            handle = win32evtlog.OpenEventLog(None, source)
            total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
            if total_records > 0:
                # Get the record number of the newest event
                start_record = get_newest_record_num(handle, source)
            else: 
                start_record = 0 # Log is empty
        except Exception as e_init_open:
            print(f"Could not open/read '{source}' during init: {e_init_open}. Starting from record 0.")
            start_record = 0 # Fallback
        finally:
             if handle:
                 try: win32evtlog.CloseEventLog(handle)
                 except: pass

        last_record_numbers[source] = start_record
        print(f"[{source}] Initialized. Will start reading *after* record number: {start_record}")


def fetch_new_events(server, log_type, last_record_number):
    """
    Reads new events reliably, handling wraps and seeking errors.
    This version automatically re-syncs if the log is cleared.
    """
    handle = None
    events_read_list = []
    highest_record_read = last_record_number
    
    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
        total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        
        if total_records == 0:
            # Log is empty, nothing to do.
            win32evtlog.CloseEventLog(handle)
            return [], 0 # Reset to 0

        # --- Check if there are any new records at all ---
        newest_available_record = get_newest_record_num(handle, log_type)
        if last_record_number >= newest_available_record:
            win32evtlog.CloseEventLog(handle)
            return [], last_record_number # No new logs

        # --- We have new logs, try to read them ---
        flags_seek = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
        read_from_record = last_record_number + 1
        
        try:
            events = win32evtlog.ReadEventLog(handle, flags_seek, read_from_record)
        
        except win32evtlog.error as e_seek:
            # This triggers if the log was cleared (e.g., Error 87 or 18)
            if e_seek.winerror == ERROR_INVALID_PARAMETER or e_seek.winerror == ERROR_NO_MORE_ITEMS:
                print(f"[{log_type}] Log cleared or record {read_from_record} overwritten. Re-syncing to newest log...")
                # Re-sync by finding the oldest available record
                oldest_record = win32evtlog.GetOldestEventLogRecord(handle)
                print(f"[{log_type}] Oldest available record is now {oldest_record}. Reading from there.")
                # Read sequentially from the new oldest record
                try:
                    flags_seq = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
                    events = win32evtlog.ReadEventLog(handle, flags_seq, oldest_record)
                except Exception as e_seq:
                    print(f"[{log_type}] Failed to re-sync sequentially: {e_seq}. Skipping cycle.")
                    win32evtlog.CloseEventLog(handle)
                    return [], newest_available_record # Reset to newest to be safe
            else:
                # Different, unexpected error
                print(f"[{log_type}] Unexpected error reading log: {e_seek}. Skipping cycle.")
                if handle: win32evtlog.CloseEventLog(handle)
                return [], last_record_number
        
        # --- Process the batch of events ---
        while events:
            for event in events:
                record_num = event.RecordNumber
                # This check is redundant due to SEEK_READ, but good for safety
                if record_num <= last_record_number:
                    continue 

                processed = get_event_details(event)
                if processed:
                    events_read_list.append(processed)
                    highest_record_read = max(highest_record_read, record_num)

            # Read the next batch
            try:
                flags_cont = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(handle, flags_cont, 0)
            except win32evtlog.error as e_cont:
                if e_cont.winerror == ERROR_NO_MORE_ITEMS:
                    events = [] # No more events, break loop
                elif e_cont.winerror == ERROR_INVALID_HANDLE:
                    print(f"[{log_type}] Handle became invalid during read. Stopping cycle.")
                    events = []
                else:
                    print(f"[{log_type}] Error continuing read: {e_cont}")
                    events = []
        
        return events_read_list, highest_record_read

    except Exception as e_outer:
        print(f"[{log_type}] CRITICAL Error in fetch_new_events: {e_outer}")
        traceback.print_exc()
        return [], last_record_number
    finally:
        if handle:
            try:
                win32evtlog.CloseEventLog(handle)
            except:
                pass # Handle might be invalid, that's fine

# --- ================================================================== ---
# --- *** END OF NEW FUNCTIONS *** ---
# --- ================================================================== ---


def send_logs_in_batches(logs, log_type):
    """Sends logs in batches to avoid overwhelming the server or hitting timeouts."""
    total_sent = 0
    batch_success = True # Assume success unless a batch fails
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
                    print(f"[{log_type}] Found {len(new_logs)} new logs (up to record {highest_record_read_this_cycle}). Sending in batches...")
                    send_success = send_logs_in_batches(new_logs, log_type)

                if send_success:
                    last_record_numbers[log_type] = highest_record_read_this_cycle
                else:
                    print(f"[{log_type}] Send failed, maintaining last record {last_record_before_fetch} for retry.")
            
            time.sleep(POLL_INTERVAL)

        except Exception as e:
            print(f"[{log_type}] UNEXPECTED ERROR in monitor loop: {e}")
            traceback.print_exc()
            print(f"[{log_type}] Attempting to recover...")
            time.sleep(POLL_INTERVAL * 3) # Wait longer after an unexpected error


def main():
    """
    Main function to start monitoring threads for each log source.
    """
    print("Starting Windows Log Agent...")
    print(f"Sending data to {SERVER_URL}")

    initialize_last_records()

    threads = []
    for source in LOG_SOURCES_TO_MONITOR:
        # Give each thread a name for easier debugging
        thread = threading.Thread(target=monitor_log, args=(source,), name=f"Monitor-{source}", daemon=True)
        threads.append(thread)
        thread.start()

    # Keep the main thread alive while monitoring threads run
    try:
        while True:
            # Check if any monitoring thread has unexpectedly died (optional but recommended)
            for i, t in enumerate(threads):
                 if not t.is_alive():
                      source = LOG_SOURCES_TO_MONITOR[i]
                      print(f"CRITICAL: Monitoring thread for '{source}' has stopped unexpectedly! Attempting restart...")
                      # Basic restart logic
                      new_thread = threading.Thread(target=monitor_log, args=(source,), name=f"Monitor-{source}-Restarted", daemon=True)
                      threads[i] = new_thread
                      new_thread.start()
                      print(f"Restarted monitor thread for {source}.")


            time.sleep(60) # Check thread status every minute

    except KeyboardInterrupt:
        print("\nCtrl+C detected. Agent shutting down gracefully.")
    except Exception as e:
         print(f"\nCRITICAL ERROR in main loop: {e}")
         traceback.print_exc()
    finally:
        print("Agent shutdown complete.")


if __name__ == "__main__":
    is_admin = False # Default to false
    try:
        # Attempt Windows check first as it's more likely needed
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (ImportError, AttributeError):
        # Fallback for non-Windows or if ctypes fails
        try:
           is_admin = os.getuid() == 0
        except AttributeError:
             print("Warning: Could not determine admin privileges. Assuming non-admin.")

    if not is_admin:
        print("\n" + "="*60)
        print("ERROR: Administrator Privileges Required")
        print("This agent needs to run as an Administrator to access Windows Event Logs.")
        print("Please close this window and re-launch the script using:")
        print("1. Right-click Command Prompt/PowerShell")
        print("2. Select 'Run as administrator'")
        print("3. Navigate to the project folder and run 'python agent.py'")
        print("="*60 + "\n")
        # Keep window open for user to read on Windows
        if os.name == 'nt':
            input("Press Enter to exit...")
    else:
        main()