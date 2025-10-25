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
# --- MODIFICATION: Use persistent MAC-based UUID for agent ID ---
# This ensures the ID is the same every time the agent starts on *this* machine
AGENT_ID = f"agent-mac-{str(uuid.getnode())}" 
AGENT_NAME = "My-Desktop-PC" # You can still customize this name
SERVER_URL = "http://127.0.0.1:5000/api/logs"
LOG_SOURCES_TO_MONITOR = ["Security", "Application", "System"]
POLL_INTERVAL = 10
REQUEST_TIMEOUT = 30
LOG_BATCH_SIZE = 200

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


def fetch_new_events(server, log_type, last_record_number):
    """
    Reads new events reliably, handling wraps and seeking errors.
    Returns (list_of_new_events, highest_record_number_successfully_read)
    """
    handle = None
    events_read_list = []
    highest_record_read = last_record_number
    read_from_record = last_record_number + 1
    total_records = -1

    try:
        # --- Open Handle and Get Initial State ---
        try:
            handle = win32evtlog.OpenEventLog(server, log_type)
            total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
            oldest_record = win32evtlog.GetOldestEventLogRecord(handle)
        except win32evtlog.error as e:
            print(f"[{log_type}] Error opening log or getting record counts: {e}. Skipping cycle.")
            return [], last_record_number
        except Exception as e_open:
            print(f"[{log_type}] Unexpected error opening handle: {e_open}.")
            traceback.print_exc()
            return [], last_record_number

        # --- Log Wrap / Clear Detection ---
        if (oldest_record > last_record_number + 1 and last_record_number != 0):
            print(f"[{log_type}] Log wrap detected (last={last_record_number}, oldest={oldest_record}). Resetting position to oldest: {oldest_record}")
            highest_record_read = oldest_record - 1
            if handle:
                try:
                    win32evtlog.CloseEventLog(handle)
                except:
                    pass
            return [], highest_record_read
        elif total_records < last_record_number and total_records > 0:
             print(f"[{log_type}] Potential log clear detected (last={last_record_number}, total={total_records}). Resetting to oldest: {oldest_record}")
             highest_record_read = oldest_record - 1
             if handle:
                 try:
                     win32evtlog.CloseEventLog(handle)
                 except:
                     pass
             return [], highest_record_read

        # --- No New Records Check ---
        if total_records <= last_record_number:
            if handle:
                try: win32evtlog.CloseEventLog(handle)
                except: pass
            return [], last_record_number

        # --- Read Events (Prefer Seek, Fallback Sequential) ---
        events = []
        read_sequentially = False
        try:
            # --- FIX: Only seek if last_record_number is not 0 ---
            if last_record_number > 0:
                flags_seek = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
                # print(f"[{log_type}] Attempting seek read from record: {read_from_record}") # Verbose
                events = win32evtlog.ReadEventLog(handle, flags_seek, read_from_record)
                # print(f"[{log_type}] Seek read successful.") # Verbose
            else:
                 # If last_record_number is 0, just start sequentially
                 print(f"[{log_type}] Starting sequential scan (last record was 0).")
                 read_sequentially = True
                 flags_seq = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                 events = win32evtlog.ReadEventLog(handle, flags_seq, 0) # Read from beginning sequentially

        except win32evtlog.error as e_seek:
            if e_seek.winerror == ERROR_INVALID_PARAMETER: # Error 87
                 print(f"[{log_type}] Seek read failed (Param Error 87). Likely gap. Falling back to sequential scan filtering from {last_record_number + 1}.")
            else:
                 print(f"[{log_type}] Seek read failed (Error {e_seek.winerror}). Falling back to sequential scan filtering from {last_record_number + 1}.")
            read_sequentially = True
            flags_seq = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            try:
                # --- FIX: Don't close/reopen, just read sequentially from beginning ---
                # Re-opening handle here can cause "invalid handle" if not done carefully
                # Try reading sequentially from beginning with the *same* handle
                events = win32evtlog.ReadEventLog(handle, flags_seq, 0)
            except win32evtlog.error as e_seq_start:
                 print(f"[{log_type}] Fallback sequential read also failed to start: {e_seq_start}. Skipping cycle.")
                 if handle:
                     try: win32evtlog.CloseEventLog(handle)
                     except: pass
                 return [], last_record_number

        # Process events
        while events:
            for event in events:
                record_num = event.RecordNumber
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
                if e_cont.winerror == ERROR_NO_MORE_ITEMS: pass
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
                # Check if handle is still valid by getting total records
                win32evtlog.GetNumberOfEventLogRecords(handle)
                win32evtlog.CloseEventLog(handle) # Only close if valid
            except win32evtlog.error as e_close:
                 if e_close.winerror != ERROR_INVALID_HANDLE:
                      print(f"[{log_type}] Error closing handle: {e_close}")
            except Exception as e_close_final:
                 print(f"[{log_type}] Unexpected error closing handle: {e_close_final}")


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
    # print(f"[{log_type}] Total logs sent in batches: {total_sent}/{len(logs)}")
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
        # print(f"[{log_type}] Sending batch of {len(payload)} logs...") # Verbose
        response = requests.post(SERVER_URL, data=json.dumps(payload), headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            # print(f"[{log_type}] Batch sent successfully.") # Verbose
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


def initialize_last_records():
    """Reads the current number of records in each log to start monitoring from the end."""
    print("Initializing start positions for log monitors...")
    print(f"--- This Agent ID: {AGENT_ID} (Name: {AGENT_NAME}) ---")
    for source in LOG_SOURCES_TO_MONITOR:
        handle = None
        start_record = 0
        try:
            try:
                handle = win32evtlog.OpenEventLog(None, source)
                total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
                # --- FIX: Get the record number of the newest event ---
                if total_records > 0:
                    flags_newest = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
                    # Read just one event from the end
                    newest_events = win32evtlog.ReadEventLog(handle, flags_newest, total_records)
                    if newest_events:
                        start_record = newest_events[0].RecordNumber
                    else:
                        # Fallback if backwards read fails
                        print(f"[{source}] Warning: Could not read newest record backwards. Attempting to use oldest+total.")
                        try:
                            oldest_record = win32evtlog.GetOldestEventLogRecord(handle)
                            start_record = oldest_record + total_records - 1
                        except Exception as e_old:
                             print(f"[{source}] Could not get oldest record: {e_old}. Using total records as approx.")
                             start_record = total_records # Less accurate fallback
                else: 
                    start_record = 0 # Log is empty
            except win32evtlog.error as e_init_open:
                 print(f"Could not open/read '{source}' during init: {e_init_open}. Starting from record 0.")
                 start_record = 0 # Fallback

            last_record_numbers[source] = start_record
            print(f"[{source}] Initialized. Will start reading *after* record number: {start_record}")
        except Exception as e:
            print(f"Unexpected error initializing handle for '{source}'. Starting from 0. Error: {e}")
            last_record_numbers[source] = 0
        finally:
             if handle:
                 try: win32evtlog.CloseEventLog(handle)
                 except: pass


def monitor_log(log_type):
    """Monitors a single log source continuously."""
    print(f"Starting monitor for '{log_type}' log...")
    while True:
        try:
            last_record_before_fetch = last_record_numbers[log_type]
            # print(f"[{log_type}] Checking for new logs after record {last_record_before_fetch}...") # Verbose Debug
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

