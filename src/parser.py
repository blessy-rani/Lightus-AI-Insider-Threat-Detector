"""
parser.py - Main parser logic that uses all modules
"""

import time
import random
from datetime import datetime

from processed_logs import is_processed, mark_processed, filter_new_logs
from baseline import update_baseline, is_rare_event
from user_window import add_event, get_ready_batches, clear_user
from incidents import save_incident, save_failed_batch

# These will be implemented separately
from s3_client import list_log_files, download_and_parse
from llm_client import analyze_batch  # We'll build this later

def process_new_logs():
    """Main function - call this every 2 minutes"""
    print(f"[{datetime.utcnow()}] Checking for new logs...")
    
    # 1. Get list of log files from S3
    all_logs = list_log_files()
    if not all_logs:
        print("No logs found")
        return
    
    # 2. Filter out already processed logs
    new_logs = filter_new_logs(all_logs)
    print(f"Found {len(new_logs)} new logs")
    
    # 3. Process each new log
    for log_key in new_logs:
        print(f"Processing: {log_key}")
        
        # Download and parse CloudTrail log
        events = download_and_parse(log_key)
        
        # Process each event
        for event in events:
            event_name = event.get('eventName', 'unknown')
            user_id = event.get('userIdentity', {}).get('arn', 'unknown')
            
            # Update baseline (always)
            update_baseline(event_name)
            
            # Check if event is rare enough to analyze
            if is_rare_event(event_name):
                # Add to user's window
                add_event(user_id, event)
        
        # Mark log as processed
        mark_processed(log_key)
    
    # 4. Check for ready batches
    batches = get_ready_batches()
    for user_id, events in batches:
        print(f"Analyzing batch for {user_id} ({len(events)} events)")
        
        try:
            # Call LLM (to be implemented)
            result = analyze_batch(events)
            
            # Save incident if high/critical
            if result['severity'] in ['High', 'Critical']:
                save_incident(
                    user_id=user_id,
                    severity=result['severity'],
                    mitre_list=result.get('mitre', []),
                    reason=result.get('reason', '')
                )
                print(f"🚨 ALERT: {result['severity']} - {user_id}")
            
            # Clear user window
            clear_user(user_id)
            
        except Exception as e:
            print(f"LLM failed: {e}")
            save_failed_batch(user_id, events, str(e))
    
    print("Done processing cycle")

if __name__ == "__main__":
    # For testing
    process_new_logs()
