"""
parser.py - Main parser for LIGHTUS insider threat detection

PURPOSE:
This file contains the main parser that:
1. Polls S3 for CloudTrail logs
2. Downloads and parses new logs
3. Groups events by user (10-minute windows)
4. Sends user activity to Claude for analysis
5. Stores incidents in SQLite database

HOW TO USE:
    parser = LIGHTUSParser("your-bucket-name")
    parser.process_logs()
"""

import boto3
import json
import gzip
import sqlite3
from datetime import datetime, timedelta
import logging
from llm_agent import LLMAgent

# Setup logging to see what's happening
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LIGHTUSParser:
    """
    Main parser class that orchestrates the entire detection process.
    
    Attributes:
        bucket_name (str): S3 bucket containing CloudTrail logs
        region (str): AWS region (default: us-east-1)
        s3 (boto3.client): S3 client for AWS operations
        llm (LLMAgent): AI agent for analyzing events
        conn (sqlite3.Connection): Database connection
    """
    
    def __init__(self, bucket_name, region='us-east-1'):
        """
        Initialize the parser with bucket name and region.
        
        Args:
            bucket_name: Your S3 bucket with CloudTrail logs
            region: AWS region (us-east-1 for N. Virginia)
        """
        self.bucket_name = bucket_name
        self.region = region
        self.s3 = boto3.client('s3', region_name=region)
        self.llm = LLMAgent(region=region)
        self._init_database()
        logger.info(f"✅ Parser initialized for bucket: {bucket_name}")
    
    def _init_database(self):
        """
        Initialize SQLite database tables.
        
        Tables:
            - incidents: Stores all detected threats
            - processed_logs: Tracks which S3 files we've processed
        """
        self.conn = sqlite3.connect('lightus.db')
        
        # Incidents table - stores all alerts from Claude
        self.conn.execute('''CREATE TABLE IF NOT EXISTS incidents
                            (id TEXT PRIMARY KEY,          -- Unique incident ID (INC-123456)
                             user_id TEXT,                  -- IAM user ARN who triggered it
                             severity TEXT,                 -- Low/Medium/High/Critical
                             mitre_techniques TEXT,         -- JSON array of MITRE IDs
                             reasoning TEXT,                -- Claude's explanation
                             confidence REAL,                -- 0.0 to 1.0 confidence score
                             events_count INTEGER,           -- Number of events analyzed
                             timestamp TIMESTAMP)''')        -- When incident occurred
        
        # Processed logs table - prevents re-processing same logs
        self.conn.execute('''CREATE TABLE IF NOT EXISTS processed_logs
                            (s3_key TEXT PRIMARY KEY,       -- S3 object key (path)
                             processed_at TIMESTAMP)''')    -- When we processed it
        
        self.conn.commit()
        logger.info("✅ Database initialized")
    
    def get_new_logs(self, prefix='AWSLogs/', max_keys=100):
        """
        Get list of unprocessed CloudTrail logs from S3.
        
        Args:
            prefix: S3 prefix where CloudTrail stores logs
            max_keys: Maximum files to list per request
        
        Returns:
            list: S3 keys of new, unprocessed log files
        
        How it works:
            1. Lists all files in S3 bucket with given prefix
            2. Checks processed_logs table to see what's already processed
            3. Filters to only return new files
            4. Focuses only on us-east-1 CloudTrail event files (not digest files)
        """
        try:
            # List objects in bucket
            response = self.s3.list_objects_v2(
                Bucket=self.bucket_name, 
                Prefix=prefix, 
                MaxKeys=max_keys
            )
            
            if 'Contents' not in response:
                logger.info("📭 No logs found in bucket")
                return []
            
            # Get already processed keys from database
            cursor = self.conn.execute('SELECT s3_key FROM processed_logs')
            processed = {row[0] for row in cursor.fetchall()}
            
            # Filter: ONLY process CloudTrail event files from us-east-1
            new_logs = []
            for obj in response['Contents']:
                key = obj['Key']
                # Condition: must be in us-east-1, be a .json.gz file, not a digest file
                if ('CloudTrail/us-east-1' in key and 
                    key.endswith('.json.gz') and 
                    'CloudTrail-Digest' not in key and 
                    key not in processed):
                    new_logs.append(key)
                    logger.debug(f"📄 Found new log: {key.split('/')[-1]}")
            
            logger.info(f"📋 Found {len(new_logs)} new us-east-1 event logs")
            return new_logs
            
        except Exception as e:
            logger.error(f"❌ Error listing S3 bucket: {e}")
            return []
    
    def download_and_parse_log(self, s3_key):
        """
        Download and parse a CloudTrail log file.
        
        Args:
            s3_key: S3 key of the log file to download
        
        Returns:
            list: CloudTrail events from the file
        
        How it works:
            1. Downloads the gzipped JSON file from S3
            2. Decompresses it
            3. Parses JSON to extract the 'Records' array
            4. Each record is a single CloudTrail event
        """
        try:
            # Download from S3
            response = self.s3.get_object(Bucket=self.bucket_name, Key=s3_key)
            
            # Decompress gzip and decode
            content = gzip.decompress(response['Body'].read()).decode('utf-8')
            
            # Parse JSON and extract events
            events = json.loads(content).get('Records', [])
            
            logger.debug(f"✅ Downloaded {s3_key.split('/')[-1]} with {len(events)} events")
            return events
            
        except Exception as e:
            logger.error(f"❌ Error downloading {s3_key}: {e}")
            return []
    
    def group_events_by_user(self, events, time_window_minutes=10):
        """
        Group events by user within specified time window.
        
        Args:
            events: List of CloudTrail events
            time_window_minutes: Only include events from last X minutes
        
        Returns:
            dict: {user_arn: [events]} for users with activity in window
        
        Why 10 minutes?
            Single events lack context. Patterns over 10 minutes
            reveal suspicious behavior (e.g., user creating IAM user,
            then access key, then admin policy in 5 minutes)
        """
        user_events = {}
        # Calculate cutoff time (current UTC minus window)
        cutoff = datetime.utcnow().replace(tzinfo=None) - timedelta(minutes=time_window_minutes)
        
        for event in events:
            # Extract user identity (ARN is unique identifier)
            user = event.get('userIdentity', {}).get('arn', 'unknown')
            
            # Parse event time (CloudTrail uses ISO format with Z)
            time_str = event.get('eventTime', '')
            try:
                # Convert to naive datetime (remove timezone for comparison)
                event_time = datetime.fromisoformat(time_str.replace('Z', '+00:00')).replace(tzinfo=None)
            except:
                # If time parsing fails, use current time
                event_time = datetime.utcnow()
            
            # Only include events within the time window
            if event_time > cutoff:
                if user not in user_events:
                    user_events[user] = []
                user_events[user].append(event)
        
        return user_events
    
    def process_logs(self, min_events=3):
        """
        Main processing function - the heart of LIGHTUS.
        
        Args:
            min_events: Minimum events needed to trigger analysis
        
        Flow:
            1. Get new logs from S3
            2. Download and parse each log
            3. Mark logs as processed
            4. Group events by user (10-min window)
            5. For users with 3+ events, send to Claude
            6. Save incidents to database
        
        Why 3+ events?
            - 1 event = Could be normal
            - 2 events = Still might be normal
            - 3+ events in 10 mins = Pattern worth analyzing
        """
        logger.info("🚀 Starting log processing cycle")
        
        # Get new logs
        new_logs = self.get_new_logs()
        
        if not new_logs:
            logger.info("📭 No new logs to process")
            return
        
        # Process each new log
        all_events = []
        for key in new_logs:
            logger.info(f"📥 Processing {key.split('/')[-1]}")
            events = self.download_and_parse_log(key)
            
            if events:
                all_events.extend(events)
                # Mark as processed in database
                self.conn.execute('INSERT INTO processed_logs (s3_key, processed_at) VALUES (?, ?)',
                                 (key, datetime.utcnow().isoformat()))
                self.conn.commit()
        
        # Group events by user
        user_events = self.group_events_by_user(all_events)
        
        # Analyze each user with enough events
        for user_id, events in user_events.items():
            if len(events) >= min_events:
                logger.info(f"🔍 Analyzing {user_id[:50]}... ({len(events)} events)")
                
                # Send to Claude for analysis
                result = self.llm.analyze(events)
                
                # Generate unique incident ID (based on timestamp)
                incident_id = f"INC-{int(datetime.utcnow().timestamp())}"
                
                # Save to database
                self.conn.execute('''INSERT INTO incidents 
                                   (id, user_id, severity, mitre_techniques, reasoning, 
                                    confidence, events_count, timestamp)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                 (incident_id, user_id, result['severity'],
                                  json.dumps(result['mitre_techniques']), result['reasoning'],
                                  result.get('confidence', 0.5), len(events),
                                  datetime.utcnow().isoformat()))
                self.conn.commit()
                
                # Log the result
                logger.info(f"🚨 Incident saved: {result['severity']}")
                if result['mitre_techniques']:
                    logger.info(f"   MITRE: {', '.join(result['mitre_techniques'])}")

# ============================================
# MAIN EXECUTION
# ============================================
if __name__ == "__main__":
    """
    When run directly, this script:
    1. Takes bucket name as command line argument
    2. Runs one processing cycle
    3. Displays recent incidents
    """
    import sys
    
    # Get bucket name from command line or prompt
    if len(sys.argv) > 1:
        bucket = sys.argv[1]
    else:
        bucket = input("Enter your S3 bucket name: ")
    
    # Create and run parser
    parser = LIGHTUSParser(bucket)
    parser.process_logs()
    
    # Display recent incidents
    print("\n" + "="*60)
    print("📊 RECENT INCIDENTS")
    print("="*60)
    
    incidents = parser.conn.execute('''
        SELECT severity, mitre_techniques, reasoning 
        FROM incidents 
        ORDER BY timestamp DESC 
        LIMIT 5
    ''').fetchall()
    
    if incidents:
        for inc in incidents:
            # Color code by severity
            if inc[0] == 'Critical':
                emoji = "🔴"
            elif inc[0] == 'High':
                emoji = "🟠"
            elif inc[0] == 'Medium':
                emoji = "🟡"
            else:
                emoji = "🟢"
            
            print(f"\n{emoji} {inc[0]}")
            print(f"   MITRE: {inc[1]}")
            print(f"   Reason: {inc[2][:100]}...")
    else:
        print("\n✅ No incidents found - all activity appears normal")
    
    parser.conn.close()
