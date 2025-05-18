import random
from datetime import datetime, timedelta
from sensitive_data_detector import SensitiveDataDetector
import random


detector = SensitiveDataDetector()

##################################################################################
#
# Synthentic Data Generator
#
# This section generates synthetic SysAid tickets for testing purposes.
#
##################################################################################
applications = [
    "Email Service", "CRM Portal", "HR Management System", "Inventory Tracker",
    "Mobile App", "Analytics Dashboard", "Customer Support Chat", "Payroll System",
    "Project Management Tool", "File Sharing Service"
]

issues = [
    ("login failure", "User John Smith (SSN: 123-45-6789) cannot log in. DOB: 01/12/1990. Rx ID: RX2025123"),
    ("slow response", "The application takes more than 10 seconds to load pages."),
    ("data sync error", "Records are not syncing across the database correctly."),
    ("timeout issue", "Frequent timeout errors are occurring during usage."),
    ("unexpected crash", "The app crashes upon submitting a form."),
    ("UI glitch", "Buttons are not responsive on certain screens."),
    ("inaccurate data", "Reports show incorrect revenue totals."),
    ("file upload failure", "Users are unable to upload attachments."),
    ("search not working", "Search returns no results even for known items."),
    ("email notifications broken", "No emails are being sent from the system."),
    ("login failure", "User Jane Doe (SSN: 123-45-6789) cannot log in. DOB: 12/12/1985. Rx ID: RX2035615")
]

priorities = ["High", "Medium", "Low"]

def generate_fake_sysaid_ticket(ticket_id):
    
    # List of possible values
    values = ["", 872]

    app = random.choice(applications)
    issue_title, issue_desc = random.choice(issues)
    priority = random.choices(priorities, weights=[0.4, 0.4, 0.2])[0]
    created_at = datetime.utcnow() - timedelta(days=random.randint(0, 30))

    ticket = {
        "id": ticket_id,
        "title": f"{app} - {issue_title.capitalize()}",
        "description": f"{app}: {issue_desc}",
        "status": "Open",
        "priority": priority,
        "parent_id": random.choice(values),  # ADO work item ID of the User Story or Task
        "created_at": created_at.isoformat() + "Z"
    }
    
    # Detect and redact PII/PHI
    findings, redacted_ticket = detector.scan_and_redact_ticket(ticket)
    
    # Log findings or store original for auditing
    if findings:
        logging.info(f"Ticket {ticket_id} PII/PHI findings: {findings}")

    return redacted_ticket 

def fetch_sysaid_tickets(count=11):
    return [generate_fake_sysaid_ticket(i) for i in range(1, count + 1)]


##################################################################################
#
# Core Code Functions
#
# Note: This section is for the production version of SysAid API integration.
# You will need a SysAid license. SysAid API details gathered from here: 
# https://documentation.sysaid.com/docs/rest-api-guide
#
# UPATE THIS SECTION WHEN YOU HAVE A LICENSE TO SYSAID
#
##################################################################################
# sysaid_api.py

from config import BaseConfig as app
import requests
import logging
import os
import json
from datetime import datetime, timezone
from typing import List, Dict

# Configure logging
logging.basicConfig(
    filename='sysaid_sync.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load environment variables
SYSAID_API_TOKEN = app.SYSAID_API_TOKEN
SYSAID_BASE_URL =  app.SYSAID_BASE_URL  # e.g., f'https://yourcompany.sysaidit.com'

# File to store the timestamp of the last successful sync
LAST_SYNC_FILE = 'last_sync.json'

def get_auth_headers() -> Dict[str, str]:
    """
    Constructs the authorization headers for SysAid API requests.
    """
    return {
        "Authorization": f"Bearer {SYSAID_API_TOKEN}",
        "Content-Type": "application/json"
    }

def get_last_sync_time() -> int:
    """
    Retrieves the timestamp of the last successful synchronization.
    Returns 0 if the timestamp file does not exist.
    """
    if os.path.exists(LAST_SYNC_FILE):
        with open(LAST_SYNC_FILE, 'r') as file:
            data = json.load(file)
            return data.get('last_sync_time', 0)
    return 0

def update_last_sync_time(timestamp: int):
    """
    Updates the timestamp of the last successful synchronization.
    """
    with open(LAST_SYNC_FILE, 'w') as file:
        json.dump({'last_sync_time': timestamp}, file)

def fetch_updated_service_records() -> List[Dict]:
    """
    Fetches service records from SysAid that have been inserted or updated
    since the last synchronization.
    """
    last_sync_time = get_last_sync_time()
    current_time = int(datetime.now(timezone.utc).timestamp() * 1000)

    url = f"{SYSAID_BASE_URL}/api/v1/sr"
    params = {
        "fields": "id,title,description,insert_time,update_time,status,priority",
        "limit": 100,
        "offset": 0
    }

    all_records = []

    while True:
        try:
            response = requests.get(url, headers=get_auth_headers(), params=params)
            response.raise_for_status()
            records = response.json()

            if not records:
                break

            for record in records:
                info = {item['key']: item['value'] for item in record.get('info', [])}
                insert_time = int(info.get('insert_time', 0))
                update_time = int(info.get('update_time', 0))

                if insert_time > last_sync_time or update_time > last_sync_time:
                    all_records.append({
                        "id": record.get("id"),
                        "title": info.get("title"),
                        "description": info.get("description"),
                        "status": info.get("status"),
                        "priority": info.get("priority"),
                        #"workitem_id": info.get("parent_id"), # Assuming this is a custom field in SysAid
                        "insert_time": insert_time,
                        "update_time": update_time
                    })

            params['offset'] += params['limit']

        except requests.RequestException as e:
            logging.error(f"Error fetching service records: {e}")
            break

    update_last_sync_time(current_time)
    return all_records
