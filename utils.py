import getpass
import os
import platform
from datetime import datetime
import logging

def log_action(action, ticket_id, bug_id=None):
    timestamp = datetime.utcnow().isoformat()
    if bug_id:
        print(f"[{timestamp}] {action}: SysAid Ticket ID {ticket_id} -> ADO Bug ID {bug_id}")
    else:
        print(f"[{timestamp}] {action}: SysAid Ticket ID {ticket_id}")

def get_current_user_identity():
    """
    Identify the current OS user or service principal running the script.
    Used for auditing purposes.
    """
    try:
        username = getpass.getuser()
        hostname = platform.node()
        return f"{username}@{hostname}"
    except Exception as e:
        return "unknown_user"

def setup_logger(log_file):
    """
    Configure and return a logger instance.
    """
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )