import os
from dotenv import load_dotenv
from config import BaseConfig as app
from sysaid_api import fetch_sysaid_tickets
from ado_api import find_existing_bug, create_ado_bug, update_ado_bug, get_work_item_last_updated
from utils import log_action, get_current_user_identity, setup_logger
import logging
from sensitive_data_detector import SensitiveDataDetector

# Setup basic logging (same log file as ado_api.py)
logging.basicConfig(
    filename="ado_sync.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def main():
    # Load environment variables from .env file
    load_dotenv()
    setup_logger(app.LOG_FILE)

    # Identify the user or service account running this script
    run_by = get_current_user_identity()
    logging.info(f"=== Azure DevOps Sync STARTED by {run_by} ===")

    # Fetch tickets from SysAid
    tickets = fetch_sysaid_tickets()
    detector = SensitiveDataDetector()

    # Counters for summary
    created_count = 0
    updated_count = 0
    failed_count = 0

    # Sync each ticket
    for ticket in tickets:
        sysaid_id = ticket["id"]

        try:
            # Redact PII/PHI before sync
            findings, ticket = detector.scan_and_redact_ticket(ticket)
            if findings:
                logging.warning(f"Ticket {sysaid_id} had sensitive data: {findings}")

            existing_bug_id = find_existing_bug(sysaid_id)

            if existing_bug_id:
                ado_updated_ts = get_work_item_last_updated(existing_bug_id)
                if ticket.get("update_time", 0) > ado_updated_ts:
                    update_ado_bug(existing_bug_id, ticket)
                    log_action("Updated", sysaid_id, existing_bug_id)
                    updated_count += 1
                else:
                    logging.info(f"SysAid ticket {sysaid_id} unchanged since ADO last update; skipping.")
            else:
                new_bug = create_ado_bug(ticket)
                log_action("Created", sysaid_id, new_bug["id"])
                created_count += 1

        except Exception as e:
            failed_count += 1
            logging.exception(f"Sync failed for SysAid ticket {sysaid_id}")

    # Run summary
    logging.info(f"=== Azure DevOps Sync COMPLETED by {run_by} ===")
    logging.info(f"Summary: {created_count} created, {updated_count} updated, {failed_count} failed")

    print(f"\nSync complete.\nCreated: {created_count}, Updated: {updated_count}, Failed: {failed_count}")

if __name__ == "__main__":
    main()

