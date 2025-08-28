# SysAid to Azure DevOps Bug Sync

This project synchronizes SysAid support tickets (Service Requests) into Azure DevOps (ADO) as **Bugs**, complete with:

- PII/PHI redaction
- Delta syncing
- Smart update detection
- Optional parent linking (to User Stories or Tasks)
- Full audit trail and logging

---

## Project Structure

```
sysaid_to_ado/
├── ado_api.py                 # ADO bug creation, update, and linking
├── main.py                    # Orchestrator: fetch, redact, sync
├── sensitive_data_detector.py # PII/PHI redaction logic
├── sysaid_api.py              # Simulated + real SysAid API integration
├── utils.py                   # Logging & user identity helpers
├── .env or config.py          # Secrets (not tracked in Git)
├── last_sync.json             # Delta sync timestamp
├── logs/
│   └── sync.log               # Audit trail
```

---

## Security & HIPAA Compliance

- Redacts fields using regex and SpaCy NER before syncing to ADO
- Logs each detection/redaction to 'logs/sync.log'
- Only '"description"' field is scanned and cleaned
- Supports detection of:
  - SSN, DOB, phone numbers, email
  - Rx numbers, medical billing info
  - Names (via NLP)
  - IP addresses and login data

---

## Sync Logic

### On each run:
1. Fetch **new or updated** SysAid tickets since last run
2. Redact sensitive '"description"' content
3. If the ticket already exists in ADO:
   - Compare SysAid's 'update_time' to ADO’s 'System.ChangedDate'
   - Skip if not newer
   - Update otherwise (with re-redaction)
4. If it's new:
   - Create as ADO **Bug**
   - Optionally link to parent User Story or Task via 'parent_id'

---

## Setup Instructions

### 1. Install Requirements

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Create '.env'

```dotenv
# Azure DevOps
ADO_ORG=your-ado-org
ADO_PROJECT=your-ado-project
ADO_PAT=your-ado-personal-access-token
ADO_API_VERSION=7.0

# SysAid
SYSAID_API_TOKEN=your-sysaid-token
SYSAID_BASE_URL=https://yourcompany.sysaidit.com
```

> Keep this file out of version control.

### 3. Run the Sync

```bash
python main.py
```

You’ll get a summary like:

```
Sync complete.
Created: 3, Updated: 2, Failed: 0
```

---

## Sample Ticket Input

Example of a SysAid ticket passed to ADO:

```python
{
  "id": 101,
  "title": "Email Service - login failure",
  "description": "User John Smith (SSN: 123-45-6789)...",
  "priority": "High",
  "status": "Open",
  "parent_id": 872,  # Optional ADO User Story ID
  "update_time": 1714458000000  # Epoch ms
}
```

---

## Parent Linking (Optional)

If 'ticket["parent_id"]' is provided:
- Bug will be linked to that work item
- Duplicate links are automatically avoided
- Uses 'System.LinkTypes.Hierarchy-Reverse'

---

## Logs and Auditing

- 'logs/sync.log' contains full run trace
- Every detection, failure, and update is logged
- Run identity is captured via 'get_current_user_identity()'

---

## Best Practices Followed

- Secrets kept in '.env' or config.py
- Redaction applied before API submission
- Updates only occur when needed
- JSON Patch structure for ADO
- Graceful exception handling
- Configurable log file via 'utils.setup_logger()'

---

## Contributions

You're welcome to extend this to:

- Bi-directional syncing
- Attachment uploads
- Field mapping UI
- Secure vault integration for secrets

---

## Created April 2025

Maintained by: **Hans Esquivel**
License: MIT (or internal)

---

## Contact

Please open an [issue](https://github.com/club-innovate/sysaidado/issues) or start a [discussion](https://github.com/club-innovate/sysaidado/discussions) if you want to get in touch.

---