# ado_api.py

import requests
import base64
import logging
import os
from config import BaseConfig as app
from utils import get_current_user_identity
from dateutil.parser import parse

# Configuration variables from external config class
ADO_ORG = app.ADO_ORG
ADO_PROJECT = app.ADO_PROJECT
ADO_PAT = app.ADO_PAT
ADO_API_VERSION = app.ADO_API_VERSION

# Setup logging for errors and audit
logging.basicConfig(
    filename="ado_sync.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Log user/service principal running the code
user_identity = get_current_user_identity()
logging.info(f"Azure DevOps sync initiated by: {user_identity}")

def get_ado_auth_header():
    """
    Build Azure DevOps API headers using PAT (Personal Access Token).
    """
    try:
        token = f":{ADO_PAT}"
        b64_token = base64.b64encode(token.encode("utf-8")).decode("utf-8")
        return {
            "Authorization": f"Basic {b64_token}",
            "Content-Type": "application/json-patch+json"
        }
    except Exception as e:
        logging.exception("Error generating Azure DevOps authorization header.")
        raise

def find_existing_bug(sysaid_id):
    """
    Check if a bug already exists in ADO matching a SysAid ticket ID.
    Returns the work item ID if found, else None.
    """
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/wiql?api-version={ADO_API_VERSION}"
    
    # Note: Update 'Custom.SysAidID' to match your custom field name in ADO
    query = {
        "query": f"SELECT [System.Id] FROM WorkItems WHERE [System.WorkItemType] = 'Bug' AND [Custom.SysAidID] = '{sysaid_id}'"
    }

    headers = get_ado_auth_header()
    headers["Content-Type"] = "application/json"

    try:
        response = requests.post(url, headers=headers, json=query)
        response.raise_for_status()
        json_data = response.json()
        work_items = json_data.get("workItems", [])
        return work_items[0]["id"] if work_items else None
    except requests.RequestException as e:
        logging.exception(f"Failed to fetch existing bug for SysAid ID {sysaid_id}.")
        return None  # Fail gracefully and treat as not found

def get_work_item_last_updated(bug_id):
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems/{bug_id}?api-version={ADO_API_VERSION}"
    headers = get_ado_auth_header()
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return parse(data["fields"]["System.ChangedDate"]).timestamp() * 1000  # in ms
    except Exception:
        logging.exception(f"Could not retrieve last update for ADO work item {bug_id}")
        return 0

def create_ado_bug(ticket):
    """
    Create a new bug in Azure DevOps corresponding to a SysAid ticket.
    Returns the created bug JSON object.
    """
    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems/$Bug?api-version={ADO_API_VERSION}"
    headers = get_ado_auth_header()

    # Construct the ADO bug fields using JSON Patch syntax
    bug_data = [
        {"op": "add", "path": "/fields/System.Title", "value": ticket["title"]},
        {"op": "add", "path": "/fields/System.Description", "value": ticket["description"]},
        {"op": "add", "path": "/fields/Custom.SysAidID", "value": str(ticket["id"])},
        {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Priority", "value": map_priority(ticket["priority"])}
    ]

    # Optional parent work item link
    if ticket.get("parent_id"):
        parent_url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workItems/{ticket['parent_id']}"
        bug_data.append({
            "op": "add",
            "path": "/relations/-",
            "value": {
                "rel": "System.LinkTypes.Hierarchy-Reverse",
                "url": parent_url,
                "attributes": {
                    "comment": "Linked to parent work item via SysAid integration"
                }
            }
        })

    try:
        response = requests.post(url, headers=headers, json=bug_data)
        response.raise_for_status()
        logging.info(f"Created ADO bug for SysAid ticket {ticket['id']}")
        return response.json()
    except requests.RequestException as e:
        logging.exception(f"Failed to create ADO bug for SysAid ticket {ticket['id']}")
        raise

def update_ado_bug(bug_id, ticket):
    """
    Update an existing ADO bug with updated data from a SysAid ticket, with safe parent linking (avoid duplicates).
    """
    def already_linked(bug_id, parent_id):
        """
        Check if the bug already has a parent link to the specified work item.
        """
        url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems/{bug_id}?$expand=relations&api-version={ADO_API_VERSION}"
        headers = get_ado_auth_header()
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            relations = data.get("relations", [])
            parent_url = f"{data['_links']['self']['href'].rsplit('/', 1)[0]}/{parent_id}"
            return any(r.get("url") == parent_url and r.get("rel") == "System.LinkTypes.Hierarchy-Reverse" for r in relations)
        except Exception:
            logging.exception(f"Failed to check existing links for bug {bug_id}")
            return False

    url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workitems/{bug_id}?api-version={ADO_API_VERSION}"
    headers = get_ado_auth_header()

    bug_data = [
        {"op": "add", "path": "/fields/System.Title", "value": ticket["title"]},
        {"op": "add", "path": "/fields/System.Description", "value": ticket["description"]},
        {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Priority", "value": map_priority(ticket["priority"])}
    ]

    # Safe parent work item link if not already linked
    if ticket.get("parent_id") and not already_linked(bug_id, ticket["parent_id"]):
        parent_url = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/wit/workItems/{ticket['parent_id']}"
        bug_data.append({
            "op": "add",
            "path": "/relations/-",
            "value": {
                "rel": "System.LinkTypes.Hierarchy-Reverse",
                "url": parent_url,
                "attributes": {
                    "comment": "Linked to parent work item via SysAid integration"
                }
            }
        })

    try:
        response = requests.patch(url, headers=headers, json=bug_data)
        response.raise_for_status()
        logging.info(f"Updated ADO bug {bug_id} for SysAid ticket {ticket['id']}")
        return response.json()
    except requests.RequestException as e:
        logging.exception(f"Failed to update ADO bug {bug_id} for SysAid ticket {ticket['id']}")
        raise

def map_priority(priority):
    """
    Map SysAid ticket priorities to Azure DevOps numeric priority values.
    Default is 2 if not matched.
    """
    priority_mapping = {
        "High": 1,
        "Medium": 2,
        "Low": 3
    }
    return priority_mapping.get(priority, 2)
