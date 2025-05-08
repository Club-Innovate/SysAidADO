import re
import logging
from typing import List, Dict, Tuple
import spacy

# Set up consistent logging (reuses main project log file)
logging.basicConfig(
    filename="logs/sync.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class SensitiveDataDetector:
    """
    Detects and redacts PII/PHI data from SysAid ticket fields to support HIPAA compliance.
    """

    def __init__(self):
        try:
            # Load SpaCy NLP model for name detection
            self.nlp = spacy.load("en_core_web_sm")

            # Define regex patterns for detecting common PII/PHI
            self.patterns = {
                # PII
                #"Full Name": re.compile(r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b"),
                "Address": re.compile(r"\d{1,5}\s\w+\s\w+"),
                "Phone Number": re.compile(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
                "Email Address": re.compile(r"\b[\w.-]+?@\w+?\.\w+?\b"),
                "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                "Driver's License": re.compile(r"[A-Z]{1,2}\d{6,9}"),
                "Passport": re.compile(r"\b\d{9}\b"),
                #"Financial Info": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
                "Date of Birth": re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
                "IP Address": re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
                "Login Credentials": re.compile(r"(username|login|password)\s*[:=]\s*\S+", re.IGNORECASE),

                # PHI Standard + Extended
                "Medical Records": re.compile(r"\bMRN\d{6,}\b", re.IGNORECASE),
                "Insurance Info": re.compile(r"(insurance|policy)\s*[:=]?\s*\S+", re.IGNORECASE),
                "Prescription": re.compile(r"\b(?:rx|prescription)\s*[:=]?\s*\S+", re.IGNORECASE),
                "Billing Info": re.compile(r"billing\s*(code|info|amount)?[:=]?\s*\S+", re.IGNORECASE),
                "Member ID": re.compile(r"\bMID[\s:_-]?\d+[A-Z]?\b", re.IGNORECASE),
                "Patient ID": re.compile(r"\bPAT[\s:_-]?ID[\s:_-]?\w+\b", re.IGNORECASE),
                "Patient Account Number": re.compile(r"\b(?:Account|Acct)[\s:_-]*#?\s*\d{6,}\b", re.IGNORECASE),
                "Medical Record Code": re.compile(r"\b(?:MRC|MedRec)[\s:_-]?\d{6,}\b", re.IGNORECASE),
                "Encounter Number": re.compile(r"\b(?:encounter|enc#)[\s:_-]?\d{5,}\b", re.IGNORECASE),
                "Treatment ID": re.compile(r"\bTREAT[\s:_-]?\d{5,}\b", re.IGNORECASE),
                "Insurance Group Number": re.compile(r"\bgroup\s*(number|#)?[:=]?\s*\d{5,}\b", re.IGNORECASE),
                "ICD Code": re.compile(r"\b(ICD(?:-10)?|Diagnosis)\s*(code)?[:=]?\s*[A-Z]\d{2}(?:\.\d{1,4})?\b", re.IGNORECASE),
                "NPI Number": re.compile(r"\bNPI[\s:_-]?\d{10}\b", re.IGNORECASE),
                "Patient Portal ID": re.compile(r"\bportal\s*(id|user)?[:=]?\s*\w{6,}\b", re.IGNORECASE),
                "Referral Code": re.compile(r"\breferral\s*(code|id)?[:=]?\s*\w{5,}\b", re.IGNORECASE),
                "Clinical Trial ID": re.compile(r"\b(?:NCT|Trial|Study)[\s:_-]?(?:ID)?[:=]?\s*\w{5,}\b", re.IGNORECASE),

                # New Extended PHI Identifiers
                "Allergy Code": re.compile(r"\ballergy\s*(code|id)?[:=]?\s*\w{4,}\b", re.IGNORECASE),
                "Vaccination Record ID": re.compile(r"\bvaccination\s*(id|record)?[:=]?\s*\w{5,}\b", re.IGNORECASE),
                "Lab Order Number": re.compile(r"\b(lab\s*(order|result)?\s*(no|number)?[:=]?\s*\w{5,})\b", re.IGNORECASE),
                "Test Result Code": re.compile(r"\b(test|result)\s*(code|id)?[:=]?\s*[A-Z0-9]{4,}\b", re.IGNORECASE),
                "Specimen ID": re.compile(r"\b(specimen|sample)\s*(id)?[:=]?\s*\w{4,}\b", re.IGNORECASE),
                "Hospital Unit Number": re.compile(r"\bunit\s*(no|number)?[:=]?\s*\w{3,}\b", re.IGNORECASE),
                "Care Plan ID": re.compile(r"\bcare\s*plan\s*(id|number)?[:=]?\s*\w{3,}\b", re.IGNORECASE),
                "Discharge Summary Code": re.compile(r"\bdischarge\s*(summary|note)?\s*(id|code)?[:=]?\s*\w{5,}\b", re.IGNORECASE),
                "Inpatient Visit ID": re.compile(r"\bvisit\s*(id|code)?[:=]?\s*\w{5,}\b", re.IGNORECASE),
            }

            logging.info("SensitiveDataDetector initialized successfully.")
        except Exception:
            logging.exception("Initialization of SensitiveDataDetector failed.")

    def scan_text(self, text: str) -> List[Tuple[str, str]]:
        """
        Scan a block of text for potential PII/PHI using regex + NLP for names.

        Returns:
            List of tuples with (label, matched_text)
        """
        
        matches = []

        try:
            for label, pattern in self.patterns.items():
                found = pattern.findall(text)
                for match in found:
                    match_str = match if isinstance(match, str) else match[0]
                    matches.append((label, match_str))

            # NLP-based detection of PERSON entities
            doc = self.nlp(text)
            for ent in doc.ents:
                if ent.label_ == "PERSON":
                    matches.append(("Full Name", ent.text))
                    logging.debug(f"SpaCy PERSON detected: '{ent.text}'")
        except Exception:
            logging.exception("scan_text() failed.")

        return matches

    def redact_text(self, text: str, findings: List[Tuple[str, str]]) -> str:
        """
        Replaces detected PII/PHI in text with '[REDACTED]'.

        Args:
            text: Original content
            findings: List of (label, sensitive_value) to remove

        Returns:
            Redacted string
        """
        try:
            redacted = text
            for _, value in findings:
                if value:
                    pattern = re.escape(value)
                    redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)
            return redacted
        except Exception:
            logging.exception("Failed redacting text.")
            return text

    def scan_and_redact_ticket(self, ticket: Dict[str, str]) -> Tuple[Dict[str, List[Tuple[str, str]]], Dict[str, str]]:
        """
        Scans ticket fields for PII/PHI, redacts them, and logs audit info.

        Args:
            ticket (dict): SysAid ticket dictionary

        Returns:
            Tuple:
              - findings: {field: [(label, match)]}
              - redacted_ticket: sanitized ticket copy
        """
        findings = {}
        redacted_ticket = ticket.copy()

        try:
            for field in ["description"]: # Add other fields as needed (e.g., "title", "description", "comments")
                content = ticket.get(field)
                if content and isinstance(content, str):
                    matches = self.scan_text(content)
                    if matches:
                        findings[field] = matches
                        redacted_ticket[field] = self.redact_text(content, matches)
                        logging.warning(
                            f"PII/PHI found in ticket {ticket.get('id', 'UNKNOWN')} field '{field}': {matches}"
                        )
        except Exception:
            logging.exception("scan_and_redact_ticket() failed.")

        return findings, redacted_ticket


# === TESTING: Example usage ===
# if __name__ == "__main__":
#     try:
#         detector = SensitiveDataDetector()

#         ticket_example = {
#             "id": 1001,
#             "title": "Login failed for John Smith",
#             "description": "User John Smith (SSN: 123-45-6789) cannot log in. DOB: 01/12/1990. Rx ID: RX2025123",
#             "notes": "Contacted Dr. Jones. Billing amount $400. Address: 123 Elm Street"
#         }

#         findings, cleaned_ticket = detector.scan_and_redact_ticket(ticket_example)

#         # Log full original + cleaned ticket
#         logging.info(f"Original Ticket {ticket_example['id']}: {ticket_example}")
#         logging.info(f"Redacted Ticket {ticket_example['id']}: {cleaned_ticket}")

#         print("=== PII/PHI DETECTED ===")
#         for field, matches in findings.items():
#             print(f"{field}: {[f'{label}: {value}' for label, value in matches]}")

#         print("\n=== CLEANED TICKET ===")
#         for k, v in cleaned_ticket.items():
#             print(f"{k}: {v}")

#     except Exception:
#         logging.exception("Unhandled exception during PII/PHI demo.")
