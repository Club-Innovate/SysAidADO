class BaseConfig(object):
    ################################################################################
    #
    # Baseline Configuration
    #
    ################################################################################
    
    # Azure DevOps
    ADO_ORG = 'orgName'
    ADO_PROJECT = 'projectName'
    ADO_PAT = 'PAT-Key'
    ADO_API_VERSION = '7.1'

    # SysAid
    SYSAID_API_TOKEN = ''
    SYSAID_BASE_URL = '' # e.g., f'https://yourcompany.sysaidit.com'    

    # Application settings
    LOG_FILE = "logs/sync.log"
    LAST_SYNC_FILE = "state/last_sync.json"