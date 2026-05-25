# core/state.py

class State:
    """Central state container for the red teaming orchestration."""
    
    def __init__(self, target: str, ip: str):
        self.target = target          # Target hostname/description
        self.ip = ip                  # Target IP address
        self.open_ports = []          # List of dicts: {'port': int, 'protocol': str, 'service': str}
        self.services = {}            # Dict service_name -> version info
        self.cve_list = []            # List of dicts: {'cve_id': str, 'description': str, ...}
        self.credentials = []         # List of dicts: {'username': str, 'password': str, 'service': str}
        self.exploits = []            # List of dicts: {'exploit_name': str, 'success': bool, ...}
        self.errors = []              # List of error dicts from tasks