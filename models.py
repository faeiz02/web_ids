import datetime
import uuid

class Host:
    """Représente un hôte actif sur le réseau."""
    def __init__(self, ip_address, hostname=None, is_active=True):
        self.ip_address = ip_address
        self.hostname = hostname if hostname else "Inconnu"
        self.is_active = is_active
        self.ports = {}  # {port: service_version}

    def __str__(self):
        return f"Host(IP: {self.ip_address}, Hostname: {self.hostname}, Active: {self.is_active})"

class Alert:
    """Représente une alerte de sécurité."""
    def __init__(self, description, event_type="Intrusion", component="IDS"):
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.datetime.now()
        self.description = description
        self.event_type = event_type
        self.component = component
        self.acknowledged = False

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "event_type": self.event_type,
            "component": self.component,
            "acknowledged": self.acknowledged
        }

    @classmethod
    def from_dict(cls, data):
        alert = cls(data['description'], data['event_type'], data['component'])
        alert.id = data['id']
        alert.timestamp = datetime.datetime.fromisoformat(data['timestamp'])
        alert.acknowledged = data['acknowledged']
        return alert

    def __str__(self):
        status = "ACK" if self.acknowledged else "UNACK"
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] ALERT ({self.event_type}/{self.component}) [{status}] ID: {self.id[:8]} - {self.description}"

class Log:
    """Représente une entrée de journalisation (Log)."""
    def __init__(self, message, event_type="INFO", component="System", details=None, user="Admin", log_id=None, timestamp=None):
        self.log_id = log_id if log_id else str(uuid.uuid4())
        if timestamp:
             self.timestamp = datetime.datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp
        else:
             self.timestamp = datetime.datetime.now()
        self.component = component
        self.event_type = event_type
        self.message = message
        self.details = details if details else {}
        self.user = user

    def to_dict(self):
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp.isoformat(),
            "component": self.component,
            "event_type": self.event_type,
            "message": self.message,
            "details": self.details,
            "user": self.user
        }

    def __str__(self):
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.event_type} [{self.component}]: {self.message}"
