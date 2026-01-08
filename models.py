import datetime
import uuid

class Host:
    """
    Représente un hôte actif sur le réseau.
    
    Utilisé par le NetworkScanner pour stocker les informations
    sur les hôtes découverts lors des scans.
    """
    def __init__(self, ip_address, hostname=None, is_active=True):
        self.ip_address = ip_address  # Adresse IP de l'hôte
        self.hostname = hostname if hostname else "Inconnu"  # Nom d'hôte DNS
        self.is_active = is_active  # Statut de l'hôte (actif/inactif)
        self.ports = {}  # Dictionnaire {port: service_version} des ports ouverts

    def __str__(self):
        return f"Host(IP: {self.ip_address}, Hostname: {self.hostname}, Active: {self.is_active})"

class Alert:
    """
    Représente une alerte de sécurité générée par l'IDS.
    
    Chaque alerte possède un ID unique et peut être acquittée
    par un administrateur.
    """
    def __init__(self, description, event_type="Intrusion", component="IDS", source_ip=None):
        self.id = str(uuid.uuid4())  # Identifiant unique de l'alerte
        self.timestamp = datetime.datetime.now()  # Date et heure de création
        self.description = description  # Description détaillée de l'alerte
        self.event_type = event_type  # Type d'événement (Port_Scan, DoS, etc.)
        self.component = component  # Composant source (IDS, Scanner)
        self.source_ip = source_ip  # Adresse IP source de la menace
        self.acknowledged = False  # Statut d'acquittement (traitée ou non)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "event_type": self.event_type,
            "component": self.component,
            "source_ip": self.source_ip,
            "acknowledged": self.acknowledged
        }

    @classmethod
    def from_dict(cls, data):
        alert = cls(
            description=data['description'], 
            event_type=data['event_type'], 
            component=data['component'],
            source_ip=data.get('source_ip') # Use .get() for backward compatibility
        )
        alert.id = data['id']
        alert.timestamp = datetime.datetime.fromisoformat(data['timestamp'])
        alert.acknowledged = data['acknowledged']
        return alert

    def __str__(self):
        status = "ACK" if self.acknowledged else "UNACK"
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] ALERT ({self.event_type}/{self.component}) [{status}] ID: {self.id[:8]} - {self.description}"

class Log:
    """
    Représente une entrée de journalisation (Log).
    
    Utilisé pour enregistrer tous les événements du système:
    scans, détections, erreurs, actions administratives, etc.
    """
    def __init__(self, message, event_type="INFO", component="System", details=None, user="Admin", log_id=None, timestamp=None):
        # Identifiant unique du log
        self.log_id = log_id if log_id else str(uuid.uuid4())
        
        # Horodatage du log (création ou fourni)
        if timestamp:
             self.timestamp = datetime.datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp
        else:
             self.timestamp = datetime.datetime.now()
        
        # Informations du log
        self.component = component  # Composant source
        self.event_type = event_type  # Type d'événement
        self.message = message  # Message descriptif
        self.details = details if details else {}  # Détails supplémentaires
        self.user = user  # Utilisateur associé

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
