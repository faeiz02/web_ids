import json
import os
from models import Log, Alert

class LogManager:
    """Gère la journalisation des événements du système."""
    def __init__(self, log_file="logs.jsonl"):
        self.log_file = os.path.join(os.path.dirname(__file__), log_file)
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        """Crée le fichier de log s'il n'existe pas."""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                pass # Crée un fichier vide

    def log(self, message, event_type="INFO", component="System", details=None, user="Admin"):
        """Enregistre un nouvel événement dans le journal."""
        new_log = Log(message, event_type, component, details, user)
        
        # Écriture dans le fichier
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(new_log.to_dict()) + '\n')
        
        # Affichage dans la console pour le feedback immédiat
        print(str(new_log))

    def get_logs(self, limit=100):
        """Récupère les derniers logs."""
        logs = []
        try:
            with open(self.log_file, 'r') as f:
                # Lire les lignes en sens inverse pour obtenir les plus récentes
                for line in reversed(f.readlines()):
                    if line.strip():
                        try:
                            logs.append(Log(**json.loads(line)).to_dict())
                            if len(logs) >= limit:
                                break
                        except json.JSONDecodeError:
                            continue # Ignorer les lignes corrompues
        except FileNotFoundError:
            pass
        return logs

    def log_from_dict(self, data):
        """Reconstruit un objet Log à partir d'un dictionnaire."""
        # Note: Le constructeur de Log ne prend pas 'log_id' et 'timestamp' directement.
        # On crée un Log temporaire, puis on écrase les champs.
        log_obj = Log(data['message'], data['event_type'], data['component'], data['details'], data.get('user', 'Admin'))
        log_obj.log_id = data['log_id']
        # On suppose que le timestamp est déjà un objet datetime si on utilise fromisoformat
        # Mais ici, on lit le dict directement, donc on doit le convertir.
        log_obj.timestamp = datetime.datetime.fromisoformat(data['timestamp'])
        return log_obj

class AlertManager:
    """Gère la création, la consultation et l'acquittement des alertes."""
    def __init__(self, alert_file="alerts.jsonl"):
        self.alert_file = os.path.join(os.path.dirname(__file__), alert_file)
        self.alerts = self._load_alerts()

    def _load_alerts(self, limit=500):
        """Charge les alertes depuis le fichier (limitées aux plus récentes)."""
        alerts = []
        if os.path.exists(self.alert_file):
            try:
                with open(self.alert_file, 'r') as f:
                    # Lire toutes les lignes
                    lines = f.readlines()
                    # Prendre seulement les dernières 'limit' lignes
                    recent_lines = lines[-limit:] if len(lines) > limit else lines
                    
                    for line in recent_lines:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                alerts.append(Alert.from_dict(data))
                            except json.JSONDecodeError as e:
                                print(f"Erreur de décodage JSON dans le fichier d'alertes: {e}")
            except Exception as e:
                print(f"Erreur lors du chargement des alertes: {e}")
        return alerts

    def _save_alerts(self):
        """Sauvegarde toutes les alertes dans le fichier."""
        with open(self.alert_file, 'w') as f:
            for alert in self.alerts:
                f.write(json.dumps(alert.to_dict()) + '\n')

    def generate_alert(self, description, event_type="Intrusion", component="IDS", source_ip=None):
        """Génère et enregistre une nouvelle alerte."""
        new_alert = Alert(description, event_type, component, source_ip)
        self.alerts.append(new_alert)
        self._save_alerts()
        print(f"!!! NOUVELLE ALERTE !!!: {str(new_alert)}")
        return new_alert

    def get_active_alerts(self):
        """Retourne les alertes non acquittées (plus récentes en premier)."""
        # Recharger les alertes depuis le fichier pour s'assurer qu'elles sont à jour
        self.alerts = self._load_alerts()
        active = [alert for alert in self.alerts if not alert.acknowledged]
        return active[::-1]

    def acknowledge_alert(self, alert_id):
        """Acquitte une alerte par son ID."""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                self._save_alerts()
                return True
        return False

    def get_all_alerts(self):
        """Retourne toutes les alertes (plus récentes en premier)."""
        # Recharger les alertes depuis le fichier pour s'assurer qu'elles sont à jour
        self.alerts = self._load_alerts()
        return self.alerts[::-1]
