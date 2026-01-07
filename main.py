import os
import sys
import time
from managers import LogManager, AlertManager
from scanner import NetworkScanner
from ids import IDS
from utils import visualize_alerts_by_type, visualize_traffic_volume

# Assurez-vous que le répertoire courant est le répertoire du projet pour les imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class SecurityAdmin:
    """
    Classe principale pour l'administration du système de sécurité réseau.
    Implémente la logique de gestion et l'interface utilisateur (3.3, 3.5).
    """
    def __init__(self):
        self.log_manager = LogManager()
        self.alert_manager = AlertManager()
        self.scanner = NetworkScanner(self.log_manager)
        self.ids = IDS(self.alert_manager, self.log_manager)
        self.log_manager.log("Système SecurityAdmin initialisé.", component="SecurityAdmin")

    def _display_menu(self):
        """Affiche le menu principal."""
        print("\n" + "="*50)
        print("  PYTHON NETWORK SECURITY MONITOR (SecurityAdmin)")
        print("="*50)
        print("1. Scan Réseau (Nmap)")
        print("2. Démarrer/Arrêter IDS (Surveillance)")
        print("3. Consulter les Hôtes Actifs")
        print("4. Consulter les Alertes")
        print("5. Consulter les Logs")
        print("6. Visualiser les Événements (Graphiques)")
        print("7. Quitter")
        print("="*50)

    def _handle_scan_menu(self):
        """Gère les options de scan réseau."""
        print("\n--- Menu Scan Réseau ---")
        print("1. Scan Complet du Réseau (Découverte + Ports/Services)")
        print("2. Scan de Ports/Services sur un Hôte Spécifique")
        print("3. Retour au Menu Principal")
        
        choice = input("Votre choix: ")
        
        if choice == '1':
            target = input("Entrez la plage réseau à scanner (ex: 192.168.1.0/24): ")
            ports = input("Entrez la plage de ports à scanner (ex: 1-100, ou laissez vide pour 1-100): ") or '1-100'
            self.scanner.perform_full_network_scan(target, ports)
        elif choice == '2':
            host_ip = input("Entrez l'adresse IP de l'hôte à scanner: ")
            ports = input("Entrez la plage de ports à scanner (ex: 1-1024): ")
            self.scanner.scan_ports_and_services(host_ip, ports)
        elif choice == '3':
            return
        else:
            print("Choix invalide.")

    def _handle_ids_menu(self):
        """Gère le démarrage et l'arrêt de l'IDS."""
        if self.ids.is_monitoring():
            print(f"L'IDS est actuellement en cours d'exécution. Arrêt en cours...")
            self.ids.stop_monitoring()
        else:
            interface = input("Entrez l'interface réseau à surveiller (ex: eth0, ou laissez vide pour auto): ") or None
            print(f"Démarrage de l'IDS sur l'interface {interface}...")
            if self.ids.start_monitoring(interface):
                print("IDS démarré avec succès. Il tourne en arrière-plan.")
            else:
                print("L'IDS n'a pas pu démarrer (peut-être déjà en cours).")

    def _handle_host_display(self):
        """Affiche les hôtes actifs."""
        hosts = self.scanner.get_active_hosts()
        if not hosts:
            print("Aucun hôte actif n'a été enregistré. Veuillez effectuer un scan d'abord.")
            return

        print("\n--- Hôtes Actifs Détectés ---")
        for host in hosts:
            print(f"  IP: {host.ip_address} | Nom: {host.hostname} | Actif: {host.is_active}")
            if host.ports:
                print("    Ports ouverts:")
                for port, service in host.ports.items():
                    print(f"      - {port}: {service}")
        print("-" * 30)

    def _handle_alert_display(self):
        """Affiche et gère les alertes."""
        alerts = self.alert_manager.get_all_alerts()
        active_alerts = self.alert_manager.get_active_alerts()

        print("\n--- Gestion des Alertes ---")
        print(f"Total Alertes: {len(alerts)} | Alertes Actives (Non Acquittées): {len(active_alerts)}")
        
        if not alerts:
            print("Aucune alerte enregistrée.")
            return

        for i, alert in enumerate(alerts):
            status = "[ACTIF]" if not alert.acknowledged else "[ACQUITTÉ]"
            print(f"[{i+1}] {status} {str(alert)}")

        if active_alerts:
            action = input("\nVoulez-vous acquitter une alerte ? (Entrez le numéro ou 'n' pour non): ")
            if action.lower() != 'n' and action.isdigit():
                try:
                    index = int(action) - 1
                    if 0 <= index < len(alerts):
                        alert_to_ack = alerts[index]
                        if not alert_to_ack.acknowledged:
                            if self.alert_manager.acknowledge_alert(alert_to_ack.id):
                                print(f"Alerte {alert_to_ack.id[:8]} acquittée.")
                                self.log_manager.log(f"Alerte acquittée par l'administrateur: {alert_to_ack.id[:8]}", event_type="ALERT_ACK", component="SecurityAdmin")
                            else:
                                print("Erreur lors de l'acquittement.")
                        else:
                            print("Cette alerte est déjà acquittée.")
                    else:
                        print("Numéro d'alerte invalide.")
                except Exception as e:
                    print(f"Erreur: {e}")

    def _handle_log_display(self):
        """Affiche les derniers logs."""
        logs = self.log_manager.get_logs(limit=20)
        print("\n--- Derniers 20 Logs ---")
        for log_data in reversed(logs): # Afficher du plus ancien au plus récent
            log = self.log_manager.log_from_dict(log_data) # Nécessite une méthode dans LogManager pour reconstruire Log
            print(log)
        print("-" * 30)

    def _handle_visualization(self):
        """Gère la génération de visualisations."""
        print("\n--- Menu Visualisation ---")
        print("1. Alertes par Type d'Événement")
        print("2. Volume de Trafic par Hôte (IDS)")
        print("3. Retour au Menu Principal")

        choice = input("Votre choix: ")

        if choice == '1':
            alerts = self.alert_manager.get_all_alerts()
            visualize_alerts_by_type(alerts)
        elif choice == '2':
            traffic_volume = self.ids.get_traffic_stats()
            visualize_traffic_volume(traffic_volume)
        elif choice == '3':
            return
        else:
            print("Choix invalide.")

    def run(self):
        """Boucle principale de l'application."""
        while True:
            self._display_menu()
            choice = input("Entrez votre choix (1-7): ")

            if choice == '1':
                self._handle_scan_menu()
            elif choice == '2':
                self._handle_ids_menu()
            elif choice == '3':
                self._handle_host_display()
            elif choice == '4':
                self._handle_alert_display()
            elif choice == '5':
                # Note: LogManager n'a pas de méthode log_from_dict, on va juste lire le fichier pour l'instant
                # Une implémentation plus robuste serait nécessaire pour une vraie application.
                print("\n--- Logs (Lecture directe du fichier) ---")
                try:
                    with open(self.log_manager.log_file, 'r') as f:
                        lines = f.readlines()
                        for line in lines[-20:]: # Afficher les 20 dernières lignes
                            print(line.strip())
                except FileNotFoundError:
                    print("Fichier de logs non trouvé.")
                print("-" * 30)
            elif choice == '6':
                self._handle_visualization()
            elif choice == '7':
                print("Arrêt du système...")
                self.ids.stop_monitoring()
                self.log_manager.log("Système SecurityAdmin arrêté.", component="SecurityAdmin")
                break
            else:
                print("Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    # Nécessite d'ajouter une méthode de reconstruction dans LogManager pour la consultation des logs
    # Ajoutons une méthode temporaire pour la démo
    def log_from_dict(self, data):
        return str(Log(data['message'], data['event_type'], data['component'], data['details'], data['user']))
    
    # Patching temporaire de LogManager pour la démo
    setattr(LogManager, 'log_from_dict', log_from_dict)

    # L'exécution de Scapy (utilisé dans IDS) nécessite des privilèges root pour sniffer le trafic.
    # Dans un environnement de sandbox, nous ne pouvons pas garantir les privilèges root pour l'exécution de Scapy.
    # Nous allons donc exécuter l'application principale.
    
    # Pour que l'IDS fonctionne correctement, l'utilisateur devra exécuter le script avec sudo
    # Exemple: sudo python3 main.py
    
    # Pour la démonstration dans la sandbox, nous allons exécuter sans sudo,
    # mais nous allons informer l'utilisateur de la limitation.
    
    try:
        app = SecurityAdmin()
        app.run()
    except Exception as e:
        print(f"\nUne erreur critique est survenue: {e}")
        print("Veuillez noter que l'IDS (surveillance du trafic) nécessite des privilèges root (sudo) pour fonctionner correctement.")
        print("Le scan Nmap peut également nécessiter des privilèges root pour certains types de scan.")
        print("Exécutez le script avec 'sudo python3 main.py' pour une fonctionnalité complète.")
