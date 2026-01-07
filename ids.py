from scapy.all import sniff, IP, TCP, UDP
from managers import AlertManager, LogManager
import threading
import time

class IDS:
    """
    Système de Détection d'Intrusion (IDS) pour la surveillance du trafic réseau.
    Implémente les fonctionnalités 3.2.1 à 3.2.4.
    """
    def __init__(self, alert_manager: AlertManager, log_manager: LogManager):
        self.alert_manager = alert_manager
        self.log_manager = log_manager
        self._monitoring_thread = None
        self._stop_event = threading.Event()
        self.port_scan_attempts = {} # {ip_src: {port: count}}
        self.traffic_volume = {} # {ip_src: bytes_count}
        self.volume_threshold = 1000000 # 1MB de trafic comme seuil simple pour DoS

    def _analyze_packet(self, packet):
        """Analyse un paquet pour détecter des activités suspectes."""
        
        # 1. Journalisation du trafic (3.2.2 - simple)
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Mise à jour du volume de trafic (3.2.4)
            packet_size = len(packet)
            self.traffic_volume[ip_src] = self.traffic_volume.get(ip_src, 0) + packet_size
            
            # Détection de DoS simple (3.2.4)
            if self.traffic_volume[ip_src] > self.volume_threshold:
                self.alert_manager.generate_alert(
                    f"Possible attaque DoS simple détectée de {ip_src}. Volume de trafic: {self.traffic_volume[ip_src]} bytes.",
                    event_type="DoS_Simple",
                    component="IDS"
                )
                # Réinitialiser pour éviter les alertes répétitives immédiates
                self.traffic_volume[ip_src] = 0 

            # 2. Détection de scan de ports (3.2.1)
            if TCP in packet:
                if packet[TCP].flags == 'S': # SYN packet - début de connexion
                    self._detect_port_scan(ip_src, packet[TCP].dport)
            
            # Journalisation (simplifiée pour éviter un journal trop volumineux)
            # self.log_manager.log(f"Trafic: {ip_src} -> {ip_dst}", event_type="TRAFFIC", component="IDS")

    def _detect_port_scan(self, ip_src, port_dst):
        """Logique de détection de scan de ports."""
        
        # Initialisation pour l'IP source
        if ip_src not in self.port_scan_attempts:
            self.port_scan_attempts[ip_src] = {}
        
        # Initialisation pour le port de destination
        if port_dst not in self.port_scan_attempts[ip_src]:
            self.port_scan_attempts[ip_src][port_dst] = 0
        
        self.port_scan_attempts[ip_src][port_dst] += 1
        
        # Seuil simple: si une IP tente de se connecter à plus de 5 ports différents en peu de temps
        if len(self.port_scan_attempts[ip_src]) > 5:
            self.alert_manager.generate_alert(
                f"Scan de ports suspect détecté de {ip_src}. Tentatives sur {len(self.port_scan_attempts[ip_src])} ports.",
                event_type="Port_Scan",
                component="IDS"
            )
            # Réinitialiser après alerte
            self.port_scan_attempts[ip_src] = {}

    def _sniff_loop(self, interface=None):
        """Boucle de sniffer de paquets."""
        self.log_manager.log("Démarrage de la surveillance du trafic réseau (IDS).", event_type="IDS_START", component="IDS")
        try:
            # Utilisation de store=0 pour ne pas stocker les paquets en mémoire
            sniff(prn=self._analyze_packet, stop_filter=lambda x: self._stop_event.is_set(), iface=interface, store=0)
        except Exception as e:
            self.log_manager.log(f"Erreur critique lors du sniffing: {e}", event_type="ERROR", component="IDS")
        finally:
            self.log_manager.log("Arrêt de la surveillance du trafic réseau (IDS).", event_type="IDS_STOP", component="IDS")

    def start_monitoring(self, interface=None):
        """Démarre la surveillance dans un thread séparé."""
        if self._monitoring_thread is None or not self._monitoring_thread.is_alive():
            self._stop_event.clear()
            self._monitoring_thread = threading.Thread(target=self._sniff_loop, args=(interface,))
            self._monitoring_thread.daemon = True
            self._monitoring_thread.start()
            return True
        return False

    def stop_monitoring(self):
        """Arrête la surveillance."""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._stop_event.set()
            # Donner un peu de temps au thread pour s'arrêter
            time.sleep(1) 
            return True
        return False

    def is_monitoring(self):
        """Vérifie si l'IDS est en cours d'exécution."""
        return self._monitoring_thread is not None and self._monitoring_thread.is_alive()

    def get_traffic_stats(self):
        """Retourne les statistiques de volume de trafic."""
        return self.traffic_volume
