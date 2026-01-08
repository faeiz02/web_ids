from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from managers import AlertManager, LogManager
import threading
import time
import json
import re
import os
from urllib.parse import unquote

class IDS:
    """
    Système de Détection d'Intrusion (IDS) pour la surveillance du trafic réseau.
    Implémente les fonctionnalités 3.2.1 à 3.2.4.
    
    Ce système analyse le trafic réseau en temps réel pour détecter:
    - Les scans de ports suspects
    - Les attaques par signature (SQL injection, XSS, etc.)
    - Les tentatives de brute force SSH
    - Les attaques DoS/DDoS
    - Les floods ICMP
    """
    def __init__(self, alert_manager: AlertManager, log_manager: LogManager):
        # Gestionnaires pour les alertes et les logs
        self.alert_manager = alert_manager
        self.log_manager = log_manager
        
        # Thread de surveillance et événement d'arrêt
        self._monitoring_thread = None
        self._stop_event = threading.Event()
        
        # Dictionnaires de suivi des tentatives d'attaque par IP source
        self.port_scan_attempts = {}  # {ip_src: {port: count}} - Suivi des scans de ports
        self.traffic_volume = {}      # {ip_src: bytes_count} - Volume de trafic par IP
        self.ssh_attempts = {}        # {ip_src: count} - Tentatives de connexion SSH
        self.icmp_packets = {}        # {ip_src: count} - Nombre de paquets ICMP
        
        # Seuil de détection DoS: 10MB de trafic par IP
        self.volume_threshold = 10000000
        
        # Chargement des signatures d'attaques depuis le fichier JSON
        self.signatures = self._load_signatures()

    def _load_signatures(self, filepath="signatures.json"):
        """Charge les signatures d'attaques depuis un fichier JSON."""
        filepath = os.path.join(os.path.dirname(__file__), filepath)
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.log_manager.log(f"Erreur lors du chargement des signatures: {e}", event_type="ERROR", component="IDS")
        return []

    def _analyze_packet(self, packet):
        """
        Analyse un paquet réseau pour détecter des activités suspectes.
        
        Cette méthode est appelée pour chaque paquet capturé et effectue:
        1. Le suivi du volume de trafic par IP
        2. La détection de scans de ports (paquets SYN)
        3. La détection par signatures (SQL injection, XSS, etc.)
        4. La détection de brute force SSH
        5. La détection de floods ICMP
        """
        
        # === ANALYSE DES PAQUETS IP ===
        if IP in packet:
            ip_src = packet[IP].src  # Adresse IP source
            ip_dst = packet[IP].dst  # Adresse IP destination
            
            # --- Suivi du volume de trafic par IP source ---
            # Permet de détecter les attaques DoS basées sur le volume
            packet_size = len(packet)
            self.traffic_volume[ip_src] = self.traffic_volume.get(ip_src, 0) + packet_size
            
            # --- Détection d'attaque DoS simple ---
            # Si une IP dépasse le seuil de volume (10MB), on génère une alerte
            if self.traffic_volume[ip_src] > self.volume_threshold:
                self.alert_manager.generate_alert(
                    f"Possible attaque DoS simple détectée de {ip_src}. Volume de trafic: {self.traffic_volume[ip_src]} bytes.",
                    event_type="DoS_Simple",
                    component="IDS",
                    source_ip=ip_src
                )
                # Réinitialisation du compteur pour éviter les alertes répétitives
                self.traffic_volume[ip_src] = 0 

            # === ANALYSE DES PAQUETS TCP ===
            if TCP in packet:
                src_port = packet[TCP].sport  # Port source
                dst_port = packet[TCP].dport  # Port destination
                
                # DEBUG: Affichage du trafic TCP pour le débogage
                print(f"[DEBUG] TCP Packet: {ip_src}:{src_port} -> {packet[IP].dst}:{dst_port}")

                # --- Détection de scan de ports ---
                # Les paquets SYN (flag 'S') indiquent une tentative de connexion
                if packet[TCP].flags == 'S':
                    self._detect_port_scan(ip_src, dst_port)
                    
                    # Détection spécifique pour SSH brute force (port 22)
                    if dst_port == 22:
                        self._detect_ssh_bruteforce(ip_src)
                
                # --- Détection par signature dans le payload TCP ---
                # Recherche de patterns d'attaques (SQL injection, XSS, etc.)
                if packet.haslayer(Raw):
                    try:
                        # Décodage du payload en UTF-8
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        # Décodage URL pour détecter les payloads encodés
                        decoded_payload = unquote(payload)
                        # Vérification des signatures avec ports source et destination
                        self._check_signatures(decoded_payload, ip_src, src_port, dst_port, "TCP")
                    except Exception as e:
                        print(f"[DEBUG] Erreur analyse: {e}")
                        pass 

            # === ANALYSE DES PAQUETS UDP ===
            if UDP in packet:
                src_port = packet[UDP].sport  # Port source UDP
                dst_port = packet[UDP].dport  # Port destination UDP
                
                # --- Détection par signature dans le payload UDP ---
                # Utile pour détecter les beacons C2 et autres attaques UDP
                if packet.haslayer(Raw):
                    try:
                        # Décodage du payload UDP
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        decoded_payload = unquote(payload)
                        # Vérification des signatures UDP
                        self._check_signatures(decoded_payload, ip_src, src_port, dst_port, "UDP")
                    except Exception as e:
                        # Ignorer les erreurs de décodage
                        pass 

            # === ANALYSE DES PAQUETS ICMP ===
            # Détection des attaques par flood ICMP (ping flood)
            if ICMP in packet:
                self._detect_icmp_flood(ip_src)

            # Note: La journalisation de chaque paquet est désactivée pour éviter
            # un fichier de logs trop volumineux. Seuls les événements importants sont loggés.

    def _check_signatures(self, payload, ip_src, src_port, dst_port, protocol):
        """
        Vérifie si le payload correspond à une signature d'attaque connue.
        
        Les signatures sont chargées depuis signatures.json et contiennent:
        - pattern: expression régulière à rechercher
        - port: port spécifique à surveiller (optionnel)
        - protocol: TCP ou UDP (optionnel)
        - severity: niveau de gravité (HIGH, MEDIUM, LOW)
        """
        for sig in self.signatures:
            # --- Filtrage par port ---
            # Si une signature spécifie un port, on vérifie qu'il correspond
            # au port source OU destination
            if sig.get('port'):
                if sig['port'] != src_port and sig['port'] != dst_port:
                    continue  # Passer à la signature suivante
                
            # --- Filtrage par protocole ---
            # Vérifier que le protocole correspond (TCP ou UDP)
            if sig.get('protocol') and sig['protocol'].upper() != protocol:
                continue  # Passer à la signature suivante
                
            # --- Recherche du pattern dans le payload ---
            # Utilisation d'une regex insensible à la casse
            if re.search(sig['pattern'], payload, re.IGNORECASE):
                print(f"[DEBUG] !! MATCH SIGNATURE !! {sig['name']}")
                self.alert_manager.generate_alert(
                    f"Attaque détectée: {sig['name']} depuis {ip_src}. Pattern: {sig['pattern']}",
                    event_type=f"Signature_Match_{sig['severity']}",
                    component="IDS",
                    source_ip=ip_src
                )
                break

    def _detect_port_scan(self, ip_src, port_dst):
        """
        Détecte les scans de ports suspects.
        
        Un scan de ports est détecté lorsqu'une IP tente de se connecter
        à plusieurs ports différents en peu de temps.
        Seuil actuel: plus de 5 ports différents = alerte
        """
        
        # Initialisation du dictionnaire pour cette IP si nécessaire
        if ip_src not in self.port_scan_attempts:
            self.port_scan_attempts[ip_src] = {}
        
        # Initialisation du compteur pour ce port si nécessaire
        if port_dst not in self.port_scan_attempts[ip_src]:
            self.port_scan_attempts[ip_src][port_dst] = 0
        
        # Incrémenter le compteur de tentatives pour ce port
        self.port_scan_attempts[ip_src][port_dst] += 1
        
        # --- Détection du scan ---
        # Si l'IP a tenté de se connecter à plus de 5 ports différents
        if len(self.port_scan_attempts[ip_src]) > 5:
            self.alert_manager.generate_alert(
                f"Scan de ports suspect détecté de {ip_src}. Tentatives sur {len(self.port_scan_attempts[ip_src])} ports.",
                event_type="Port_Scan",
                component="IDS",
                source_ip=ip_src
            )
            # Réinitialiser après alerte
            self.port_scan_attempts[ip_src] = {}

    def _detect_ssh_bruteforce(self, ip_src):
        """
        Détecte les tentatives de brute force SSH.
        
        Une attaque brute force SSH est détectée lorsqu'une IP effectue
        plusieurs tentatives de connexion SSH en peu de temps.
        Seuil actuel: plus de 5 tentatives = alerte
        """
        
        # Initialisation du compteur pour cette IP si nécessaire
        if ip_src not in self.ssh_attempts:
            self.ssh_attempts[ip_src] = 0
        
        # Incrémenter le compteur de tentatives SSH
        self.ssh_attempts[ip_src] += 1
        
        # --- Détection du brute force ---
        # Si l'IP a effectué plus de 5 tentatives de connexion SSH
        if self.ssh_attempts[ip_src] > 5:
            self.alert_manager.generate_alert(
                f"Attaque SSH Brute Force détectée de {ip_src}. {self.ssh_attempts[ip_src]} tentatives de connexion.",
                event_type="SSH_Brute_Force",
                component="IDS",
                source_ip=ip_src
            )
            # Réinitialiser après alerte
            self.ssh_attempts[ip_src] = 0

    def _detect_icmp_flood(self, ip_src):
        """
        Détecte les attaques ICMP flood (ping flood).
        
        Une attaque ICMP flood est détectée lorsqu'une IP envoie
        un grand nombre de paquets ICMP (ping) en peu de temps.
        Seuil actuel: plus de 50 paquets ICMP = alerte
        """
        
        # Initialisation du compteur pour cette IP si nécessaire
        if ip_src not in self.icmp_packets:
            self.icmp_packets[ip_src] = 0
        
        # Incrémenter le compteur de paquets ICMP
        self.icmp_packets[ip_src] += 1
        
        # --- Détection du flood ICMP ---
        # Si l'IP a envoyé plus de 50 paquets ICMP
        if self.icmp_packets[ip_src] > 50:
            self.alert_manager.generate_alert(
                f"Attaque ICMP Flood détectée de {ip_src}. {self.icmp_packets[ip_src]} paquets ICMP reçus.",
                event_type="ICMP_Flood",
                component="IDS",
                source_ip=ip_src
            )
            # Réinitialiser après alerte
            self.icmp_packets[ip_src] = 0

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
