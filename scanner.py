import nmap
import json
import concurrent.futures
from models import Host
from managers import LogManager

class NetworkScanner:
    """
    Effectue des scans réseau en utilisant la bibliothèque python-nmap.
    Implémente les fonctionnalités 3.1.1 à 3.1.4 avec options avancées.
    
    Fonctionnalités:
    - Détection d'hôtes actifs sur le réseau
    - Scan de ports et détection de services
    - Scan parallèle pour améliorer les performances
    - Support de différentes vitesses de scan (T1-T5)
    - Détection d'OS et de versions de services
    """
    def __init__(self, log_manager: LogManager):
        self.nm = nmap.PortScanner()  # Instance du scanner Nmap
        self.log_manager = log_manager  # Gestionnaire de logs
        self.active_hosts = {}  # Dictionnaire {ip_address: Host object}
        self.current_executor = None  # Exécuteur de threads pour scans parallèles
        self.stop_event = concurrent.futures.Future()  # Flag pour arrêter les scans
        self.stop_requested = False  # Indicateur d'arrêt demandé
        
        # Paramètres de performance configurables
        self.max_threads = 30  # Nombre de threads pour scanner plusieurs hôtes
        self.min_parallelism = 100  # Nombre de probes parallèles Nmap par hôte
        self.min_rate = 300  # Débit minimum en paquets/seconde
        self._load_config()

    def _load_config(self):
        """Charge la configuration du scanner depuis config.json."""
        import os
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    scanner_config = config.get('scanner', {})
                    self.max_threads = scanner_config.get('max_threads', 30)
                    self.min_parallelism = scanner_config.get('min_parallelism', 100)
                    self.min_rate = scanner_config.get('min_rate', 300)
                    self.log_manager.log(
                        f"Configuration du scanner chargée: max_threads={self.max_threads}, min_parallelism={self.min_parallelism}, min_rate={self.min_rate}",
                        event_type="CONFIG_LOADED",
                        component="NetworkScanner"
                    )
            except Exception as e:
                self.log_manager.log(f"Erreur lors du chargement de la configuration du scanner: {e}", event_type="ERROR", component="NetworkScanner")



    def stop_scan(self):
        """
        Arrête le scan en cours.
        
        Utilisé pour interrompre un scan long qui prend trop de temps.
        """
        self.stop_requested = True
        if self.current_executor:
            # Arrêt sans attendre les tâches en attente
            self.current_executor.shutdown(wait=False, cancel_futures=True)
            self.log_manager.log("Demande d'arrêt du scan reçue.", event_type="SCAN_ABORTED", component="NetworkScanner")

    def _log_scan_start(self, scan_type, targets, options=None):
        """Journalise le début d'un scan."""
        details = {"targets": targets, "scan_type": scan_type}
        if options:
            details.update(options)
        
        self.log_manager.log(
            f"Démarrage du scan: {scan_type} sur {targets}",
            event_type="SCAN_START",
            component="NetworkScanner",
            details=details
        )

    def _log_scan_end(self, scan_type, targets, result_count):
        """Journalise la fin d'un scan."""
        self.log_manager.log(
            f"Fin du scan: {scan_type}. {result_count} hôtes traités.",
            event_type="SCAN_END",
            component="NetworkScanner",
            details={"targets": targets, "scan_type": scan_type, "hosts_found": result_count}
        )

    def _build_nmap_arguments(self, scan_type, ports=None, detection='none', speed='T3', scan_method='connect'):
        """
        Construit les arguments Nmap selon les options choisies.
        
        Args:
            scan_type: 'discovery' (découverte d'hôtes), 'ports' (scan de ports), ou 'full' (complet)
            ports: plage de ports (ex: '1-1024', '80,443')
            detection: 'none' (standard), 'services' (détection avancée avec OS et versions)
            speed: 'T1' (lent/furtif), 'T3' (normal), 'T4' (rapide), 'T5' (très rapide)
            scan_method: 'connect' (-sT, compatible Windows) ou 'syn' (-sS, nécessite root)
        
        Returns:
            Chaîne d'arguments Nmap prête à l'emploi
        """
        args = []
        
        # === Type de scan de base et méthode ===
        if scan_type == 'discovery':
            args.append('-sn')  # Ping scan uniquement (pas de scan de ports)
        elif scan_type in ['ports', 'full']:
            if scan_method == 'syn':
                args.append('-sS')  # SYN scan (rapide mais nécessite root)
            else:
                args.append('-sT')  # Connect scan (par défaut, fiable, compatible Windows)
            
        # === Options de détection avancée ===
        if detection == 'services':
            args.append('-sV')  # Détection de version des services
            args.append('-O')   # Détection de l'OS
            args.append('--version-intensity 5')  # Intensité maximale pour la détection
        
        # === Vitesse du scan ===
        args.append(f'-{speed}')  # T1 = lent, T3 = normal, T5 = très rapide
        
        # === Optimisations de performance ===
        # Ces paramètres accélèrent significativement les scans
        if scan_type in ['ports', 'full']:
            args.append(f'--min-rate {self.min_rate}')        # Débit minimum configurable
            args.append('--max-retries 1')                     # Réduire les tentatives (plus rapide)
            args.append('--host-timeout 5m')                   # Timeout de 5 minutes par hôte
            args.append(f'--min-parallelism {self.min_parallelism}')  # Parallélisme configurable
        
        # === Ports spécifiques ===
        if ports and scan_type != 'discovery':
            args.append(f'-p {ports}')
        
        return ' '.join(args)

    def _format_results(self, scan_results, format_type='normal'):
        """
        Formate les résultats selon le type demandé.
        
        Args:
            scan_results: données brutes du scan
            format_type: 'normal', 'detailed', 'json', 'xml'
        """
        if format_type == 'json':
            return json.dumps(scan_results, indent=2)
        elif format_type == 'xml':
            # Nmap peut générer du XML nativement
            return self.nm.get_nmap_last_output()
        elif format_type == 'detailed':
            # Format détaillé avec toutes les informations
            detailed = []
            for host_ip, host_data in scan_results.items():
                detailed.append(f"\n{'='*60}")
                detailed.append(f"Hôte: {host_ip}")
                detailed.append(f"Hostname: {host_data.get('hostname', 'N/A')}")
                detailed.append(f"État: {host_data.get('state', 'N/A')}")
                
                if 'ports' in host_data and host_data['ports']:
                    detailed.append("\nPorts ouverts:")
                    for port, service in host_data['ports'].items():
                        detailed.append(f"  - Port {port}: {service}")
                
                if 'os' in host_data:
                    detailed.append(f"\nOS détecté: {host_data['os']}")
            
            return '\n'.join(detailed)
        else:  # format normal
            return scan_results

    def detect_active_hosts(self, target_range, detection='none', speed='T3', scan_method='connect'):
        """
        Détecte les hôtes actifs sur le réseau (3.1.1).
        
        Effectue un scan de découverte pour identifier les machines
        connectées au réseau. Utilise des threads pour scanner en parallèle.
        
        Args:
            target_range: plage réseau (ex: '192.168.1.0/24')
            detection: niveau de détection ('none' ou 'services')
            speed: vitesse du scan ('T1' à 'T5')
            scan_method: 'connect' ou 'syn'
        
        Returns:
            Dictionnaire des hôtes actifs {ip: Host object}
        """
        options = {'detection': detection, 'speed': speed, 'method': scan_method}
        self._log_scan_start("Host Discovery", target_range, options)
        
        # Log du début du scan parallèle pour la détection d'hôtes
        self.log_manager.log(
            f"Détection d'hôtes avec {self.max_threads} threads sur {target_range}",
            event_type="HOST_DISCOVERY_PARALLEL_START",
            component="NetworkScanner",
            details={'max_threads': self.max_threads, 'target': target_range}
        )
        
        # Diviser le réseau en sous-réseaux pour scan parallèle
        import ipaddress
        try:
            network = ipaddress.ip_network(target_range, strict=False)
            # Diviser en sous-réseaux de /30 (4 IPs par sous-réseau) pour parallélisation
            # Cela permet de scanner plusieurs groupes d'IPs simultanément
            subnets = list(network.subnets(new_prefix=30)) if network.prefixlen < 30 else [network]
            
            self.log_manager.log(
                f"Réseau divisé en {len(subnets)} sous-réseaux pour scan parallèle",
                event_type="NETWORK_SPLIT",
                component="NetworkScanner",
                details={'subnets_count': len(subnets)}
            )
        except ValueError:
            # Si ce n'est pas un réseau valide, scanner directement
            subnets = [target_range]
        
        # Fonction pour scanner un sous-réseau
        def scan_subnet(subnet_range):
            nm = nmap.PortScanner()
            hosts_found = []
            try:
                args = self._build_nmap_arguments('discovery', detection=detection, speed=speed, scan_method=scan_method)
                nm.scan(hosts=str(subnet_range), arguments=args)
                
                for host_ip in nm.all_hosts():
                    if nm[host_ip].state() == 'up':
                        hostname = nm[host_ip].hostname()
                        host = Host(host_ip, hostname)
                        
                        # Si détection avancée, ajouter les infos OS
                        if detection == 'services' and 'osmatch' in nm[host_ip]:
                            os_matches = nm[host_ip]['osmatch']
                            if os_matches:
                                host.os_info = os_matches[0].get('name', 'Unknown')
                        
                        hosts_found.append((host_ip, host))
                        
                        self.log_manager.log(
                            f"Hôte actif détecté: {host_ip} ({hostname})", 
                            event_type="HOST_DETECTED", 
                            component="NetworkScanner"
                        )
            except nmap.PortScannerError as e:
                self.log_manager.log(
                    f"Erreur Nmap lors de la détection d'hôtes sur {subnet_range}: {e}", 
                    event_type="ERROR", 
                    component="NetworkScanner"
                )
            return hosts_found
        
        # Scanner tous les sous-réseaux en parallèle avec ThreadPoolExecutor
        all_hosts = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Soumettre toutes les tâches de scan de sous-réseaux
                future_to_subnet = {executor.submit(scan_subnet, subnet): subnet for subnet in subnets}
                
                completed_count = 0
                total_subnets = len(future_to_subnet)
                
                for future in concurrent.futures.as_completed(future_to_subnet):
                    subnet = future_to_subnet[future]
                    try:
                        hosts = future.result()
                        all_hosts.extend(hosts)
                        completed_count += 1
                        
                        # Log de progression tous les 25% ou à la fin
                        if completed_count % max(1, total_subnets // 4) == 0 or completed_count == total_subnets:
                            self.log_manager.log(
                                f"Progression détection: {completed_count}/{total_subnets} sous-réseaux scannés ({len(all_hosts)} hôtes trouvés)",
                                event_type="HOST_DISCOVERY_PROGRESS",
                                component="NetworkScanner",
                                details={'completed': completed_count, 'total': total_subnets, 'hosts_found': len(all_hosts)}
                            )
                    except Exception as exc:
                        self.log_manager.log(f"Erreur lors du scan de {subnet}: {exc}", event_type="ERROR", component="NetworkScanner")
        except Exception as e:
            self.log_manager.log(
                f"Erreur lors du scan parallèle de détection d'hôtes: {e}", 
                event_type="ERROR", 
                component="NetworkScanner"
            )
            return {}
        
        # Enregistrer tous les hôtes trouvés
        for host_ip, host in all_hosts:
            self.active_hosts[host_ip] = host
        
        hosts_found = len(all_hosts)
        self.log_manager.log(
            f"Détection d'hôtes terminée: {hosts_found} hôtes trouvés avec {self.max_threads} threads",
            event_type="HOST_DISCOVERY_PARALLEL_END",
            component="NetworkScanner",
            details={'hosts_found': hosts_found, 'threads': self.max_threads}
        )
        
        self._log_scan_end("Host Discovery", target_range, hosts_found)
        return self.active_hosts


    def scan_ports_and_services(self, host_ip, ports='1-1024', detection='none', speed='T3', scan_method='connect'):
        """
        Détecte les ports ouverts et les services/versions (3.1.2, 3.1.3).
        Optimisé avec une seule commande Nmap qui utilise ses propres optimisations internes.
        
        Args:
            host_ip: adresse IP de l'hôte
            ports: plage de ports (ex: '1-1024', '80,443,8080')
            detection: niveau de détection ('none' ou 'services')
            speed: vitesse du scan ('T1' à 'T5')
            scan_method: 'connect' ou 'syn'
        """
        options = {'ports': ports, 'detection': detection, 'speed': speed, 'method': scan_method}
        self._log_scan_start("Port/Service Scan", host_ip, options)
        
        # Scanner tous les ports en une seule commande Nmap optimisée
        # Nmap gère déjà la parallélisation en interne de manière optimale
        all_ports = {}
        
        try:
            # Construire les arguments Nmap avec optimisations
            args = self._build_nmap_arguments('ports', ports=ports, detection=detection, speed=speed, scan_method=scan_method)
            
            self.log_manager.log(
                f"Scan de ports sur {host_ip} avec arguments optimisés: {args}",
                event_type="PORT_SCAN_START",
                component="NetworkScanner",
                details={'host': host_ip, 'ports': ports, 'args': args}
            )
            
            # Exécuter le scan Nmap
            self.nm.scan(hosts=host_ip, arguments=args)
            
            # Collecter les résultats
            if host_ip in self.nm.all_hosts() and 'tcp' in self.nm[host_ip]:
                for port, data in self.nm[host_ip]['tcp'].items():
                    if data['state'] == 'open':
                        service = data.get('name', 'unknown')
                        version = data.get('version', 'N/A')
                        product = data.get('product', '')
                        
                        # Format différent selon le niveau de détection
                        if detection == 'services':
                            service_info = f"{service} {product} {version}".strip()
                        else:
                            service_info = service
                        
                        all_ports[port] = service_info
                        
                        self.log_manager.log(
                            f"Port ouvert détecté sur {host_ip}: {port}/tcp - Service: {service_info}",
                            event_type="PORT_OPEN",
                            component="NetworkScanner",
                            details={"ip": host_ip, "port": port, "service": service, "version": version}
                        )
            
            # Mettre à jour l'hôte avec les ports trouvés
            if host_ip not in self.active_hosts:
                self.active_hosts[host_ip] = Host(host_ip, "")
            
            host = self.active_hosts[host_ip]
            host.ports.update(all_ports)
            
            self.log_manager.log(
                f"Scan de ports terminé sur {host_ip}: {len(all_ports)} ports ouverts trouvés (scan optimisé)",
                event_type="PORT_SCAN_END",
                component="NetworkScanner",
                details={'host': host_ip, 'open_ports': len(all_ports)}
            )
            
        except nmap.PortScannerError as e:
            self.log_manager.log(
                f"Erreur Nmap lors du scan de {host_ip}: {e}",
                event_type="ERROR",
                component="NetworkScanner"
            )
        except Exception as e:
            self.log_manager.log(
                f"Erreur lors du scan de ports sur {host_ip}: {e}",
                event_type="ERROR",
                component="NetworkScanner"
            )
        
        self._log_scan_end("Port/Service Scan", host_ip, len(all_ports))
        return all_ports


    def perform_full_network_scan(self, target_range, ports='1-100', detection='none', 
                                   speed='T3', output_format='normal', scan_method='connect'):
        """
        Effectue un scan complet du réseau (3.1.4).
        Détecte les hôtes actifs, puis scanne les ports et services sur chacun.
        
        Args:
            target_range: plage réseau (ex: '192.168.1.0/24')
            ports: plage de ports à scanner
            detection: niveau de détection ('none' ou 'services')
            speed: vitesse du scan ('T1' à 'T5')
            output_format: format de sortie ('normal', 'detailed', 'json', 'xml')
            scan_method: 'connect' ou 'syn'
        """
        options = {
            'ports': ports,
            'detection': detection,
            'speed': speed,
            'format': output_format,
            'method': scan_method
        }
        
        self.log_manager.log(
            f"Démarrage du scan réseau complet sur {target_range}", 
            event_type="FULL_SCAN_START", 
            component="NetworkScanner",
            details=options
        )
        
        # 1. Détection des hôtes actifs
        active_hosts = self.detect_active_hosts(target_range, detection=detection, speed=speed, scan_method=scan_method)
        
        if not active_hosts:
            self.log_manager.log(
                "Aucun hôte actif trouvé.", 
                event_type="FULL_SCAN_END", 
                component="NetworkScanner"
            )
            return self._format_results({}, output_format)

        # === 2. Scan de ports et services sur chaque hôte actif (PARALLÈLE) ===
        # Utilisation de ThreadPoolExecutor pour scanner plusieurs hôtes simultanément
        # Cela améliore considérablement les performances pour les réseaux avec plusieurs hôtes
        scan_results = {}
        self.stop_requested = False
        
        # Log du nombre de threads qui seront utilisés
        self.log_manager.log(
            f"Démarrage du scan parallèle avec {self.max_threads} threads pour {len(active_hosts)} hôtes",
            event_type="PARALLEL_SCAN_START",
            component="NetworkScanner",
            details={'max_threads': self.max_threads, 'hosts_count': len(active_hosts)}
        )
        
        # Configuration de l'exécuteur avec le nombre de threads configurable
        try:
            self.current_executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads)
            with self.current_executor as executor:
                # Soumission de toutes les tâches de scan
                future_to_ip = {}
                for ip in active_hosts:
                    if self.stop_requested:
                        break
                    # Création d'une tâche de scan pour chaque hôte
                    future_to_ip[executor.submit(self.scan_ports_and_services, ip, ports, detection, speed, scan_method)] = ip
                
                # Compteur pour suivre la progression
                completed_count = 0
                total_hosts = len(future_to_ip)
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if self.stop_requested:
                        break
                    ip = future_to_ip[future]
                    try:
                        future.result()
                        completed_count += 1
                        
                        # Log de progression tous les 10 hôtes
                        if completed_count % 10 == 0 or completed_count == total_hosts:
                            self.log_manager.log(
                                f"Progression du scan: {completed_count}/{total_hosts} hôtes scannés ({self.max_threads} threads actifs)",
                                event_type="SCAN_PROGRESS",
                                component="NetworkScanner",
                                details={'completed': completed_count, 'total': total_hosts, 'threads': self.max_threads}
                            )
                    except concurrent.futures.CancelledError:
                        pass # Scan was cancelled
                    except Exception as exc:
                        self.log_manager.log(f"Scan generated an exception for {ip}: {exc}", event_type="ERROR", component="NetworkScanner")
        finally:
            self.current_executor = None
            self.log_manager.log(
                f"Scan parallèle terminé ({self.max_threads} threads utilisés)",
                event_type="PARALLEL_SCAN_END",
                component="NetworkScanner"
            )


        if self.stop_requested:
            self.log_manager.log("Scan complet arrêté par l'utilisateur.", event_type="SCAN_ABORTED", component="NetworkScanner")
            
            # But active_hosts might be partially updated.


        # Collect results
        for ip, host in active_hosts.items():
            scan_results[ip] = {
                'hostname': host.hostname,
                'state': 'up',
                'ports': host.ports,
                'os': getattr(host, 'os_info', 'N/A')
            }

        self.log_manager.log(
            f"Scan réseau complet terminé. {len(self.active_hosts)} hôtes traités.", 
            event_type="FULL_SCAN_END", 
            component="NetworkScanner"
        )
        
        # 3. Formater et retourner les résultats
        formatted_results = self._format_results(scan_results, output_format)
        
        # Enregistrer les résultats formatés dans les logs
        self.log_manager.log(
            "Résultats du scan complet générés",
            event_type="SCAN_RESULTS",
            component="NetworkScanner",
            details={'format': output_format, 'hosts_count': len(scan_results)}
        )
        
        return formatted_results

    def get_active_hosts(self):
        """Retourne la liste des objets Host actifs."""
        return list(self.active_hosts.values())

    def export_scan_results(self, output_format='json', filename=None):
        """
        Exporte les résultats du dernier scan dans un fichier.
        
        Args:
            output_format: format d'export ('json', 'xml', 'txt')
            filename: nom du fichier de sortie (optionnel)
        """
        if not self.active_hosts:
            self.log_manager.log(
                "Aucun résultat à exporter",
                event_type="EXPORT_ERROR",
                component="NetworkScanner"
            )
            return None
        
        # Préparer les données
        scan_results = {}
        for ip, host in self.active_hosts.items():
            scan_results[ip] = {
                'hostname': host.hostname,
                'state': 'up',
                'ports': host.ports,
                'os': getattr(host, 'os_info', 'N/A')
            }
        
        # Formater
        formatted_data = self._format_results(scan_results, output_format)
        
        # Enregistrer dans un fichier si demandé
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(str(formatted_data))
                
                self.log_manager.log(
                    f"Résultats exportés vers {filename}",
                    event_type="EXPORT_SUCCESS",
                    component="NetworkScanner"
                )
                return filename
            except Exception as e:
                self.log_manager.log(
                    f"Erreur lors de l'export: {e}",
                    event_type="EXPORT_ERROR",
                    component="NetworkScanner"
                )
                return None
        
        return formatted_data