import nmap
import json
import concurrent.futures
from models import Host
from managers import LogManager

class NetworkScanner:
    """
    Effectue des scans réseau en utilisant la bibliothèque python-nmap.
    Implémente les fonctionnalités 3.1.1 à 3.1.4 avec options avancées.
    """
    def __init__(self, log_manager: LogManager):
        self.nm = nmap.PortScanner()
        self.log_manager = log_manager
        self.active_hosts = {} # {ip_address: Host object}
        self.current_executor = None
        self.stop_event = concurrent.futures.Future() # Using a Future as a flag or simple Event wrapper
        self.stop_requested = False

    def stop_scan(self):
        """Arrête le scan en cours."""
        self.stop_requested = True
        if self.current_executor:
            # Shutdown without waiting for pending futures
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
            scan_type: 'discovery', 'ports', ou 'full'
            ports: plage de ports (ex: '1-1024', '80,443')
            detection: 'none' (standard), 'services' (détection avancée)
            speed: 'T1' (lent), 'T3' (normal), 'T4' (rapide), 'T5' (très rapide)
            scan_method: 'connect' (-sT) ou 'syn' (-sS)
        """
        args = []
        
        # Type de scan de base et méthode
        if scan_type == 'discovery':
            args.append('-sn')  # Ping scan uniquement
        elif scan_type in ['ports', 'full']:
            if scan_method == 'syn':
                args.append('-sS')  # SYN scan (root required)
            else:
                args.append('-sT')  # Connect scan (default, reliable)
            
        # Options de détection
        if detection == 'services':
            args.append('-sV')  # Détection de version des services
            args.append('-O')   # Détection de l'OS
            args.append('--version-intensity 5')  # Intensité maximale
        
        # Vitesse du scan
        args.append(f'-{speed}')
        
        # Ports spécifiques
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
        
        Args:
            target_range: plage réseau (ex: '192.168.1.0/24')
            detection: niveau de détection ('none' ou 'services')
            speed: vitesse du scan ('T1' à 'T5')
            scan_method: 'connect' ou 'syn'
        """
        options = {'detection': detection, 'speed': speed, 'method': scan_method}
        self._log_scan_start("Host Discovery", target_range, options)
        
        try:
            args = self._build_nmap_arguments('discovery', detection=detection, speed=speed, scan_method=scan_method)
            self.nm.scan(hosts=target_range, arguments=args)
        except nmap.PortScannerError as e:
            self.log_manager.log(
                f"Erreur Nmap lors de la détection d'hôtes: {e}", 
                event_type="ERROR", 
                component="NetworkScanner"
            )
            return {}

        hosts_found = 0
        for host_ip in self.nm.all_hosts():
            if self.nm[host_ip].state() == 'up':
                hostname = self.nm[host_ip].hostname()
                host = Host(host_ip, hostname)
                
                # Si détection avancée, ajouter les infos OS
                if detection == 'services' and 'osmatch' in self.nm[host_ip]:
                    os_matches = self.nm[host_ip]['osmatch']
                    if os_matches:
                        host.os_info = os_matches[0].get('name', 'Unknown')
                
                self.active_hosts[host_ip] = host
                hosts_found += 1
                
                self.log_manager.log(
                    f"Hôte actif détecté: {host_ip} ({hostname})", 
                    event_type="HOST_DETECTED", 
                    component="NetworkScanner"
                )

        self._log_scan_end("Host Discovery", target_range, hosts_found)
        return self.active_hosts

    def scan_ports_and_services(self, host_ip, ports='1-1024', detection='none', speed='T3', scan_method='connect'):
        """
        Détecte les ports ouverts et les services/versions (3.1.2, 3.1.3).
        
        Args:
            host_ip: adresse IP de l'hôte
            ports: plage de ports (ex: '1-1024', '80,443,8080')
            detection: niveau de détection ('none' ou 'services')
            speed: vitesse du scan ('T1' à 'T5')
            scan_method: 'connect' ou 'syn'
        """
        options = {'ports': ports, 'detection': detection, 'speed': speed, 'method': scan_method}
        self._log_scan_start("Port/Service Scan", host_ip, options)
        
        # Use a local nmap instance for thread safety during parallel scans
        nm = nmap.PortScanner()
        
        try:
            args = self._build_nmap_arguments('ports', ports=ports, detection=detection, speed=speed, scan_method=scan_method)
            nm.scan(hosts=host_ip, arguments=args)
        except nmap.PortScannerError as e:
            self.log_manager.log(
                f"Erreur Nmap lors du scan de ports: {e}", 
                event_type="ERROR", 
                component="NetworkScanner"
            )
            return {}

        if host_ip in nm.all_hosts() and 'tcp' in nm[host_ip]:
            # Update shared state appropriately - protected by GIL for dict operations, and we are working on distinct keys per thread usually
            if host_ip not in self.active_hosts:
                self.active_hosts[host_ip] = Host(host_ip, nm[host_ip].hostname())

            host = self.active_hosts[host_ip]
            open_ports_count = 0
            
            for port, data in nm[host_ip]['tcp'].items():
                if data['state'] == 'open':
                    service = data.get('name', 'unknown')
                    version = data.get('version', 'N/A')
                    product = data.get('product', '')
                    
                    # Format différent selon le niveau de détection
                    if detection == 'services':
                        service_info = f"{service} {product} {version}".strip()
                    else:
                        service_info = service
                    
                    host.ports[port] = service_info
                    open_ports_count += 1
                    
                    self.log_manager.log(
                        f"Port ouvert détecté sur {host_ip}: {port}/{data['state']} - Service: {service_info}",
                        event_type="PORT_OPEN",
                        component="NetworkScanner",
                        details={"ip": host_ip, "port": port, "service": service, "version": version}
                    )
            
            # Détection OS si demandée
            if detection == 'services' and 'osmatch' in nm[host_ip]:
                os_matches = nm[host_ip]['osmatch']
                if os_matches:
                    host.os_info = os_matches[0].get('name', 'Unknown')
                    self.log_manager.log(
                        f"OS détecté sur {host_ip}: {host.os_info}",
                        event_type="OS_DETECTED",
                        component="NetworkScanner"
                    )
            
            self._log_scan_end("Port/Service Scan", host_ip, open_ports_count)
            return host.ports
        
        self._log_scan_end("Port/Service Scan", host_ip, 0)
        return {}

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

        # 2. Scan de ports et services sur chaque hôte actif (PARALLEL)
        scan_results = {}
        self.stop_requested = False
        
        # Use ThreadPoolExecutor to scan multiple hosts simultaneously
        # Increased max_workers to 30 for faster parallel scanning
        try:
            self.current_executor = concurrent.futures.ThreadPoolExecutor(max_workers=30)
            with self.current_executor as executor:
                future_to_ip = {}
                for ip in active_hosts:
                    if self.stop_requested:
                        break
                    future_to_ip[executor.submit(self.scan_ports_and_services, ip, ports, detection, speed, scan_method)] = ip
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if self.stop_requested:
                        break
                    ip = future_to_ip[future]
                    try:
                        future.result()
                    except concurrent.futures.CancelledError:
                        pass # Scan was cancelled
                    except Exception as exc:
                        self.log_manager.log(f"Scan generated an exception for {ip}: {exc}", event_type="ERROR", component="NetworkScanner")
        finally:
            self.current_executor = None

        if self.stop_requested:
            self.log_manager.log("Scan complet arrêté par l'utilisateur.", event_type="SCAN_ABORTED", component="NetworkScanner")
            # Return partial results? Or empty? Let's return partial.
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