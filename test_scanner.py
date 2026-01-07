import os
import sys
import socket
# Ajouter le répertoire parent au chemin pour les imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from managers import LogManager
from scanner import NetworkScanner

def test_scanner():
    print("--- Test du NetworkScanner ---")
    
    # Initialisation
    log_manager = LogManager(log_file="test_scanner_logs.jsonl")
    scanner = NetworkScanner(log_manager)
    
    # Utiliser localhost pour un test sûr dans la sandbox
    target_ip = "127.0.0.1"
    
    # 1. Test de la détection d'hôtes (sur localhost)
    print(f"\n1. Test de la détection d'hôtes sur {target_ip}...")
    # Nmap -sn sur 127.0.0.1 devrait le trouver actif
    scanner.detect_active_hosts(target_ip)
    
    hosts = scanner.get_active_hosts()
    if hosts:
        print(f"Hôtes actifs trouvés: {len(hosts)}")
        for host in hosts:
            print(f"  - {host}")
    else:
        print("Aucun hôte actif trouvé (ce qui est inattendu pour 127.0.0.1).")

    # 2. Test du scan de ports et services (sur localhost)
    print(f"\n2. Test du scan de ports sur {target_ip} (ports 22, 80, 443)...")
    # Scanner des ports communs (même s'ils ne sont pas ouverts dans la sandbox)
    ports_to_scan = "22,80,443"
    ports_data = scanner.scan_ports_and_services(target_ip, ports_to_scan)
    
    if ports_data:
        print(f"Ports scannés sur {target_ip}:")
        for port, service in ports_data.items():
            print(f"  - Port {port}: {service}")
    else:
        print(f"Aucun port ouvert trouvé sur {target_ip} ou erreur de scan.")

    # 3. Nettoyage des fichiers de test
    os.remove(log_manager.log_file)
    print("\nNettoyage des fichiers de test effectué.")

if __name__ == "__main__":
    test_scanner()
