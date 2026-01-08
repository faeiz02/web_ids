import requests
import socket
import time
import sys

# Configuration
TARGET_IP = "127.0.0.1" # Changez si l'IDS écoute sur une autre interface (ex: 192.168.x.x)
TARGET_PORT = 5000 # Port de l'application Flask

def test_sql_injection():
    print(f"[*] Test 1: Simulation SQL Injection vers {TARGET_IP}:{TARGET_PORT}...")
    try:
        # Pattern: ' OR '1'='1
        payload = {'q': "' OR '1'='1"}
        url = f"http://{TARGET_IP}:{TARGET_PORT}/"
        requests.get(url, params=payload, timeout=2)
        print("    -> Requête envoyée.")
    except Exception as e:
        print(f"    -> Erreur d'envoi: {e}")

def test_xss():
    print(f"[*] Test 2: Simulation XSS vers {TARGET_IP}:{TARGET_PORT}...")
    try:
        # Pattern: <script>
        payload = {'q': "<script>alert('test')</script>"}
        url = f"http://{TARGET_IP}:{TARGET_PORT}/"
        requests.get(url, params=payload, timeout=2)
        print("    -> Requête envoyée.")
    except Exception as e:
        print(f"    -> Erreur d'envoi: {e}")

def test_port_scan():
    print(f"[*] Test 3: Simulation Scan de Ports (5+ ports) vers {TARGET_IP}...")
    ports_to_scan = [5000, 8080, 21, 22, 443, 3306]
    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((TARGET_IP, port))
            sock.close()
        except:
            pass
    print(f"    -> Tentatives de connexion effectuées sur {len(ports_to_scan)} ports.")

def test_shellshock():
    print(f"[*] Test 4: Simulation Shellshock vers {TARGET_IP}:{TARGET_PORT}...")
    try:
        # Pattern: () { :; };
        headers = {'User-Agent': '() { :; }; echo "VULNERABLE"'}
        url = f"http://{TARGET_IP}:{TARGET_PORT}/cgi-bin/test"
        requests.get(url, headers=headers, timeout=2)
        print("    -> Requête envoyée.")
    except Exception as e:
        print(f"    -> Erreur d'envoi: {e}")

def test_sensitive_files():
    print(f"[*] Test 5: Accès Fichiers Sensibles vers {TARGET_IP}:{TARGET_PORT}...")
    files = ['.env', 'wp-config.php']
    for f in files:
        try:
            url = f"http://{TARGET_IP}:{TARGET_PORT}/{f}"
            requests.get(url, timeout=2)
            print(f"    -> Requête vers /{f} envoyée.")
        except Exception as e:
            pass

def test_malicious_user_agent():
    print(f"[*] Test 6: Simulation Malicious User-Agent vers {TARGET_IP}:{TARGET_PORT}...")
    try:
        # Pattern: sqlmap
        headers = {'User-Agent': 'sqlmap/1.0'}
        url = f"http://{TARGET_IP}:{TARGET_PORT}/"
        requests.get(url, headers=headers, timeout=2)
        print("    -> Requête envoyée.")
    except Exception as e:
        print(f"    -> Erreur d'envoi: {e}")

def test_malware_c2():
    print(f"[*] Test 7: Simulation Malware C2 Beacon (UDP) vers {TARGET_IP}...")
    try:
        # Pattern: C2_HEARTBEAT_REQUEST (UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        msg = b"C2_HEARTBEAT_REQUEST"
        sock.sendto(msg, (TARGET_IP, TARGET_PORT))
        print("    -> Paquet UDP envoyé.")
        sock.close()
    except Exception as e:
        print(f"    -> Erreur d'envoi UDP: {e}")

def test_cleartext_credentials():
    print(f"[*] Test 8: Simulation Credentials en clair (TCP) vers {TARGET_IP}:{TARGET_PORT}...")
    try:
        # Pattern: PASS admin123
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((TARGET_IP, TARGET_PORT))
        sock.sendall(b"USER admin\r\nPASS admin123\r\n")
        sock.close()
        print("    -> Données TCP envoyées.")
    except Exception as e:
        print(f"    -> Erreur d'envoi TCP: {e}")

if __name__ == "__main__":
    print("=== Script de Test IDS ===")
    print("Assurez-vous que l'application (et l'IDS) est lancée !")
    if len(sys.argv) > 1:
        TARGET_IP = sys.argv[1]
    
    print(f"Cible: {TARGET_IP}")
    
    test_sql_injection()
    time.sleep(1)
    test_xss()
    time.sleep(1)
    test_port_scan()
    time.sleep(1)
    test_shellshock()
    time.sleep(1)
    test_sensitive_files()
    time.sleep(1)
    test_malicious_user_agent()
    time.sleep(1)
    test_malware_c2()
    time.sleep(1)
    test_cleartext_credentials()
    
    print("\n=== Test Terminé ===")
    print("Vérifiez maintenant l'onglet 'Alertes' dans l'application.")
