
import os
import sys
from managers import LogManager
from scanner import NetworkScanner

# Ensure we can import modules
sys.path.append(os.getcwd())

def debug_scan():
    print("Initializing Scanner...")
    log_manager = LogManager(log_file="debug_scan.log")
    scanner = NetworkScanner(log_manager)
    
    target = "192.168.1.1" # Gateway, usually active
    
    print(f"Scanning Host Discovery on {target}...")
    hosts = scanner.detect_active_hosts(target)
    print(f"Hosts found: {len(hosts)}")
    for ip, host in hosts.items():
        print(f" - {ip} ({host.hostname})")
        
    if hosts:
        print(f"\nScanning Ports on {target}...")
        ports = scanner.scan_ports_and_services(target, ports="80,443,53,22")
        print(f"Ports found: {ports}")
    else:
        print("No hosts found. Testing with nmap command line via python...")
        import subprocess
        try:
            res = subprocess.check_output(["nmap", "-sn", target], stderr=subprocess.STDOUT)
            print("Nmap CLI output:")
            print(res.decode())
        except Exception as e:
            print(f"Nmap CLI failed: {e}")

if __name__ == "__main__":
    debug_scan()
