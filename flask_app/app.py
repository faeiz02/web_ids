"""
Application Flask pour le Moniteur de Sécurité Réseau Python.
Intègre les fonctionnalités de scan réseau (Nmap) et de détection d'intrusion (Scapy).
"""

import os
import sys
import json
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import io
import base64

# Ajouter le répertoire parent au chemin pour importer les modules Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Host, Alert, Log
from managers import LogManager, AlertManager
from scanner import NetworkScanner
from ids import IDS
from utils import visualize_alerts_by_type, visualize_traffic_volume

# Initialisation de l'application Flask
app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

# Configuration
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Initialisation des composants du système de sécurité
log_manager = LogManager()
alert_manager = AlertManager()
scanner = NetworkScanner(log_manager)
ids = IDS(alert_manager, log_manager)

# Variables globales pour le suivi des scans
scan_in_progress = False
current_scan_status = "Prêt"
last_manual_scan_host = None  # Stocke le dernier hôte scanné manuellement
scan_mode = "full"  # "full" pour scan complet, "manual" pour scan manuel



# ============================================================================
# ROUTES PRINCIPALES (Pages HTML)
# ============================================================================

@app.route('/')
def index():
    """Page d'accueil du dashboard."""
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    """Page du tableau de bord principal."""
    hosts = scanner.get_active_hosts()
    alerts = alert_manager.get_all_alerts()
    active_alerts = alert_manager.get_active_alerts()
    
    stats = {
        'total_hosts': len(hosts),
        'total_alerts': len(alerts),
        'active_alerts': len(active_alerts),
        'ids_running': ids.is_monitoring()
    }
    
    return render_template('dashboard.html', stats=stats)


@app.route('/scan')
def scan_page():
    """Page de gestion des scans réseau."""
    return render_template('scan.html')


@app.route('/alerts')
def alerts_page():
    """Page de gestion des alertes."""
    return render_template('alerts.html')


@app.route('/logs')
def logs_page():
    """Page de consultation des logs."""
    return render_template('logs.html')


@app.route('/visualization')
def visualization_page():
    """Page de visualisation des événements."""
    return render_template('visualization.html')


@app.route('/config')
def config_page():
    """Page de configuration de l'IDS."""
    return render_template('config.html')



# ============================================================================
# API ENDPOINTS - SCANNER
# ============================================================================

@app.route('/api/scan/status', methods=['GET'])
def get_scan_status():
    """Retourne le statut actuel du scan."""
    return jsonify({
        'in_progress': scan_in_progress,
        'status': current_scan_status
    })


@app.route('/api/scan/full', methods=['POST'])
def perform_full_scan():
    """Lance un scan réseau complet."""
    global scan_in_progress, current_scan_status
    
    if scan_in_progress:
        return jsonify({'error': 'Un scan est déjà en cours'}), 400
    
    data = request.get_json()
    target_range = data.get('target_range', '192.168.1.0/24')
    ports = data.get('ports', '1-100')
    scan_method = data.get('scan_method', 'connect')
    speed = 'T4' # Default speed since user removed control
    
    def run_scan():
        global scan_in_progress, current_scan_status, scan_mode, last_manual_scan_host
        try:
            scan_in_progress = True
            scan_mode = "full"  # Mode scan complet
            last_manual_scan_host = None  # Réinitialiser le dernier hôte manuel
            current_scan_status = f"Scan en cours sur {target_range} (Méthode: {scan_method})..."
            scanner.perform_full_network_scan(target_range, ports, speed=speed, scan_method=scan_method)
            current_scan_status = "Scan terminé"
        except Exception as e:
            current_scan_status = f"Erreur: {str(e)}"
            log_manager.log(f"Erreur lors du scan: {str(e)}", event_type="ERROR", component="Flask")
        finally:
            scan_in_progress = False

    
    # Lancer le scan dans un thread séparé
    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()
    
    return jsonify({'message': 'Scan lancé', 'target': target_range})


@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    """Arrête le scan en cours."""
    global scan_in_progress, current_scan_status
    
    if not scan_in_progress:
        return jsonify({'error': 'Aucun scan en cours'}), 400
        
    try:
        scanner.stop_scan()
        scan_in_progress = False
        current_scan_status = "Scan arrêté par l'utilisateur"
        log_manager.log("Scan arrêté par l'utilisateur via l'API", event_type="SCAN_ABORTED", component="Flask")
        return jsonify({'message': 'Scan arrêté'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/ports', methods=['POST'])
def scan_ports():
    """Lance un scan de ports sur un hôte spécifique."""
    global scan_in_progress, current_scan_status
    
    if scan_in_progress:
        return jsonify({'error': 'Un scan est déjà en cours'}), 400
    
    data = request.get_json()
    host_ip = data.get('host_ip')
    ports = data.get('ports', '1-1024')
    scan_method = data.get('scan_method', 'connect')
    speed = 'T4'
    
    if not host_ip:
        return jsonify({'error': 'Adresse IP requise'}), 400
    
    def run_scan():
        global scan_in_progress, current_scan_status, last_manual_scan_host, scan_mode
        try:
            scan_in_progress = True
            scan_mode = "manual"  # Mode scan manuel
            last_manual_scan_host = host_ip  # Stocker l'IP du dernier hôte scanné manuellement AVANT le scan
            current_scan_status = f"Scan de ports sur {host_ip} (Méthode: {scan_method})..."
            scanner.scan_ports_and_services(host_ip, ports, speed=speed, scan_method=scan_method)
            current_scan_status = "Scan terminé"
        except Exception as e:
            current_scan_status = f"Erreur: {str(e)}"
            log_manager.log(f"Erreur lors du scan: {str(e)}", event_type="ERROR", component="Flask")
        finally:
            scan_in_progress = False
    
    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()
    
    return jsonify({'message': 'Scan lancé', 'host': host_ip})


@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    """Retourne la liste des hôtes actifs.
    En mode manuel, retourne seulement le dernier hôte scanné.
    En mode complet, retourne tous les hôtes.
    """
    global scan_mode, last_manual_scan_host
    
    hosts = scanner.get_active_hosts()
    hosts_data = []
    
    # Si on est en mode manuel et qu'un hôte a été scanné, afficher seulement celui-là
    if scan_mode == "manual" and last_manual_scan_host:
        for host in hosts:
            if host.ip_address == last_manual_scan_host:
                host_data = {
                    'ip_address': host.ip_address,
                    'hostname': host.hostname,
                    'is_active': host.is_active,
                    'ports': host.ports
                }
                hosts_data.append(host_data)
                break
    else:
        # Mode complet : afficher tous les hôtes
        for host in hosts:
            host_data = {
                'ip_address': host.ip_address,
                'hostname': host.hostname,
                'is_active': host.is_active,
                'ports': host.ports
            }
            hosts_data.append(host_data)
    
    return jsonify(hosts_data)


# ============================================================================
# API ENDPOINTS - IDS
# ============================================================================

@app.route('/api/ids/status', methods=['GET'])
def get_ids_status():
    """Retourne le statut de l'IDS."""
    return jsonify({
        'running': ids.is_monitoring(),
        'traffic_stats': ids.get_traffic_stats()
    })


@app.route('/api/ids/start', methods=['POST'])
def start_ids():
    """Démarre la surveillance IDS."""
    data = request.get_json()
    interface = data.get('interface', None)
    
    if ids.start_monitoring(interface):
        log_manager.log("IDS démarré via l'interface Flask", event_type="IDS_START", component="Flask")
        return jsonify({'message': 'IDS démarré avec succès'})
    else:
        return jsonify({'error': 'L\'IDS est déjà en cours d\'exécution'}), 400


@app.route('/api/ids/stop', methods=['POST'])
def stop_ids():
    """Arrête la surveillance IDS."""
    if ids.stop_monitoring():
        log_manager.log("IDS arrêté via l'interface Flask", event_type="IDS_STOP", component="Flask")
        return jsonify({'message': 'IDS arrêté avec succès'})
    else:
        return jsonify({'error': 'L\'IDS n\'est pas en cours d\'exécution'}), 400


# ============================================================================
# API ENDPOINTS - ALERTES
# ============================================================================

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Retourne toutes les alertes."""
    alerts = alert_manager.get_all_alerts()
    alerts_data = [alert.to_dict() for alert in alerts]
    return jsonify(alerts_data)


@app.route('/api/alerts/active', methods=['GET'])
def get_active_alerts():
    """Retourne les alertes non acquittées."""
    alerts = alert_manager.get_active_alerts()
    alerts_data = [alert.to_dict() for alert in alerts]
    return jsonify(alerts_data)


@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acquitte une alerte."""
    if alert_manager.acknowledge_alert(alert_id):
        log_manager.log(f"Alerte acquittée: {alert_id}", event_type="ALERT_ACK", component="Flask")
        return jsonify({'message': 'Alerte acquittée'})
    else:
        return jsonify({'error': 'Alerte non trouvée'}), 404


@app.route('/api/alerts/count', methods=['GET'])
def get_alerts_count():
    """Retourne le nombre d'alertes."""
    all_alerts = alert_manager.get_all_alerts()
    active_alerts = alert_manager.get_active_alerts()
    return jsonify({
        'total': len(all_alerts),
        'active': len(active_alerts)
    })


# ============================================================================
# API ENDPOINTS - LOGS
# ============================================================================

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Retourne les logs."""
    limit = request.args.get('limit', 100, type=int)
    logs = log_manager.get_logs(limit=limit)
    return jsonify(logs)


@app.route('/api/logs/count', methods=['GET'])
def get_logs_count():
    """Retourne le nombre de logs."""
    logs = log_manager.get_logs(limit=10000)
    return jsonify({'count': len(logs)})


# ============================================================================
# API ENDPOINTS - VISUALISATION
# ============================================================================

@app.route('/api/visualization/alerts', methods=['GET'])
def visualization_alerts():
    """Retourne les données des alertes par type pour Chart.js."""
    alerts = alert_manager.get_all_alerts()
    
    # Compter les alertes par type
    alert_counts = {}
    for alert in alerts:
        event_type = alert.event_type
        alert_counts[event_type] = alert_counts.get(event_type, 0) + 1
    
    # Préparer les données pour Chart.js
    labels = list(alert_counts.keys())
    data = list(alert_counts.values())
    
    return jsonify({
        'labels': labels,
        'data': data,
        'total': len(alerts)
    })


@app.route('/api/visualization/traffic', methods=['GET'])
def visualization_traffic():
    """Retourne les données du volume de trafic pour Chart.js."""
    traffic_stats = ids.get_traffic_stats()
    
    if not traffic_stats:
        return jsonify({'labels': [], 'data': [], 'total': 0})
    
    # Convertir en Mo et préparer les données
    labels = list(traffic_stats.keys())
    data = [v / (1024 * 1024) for v in traffic_stats.values()]  # Convertir en Mo
    
    return jsonify({
        'labels': labels,
        'data': data,
        'total': len(traffic_stats)
    })


@app.route('/api/visualization/timeline', methods=['GET'])
def visualization_timeline():
    """Retourne l'évolution des alertes dans le temps pour Chart.js."""
    alerts = alert_manager.get_all_alerts()
    
    if not alerts:
        return jsonify({'labels': [], 'data': [], 'total': 0})
    
    # Grouper les alertes par heure
    from collections import defaultdict
    hourly_counts = defaultdict(int)
    
    for alert in alerts:
        # Extraire l'heure depuis le timestamp
        timestamp = alert.timestamp
        hour_key = timestamp.strftime('%Y-%m-%d %H:00')
        hourly_counts[hour_key] += 1
    
    # Trier par heure
    sorted_hours = sorted(hourly_counts.keys())
    labels = [h.split(' ')[1] for h in sorted_hours]  # Garder seulement l'heure
    data = [hourly_counts[h] for h in sorted_hours]
    
    return jsonify({
        'labels': labels,
        'data': data,
        'total': len(alerts)
    })


@app.route('/api/visualization/severity', methods=['GET'])
def visualization_severity():
    """Retourne la distribution des alertes par sévérité pour Chart.js."""
    alerts = alert_manager.get_all_alerts()
    
    # Extraire la sévérité depuis le type d'événement
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    
    for alert in alerts:
        event_type = alert.event_type.upper()
        if 'HIGH' in event_type or 'CRITICAL' in event_type:
            severity_counts['HIGH'] += 1
        elif 'MEDIUM' in event_type or 'WARNING' in event_type:
            severity_counts['MEDIUM'] += 1
        elif 'LOW' in event_type:
            severity_counts['LOW'] += 1
        else:
            severity_counts['INFO'] += 1
    
    # Filtrer les sévérités avec 0 alertes
    labels = [k for k, v in severity_counts.items() if v > 0]
    data = [v for v in severity_counts.values() if v > 0]
    
    return jsonify({
        'labels': labels,
        'data': data,
        'total': len(alerts)
    })


# ============================================================================
# API ENDPOINTS - STATISTIQUES
# ============================================================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Retourne les statistiques globales du système."""
    hosts = scanner.get_active_hosts()
    all_alerts = alert_manager.get_all_alerts()
    active_alerts = alert_manager.get_active_alerts()
    logs = log_manager.get_logs(limit=10000)
    traffic_stats = ids.get_traffic_stats()
    
    stats = {
        'hosts': {
            'total': len(hosts),
            'details': [
                {
                    'ip': h.ip_address,
                    'hostname': h.hostname,
                    'ports_open': len(h.ports)
                }
                for h in hosts
            ]
        },
        'alerts': {
            'total': len(all_alerts),
            'active': len(active_alerts)
        },
        'logs': {
            'total': len(logs)
        },
        'ids': {
            'running': ids.is_monitoring(),
            'traffic_sources': len(traffic_stats)
        }
    }
    
    return jsonify(stats)


# ============================================================================
# API ENDPOINTS - CONFIGURATION
# ============================================================================

@app.route('/api/config', methods=['GET'])
def get_config():
    """Retourne la configuration actuelle de l'IDS."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return jsonify(config)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/thresholds', methods=['PUT'])
def update_thresholds():
    """Met à jour les seuils de détection de l'IDS."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Données invalides'}), 400
    
    # Mise à jour des seuils IDS
    if 'thresholds' in data:
        thresholds = data['thresholds']
        
        # Validation des données
        try:
            dos_volume = int(thresholds.get('dos_volume', ids.volume_threshold))
            port_scan_max_ports = int(thresholds.get('port_scan_max_ports', ids.port_scan_threshold))
            ssh_bruteforce_attempts = int(thresholds.get('ssh_bruteforce_attempts', ids.ssh_bruteforce_threshold))
            icmp_flood_packets = int(thresholds.get('icmp_flood_packets', ids.icmp_flood_threshold))
        except ValueError:
            return jsonify({'error': 'Les valeurs doivent être des entiers'}), 400
        
        # Mettre à jour les seuils dans l'IDS
        ids.update_thresholds(
            dos_volume=dos_volume,
            port_scan_max_ports=port_scan_max_ports,
            ssh_bruteforce_attempts=ssh_bruteforce_attempts,
            icmp_flood_packets=icmp_flood_packets
        )
    
    # Sauvegarder dans le fichier config.json
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
    try:
        config = {}
        if 'thresholds' in data:
            config['thresholds'] = {
                'dos_volume': dos_volume,
                'port_scan_max_ports': port_scan_max_ports,
                'ssh_bruteforce_attempts': ssh_bruteforce_attempts,
                'icmp_flood_packets': icmp_flood_packets
            }
        
        # Charger la config existante et la fusionner
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                existing_config = json.load(f)
                existing_config.update(config)
                config = existing_config
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        log_manager.log("Configuration mise à jour via l'API", event_type="CONFIG_UPDATE", component="Flask")
        return jsonify({'message': 'Configuration mise à jour avec succès', 'config': config})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/scanner', methods=['PUT'])
def update_scanner_config():
    """Met à jour la configuration du scanner (profils de performance)."""
    data = request.get_json()
    
    if not data or 'scanner' not in data:
        return jsonify({'error': 'Données invalides'}), 400
    
    scanner_data = data['scanner']
    
    try:
        max_threads = int(scanner_data.get('max_threads', 30))
        min_parallelism = int(scanner_data.get('min_parallelism', 100))
        min_rate = int(scanner_data.get('min_rate', 300))
        
        # Validation des valeurs
        if not (1 <= max_threads <= 100):
            return jsonify({'error': 'max_threads doit être entre 1 et 100'}), 400
        if not (1 <= min_parallelism <= 1000):
            return jsonify({'error': 'min_parallelism doit être entre 1 et 1000'}), 400
        if not (1 <= min_rate <= 10000):
            return jsonify({'error': 'min_rate doit être entre 1 et 10000'}), 400
        
        # Mettre à jour le scanner en mémoire
        scanner.max_threads = max_threads
        scanner.min_parallelism = min_parallelism
        scanner.min_rate = min_rate
        
        # Sauvegarder dans config.json
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
        
        config = {}
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
        
        config['scanner'] = {
            'max_threads': max_threads,
            'min_parallelism': min_parallelism,
            'min_rate': min_rate
        }
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        log_manager.log(
            f"Configuration scanner mise à jour: threads={max_threads}, parallelism={min_parallelism}, rate={min_rate}",
            event_type="CONFIG_UPDATE",
            component="Flask"
        )
        return jsonify({'message': 'Configuration scanner mise à jour avec succès', 'config': config['scanner']})
        
    except ValueError:
        return jsonify({'error': 'Les valeurs doivent être des entiers'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/api/signatures', methods=['GET'])
def get_signatures():
    """Retourne toutes les signatures d'attaques."""
    signatures_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'signatures.json')
    try:
        with open(signatures_path, 'r') as f:
            signatures = json.load(f)
        return jsonify(signatures)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/signatures', methods=['POST'])
def add_signature():
    """Ajoute une nouvelle signature d'attaque."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Données invalides'}), 400
    
    # Validation des champs requis
    required_fields = ['id', 'name', 'pattern', 'protocol', 'severity']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Champ requis manquant: {field}'}), 400
    
    signatures_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'signatures.json')
    try:
        # Charger les signatures existantes
        with open(signatures_path, 'r') as f:
            signatures = json.load(f)
        
        # Vérifier si l'ID existe déjà
        if any(sig['id'] == data['id'] for sig in signatures):
            return jsonify({'error': 'Une signature avec cet ID existe déjà'}), 400
        
        # Ajouter la nouvelle signature
        new_signature = {
            'id': data['id'],
            'name': data['name'],
            'pattern': data['pattern'],
            'protocol': data['protocol'],
            'port': int(data.get('port', 0)),
            'severity': data['severity']
        }
        signatures.append(new_signature)
        
        # Sauvegarder
        with open(signatures_path, 'w') as f:
            json.dump(signatures, f, indent=4)
        
        # Recharger les signatures dans l'IDS
        ids.signatures = ids._load_signatures()
        
        log_manager.log(f"Nouvelle signature ajoutée: {data['name']}", event_type="SIGNATURE_ADD", component="Flask")
        return jsonify({'message': 'Signature ajoutée avec succès', 'signature': new_signature})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/signatures/<signature_id>', methods=['PUT'])
def update_signature(signature_id):
    """Met à jour une signature existante."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Données invalides'}), 400
    
    signatures_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'signatures.json')
    try:
        # Charger les signatures existantes
        with open(signatures_path, 'r') as f:
            signatures = json.load(f)
        
        # Trouver la signature à mettre à jour
        signature_index = None
        for i, sig in enumerate(signatures):
            if sig['id'] == signature_id:
                signature_index = i
                break
        
        if signature_index is None:
            return jsonify({'error': 'Signature non trouvée'}), 404
        
        # Mettre à jour la signature
        signatures[signature_index] = {
            'id': signature_id,
            'name': data.get('name', signatures[signature_index]['name']),
            'pattern': data.get('pattern', signatures[signature_index]['pattern']),
            'protocol': data.get('protocol', signatures[signature_index]['protocol']),
            'port': int(data.get('port', signatures[signature_index].get('port', 0))),
            'severity': data.get('severity', signatures[signature_index]['severity'])
        }
        
        # Sauvegarder
        with open(signatures_path, 'w') as f:
            json.dump(signatures, f, indent=4)
        
        # Recharger les signatures dans l'IDS
        ids.signatures = ids._load_signatures()
        
        log_manager.log(f"Signature mise à jour: {signature_id}", event_type="SIGNATURE_UPDATE", component="Flask")
        return jsonify({'message': 'Signature mise à jour avec succès', 'signature': signatures[signature_index]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/signatures/<signature_id>', methods=['DELETE'])
def delete_signature(signature_id):
    """Supprime une signature."""
    signatures_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'signatures.json')
    try:
        # Charger les signatures existantes
        with open(signatures_path, 'r') as f:
            signatures = json.load(f)
        
        # Trouver et supprimer la signature
        signature_index = None
        for i, sig in enumerate(signatures):
            if sig['id'] == signature_id:
                signature_index = i
                break
        
        if signature_index is None:
            return jsonify({'error': 'Signature non trouvée'}), 404
        
        deleted_signature = signatures.pop(signature_index)
        
        # Sauvegarder
        with open(signatures_path, 'w') as f:
            json.dump(signatures, f, indent=4)
        
        # Recharger les signatures dans l'IDS
        ids.signatures = ids._load_signatures()
        
        log_manager.log(f"Signature supprimée: {signature_id}", event_type="SIGNATURE_DELETE", component="Flask")
        return jsonify({'message': 'Signature supprimée avec succès', 'signature': deleted_signature})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# ============================================================================
# GESTION DES ERREURS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Gère les erreurs 404."""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Gère les erreurs 500."""
    log_manager.log(f"Erreur serveur: {str(error)}", event_type="ERROR", component="Flask")
    return render_template('500.html'), 500


# ============================================================================
# INITIALISATION
# ============================================================================

if __name__ == '__main__':
    log_manager.log("Application Flask démarrée", event_type="APP_START", component="Flask")
    app.run(debug=True, host='0.0.0.0', port=5000)
