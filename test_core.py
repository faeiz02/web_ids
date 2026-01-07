import os
import sys
# Ajouter le répertoire parent au chemin pour les imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from managers import LogManager, AlertManager

def test_managers():
    print("--- Test des Managers (LogManager et AlertManager) ---")
    
    # Initialisation
    log_manager = LogManager(log_file="test_logs.jsonl")
    alert_manager = AlertManager(alert_file="test_alerts.jsonl")
    
    # 1. Test de la journalisation
    print("\n1. Test de la journalisation:")
    log_manager.log("Démarrage du test des managers.", component="TestScript")
    log_manager.log("Événement important simulé.", event_type="CRITICAL", component="TestScript", details={"data": 123})
    
    # 2. Test de la génération d'alerte
    print("\n2. Test de la génération d'alerte:")
    alert1 = alert_manager.generate_alert("Scan de ports suspect détecté de 192.168.1.5", event_type="Port_Scan")
    alert2 = alert_manager.generate_alert("Volume de trafic anormalement élevé.", event_type="DoS_Simple")
    
    # 3. Consultation des alertes actives
    print("\n3. Consultation des alertes actives:")
    active_alerts = alert_manager.get_active_alerts()
    print(f"Nombre d'alertes actives: {len(active_alerts)}")
    for alert in active_alerts:
        print(f"  - {alert}")
        
    # 4. Acquittement d'une alerte
    print("\n4. Acquittement de l'alerte 1:")
    if alert_manager.acknowledge_alert(alert1.id):
        print(f"Alerte {alert1.id[:8]} acquittée avec succès.")
    else:
        print("Échec de l'acquittement.")
        
    # 5. Consultation des alertes actives après acquittement
    print("\n5. Consultation des alertes actives après acquittement:")
    active_alerts_after_ack = alert_manager.get_active_alerts()
    print(f"Nombre d'alertes actives: {len(active_alerts_after_ack)}")
    for alert in active_alerts_after_ack:
        print(f"  - {alert}")

    # 6. Nettoyage des fichiers de test
    os.remove(log_manager.log_file)
    os.remove(alert_manager.alert_file)
    print("\nNettoyage des fichiers de test effectué.")

if __name__ == "__main__":
    test_managers()
