"""
Script de vérification pour tester le fonctionnement de l'AlertManager.

Ce script vérifie que:
- L'AlertManager peut être initialisé correctement
- Les alertes peuvent être générées avec une IP source
- L'IP source est correctement stockée dans l'alerte
"""

from managers import AlertManager
from models import Alert

try:
    # Initialisation de l'AlertManager
    am = AlertManager()
    print("AlertManager initialized.")
    
    # Génération d'une alerte de test avec une IP source spécifique
    alert = am.generate_alert("Test Alert", source_ip="1.2.3.4")
    print(f"Generated Alert: {alert}")
    print(f"Source IP: {alert.source_ip}")
    
    # Vérification que l'IP source a été correctement enregistrée
    if alert.source_ip == "1.2.3.4":
        print("SUCCESS: Source IP verified.")
    else:
        print("FAILURE: Source IP not set.")
        
except Exception as e:
    print(f"ERROR: {e}")

