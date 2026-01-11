#!/usr/bin/env python3
"""
Script de démarrage pour l'application Flask du Moniteur de Sécurité Réseau.

Ce script configure et lance l'interface web Flask qui permet:
- De gérer les scans réseau via une interface graphique
- De visualiser les alertes de sécurité en temps réel
- De consulter les logs du système
- De démarrer/arrêter l'IDS
"""

import os
import sys

# Ajouter le répertoire courant au chemin Python pour les imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask_app.app import app

if __name__ == '__main__':
    # === Configuration de l'application ===
    # Lecture des variables d'environnement pour la configuration
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '0.0.0.0')  # 0.0.0.0 = accessible depuis toutes les interfaces
    port = int(os.environ.get('FLASK_PORT', 5000))

    # Affichage du banner de démarrage
    print(f"""
    ╔══════════════════════════════════════════════════════════════════╗
    ║     Moniteur de Sécurité Réseau Python - Interface Flask        ║
    ║                                                                  ║
    ║  Démarrage de l'application...                                  ║
    ║  URL: http://{host}:{port}                                        ║
    ║  Mode Debug: {debug_mode}                                         ║
    ║                                                                  ║
    ║  Fonctionnalités:                                               ║
    ║  - Scan réseau (Nmap)                                           ║
    ║  - Détection d'intrusion (Scapy)                                ║
    ║  - Gestion des alertes                                          ║
    ║  - Visualisation des événements                                 ║
    ║                                                                  ║
    ║  Note: L'IDS (Scapy) nécessite des privilèges root pour         ║
    ║  sniffer le trafic réseau. Exécutez avec 'sudo' si nécessaire.  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)

    # === Empêcher les instances multiples ===
    import os
    lock_file = os.path.join(os.path.dirname(__file__), "app.lock")
    
    if os.path.exists(lock_file):
        # Vérifier si le process est toujours en vie (sur Windows simple check d'existence suffit souvent, 
        # mais on va essayer de le supprimer au cas où c'est un reste de crash)
        try:
            os.remove(lock_file)
        except Exception:
            print("\n" + "!"*60)
            print("ERREUR: Une instance du serveur est déjà en cours d'exécution.")
            print("Fermez tous les autres terminaux python avant de relancer.")
            print("!"*60 + "\n")
            sys.exit(1)
            
    # Créer le lock
    with open(lock_file, "w") as f:
        f.write(str(os.getpid()))
        
    try:
        # Démarrer l'application Flask
        app.run(debug=debug_mode, host=host, port=port)
    finally:
        # Supprimer le lock à l'arrêt
        if os.path.exists(lock_file):
            try:
                os.remove(lock_file)
            except:
                pass

