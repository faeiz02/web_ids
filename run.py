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

    # Démarrer l'application Flask
    app.run(debug=debug_mode, host=host, port=port)

