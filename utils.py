import matplotlib.pyplot as plt
import io
import base64
import datetime
import os
from models import Alert # Nécessaire pour le type hint

def generate_plot_base64(plt_figure):
    """
    Sauvegarde une figure Matplotlib dans un buffer et la retourne en base64.
    
    Utilisé pour intégrer des graphiques dans des pages HTML.
    
    Args:
        plt_figure: Figure Matplotlib à convertir
    
    Returns:
        Chaîne base64 au format data URI (data:image/png;base64,...)
    """
    buf = io.BytesIO()
    plt_figure.savefig(buf, format='png')
    plt.close(plt_figure)
    data = base64.b64encode(buf.getbuffer()).decode("ascii")
    return f"data:image/png;base64,{data}"

def visualize_alerts_by_type(alerts: list):
    """
    Génère un graphique à barres du nombre d'alertes par type d'événement.
    
    Permet de visualiser la distribution des différents types d'attaques détectées.
    
    Args:
        alerts: Liste d'objets Alert ou de dictionnaires
    
    Returns:
        Image encodée en base64 prête pour l'affichage HTML
    """
    # Cas où il n'y a aucune alerte à afficher
    if not alerts:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "Aucune alerte à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Distribution des Alertes par Type d'Événement")
        ax.axis('off')
        return generate_plot_base64(fig)

    # Comptage des alertes par type
    alert_counts = {}
    for alert in alerts:
        # Support pour objets Alert ou dictionnaires
        event_type = alert.get('event_type', 'Inconnu') if isinstance(alert, dict) else alert.event_type
        alert_counts[event_type] = alert_counts.get(event_type, 0) + 1

    # Préparation des données pour le graphique
    types = list(alert_counts.keys())
    counts = list(alert_counts.values())

    # Création du graphique à barres
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(types, counts, color='skyblue')
    ax.set_xlabel("Type d'événement")
    ax.set_ylabel("Nombre d'alertes")
    ax.set_title("Distribution des Alertes par Type d'Événement")
    plt.xticks(rotation=45, ha='right')  # Rotation des labels pour meilleure lisibilité
    plt.tight_layout()
    
    return generate_plot_base64(fig)

def visualize_traffic_volume(traffic_volume: dict):
    """
    Génère un graphique à barres du volume de trafic par hôte.
    
    Permet d'identifier les hôtes générant le plus de trafic,
    utile pour détecter les attaques DoS.
    
    Args:
        traffic_volume: Dictionnaire {ip: bytes_count}
    
    Returns:
        Image encodée en base64 prête pour l'affichage HTML
    """
    # Cas où il n'y a aucune donnée de trafic
    if not traffic_volume:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "Aucune donnée de volume de trafic à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Volume de Trafic Réseau par Hôte (IDS)")
        ax.axis('off')
        return generate_plot_base64(fig)

    # Préparation des données (conversion en Mo pour meilleure lisibilité)
    ips = list(traffic_volume.keys())
    volumes = [v / (1024 * 1024) for v in traffic_volume.values()]  # Conversion bytes -> Mo

    # Création du graphique à barres
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(ips, volumes, color='lightcoral')
    ax.set_xlabel("Adresse IP Source")
    ax.set_ylabel("Volume de Trafic (Mo)")
    ax.set_title("Volume de Trafic Réseau par Hôte (IDS)")
    plt.xticks(rotation=45, ha='right')  # Rotation des labels pour meilleure lisibilité
    plt.tight_layout()
    
    return generate_plot_base64(fig)
