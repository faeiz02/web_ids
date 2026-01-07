import matplotlib.pyplot as plt
import io
import base64
import datetime
import os
from models import Alert # Nécessaire pour le type hint

def generate_plot_base64(plt_figure):
    """Sauvegarde une figure Matplotlib dans un buffer et la retourne en base64."""
    buf = io.BytesIO()
    plt_figure.savefig(buf, format='png')
    plt.close(plt_figure)
    data = base64.b64encode(buf.getbuffer()).decode("ascii")
    return f"data:image/png;base64,{data}"

def visualize_alerts_by_type(alerts: list):
    """
    Génère un graphique à barres du nombre d'alertes par type d'événement.
    Retourne l'image encodée en base64.
    """
    if not alerts:
        # Créer un graphique vide pour indiquer l'absence de données
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "Aucune alerte à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Distribution des Alertes par Type d'Événement")
        ax.axis('off')
        return generate_plot_base64(fig)

    alert_counts = {}
    for alert in alerts:
        # Assurez-vous que l'objet est un dictionnaire ou a un attribut event_type
        event_type = alert.get('event_type', 'Inconnu') if isinstance(alert, dict) else alert.event_type
        alert_counts[event_type] = alert_counts.get(event_type, 0) + 1

    types = list(alert_counts.keys())
    counts = list(alert_counts.values())

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(types, counts, color='skyblue')
    ax.set_xlabel("Type d'événement")
    ax.set_ylabel("Nombre d'alertes")
    ax.set_title("Distribution des Alertes par Type d'Événement")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return generate_plot_base64(fig)

def visualize_traffic_volume(traffic_volume: dict):
    """
    Génère un graphique à barres du volume de trafic par hôte.
    Retourne l'image encodée en base64.
    """
    if not traffic_volume:
        # Créer un graphique vide pour indiquer l'absence de données
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "Aucune donnée de volume de trafic à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Volume de Trafic Réseau par Hôte (IDS)")
        ax.axis('off')
        return generate_plot_base64(fig)

    ips = list(traffic_volume.keys())
    volumes = [v / (1024 * 1024) for v in traffic_volume.values()] # Convertir en Mo

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(ips, volumes, color='lightcoral')
    ax.set_xlabel("Adresse IP Source")
    ax.set_ylabel("Volume de Trafic (Mo)")
    ax.set_title("Volume de Trafic Réseau par Hôte (IDS)")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return generate_plot_base64(fig)
