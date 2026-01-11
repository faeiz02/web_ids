import matplotlib
matplotlib.use('Agg')
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
    plt_figure.savefig(buf, format='png', dpi=100, bbox_inches='tight')
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

    # Création du graphique à barres avec style moderne
    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(types, counts, color='#3498db', edgecolor='#2c3e50', linewidth=1.5)
    
    # Ajouter les valeurs au-dessus des barres
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax.set_xlabel("Type d'événement", fontsize=12, fontweight='bold')
    ax.set_ylabel("Nombre d'alertes", fontsize=12, fontweight='bold')
    ax.set_title("Distribution des Alertes par Type d'Événement", fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    plt.xticks(rotation=45, ha='right')
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

    # Création du graphique à barres avec style moderne
    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(ips, volumes, color='#e74c3c', edgecolor='#c0392b', linewidth=1.5)
    
    # Ajouter les valeurs au-dessus des barres
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax.set_xlabel("Adresse IP Source", fontsize=12, fontweight='bold')
    ax.set_ylabel("Volume de Trafic (Mo)", fontsize=12, fontweight='bold')
    ax.set_title("Volume de Trafic Réseau par Hôte (IDS)", fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return generate_plot_base64(fig)

def visualize_alerts_timeline(alerts: list):
    """
    Génère un graphique de l'évolution des alertes dans le temps.
    
    Args:
        alerts: Liste d'objets Alert ou de dictionnaires
    
    Returns:
        Image encodée en base64 prête pour l'affichage HTML
    """
    if not alerts:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "Aucune alerte à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Évolution des Alertes dans le Temps")
        ax.axis('off')
        return generate_plot_base64(fig)
    
    # Extraire les timestamps
    timestamps = []
    for alert in alerts:
        if isinstance(alert, dict):
            ts = alert.get('timestamp')
            if isinstance(ts, str):
                timestamps.append(datetime.datetime.fromisoformat(ts))
            else:
                timestamps.append(ts)
        else:
            timestamps.append(alert.timestamp)
    
    # Compter les alertes par heure
    from collections import Counter
    hourly_counts = Counter([ts.replace(minute=0, second=0, microsecond=0) for ts in timestamps])
    
    # Trier par date
    sorted_times = sorted(hourly_counts.keys())
    counts = [hourly_counts[t] for t in sorted_times]
    
    # Création du graphique
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(sorted_times, counts, marker='o', linewidth=2, markersize=8, 
            color='#9b59b6', markerfacecolor='#8e44ad', markeredgecolor='#6c3483')
    ax.fill_between(sorted_times, counts, alpha=0.3, color='#9b59b6')
    
    ax.set_xlabel("Date et Heure", fontsize=12, fontweight='bold')
    ax.set_ylabel("Nombre d'Alertes", fontsize=12, fontweight='bold')
    ax.set_title("Évolution des Alertes dans le Temps", fontsize=14, fontweight='bold', pad=20)
    ax.grid(True, alpha=0.3, linestyle='--')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return generate_plot_base64(fig)

def visualize_severity_distribution(alerts: list):
    """
    Génère un graphique circulaire de la distribution des alertes par sévérité.
    
    Args:
        alerts: Liste d'objets Alert ou de dictionnaires
    
    Returns:
        Image encodée en base64 prête pour l'affichage HTML
    """
    if not alerts:
        fig, ax = plt.subplots(figsize=(8, 8))
        ax.text(0.5, 0.5, "Aucune alerte à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Distribution par Sévérité")
        ax.axis('off')
        return generate_plot_base64(fig)
    
    # Compter par sévérité (basé sur le type d'événement)
    severity_map = {
        'Port_Scan': 'MEDIUM',
        'DoS_Simple': 'HIGH',
        'SSH_Bruteforce': 'HIGH',
        'ICMP_Flood': 'MEDIUM',
        'SQL_Injection': 'CRITICAL',
        'XSS': 'HIGH',
        'Path_Traversal': 'HIGH',
        'Command_Injection': 'CRITICAL'
    }
    
    severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for alert in alerts:
        event_type = alert.get('event_type', 'Unknown') if isinstance(alert, dict) else alert.event_type
        severity = severity_map.get(event_type, 'MEDIUM')
        severity_counts[severity] += 1
    
    # Filtrer les sévérités avec 0 alertes
    labels = [k for k, v in severity_counts.items() if v > 0]
    sizes = [v for v in severity_counts.values() if v > 0]
    colors = {'LOW': '#2ecc71', 'MEDIUM': '#f39c12', 'HIGH': '#e67e22', 'CRITICAL': '#e74c3c'}
    plot_colors = [colors[label] for label in labels]
    
    # Création du graphique circulaire
    fig, ax = plt.subplots(figsize=(10, 8))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=plot_colors, autopct='%1.1f%%',
                                        startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    # Améliorer le style
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontsize(14)
        autotext.set_fontweight('bold')
    
    ax.set_title("Distribution des Alertes par Sévérité", fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    
    return generate_plot_base64(fig)
