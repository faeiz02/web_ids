import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
import datetime
import os
from collections import Counter, defaultdict
from models import Alert

# ============================================================================
# UTILS POUR MATPLOTLIB (Images Statiques)
# ============================================================================

def generate_plot_base64(plt_figure):
    """Génère une image Base64 à partir d'une figure Matplotlib."""
    buf = io.BytesIO()
    plt_figure.savefig(buf, format='png', dpi=100, bbox_inches='tight')
    plt.close(plt_figure)
    data = base64.b64encode(buf.getbuffer()).decode("ascii")
    return f"data:image/png;base64,{data}"

def visualize_alerts_by_type(alerts: list):
    """Génère un graphique à barres des alertes par type (Matplotlib)."""
    if not alerts:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "Aucune alerte à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Distribution des Alertes par Type d'Événement")
        ax.axis('off')
        return generate_plot_base64(fig)

    alert_counts = {}
    for alert in alerts:
        event_type = alert.get('event_type', 'Inconnu') if isinstance(alert, dict) else alert.event_type
        alert_counts[event_type] = alert_counts.get(event_type, 0) + 1

    types = list(alert_counts.keys())
    counts = list(alert_counts.values())

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(types, counts, color='#3498db', edgecolor='#2c3e50', linewidth=1.5)
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height, f'{int(height)}',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax.set_xlabel("Type d'événement", fontsize=12, fontweight='bold')
    ax.set_ylabel("Nombre d'alertes", fontsize=12, fontweight='bold')
    ax.set_title("Distribution des Alertes par Type d'Événement", fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return generate_plot_base64(fig)

def visualize_traffic_volume(traffic_volume: dict):
    """Génère un graphique de volume de trafic (Matplotlib)."""
    if not traffic_volume:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "Aucune donnée de volume de trafic à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Volume de Trafic Réseau par Hôte (IDS)")
        ax.axis('off')
        return generate_plot_base64(fig)

    ips = list(traffic_volume.keys())
    volumes = [v / (1024 * 1024) for v in traffic_volume.values()] 

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(ips, volumes, color='#e74c3c', edgecolor='#c0392b', linewidth=1.5)
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height, f'{height:.2f}',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax.set_xlabel("Adresse IP Source", fontsize=12, fontweight='bold')
    ax.set_ylabel("Volume de Trafic (Mo)", fontsize=12, fontweight='bold')
    ax.set_title("Volume de Trafic Réseau par Hôte (IDS)", fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return generate_plot_base64(fig)

def visualize_alerts_timeline(alerts: list):
    """Génère une timeline des alertes (Matplotlib)."""
    if not alerts:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.text(0.5, 0.5, "Aucune alerte à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Évolution des Alertes dans le Temps")
        ax.axis('off')
        return generate_plot_base64(fig)
    
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
    
    hourly_counts = Counter([ts.replace(minute=0, second=0, microsecond=0) for ts in timestamps])
    sorted_times = sorted(hourly_counts.keys())
    counts = [hourly_counts[t] for t in sorted_times]
    
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
    """Génère un camembert de sévérité (Matplotlib)."""
    if not alerts:
        fig, ax = plt.subplots(figsize=(8, 8))
        ax.text(0.5, 0.5, "Aucune alerte à visualiser.", ha='center', va='center', fontsize=14)
        ax.set_title("Distribution par Sévérité")
        ax.axis('off')
        return generate_plot_base64(fig)
    
    severity_map = {
        'Port_Scan': 'MEDIUM', 'DoS_Simple': 'HIGH', 'SSH_Bruteforce': 'HIGH',
        'ICMP_Flood': 'MEDIUM', 'SQL_Injection': 'CRITICAL', 'XSS': 'HIGH',
        'Path_Traversal': 'HIGH', 'Command_Injection': 'CRITICAL'
    }
    
    severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for alert in alerts:
        event_type = alert.get('event_type', 'Unknown') if isinstance(alert, dict) else alert.event_type
        severity = severity_map.get(event_type, 'MEDIUM')
        severity_counts[severity] += 1
    
    labels = [k for k, v in severity_counts.items() if v > 0]
    sizes = [v for v in severity_counts.values() if v > 0]
    colors = {'LOW': '#2ecc71', 'MEDIUM': '#f39c12', 'HIGH': '#e67e22', 'CRITICAL': '#e74c3c'}
    plot_colors = [colors[label] for label in labels]
    
    fig, ax = plt.subplots(figsize=(10, 8))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=plot_colors, autopct='%1.1f%%',
                                        startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontsize(14)
        autotext.set_fontweight('bold')
    
    ax.set_title("Distribution des Alertes par Sévérité", fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    
    return generate_plot_base64(fig)

# ============================================================================
# UTILS POUR CHART.JS (Données JSON)
# ============================================================================

def prepare_alerts_chart_data(alerts: list):
    """Prépare les données pour le graphique des alertes (Chart.js)."""
    alert_counts = {}
    for alert in alerts:
        event_type = alert.get('event_type', 'Inconnu') if isinstance(alert, dict) else alert.event_type
        alert_counts[event_type] = alert_counts.get(event_type, 0) + 1
    
    return {
        'labels': list(alert_counts.keys()),
        'data': list(alert_counts.values()),
        'total': len(alerts)
    }

def prepare_traffic_chart_data(traffic_stats: dict):
    """Prépare les données pour le graphique du trafic (Chart.js)."""
    if not traffic_stats:
        return {'labels': [], 'data': [], 'total': 0}
    
    labels = list(traffic_stats.keys())
    data = [v / (1024 * 1024) for v in traffic_stats.values()]
    
    return {
        'labels': labels,
        'data': data,
        'total': len(traffic_stats)
    }

def prepare_timeline_chart_data(alerts: list):
    """Prépare les données pour le graphique de timeline (Chart.js)."""
    if not alerts:
        return {'labels': [], 'data': [], 'total': 0}
    
    hourly_counts = defaultdict(int)
    for alert in alerts:
        timestamp = alert.get('timestamp') if isinstance(alert, dict) else alert.timestamp
        if isinstance(timestamp, str):
            timestamp = datetime.datetime.fromisoformat(timestamp)
        hour_key = timestamp.strftime('%Y-%m-%d %H:00')
        hourly_counts[hour_key] += 1
    
    sorted_hours = sorted(hourly_counts.keys())
    labels = [h.split(' ')[1] for h in sorted_hours]
    data = [hourly_counts[h] for h in sorted_hours]
    
    return {
        'labels': labels,
        'data': data,
        'total': len(alerts)
    }

def prepare_severity_chart_data(alerts: list):
    """Prépare les données pour le graphique de sévérité (Chart.js)."""
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for alert in alerts:
        event_type = (alert.get('event_type', '') if isinstance(alert, dict) else alert.event_type).upper()
        if 'HIGH' in event_type or 'CRITICAL' in event_type:
            severity_counts['HIGH'] += 1
        elif 'MEDIUM' in event_type or 'WARNING' in event_type:
            severity_counts['MEDIUM'] += 1
        elif 'LOW' in event_type:
            severity_counts['LOW'] += 1
        else:
            severity_counts['INFO'] += 1
    
    labels = [k for k, v in severity_counts.items() if v > 0]
    data = [v for v in severity_counts.values() if v > 0]
    
    return {
        'labels': labels,
        'data': data,
        'total': len(alerts)
    }
