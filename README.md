# 🛡️ Web IDS — Moniteur de Sécurité Réseau Python

> Système de Détection d'Intrusion (IDS) et Scanner Réseau avec interface web Flask.

---

## 📋 Table des Matières

- [Présentation](#-présentation)
- [Fonctionnalités](#-fonctionnalités)
- [Technologies Utilisées](#-technologies-utilisées)
- [Architecture du Projet](#-architecture-du-projet)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Configuration](#-configuration)
- [Signatures d'Attaques](#-signatures-dattaques)
- [Script de Test (Kali)](#-script-de-test-kali)
- [Endpoints API](#-endpoints-api)
- [Auteur](#-auteur)

---

## 🎯 Présentation

**Web IDS** est une application de cybersécurité qui combine :

1. **Un Scanner Réseau** — découvre les hôtes actifs sur un réseau et identifie leurs ports ouverts et services.
2. **Un Système de Détection d'Intrusion (IDS)** — surveille le trafic réseau en temps réel pour détecter les attaques.
3. **Une Interface Web (Dashboard)** — permet de piloter le tout depuis un navigateur avec des graphiques et des statistiques en direct.

---

## ✨ Fonctionnalités

### Scanner Réseau (Nmap)
- Découverte d'hôtes actifs sur un sous-réseau (ping scan)
- Scan de ports TCP (Connect ou SYN)
- Détection des services et versions (`-sV`)
- Détection du système d'exploitation (`-O`)
- Scan parallèle multi-threads configurable
- Profils de vitesse (T1 à T5)

### Détection d'Intrusion (Scapy)
- **Scan de ports** — détecte les balayages de ports (paquets SYN multiples)
- **Brute Force SSH** — détecte les tentatives répétées de connexion sur le port 22
- **DoS / DDoS** — détecte les attaques par volume de trafic et par flood de paquets (PPS)
- **ICMP Flood** — détecte les attaques par ping flood
- **Détection par signatures** — analyse le payload des paquets TCP/UDP pour y chercher des patterns d'attaques connus :
  - Injection de commandes / RCE
  - Shellshock
  - Accès à des fichiers sensibles (`.env`, `wp-config.php`, `id_rsa`)
  - User-Agents de scanners malveillants (sqlmap, nikto, etc.)
  - Beacons de malware C2 (UDP)
  - Mots de passe en clair

### Interface Web
- **Dashboard** — vue d'ensemble avec statistiques (hôtes, alertes, statut IDS)
- **Scan** — lancer / arrêter des scans réseau, voir les résultats
- **Alertes** — consulter, filtrer et acquitter les alertes de sécurité
- **Logs** — historique complet des événements du système
- **Visualisation** — graphiques interactifs (Chart.js) et images statiques (Matplotlib)
- **Configuration** — modifier les seuils de détection, les signatures et les paramètres du scanner

---

## 🔧 Technologies Utilisées

| Composant | Technologie | Rôle |
|---|---|---|
| **Langage principal** | Python 3 | Logique métier, IDS, scanner, API |
| **Capture réseau** | [Scapy](https://scapy.net/) | Sniffing de paquets, analyse protocolaire (IP, TCP, UDP, ICMP) |
| **Scan réseau** | [Nmap](https://nmap.org/) + [python-nmap](https://pypi.org/project/python-nmap/) | Découverte d'hôtes, scan de ports, détection de services/OS |
| **Framework web** | [Flask](https://flask.palletsprojects.com/) | Serveur HTTP, routage, API REST, rendu de templates HTML |
| **CORS** | Flask-CORS | Gestion des requêtes cross-origin |
| **Graphiques serveur** | [Matplotlib](https://matplotlib.org/) | Génération d'images PNG encodées en Base64 (barres, courbes, camemberts) |
| **Graphiques client** | [Chart.js](https://www.chartjs.org/) | Graphiques interactifs dynamiques dans le navigateur |
| **Front-end** | HTML5, CSS3, JavaScript | Interface utilisateur, templates Jinja2 |
| **Stockage** | JSON / JSONL (fichiers plats) | Persistance des logs, alertes, configuration et signatures |
| **Parallélisation** | `threading`, `concurrent.futures` | Threads pour l'IDS, ThreadPoolExecutor pour les scans parallèles |

---

## 🏗️ Architecture du Projet

```
web_ids/
│
├── run.py                  # Point d'entrée — lance le serveur Flask
├── ids.py                  # Système de Détection d'Intrusion (Scapy)
├── scanner.py              # Scanner réseau (python-nmap)
├── models.py               # Modèles de données (Host, Alert, Log)
├── managers.py             # Gestionnaires (AlertManager, LogManager)
├── utils.py                # Utilitaires de visualisation (Matplotlib + Chart.js)
│
├── config.json             # Configuration des seuils et paramètres
├── signatures.json         # Signatures d'attaques (regex)
├── alerts.jsonl            # Fichier de persistance des alertes
├── logs.jsonl              # Fichier de persistance des logs
├── alert_cache.json        # Cache de déduplication des alertes
│
├── kali_attack.sh          # Script de simulation d'attaques (Kali Linux)
│
├── flask_app/
│   ├── app.py              # Application Flask (routes + API REST)
│   ├── templates/          # Templates HTML (Jinja2)
│   │   ├── layout.html     #   └─ Template de base
│   │   ├── index.html      #   └─ Page d'accueil
│   │   ├── dashboard.html  #   └─ Tableau de bord
│   │   ├── scan.html       #   └─ Page de scan réseau
│   │   ├── alerts.html     #   └─ Page des alertes
│   │   ├── logs.html       #   └─ Page des logs
│   │   ├── visualization.html # └─ Page de visualisation
│   │   ├── config.html     #   └─ Page de configuration
│   │   ├── 404.html        #   └─ Page d'erreur 404
│   │   └── 500.html        #   └─ Page d'erreur 500
│   └── static/
│       ├── css/            # Feuilles de style
│       └── js/             # Scripts JavaScript
│
└── nmap_portable/          # Distribution portable de Nmap (optionnel)
```

### Diagramme d'Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Navigateur Web                     │
│         (Dashboard, Alertes, Logs, Graphiques)       │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP (port 5000)
                       ▼
┌─────────────────────────────────────────────────────┐
│                   Flask (app.py)                     │
│         Routes HTML + API REST (JSON)                │
│                                                      │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Scanner  │  │     IDS      │  │    Utils      │  │
│  │ (Nmap)   │  │  (Scapy)     │  │ (Matplotlib)  │  │
│  └────┬─────┘  └──────┬───────┘  └───────────────┘  │
│       │               │                              │
│  ┌────┴─────┐  ┌──────┴───────┐                     │
│  │ LogMgr   │  │  AlertMgr    │                     │
│  └────┬─────┘  └──────┬───────┘                     │
└───────┼───────────────┼─────────────────────────────┘
        │               │
        ▼               ▼
   logs.jsonl      alerts.jsonl
```

---

## 📦 Prérequis

- **Python 3.8+**
- **Nmap** installé et accessible dans le `PATH` (ou utiliser le dossier `nmap_portable/`)
- **Privilèges administrateur / root** requis pour :
  - Le sniffing de paquets (IDS via Scapy)
  - Les scans SYN (`-sS`) de Nmap

### Bibliothèques Python

```
flask
flask-cors
scapy
python-nmap
matplotlib
```

---

## 🚀 Installation

1. **Cloner le dépôt**
   ```bash
   git clone <url-du-depot>
   cd web_ids
   ```

2. **Installer les dépendances Python**
   ```bash
   pip install flask flask-cors scapy python-nmap matplotlib
   ```

3. **Vérifier que Nmap est installé**
   ```bash
   nmap --version
   ```

4. **Lancer l'application**
   ```bash
   # Sous Linux/macOS (avec privilèges root pour Scapy)
   sudo python run.py

   # Sous Windows (en tant qu'Administrateur)
   python run.py
   ```

5. **Ouvrir le navigateur** sur `http://localhost:5000`

---

## 🖥️ Utilisation

### Lancer un scan réseau
1. Aller sur la page **Scan**
2. Entrer la plage cible (ex: `192.168.1.0/24`)
3. Choisir les ports, la méthode de scan et le niveau de détection
4. Cliquer sur **Lancer le scan**

### Activer l'IDS
1. Aller sur le **Dashboard** ou utiliser l'API
2. Cliquer sur **Démarrer l'IDS**
3. L'IDS commence à capturer et analyser le trafic réseau en arrière-plan
4. Les alertes apparaissent en temps réel sur la page **Alertes**

### Visualiser les résultats
- **Dashboard** : statistiques globales
- **Alertes** : liste des menaces détectées (acquittement possible)
- **Logs** : historique complet des événements
- **Visualisation** : graphiques interactifs et images générées

---

## ⚙️ Configuration

La configuration se fait via le fichier `config.json` ou directement depuis la page **Configuration** de l'interface web.

```json
{
  "thresholds": {
    "dos_volume": 90177536,
    "port_scan_max_ports": 3,
    "ssh_bruteforce_attempts": 1,
    "icmp_flood_packets": 10
  },
  "scanner": {
    "max_threads": 20,
    "min_parallelism": 75,
    "min_rate": 250
  },
  "whitelist": [
    "127.0.0.1",
    "::1"
  ]
}
```

| Paramètre | Description |
|---|---|
| `dos_volume` | Volume de trafic (octets) avant de déclencher une alerte DoS |
| `port_scan_max_ports` | Nombre de ports différents scannés avant alerte |
| `ssh_bruteforce_attempts` | Tentatives SSH avant alerte brute force |
| `icmp_flood_packets` | Paquets ICMP avant alerte flood |
| `max_threads` | Nombre de threads pour le scan parallèle |
| `min_parallelism` | Nombre de probes parallèles Nmap |
| `min_rate` | Débit minimum de paquets/seconde pour Nmap |
| `whitelist` | Adresses IP à ignorer (pas d'alerte générée) |

---

## 🔍 Signatures d'Attaques

Les signatures sont définies dans `signatures.json`. Chaque signature comporte :

| Champ | Description |
|---|---|
| `id` | Identifiant unique (ex: `SIG-004`) |
| `name` | Nom de l'attaque |
| `pattern` | Expression régulière à chercher dans le payload |
| `protocol` | Protocole ciblé (`TCP` ou `UDP`) |
| `port` | Port spécifique (0 = tous les ports) |
| `severity` | Niveau de sévérité (`Low`, `Medium`, `High`, `Critical`) |

### Signatures pré-configurées

| ID | Nom | Sévérité |
|---|---|---|
| SIG-004 | Command Injection / RCE | Critical |
| SIG-005 | Shellshock Vulnerability | Critical |
| SIG-006 | Sensitive File Access | High |
| SIG-007 | Malicious Scanner User-Agent | Low |
| SIG-008 | Malware C2 Beacon (UDP) | Critical |
| SIG-009 | Cleartext Password | High |

Les signatures peuvent être ajoutées, modifiées ou supprimées via l'API REST ou la page **Configuration**.

---

## 🗡️ Script de Test (Kali)

Le fichier `kali_attack.sh` permet de simuler différents vecteurs d'attaque depuis une machine Kali Linux pour tester la détection :

```bash
# Modifier TARGET_IP et TARGET_PORT si nécessaire
sudo bash kali_attack.sh
```

**Attaques simulées :**
1. **Scan de ports** — Nmap sur 10 ports
2. **Injection de commandes** — curl avec payload malveillant
3. **Shellshock** — Header User-Agent exploitant la faille
4. **Fichiers sensibles** — Accès à `.env`
5. **Scanner malveillant** — User-Agent `sqlmap`
6. **Mot de passe clair** — POST avec `password=`
7. **Beacon C2** — Paquet UDP `C2_HEARTBEAT_REQUEST`
8. **ICMP Flood** — 100 pings rapides via `hping3`
9. **SYN Flood** — 300 paquets SYN via `hping3`

---

## 🌐 Endpoints API

### Scanner

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/scan/status` | Statut du scan en cours |
| `POST` | `/api/scan/full` | Lancer un scan réseau complet |
| `POST` | `/api/scan/ports` | Scanner les ports d'un hôte spécifique |
| `POST` | `/api/scan/stop` | Arrêter le scan en cours |
| `GET` | `/api/hosts` | Liste des hôtes actifs découverts |

### IDS

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/ids/status` | Statut de l'IDS (actif/inactif + stats trafic) |
| `POST` | `/api/ids/start` | Démarrer la surveillance IDS |
| `POST` | `/api/ids/stop` | Arrêter la surveillance IDS |

### Alertes

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/alerts` | Toutes les alertes |
| `GET` | `/api/alerts/active` | Alertes non acquittées |
| `GET` | `/api/alerts/count` | Nombre d'alertes (total + actives) |
| `POST` | `/api/alerts/<id>/acknowledge` | Acquitter une alerte |

### Logs & Statistiques

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/logs` | Derniers logs (paramètre `?limit=N`) |
| `GET` | `/api/logs/count` | Nombre total de logs |
| `GET` | `/api/stats` | Statistiques globales du système |

### Visualisation

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/visualization/alerts` | Données des alertes par type |
| `GET` | `/api/visualization/traffic` | Données du volume de trafic |
| `GET` | `/api/visualization/timeline` | Évolution temporelle des alertes |
| `GET` | `/api/visualization/severity` | Distribution par sévérité |

### Configuration & Signatures

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/config` | Configuration actuelle |
| `PUT` | `/api/config/thresholds` | Modifier les seuils IDS |
| `PUT` | `/api/config/scanner` | Modifier les paramètres du scanner |
| `GET` | `/api/signatures` | Liste des signatures |
| `POST` | `/api/signatures` | Ajouter une signature |
| `PUT` | `/api/signatures/<id>` | Modifier une signature |
| `DELETE` | `/api/signatures/<id>` | Supprimer une signature |

---

## 📄 Licence

Ce projet est développé dans un cadre éducatif et de recherche en cybersécurité.

> ⚠️ **Avertissement** : Cet outil est destiné à être utilisé uniquement sur des réseaux dont vous avez l'autorisation. L'utilisation de cet outil pour scanner ou attaquer des réseaux sans autorisation est illégale.
