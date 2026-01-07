/**
 * Fonctions utilitaires globales
 */

/**
 * Formate une date au format français
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    const options = {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    };
    return date.toLocaleDateString('fr-FR', options);
}

/**
 * Formate une date en temps relatif (ex: "il y a 2 heures")
 */
function formatRelativeTime(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (seconds < 60) return 'à l\'instant';
    if (minutes < 60) return `il y a ${minutes} minute${minutes > 1 ? 's' : ''}`;
    if (hours < 24) return `il y a ${hours} heure${hours > 1 ? 's' : ''}`;
    if (days < 7) return `il y a ${days} jour${days > 1 ? 's' : ''}`;
    
    return formatDate(dateString);
}

/**
 * Formate une taille de fichier en unités lisibles
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Copie du texte dans le presse-papiers
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        Toast.success('Copié dans le presse-papiers');
    }).catch(() => {
        Toast.error('Erreur lors de la copie');
    });
}

/**
 * Valide une adresse IP
 */
function isValidIP(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => parseInt(part) >= 0 && parseInt(part) <= 255);
}

/**
 * Valide une plage CIDR
 */
function isValidCIDR(cidr) {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrRegex.test(cidr)) return false;
    
    const [ip, mask] = cidr.split('/');
    const maskNum = parseInt(mask);
    
    return isValidIP(ip) && maskNum >= 0 && maskNum <= 32;
}

/**
 * Valide une plage de ports
 */
function isValidPortRange(range) {
    const rangeRegex = /^\d+(-\d+)?$/;
    if (!rangeRegex.test(range)) return false;
    
    if (range.includes('-')) {
        const [start, end] = range.split('-').map(Number);
        return start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end;
    } else {
        const port = parseInt(range);
        return port >= 1 && port <= 65535;
    }
}

/**
 * Crée un élément avec classe et contenu
 */
function createElement(tag, className = '', innerHTML = '') {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (innerHTML) element.innerHTML = innerHTML;
    return element;
}

/**
 * Affiche un spinner de chargement
 */
function showSpinner(container) {
    const spinner = createElement('div', 'spinner');
    container.appendChild(spinner);
    return spinner;
}

/**
 * Affiche un message vide
 */
function showEmptyState(container, message = 'Aucune donnée disponible') {
    container.innerHTML = `
        <div style="text-align: center; padding: 2rem; color: var(--text-tertiary);">
            <i class="fas fa-inbox" style="font-size: 3rem; margin-bottom: 1rem; display: block; opacity: 0.5;"></i>
            <p>${message}</p>
        </div>
    `;
}

/**
 * Affiche un message d'erreur
 */
function showError(container, message = 'Une erreur est survenue') {
    container.innerHTML = `
        <div class="alert alert-danger">
            <i class="fas fa-exclamation-circle"></i>
            <span>${message}</span>
        </div>
    `;
}

/**
 * Débounce une fonction
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Throttle une fonction
 */
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 * Récupère les paramètres de l'URL
 */
function getUrlParams() {
    const params = new URLSearchParams(window.location.search);
    const result = {};
    for (let [key, value] of params) {
        result[key] = value;
    }
    return result;
}

/**
 * Ajoute des paramètres à l'URL
 */
function updateUrlParams(params) {
    const url = new URL(window.location);
    Object.keys(params).forEach(key => {
        url.searchParams.set(key, params[key]);
    });
    window.history.replaceState({}, '', url);
}

/**
 * Détermine la couleur d'un badge basée sur le type
 */
function getBadgeClass(type) {
    const typeMap = {
        'success': 'badge-success',
        'error': 'badge-danger',
        'danger': 'badge-danger',
        'warning': 'badge-warning',
        'info': 'badge-info',
        'Port_Scan': 'badge-danger',
        'DoS_Simple': 'badge-danger',
        'Intrusion': 'badge-danger'
    };
    return typeMap[type] || 'badge-info';
}

/**
 * Obtient l'icône basée sur le type d'événement
 */
function getEventIcon(type) {
    const iconMap = {
        'Port_Scan': 'fa-network-wired',
        'DoS_Simple': 'fa-exclamation-triangle',
        'Intrusion': 'fa-shield-alt',
        'SCAN_START': 'fa-play',
        'SCAN_END': 'fa-check',
        'HOST_DETECTED': 'fa-desktop',
        'PORT_OPEN': 'fa-door-open',
        'IDS_START': 'fa-play-circle',
        'IDS_STOP': 'fa-stop-circle',
        'ALERT_ACK': 'fa-check-double'
    };
    return iconMap[type] || 'fa-info-circle';
}

/**
 * Exporte les données en CSV
 */
function exportToCSV(data, filename = 'export.csv') {
    if (!Array.isArray(data) || data.length === 0) {
        Toast.warning('Aucune donnée à exporter');
        return;
    }
    
    const headers = Object.keys(data[0]);
    const csv = [
        headers.join(','),
        ...data.map(row => 
            headers.map(header => {
                const value = row[header];
                // Échappe les valeurs contenant des guillemets ou des virgules
                if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
                    return `"${value.replace(/"/g, '""')}"`;
                }
                return value;
            }).join(',')
        )
    ].join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    Toast.success('Données exportées');
}

/**
 * Initialise les tooltips
 */
function initTooltips() {
    const tooltips = document.querySelectorAll('[title]');
    tooltips.forEach(element => {
        element.addEventListener('mouseenter', (e) => {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = e.target.title;
            tooltip.style.cssText = `
                position: absolute;
                background-color: var(--bg-tertiary);
                color: var(--text-primary);
                padding: 0.5rem 1rem;
                border-radius: 4px;
                font-size: 0.875rem;
                z-index: 1000;
                white-space: nowrap;
                pointer-events: none;
            `;
            document.body.appendChild(tooltip);
            
            const rect = e.target.getBoundingClientRect();
            tooltip.style.left = (rect.left + rect.width / 2 - tooltip.offsetWidth / 2) + 'px';
            tooltip.style.top = (rect.top - tooltip.offsetHeight - 10) + 'px';
            
            element.addEventListener('mouseleave', () => tooltip.remove());
        });
    });
}

// Initialiser les tooltips au chargement
document.addEventListener('DOMContentLoaded', initTooltips);
