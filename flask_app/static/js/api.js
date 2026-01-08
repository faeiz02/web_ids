/**
 * Client API pour le Moniteur de Sécurité Réseau
 * Version améliorée avec support complet des options de scan
 */

const API_BASE_URL = window.location.origin;

const API = {
    /**
     * Module Scanner - Opérations de scan réseau
     */
    scanner: {
        /**
         * Effectue un scan complet du réseau avec toutes les options
         * @param {string} targetRange - Plage réseau (ex: '192.168.1.0/24')
         * @param {string} ports - Plage de ports (ex: '1-100', '80,443')
         * @param {string} detection - Niveau de détection ('none' ou 'services')
         * @param {string} speed - Vitesse du scan ('T1' à 'T5')
         * @param {string} format - Format de sortie ('normal', 'detailed', 'json', 'xml')
         */
        performFullScan: async (targetRange, ports = '1-100', detection = 'none', speed = 'T3', format = 'normal') => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/scan/full`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target_range: targetRange,
                        ports: ports,
                        detection: detection,
                        speed: speed,
                        format: format
                    })
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Erreur lors du scan');
                }

                return await response.json();
            } catch (error) {
                console.error('Erreur API performFullScan:', error);
                throw error;
            }
        },

        /**
         * Effectue un scan manuel de ports sur un hôte spécifique
         * @param {string} hostIp - Adresse IP cible
         * @param {string} ports - Plage de ports
         * @param {string} detection - Niveau de détection
         * @param {string} speed - Vitesse du scan
         * @param {string} format - Format de sortie
         */
        scanPorts: async (hostIp, ports = '1-1024', detection = 'none', speed = 'T3', format = 'normal') => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/scan/ports`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        host_ip: hostIp,
                        ports: ports,
                        detection: detection,
                        speed: speed,
                        format: format
                    })
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Erreur lors du scan');
                }

                return await response.json();
            } catch (error) {
                console.error('Erreur API scanPorts:', error);
                throw error;
            }
        },

        /**
         * Récupère le statut du scan en cours
         */
        getStatus: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/scan/status`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API getStatus:', error);
                throw error;
            }
        },

        /**
         * Récupère les résultats du dernier scan
         */
        getResults: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/scan/results`);

                if (response.status === 404) {
                    return null; // Aucun résultat disponible
                }

                if (!response.ok) {
                    throw new Error('Erreur lors de la récupération des résultats');
                }

                return await response.json();
            } catch (error) {
                console.error('Erreur API getResults:', error);
                throw error;
            }
        },

        /**
         * Exporte les résultats du scan
         * @param {string} format - Format d'export ('json', 'xml', 'txt')
         * @param {string} filename - Nom du fichier (optionnel)
         */
        exportResults: async (format = 'json', filename = null) => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/scan/export`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        format: format,
                        filename: filename
                    })
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Erreur lors de l\'export');
                }

                return await response.json();
            } catch (error) {
                console.error('Erreur API exportResults:', error);
                throw error;
            }
        },

        /**
         * Récupère la liste des hôtes actifs
         */
        getHosts: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/hosts`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API getHosts:', error);
                throw error;
            }
        }
    },

    /**
     * Module IDS - Système de détection d'intrusion
     */
    ids: {
        /**
         * Récupère le statut de l'IDS
         */
        getStatus: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/ids/status`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API IDS getStatus:', error);
                throw error;
            }
        },

        /**
         * Démarre la surveillance IDS
         * @param {string} interface - Interface réseau (optionnel)
         */
        start: async (interface = null) => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/ids/start`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ interface: interface })
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Erreur lors du démarrage de l\'IDS');
                }

                return await response.json();
            } catch (error) {
                console.error('Erreur API IDS start:', error);
                throw error;
            }
        },

        /**
         * Arrête la surveillance IDS
         */
        stop: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/ids/stop`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Erreur lors de l\'arrêt de l\'IDS');
                }

                return await response.json();
            } catch (error) {
                console.error('Erreur API IDS stop:', error);
                throw error;
            }
        }
    },

    /**
     * Module Alerts - Gestion des alertes
     */
    alerts: {
        /**
         * Récupère toutes les alertes
         */
        getAll: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/alerts`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API alerts getAll:', error);
                throw error;
            }
        },

        /**
         * Récupère les alertes actives (non acquittées)
         */
        getActive: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/alerts/active`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API alerts getActive:', error);
                throw error;
            }
        },

        /**
         * Acquitte une alerte
         * @param {string} alertId - ID de l'alerte
         */
        acknowledge: async (alertId) => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/alerts/${alertId}/acknowledge`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Erreur lors de l\'acquittement');
                }

                return await response.json();
            } catch (error) {
                console.error('Erreur API alerts acknowledge:', error);
                throw error;
            }
        },

        /**
         * Récupère le nombre d'alertes
         */
        getCount: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/alerts/count`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API alerts getCount:', error);
                throw error;
            }
        }
    },

    /**
     * Module Logs - Consultation des logs
     */
    logs: {
        /**
         * Récupère les logs
         * @param {number} limit - Nombre maximum de logs à récupérer
         */
        get: async (limit = 100) => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/logs?limit=${limit}`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API logs get:', error);
                throw error;
            }
        },

        /**
         * Récupère le nombre total de logs
         */
        getCount: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/logs/count`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API logs getCount:', error);
                throw error;
            }
        }
    },

    /**
     * Module Visualization - Graphiques et visualisations
     */
    visualization: {
        /**
         * Récupère les données pour le graphique des alertes
         */
        getAlertsChart: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/visualization/alerts`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API visualization alerts:', error);
                throw error;
            }
        },

        /**
         * Récupère les données pour le graphique du trafic
         */
        getTrafficChart: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/visualization/traffic`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API visualization traffic:', error);
                throw error;
            }
        },

        /**
         * Récupère les données pour le graphique de la timeline
         */
        getTimelineChart: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/visualization/timeline`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API visualization timeline:', error);
                throw error;
            }
        },

        /**
         * Récupère les données pour le graphique de sévérité
         */
        getSeverityChart: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/visualization/severity`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API visualization severity:', error);
                throw error;
            }
        }
    },

    /**
     * Module Stats - Statistiques globales
     */
    stats: {
        /**
         * Récupère toutes les statistiques du système
         */
        getAll: async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/stats`);
                return await response.json();
            } catch (error) {
                console.error('Erreur API stats getAll:', error);
                throw error;
            }
        }
    }
};

/**
 * Système de notifications Toast
 */
const Toast = {
    /**
     * Affiche une notification de succès
     * @param {string} message - Message à afficher
     */
    success: (message) => {
        console.log('✅ SUCCESS:', message);
        // Implémenter ici l'affichage visuel (toast notification)
        if (typeof showToast === 'function') {
            showToast(message, 'success');
        }
    },

    /**
     * Affiche une notification d'erreur
     * @param {string} message - Message d'erreur
     */
    error: (message) => {
        console.error('❌ ERROR:', message);
        // Implémenter ici l'affichage visuel (toast notification)
        if (typeof showToast === 'function') {
            showToast(message, 'error');
        }
    },

    /**
     * Affiche une notification d'information
     * @param {string} message - Message d'information
     */
    info: (message) => {
        console.info('ℹ️ INFO:', message);
        // Implémenter ici l'affichage visuel (toast notification)
        if (typeof showToast === 'function') {
            showToast(message, 'info');
        }
    },

    /**
     * Affiche une notification d'avertissement
     * @param {string} message - Message d'avertissement
     */
    warning: (message) => {
        console.warn('⚠️ WARNING:', message);
        // Implémenter ici l'affichage visuel (toast notification)
        if (typeof showToast === 'function') {
            showToast(message, 'warning');
        }
    }
};

// Exporter pour utilisation dans d'autres fichiers
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { API, Toast };
}