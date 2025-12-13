/**
 * Logs Page JavaScript
 * Handles tab switching, log fetching, filtering, and auto-refresh functionality.
 */

(function() {
    'use strict';

    // State
    let autoRefreshInterval = null;
    let eventsOffset = 0;
    const EVENTS_LIMIT = 50;

    // DOM Elements
    const tabButtons = document.querySelectorAll('.log-tab');
    const tabContents = document.querySelectorAll('.log-tab-content');

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', function() {
        initTabs();
        initAppLogs();
        initScanLogs();
        initEvents();

        // Re-create lucide icons after dynamic content
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    });

    /**
     * Initialize tab switching
     */
    function initTabs() {
        tabButtons.forEach(button => {
            button.addEventListener('click', function() {
                const tabId = this.dataset.tab;

                // Update active states
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));

                this.classList.add('active');
                document.getElementById(tabId).classList.add('active');

                // Load content for the selected tab
                if (tabId === 'app-logs') {
                    loadAppLogs();
                } else if (tabId === 'scan-logs') {
                    loadScanLogs();
                } else if (tabId === 'events') {
                    loadEvents(true);
                }
            });
        });
    }

    /**
     * Initialize App Logs tab
     */
    function initAppLogs() {
        const refreshBtn = document.getElementById('refresh-app-logs');
        const autoRefreshCheckbox = document.getElementById('app-auto-refresh');
        const levelSelect = document.getElementById('app-log-level');
        const linesInput = document.getElementById('app-log-lines');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadAppLogs);
        }

        if (autoRefreshCheckbox) {
            autoRefreshCheckbox.addEventListener('change', function() {
                if (this.checked) {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
            });
        }

        if (levelSelect) {
            levelSelect.addEventListener('change', loadAppLogs);
        }

        if (linesInput) {
            linesInput.addEventListener('change', loadAppLogs);
        }

        // Load initial data
        loadAppLogs();
    }

    /**
     * Initialize Scan Logs tab
     */
    function initScanLogs() {
        const refreshBtn = document.getElementById('refresh-scan-logs');
        const typeSelect = document.getElementById('scan-log-type');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadScanLogs);
        }

        if (typeSelect) {
            typeSelect.addEventListener('change', loadScanLogs);
        }
    }

    /**
     * Initialize Events tab
     */
    function initEvents() {
        const refreshBtn = document.getElementById('refresh-events');
        const typeSelect = document.getElementById('event-type');
        const loadMoreBtn = document.getElementById('load-more-events');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => loadEvents(true));
        }

        if (typeSelect) {
            typeSelect.addEventListener('change', () => loadEvents(true));
        }

        if (loadMoreBtn) {
            loadMoreBtn.addEventListener('click', () => loadEvents(false));
        }
    }

    /**
     * Load application logs from API
     */
    async function loadAppLogs() {
        const container = document.getElementById('app-log-container');
        const levelSelect = document.getElementById('app-log-level');
        const linesInput = document.getElementById('app-log-lines');

        if (!container) return;

        container.innerHTML = '<div class="log-loading">Loading logs...</div>';

        try {
            const params = new URLSearchParams();
            params.set('lines', linesInput?.value || '100');
            if (levelSelect?.value) {
                params.set('level', levelSelect.value);
            }

            const response = await fetch(`/api/logs/app?${params}`);
            if (!response.ok) throw new Error('Failed to fetch logs');

            const logs = await response.json();

            if (logs.length === 0) {
                container.innerHTML = '<div class="log-empty">No log entries found</div>';
                return;
            }

            container.innerHTML = logs.map(log => renderAppLogEntry(log)).join('');

        } catch (error) {
            console.error('Error loading app logs:', error);
            container.innerHTML = `<div class="log-empty">Error loading logs: ${error.message}</div>`;
        }
    }

    /**
     * Render a single app log entry
     */
    function renderAppLogEntry(log) {
        const level = (log.level || log.log_type || 'info').toLowerCase();
        const timestamp = formatTimestamp(log.timestamp);

        return `
            <div class="log-entry">
                <span class="log-timestamp">${timestamp}</span>
                <span class="log-level ${level}">${(log.level || level).toUpperCase()}</span>
                <span class="log-message">${escapeHtml(log.message)}</span>
                ${log.logger ? `<span class="log-logger">${escapeHtml(log.logger)}</span>` : ''}
            </div>
        `;
    }

    /**
     * Load scan logs from API
     */
    async function loadScanLogs() {
        const container = document.getElementById('scan-log-container');
        const typeSelect = document.getElementById('scan-log-type');

        if (!container) return;

        container.innerHTML = '<div class="log-loading">Loading scan logs...</div>';

        try {
            const params = new URLSearchParams();
            params.set('limit', '200');
            if (typeSelect?.value) {
                params.set('log_type', typeSelect.value);
            }

            const response = await fetch(`/api/logs/scans?${params}`);
            if (!response.ok) throw new Error('Failed to fetch scan logs');

            const logs = await response.json();

            if (logs.length === 0) {
                container.innerHTML = '<div class="log-empty">No scan log entries found</div>';
                return;
            }

            container.innerHTML = logs.map(log => renderScanLogEntry(log)).join('');

        } catch (error) {
            console.error('Error loading scan logs:', error);
            container.innerHTML = `<div class="log-empty">Error loading logs: ${error.message}</div>`;
        }
    }

    /**
     * Render a single scan log entry
     */
    function renderScanLogEntry(log) {
        const level = (log.log_type || 'info').toLowerCase();
        const timestamp = formatTimestamp(log.timestamp);
        const shortScanId = log.scan_id ? log.scan_id.substring(0, 8) : '';

        return `
            <div class="log-entry">
                <span class="log-timestamp">${timestamp}</span>
                <span class="log-level ${level}">${level.toUpperCase()}</span>
                <span class="log-message">${escapeHtml(log.message)}</span>
                ${shortScanId ? `<a href="/scan/${log.scan_id}" class="log-logger" title="View scan">${shortScanId}...</a>` : ''}
            </div>
        `;
    }

    /**
     * Load events from API
     * @param {boolean} reset - Whether to reset offset and replace content
     */
    async function loadEvents(reset = false) {
        const container = document.getElementById('events-container');
        const typeSelect = document.getElementById('event-type');
        const loadMoreBtn = document.getElementById('load-more-events');

        if (!container) return;

        if (reset) {
            eventsOffset = 0;
            container.innerHTML = '<div class="log-loading">Loading events...</div>';
        }

        try {
            const params = new URLSearchParams();
            params.set('limit', EVENTS_LIMIT.toString());
            params.set('offset', eventsOffset.toString());
            if (typeSelect?.value) {
                params.set('event_type', typeSelect.value);
            }

            const response = await fetch(`/api/logs/events?${params}`);
            if (!response.ok) throw new Error('Failed to fetch events');

            const events = await response.json();

            if (events.length === 0 && reset) {
                container.innerHTML = '<div class="log-empty">No events found</div>';
                if (loadMoreBtn) loadMoreBtn.style.display = 'none';
                return;
            }

            const eventsHtml = events.map(event => renderEventEntry(event)).join('');

            if (reset) {
                container.innerHTML = eventsHtml;
            } else {
                container.insertAdjacentHTML('beforeend', eventsHtml);
            }

            eventsOffset += events.length;

            // Show/hide load more button
            if (loadMoreBtn) {
                loadMoreBtn.style.display = events.length < EVENTS_LIMIT ? 'none' : 'inline-flex';
            }

        } catch (error) {
            console.error('Error loading events:', error);
            if (reset) {
                container.innerHTML = `<div class="log-empty">Error loading events: ${error.message}</div>`;
            }
        }
    }

    /**
     * Render a single event entry
     */
    function renderEventEntry(event) {
        const timestamp = formatTimestamp(event.timestamp);
        const eventType = event.event_type || 'unknown';

        let detailsHtml = '';
        if (event.details) {
            const details = [];
            if (event.details.scan_id) {
                details.push(`<a href="/scan/${event.details.scan_id}">View Scan</a>`);
            }
            if (event.details.status) {
                details.push(`Status: ${event.details.status}`);
            }
            if (event.details.error_message) {
                details.push(`Error: ${event.details.error_message}`);
            }
            if (details.length > 0) {
                detailsHtml = `<div class="event-details">${details.join(' | ')}</div>`;
            }
        }

        return `
            <div class="log-entry">
                <div class="event-header">
                    <span class="log-timestamp">${timestamp}</span>
                    <span class="event-type ${eventType}">${formatEventType(eventType)}</span>
                    <span class="log-message">${escapeHtml(event.message)}</span>
                </div>
                ${detailsHtml}
            </div>
        `;
    }

    /**
     * Format event type for display
     */
    function formatEventType(type) {
        const typeMap = {
            'scan': 'Scan',
            'notification': 'Notification',
            'port_change': 'Port Change',
            'host_check': 'Host Check'
        };
        return typeMap[type] || type;
    }

    /**
     * Start auto-refresh for app logs
     */
    function startAutoRefresh() {
        stopAutoRefresh();
        autoRefreshInterval = setInterval(loadAppLogs, 5000);
    }

    /**
     * Stop auto-refresh
     */
    function stopAutoRefresh() {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
        }
    }

    /**
     * Format timestamp for display
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return '-';

        try {
            const date = new Date(timestamp);
            if (isNaN(date.getTime())) return timestamp;

            // Format: YYYY-MM-DD HH:MM:SS
            const year = date.getFullYear();
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const day = String(date.getDate()).padStart(2, '0');
            const hours = String(date.getHours()).padStart(2, '0');
            const minutes = String(date.getMinutes()).padStart(2, '0');
            const seconds = String(date.getSeconds()).padStart(2, '0');

            return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
        } catch (e) {
            return timestamp;
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

})();
