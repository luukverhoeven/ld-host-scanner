/**
 * Dashboard JavaScript
 */

// Active SSE connection
let progressEventSource = null;

// Scan timing state
let scanStartTime = null;
let elapsedTimerId = null;
let lastLogCount = 0;

// Track discovered ports to avoid duplicates
let knownDiscoveredPorts = new Set();

// Phase display names
const PHASE_NAMES = {
    'starting': 'Starting scan...',
    'scanning': 'Scanning ports...',
    'enriching': 'Detecting services...',
    'saving': 'Saving results...',
    'completed': 'Scan complete!'
};

// Status icons for TCP/UDP indicators
const STATUS_ICONS = {
    'not_started': '&#9675;',  // Empty circle
    'in_progress': '&#9684;',  // Half circle
    'completed': '&#9679;'     // Filled circle
};

// Status text mapping
const STATUS_TEXT = {
    'not_started': 'Waiting...',
    'in_progress': 'Scanning...',
    'completed': 'Done'
};

// Update elapsed time display
function updateElapsedTime() {
    if (!scanStartTime) return;

    const elapsed = Date.now() - scanStartTime;
    const minutes = Math.floor(elapsed / 60000);
    const seconds = Math.floor((elapsed % 60000) / 1000);

    const elapsedEl = document.getElementById('elapsed-time');
    if (elapsedEl) {
        elapsedEl.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    }

    // Update ETA based on progress
    updateETA(elapsed);
}

// Calculate and display ETA
function updateETA(elapsedMs) {
    const progressFill = document.getElementById('progress-fill');
    const etaEl = document.getElementById('eta-time');
    if (!progressFill || !etaEl) return;

    const progressWidth = parseFloat(progressFill.style.width) || 0;

    if (progressWidth > 10 && progressWidth < 100) {
        // Estimate based on current progress
        const estimatedTotal = (elapsedMs / progressWidth) * 100;
        const remaining = Math.max(0, estimatedTotal - elapsedMs);

        const minutes = Math.floor(remaining / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);

        etaEl.textContent = `~${minutes}m ${seconds}s`;
    } else if (progressWidth >= 100) {
        etaEl.textContent = 'Complete';
    } else {
        etaEl.textContent = 'Calculating...';
    }
}

// Update TCP/UDP status indicators
function updateScanTypeStatus(data) {
    // TCP Status
    const tcpIcon = document.getElementById('tcp-icon');
    const tcpStatus = document.getElementById('tcp-status');
    const tcpCount = document.getElementById('tcp-count');

    if (tcpIcon) {
        tcpIcon.innerHTML = STATUS_ICONS[data.tcp_status] || STATUS_ICONS['not_started'];
        tcpIcon.className = `scan-type-icon ${data.tcp_status || 'not_started'}`;
    }
    if (tcpStatus) {
        tcpStatus.textContent = STATUS_TEXT[data.tcp_status] || STATUS_TEXT['not_started'];
    }
    if (tcpCount) {
        tcpCount.textContent = `${data.tcp_ports_found || 0} ports`;
    }

    // UDP Status
    const udpIcon = document.getElementById('udp-icon');
    const udpStatus = document.getElementById('udp-status');
    const udpCount = document.getElementById('udp-count');

    if (udpIcon) {
        udpIcon.innerHTML = STATUS_ICONS[data.udp_status] || STATUS_ICONS['not_started'];
        udpIcon.className = `scan-type-icon ${data.udp_status || 'not_started'}`;
    }
    if (udpStatus) {
        udpStatus.textContent = STATUS_TEXT[data.udp_status] || STATUS_TEXT['not_started'];
    }
    if (udpCount) {
        udpCount.textContent = `${data.udp_ports_found || 0} ports`;
    }
}

// Update activity log with new entries
function updateActivityLog(entries) {
    const logContainer = document.getElementById('activity-log');
    if (!logContainer || !entries || !Array.isArray(entries)) return;

    // Only add new entries (those after lastLogCount)
    const newEntries = entries.slice(lastLogCount);
    lastLogCount = entries.length;

    newEntries.forEach(entry => {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-${entry.type || 'info'}`;

        const timestamp = document.createElement('span');
        timestamp.className = 'log-timestamp';
        try {
            const time = new Date(entry.ts);
            timestamp.textContent = time.toLocaleTimeString();
        } catch (e) {
            timestamp.textContent = entry.ts || '';
        }

        const message = document.createElement('span');
        message.className = 'log-message';
        message.textContent = entry.msg || '';

        logEntry.appendChild(timestamp);
        logEntry.appendChild(message);
        logContainer.appendChild(logEntry);
    });

    // Auto-scroll to bottom
    logContainer.scrollTop = logContainer.scrollHeight;
}

// Update discovered ports display
function updateDiscoveredPorts(ports) {
    const container = document.getElementById('discovered-ports-container');
    const list = document.getElementById('discovered-ports-list');
    const countSpan = document.getElementById('discovered-ports-count');

    if (!container || !list || !ports) return;

    // Show container when we have ports or scan is active
    container.style.display = 'block';

    // Add only new ports
    ports.forEach(port => {
        const portKey = `${port.port}/${port.protocol}`;
        if (knownDiscoveredPorts.has(portKey)) return;
        knownDiscoveredPorts.add(portKey);

        const item = document.createElement('div');
        item.className = 'discovered-port-item';

        const portNum = document.createElement('code');
        portNum.textContent = portKey;
        item.appendChild(portNum);

        if (port.common_service) {
            const service = document.createElement('span');
            service.className = 'port-service';
            service.textContent = ` ${port.common_service}`;
            item.appendChild(service);
        } else if (port.service && port.service !== 'unknown') {
            const service = document.createElement('span');
            service.className = 'port-service';
            service.textContent = ` ${port.service}`;
            item.appendChild(service);
        }

        // Insert at top (newest first)
        list.insertBefore(item, list.firstChild);
    });

    // Update count
    if (countSpan) {
        countSpan.textContent = knownDiscoveredPorts.size;
    }
}

// Toggle activity log visibility
function toggleActivityLog() {
    const logContainer = document.getElementById('activity-log');
    const toggleBtn = document.getElementById('toggle-log');

    if (!logContainer || !toggleBtn) return;

    if (logContainer.classList.contains('collapsed')) {
        logContainer.classList.remove('collapsed');
        toggleBtn.innerHTML = '&#9660;';  // Down arrow
    } else {
        logContainer.classList.add('collapsed');
        toggleBtn.innerHTML = '&#9654;';  // Right arrow
    }
}

// Clean up scan progress state
function cleanupScanProgress() {
    if (elapsedTimerId) {
        clearInterval(elapsedTimerId);
        elapsedTimerId = null;
    }
    scanStartTime = null;
    lastLogCount = 0;
    knownDiscoveredPorts.clear();

    // Hide discovered ports container
    const container = document.getElementById('discovered-ports-container');
    if (container) {
        container.style.display = 'none';
    }
    const list = document.getElementById('discovered-ports-list');
    if (list) {
        list.innerHTML = '';
    }
}

// Update progress UI
function updateProgressUI(data) {
    const progressDiv = document.getElementById('scan-progress');
    const phaseSpan = document.getElementById('progress-phase');
    const progressFill = document.getElementById('progress-fill');

    if (!progressDiv) return;

    // Show progress div
    progressDiv.classList.remove('hidden');

    // Start elapsed time tracking if not started
    if (data.started_at && !scanStartTime) {
        scanStartTime = new Date(data.started_at).getTime();
        elapsedTimerId = setInterval(updateElapsedTime, 1000);
        updateElapsedTime(); // Initial update
    }

    // Update phase text
    if (phaseSpan) {
        phaseSpan.textContent = PHASE_NAMES[data.current_phase] || data.current_phase;
    }

    // Update progress bar based on phase
    const phaseProgress = {
        'starting': 10,
        'scanning': 40,
        'enriching': 60,
        'saving': 80,
        'completed': 100
    };
    if (progressFill) {
        progressFill.style.width = (phaseProgress[data.current_phase] || 0) + '%';
    }

    // Update TCP/UDP status indicators
    updateScanTypeStatus(data);

    // Update activity log (only new entries)
    if (data.activity_log) {
        updateActivityLog(data.activity_log);
    }

    // Update discovered ports list
    if (data.discovered_ports) {
        updateDiscoveredPorts(data.discovered_ports);
    }
}

// Start SSE progress stream
function startProgressStream(scanId) {
    if (progressEventSource) {
        progressEventSource.close();
    }

    // Reset state for new scan
    cleanupScanProgress();

    progressEventSource = new EventSource(`/api/scans/${scanId}/progress`);

    progressEventSource.addEventListener('progress', (e) => {
        const data = JSON.parse(e.data);
        updateProgressUI(data);
    });

    progressEventSource.addEventListener('complete', (e) => {
        const data = JSON.parse(e.data);
        updateProgressUI(data);
        cleanupScanProgress();
        progressEventSource.close();
        progressEventSource = null;

        // Reload page after brief delay to show completion
        setTimeout(() => {
            window.location.reload();
        }, 1500);
    });

    progressEventSource.addEventListener('error', (e) => {
        cleanupScanProgress();
        progressEventSource.close();
        progressEventSource = null;

        // Reload page on error
        setTimeout(() => {
            window.location.reload();
        }, 2000);
    });
}

// Poll for running scan and start progress stream
async function pollForRunningScan(maxAttempts = 15) {
    for (let i = 0; i < maxAttempts; i++) {
        try {
            const response = await fetch('/api/scans/running');
            if (response.ok) {
                const data = await response.json();
                if (data && data.scan_id) {
                    startProgressStream(data.scan_id);
                    return true;
                }
            }
        } catch (error) {
            console.error('Error polling for running scan:', error);
        }
        // Progressive backoff: 500ms, 750ms, 1000ms, 1250ms... capped at 2s
        const delay = Math.min(500 + (i * 250), 2000);
        await new Promise(resolve => setTimeout(resolve, delay));
    }
    return false;
}

// Trigger manual scan
async function triggerScan() {
    const button = document.getElementById('trigger-scan');
    const statusDiv = document.getElementById('scan-status');
    const progressDiv = document.getElementById('scan-progress');

    // Disable button
    button.disabled = true;
    button.innerHTML = '<span class="btn-icon">&#9203;</span> Scanning...';

    // Show initial status
    statusDiv.classList.remove('hidden', 'success', 'error');
    statusDiv.textContent = 'Triggering scan...';
    statusDiv.classList.add('success');

    try {
        const response = await fetch('/api/scans/trigger', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        const data = await response.json();

        if (response.ok) {
            statusDiv.textContent = data.message;

            // Show progress div and poll for the running scan
            if (progressDiv) {
                progressDiv.classList.remove('hidden');
            }

            // Poll for the running scan and start progress stream
            const found = await pollForRunningScan();
            if (!found) {
                // Show message but don't reload immediately - scan may still be starting
                statusDiv.textContent = 'Scan queued. Checking for progress...';

                // Set up a delayed secondary check
                setTimeout(async () => {
                    const secondCheck = await pollForRunningScan(5);
                    if (!secondCheck) {
                        // Only reload if still no scan found after secondary check
                        statusDiv.textContent = 'Scan may have completed quickly. Refreshing...';
                        setTimeout(() => {
                            window.location.reload();
                        }, 1500);
                    }
                }, 3000);
            }
        } else {
            throw new Error(data.detail || 'Failed to trigger scan');
        }
    } catch (error) {
        statusDiv.textContent = 'Error: ' + error.message;
        statusDiv.classList.remove('success');
        statusDiv.classList.add('error');

        // Hide progress and re-enable button on error
        if (progressDiv) {
            progressDiv.classList.add('hidden');
        }
        button.disabled = false;
        button.innerHTML = '<span class="btn-icon">&#9654;</span> Trigger Manual Scan';
    }
}

// Rescan a single port with nmap for detailed service detection
async function rescanPort(port, protocol) {
    const row = document.getElementById(`port-row-${port}-${protocol}`);
    const button = row ? row.querySelector('.btn-rescan') : null;
    const serviceCell = row ? row.querySelector('.service-cell') : null;

    if (!button || !serviceCell) {
        console.error('Could not find row elements for port', port);
        return;
    }

    // Show loading state
    const originalContent = button.innerHTML;
    button.disabled = true;
    button.classList.add('loading');

    // Store original service content
    const originalServiceContent = serviceCell.innerHTML;

    try {
        const response = await fetch(`/api/ports/${port}/rescan?protocol=${protocol}&intensity=normal`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        const data = await response.json();

        if (response.ok) {
            // Update the service cell with new data (avoid innerHTML to prevent XSS)
            serviceCell.textContent = '';

            const service = data.service;
            const commonService = data.common_service;
            const version = data.version;

            if (service && service !== 'unknown') {
                serviceCell.appendChild(document.createTextNode(service));
                if (commonService && commonService !== service) {
                    serviceCell.appendChild(document.createTextNode(' '));
                    const commonSpan = document.createElement('span');
                    commonSpan.className = 'common-service';
                    commonSpan.textContent = `(${commonService})`;
                    serviceCell.appendChild(commonSpan);
                }
            } else if (commonService) {
                const unknownSpan = document.createElement('span');
                unknownSpan.className = 'unknown-service';
                unknownSpan.textContent = 'unknown';
                serviceCell.appendChild(unknownSpan);

                serviceCell.appendChild(document.createTextNode(' '));
                const commonSpan = document.createElement('span');
                commonSpan.className = 'common-service';
                commonSpan.textContent = `(${commonService})`;
                serviceCell.appendChild(commonSpan);
            } else {
                const unknownSpan = document.createElement('span');
                unknownSpan.className = 'unknown-service';
                unknownSpan.textContent = 'unknown';
                serviceCell.appendChild(unknownSpan);
            }

            if (version) {
                serviceCell.appendChild(document.createTextNode(' '));
                const versionSpan = document.createElement('span');
                versionSpan.className = 'version-info';
                versionSpan.textContent = version;
                serviceCell.appendChild(versionSpan);
            }

            // Show success indicator briefly
            button.innerHTML = '&#x2713;';
            button.classList.remove('loading');
            setTimeout(() => {
                button.innerHTML = originalContent;
                button.disabled = false;
            }, 2000);
        } else {
            throw new Error(data.detail || 'Rescan failed');
        }
    } catch (error) {
        console.error('Rescan failed:', error);

        // Show error state
        button.innerHTML = '&#x2717;';
        button.classList.remove('loading');
        button.classList.add('error');

        // Restore after delay
        setTimeout(() => {
            button.innerHTML = originalContent;
            button.disabled = false;
            button.classList.remove('error');
        }, 3000);
    }
}

// Get server timezone from body data attribute
function getServerTimezone() {
    return document.body.dataset.timezone || 'UTC';
}

// Format timestamps to server timezone
function formatTimestamps() {
    const timestamps = document.querySelectorAll('.timestamp');
    const serverTimezone = getServerTimezone();

    timestamps.forEach(el => {
        const timeStr = el.dataset.time || el.textContent;
        if (!timeStr || timeStr === 'None') return;

        try {
            const date = new Date(timeStr);
            if (isNaN(date.getTime())) return;

            // Format in server timezone
            const options = {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                timeZone: serverTimezone,
            };

            el.textContent = date.toLocaleString(undefined, options);
            el.title = date.toISOString();
        } catch (e) {
            // Keep original text if parsing fails
        }
    });
}

// Auto-refresh dashboard every 60 seconds
function setupAutoRefresh() {
    // Only on dashboard page
    if (window.location.pathname === '/') {
        setInterval(() => {
            // Only refresh if no scan is in progress
            const button = document.getElementById('trigger-scan');
            if (button && !button.disabled) {
                window.location.reload();
            }
        }, 60000); // 60 seconds
    }
}

// Fetch and display current status
async function updateStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        // Update status indicator if element exists
        const statusText = document.querySelector('.status-text');
        if (statusText && data.host_status) {
            statusText.textContent = data.host_status.toUpperCase();
        }
    } catch (error) {
        console.error('Failed to update status:', error);
    }
}

// Port history chart instance
let portHistoryChart = null;

// Host uptime chart instance
let hostUptimeChart = null;

// Load and render port history chart
async function loadPortHistoryChart() {
    const canvas = document.getElementById('portHistoryChart');
    if (!canvas) return;

    try {
        const response = await fetch('/api/port-history?limit=30');
        const data = await response.json();

        if (data.length === 0) {
            // No data available
            const ctx = canvas.getContext('2d');
            ctx.font = '14px system-ui';
            ctx.fillStyle = '#666';
            ctx.textAlign = 'center';
            ctx.fillText('No scan history available yet', canvas.width / 2, canvas.height / 2);
            return;
        }

        // Format data for Chart.js (use server timezone)
        const serverTimezone = getServerTimezone();
        const labels = data.map(item => {
            const date = new Date(item.completed_at);
            return date.toLocaleString(undefined, {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                timeZone: serverTimezone,
            });
        });
        const portCounts = data.map(item => item.open_port_count);

        // Destroy existing chart if any
        if (portHistoryChart) {
            portHistoryChart.destroy();
        }

        // Create new chart
        portHistoryChart = new Chart(canvas, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Open Ports',
                    data: portCounts,
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointBackgroundColor: '#3498db',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            precision: 0
                        },
                        title: {
                            display: true,
                            text: 'Open Ports'
                        }
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }
            }
        });
    } catch (error) {
        console.error('Failed to load port history chart:', error);
    }
}

// Load and render host uptime chart
async function loadHostUptimeChart() {
    const canvas = document.getElementById('hostUptimeChart');
    if (!canvas) return;

    try {
        // Fetch 48 data points (~12 hours at 15-minute intervals)
        const response = await fetch('/api/host-status-history?limit=48');
        const data = await response.json();

        if (data.length === 0) {
            const ctx = canvas.getContext('2d');
            ctx.font = '14px system-ui';
            ctx.fillStyle = '#666';
            ctx.textAlign = 'center';
            ctx.fillText('No host status history available yet', canvas.width / 2, canvas.height / 2);
            return;
        }

        // Format data for Chart.js
        const serverTimezone = getServerTimezone();
        const labels = data.map(item => {
            const date = new Date(item.checked_at);
            return date.toLocaleString(undefined, {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                timeZone: serverTimezone,
            });
        });

        // Convert status to numeric: online=1, dns_only=0.5, offline=0
        const statusValues = data.map(item => {
            if (item.status === 'online') return 1;
            if (item.status === 'dns_only') return 0.5;
            return 0;
        });

        // Color based on status
        const pointColors = data.map(item => {
            if (item.status === 'online') return '#27ae60';  // success green
            if (item.status === 'dns_only') return '#f39c12';  // warning orange
            return '#e74c3c';  // danger red
        });

        // Destroy existing chart if any
        if (hostUptimeChart) {
            hostUptimeChart.destroy();
        }

        // Create step chart for uptime status
        hostUptimeChart = new Chart(canvas, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Host Status',
                    data: statusValues,
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    stepped: 'before',  // Step chart for status changes
                    pointBackgroundColor: pointColors,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            label: function(context) {
                                const item = data[context.dataIndex];
                                let label = item.status.toUpperCase();
                                if (item.check_method) {
                                    label += ` (via ${item.check_method})`;
                                }
                                return label;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45
                        }
                    },
                    y: {
                        min: 0,
                        max: 1,
                        ticks: {
                            stepSize: 0.5,
                            callback: function(value) {
                                if (value === 1) return 'Online';
                                if (value === 0.5) return 'DNS Only';
                                if (value === 0) return 'Offline';
                                return '';
                            }
                        },
                        title: {
                            display: true,
                            text: 'Status'
                        }
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }
            }
        });
    } catch (error) {
        console.error('Failed to load host uptime chart:', error);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    formatTimestamps();
    setupAutoRefresh();

    // Initial status update
    updateStatus();

    // Load charts
    loadPortHistoryChart();
    loadHostUptimeChart();
});
