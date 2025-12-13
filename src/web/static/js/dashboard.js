/**
 * Dashboard JavaScript
 */

// Active SSE connection
let progressEventSource = null;

// Phase display names
const PHASE_NAMES = {
    'starting': 'Starting scan...',
    'scanning': 'Scanning ports...',
    'enriching': 'Detecting services...',
    'saving': 'Saving results...',
    'completed': 'Scan complete!'
};

// Update progress UI
function updateProgressUI(data) {
    const progressDiv = document.getElementById('scan-progress');
    const phaseSpan = document.getElementById('progress-phase');
    const portsSpan = document.getElementById('progress-ports');
    const progressFill = document.getElementById('progress-fill');

    if (!progressDiv) return;

    // Show progress div
    progressDiv.classList.remove('hidden');

    // Update phase text
    phaseSpan.textContent = PHASE_NAMES[data.current_phase] || data.current_phase;

    // Update port counts
    portsSpan.textContent = `TCP: ${data.tcp_ports_found || 0} | UDP: ${data.udp_ports_found || 0}`;

    // Update progress bar based on phase
    const phaseProgress = {
        'starting': 10,
        'scanning': 40,
        'enriching': 60,
        'saving': 80,
        'completed': 100
    };
    progressFill.style.width = (phaseProgress[data.current_phase] || 0) + '%';
}

// Start SSE progress stream
function startProgressStream(scanId) {
    if (progressEventSource) {
        progressEventSource.close();
    }

    progressEventSource = new EventSource(`/api/scans/${scanId}/progress`);

    progressEventSource.addEventListener('progress', (e) => {
        const data = JSON.parse(e.data);
        updateProgressUI(data);
    });

    progressEventSource.addEventListener('complete', (e) => {
        const data = JSON.parse(e.data);
        updateProgressUI(data);
        progressEventSource.close();
        progressEventSource = null;

        // Reload page after brief delay to show completion
        setTimeout(() => {
            window.location.reload();
        }, 1500);
    });

    progressEventSource.addEventListener('error', (e) => {
        progressEventSource.close();
        progressEventSource = null;

        // Reload page on error
        setTimeout(() => {
            window.location.reload();
        }, 2000);
    });
}

// Poll for running scan and start progress stream
async function pollForRunningScan(maxAttempts = 10) {
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
        await new Promise(resolve => setTimeout(resolve, 1000));
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
                // Fallback: reload after timeout if no running scan found
                statusDiv.textContent = 'Scan running, refreshing soon...';
                setTimeout(() => {
                    window.location.reload();
                }, 5000);
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

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    formatTimestamps();
    setupAutoRefresh();

    // Initial status update
    updateStatus();

    // Load port history chart
    loadPortHistoryChart();
});
