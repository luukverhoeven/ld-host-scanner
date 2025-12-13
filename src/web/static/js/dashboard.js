/**
 * Dashboard JavaScript
 */

// Trigger manual scan
async function triggerScan() {
    const button = document.getElementById('trigger-scan');
    const statusDiv = document.getElementById('scan-status');

    // Disable button
    button.disabled = true;
    button.innerHTML = '<span class="btn-icon">&#9203;</span> Scanning...';

    // Show status
    statusDiv.classList.remove('hidden', 'success', 'error');
    statusDiv.textContent = 'Scan triggered, please wait...';
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
            statusDiv.textContent = data.message + '. Page will refresh in 5 seconds...';
            statusDiv.classList.add('success');

            // Refresh page after 5 seconds
            setTimeout(() => {
                window.location.reload();
            }, 5000);
        } else {
            throw new Error(data.detail || 'Failed to trigger scan');
        }
    } catch (error) {
        statusDiv.textContent = 'Error: ' + error.message;
        statusDiv.classList.remove('success');
        statusDiv.classList.add('error');

        // Re-enable button on error
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
            // Update the service cell with new data
            let serviceHtml = '';
            if (data.service && data.service !== 'unknown') {
                serviceHtml = data.service;
                if (data.common_service && data.common_service !== data.service) {
                    serviceHtml += ` <span class="common-service">(${data.common_service})</span>`;
                }
            } else if (data.common_service) {
                serviceHtml = `<span class="unknown-service">unknown</span> <span class="common-service">(${data.common_service})</span>`;
            } else {
                serviceHtml = '<span class="unknown-service">unknown</span>';
            }

            // Add version if available
            if (data.version) {
                serviceHtml += ` <span class="version-info">${data.version}</span>`;
            }

            serviceCell.innerHTML = serviceHtml;

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
