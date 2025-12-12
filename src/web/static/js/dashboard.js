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

// Format timestamps to local time
function formatTimestamps() {
    const timestamps = document.querySelectorAll('.timestamp');

    timestamps.forEach(el => {
        const timeStr = el.dataset.time || el.textContent;
        if (!timeStr || timeStr === 'None') return;

        try {
            const date = new Date(timeStr);
            if (isNaN(date.getTime())) return;

            // Format as local date/time
            const options = {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
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

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    formatTimestamps();
    setupAutoRefresh();

    // Initial status update
    updateStatus();
});
