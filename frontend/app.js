document.addEventListener('DOMContentLoaded', () => {
    // Navigation Logic
    const navs = ['dashboard', 'education', 'settings'];
    
    function switchView(view) {
        navs.forEach(n => {
            document.getElementById(`nav-${n}`).classList.remove('active');
            document.getElementById(`view-${n}`).classList.add('hidden');
        });
        
        document.getElementById(`nav-${view}`).classList.add('active');
        document.getElementById(`view-${view}`).classList.remove('hidden');

        // Page Titles
        const titles = {
            'dashboard': 'Operations Center',
            'education': 'Threat Intelligence',
            'settings': 'Heuristic Config'
        };
        const subs = {
            'dashboard': 'Real-time endpoint detection and response telemetry.',
            'education': 'Analyze mechanisms used by unauthorized input monitors.',
            'settings': 'Tune engine sensitivity and blocking protocols.'
        };
        document.getElementById('page-header-title').textContent = titles[view];
        document.getElementById('page-header-sub').textContent = subs[view];
    }

    navs.forEach(n => {
        document.getElementById(`nav-${n}`).addEventListener('click', () => switchView(n));
    });

    // Terminal Logging Logic
    const terminalLog = document.getElementById('terminal-log');
    
    window.logTerminal = function(message, type = 'sys') {
        const time = new Date().toLocaleTimeString('en-US', { hour12: false });
        const div = document.createElement('div');
        div.className = `log-line ${type}-msg`;
        div.innerHTML = `<span class="text-muted">[${time}]</span> ${message}`;
        terminalLog.appendChild(div);
        terminalLog.scrollTop = terminalLog.scrollHeight;
    };

    // Scan Logic
    const scanBtn = document.getElementById('scan-btn');
    const scanIcon = document.getElementById('scan-icon');
    const btnText = scanBtn.querySelector('.btn-text');
    const tableBody = document.getElementById('process-table-body');
    const radarOverlay = document.getElementById('radar-overlay');

    scanBtn.addEventListener('click', async () => {
        // UI Loading state
        radarOverlay.classList.remove('hidden');
        btnText.textContent = 'SCANNING...';
        scanBtn.disabled = true;
        scanIcon.classList.add('fa-spin');
        
        logTerminal('Initializing deep heuristic memory scan...', 'sys');
        
        // Fake delay to show off radar
        await new Promise(r => setTimeout(r, 1500));
        logTerminal('Connecting to EDR API gateway...', 'sys');

        try {
            const response = await fetch('http://localhost:5001/api/scan');
            const result = await response.json();

            if (result.status === 'success') {
                logTerminal(`Analysis complete. Interrogated ${result.data.total_processes} process images.`, 'ok');
                if(result.data.suspicious_found > 0) {
                    logTerminal(`CRITICAL: Identified ${result.data.suspicious_found} potential monitoring threats!`, 'err');
                }
                renderProcesses(result.data);
            } else {
                logTerminal(`API Error: ${result.message}`, 'err');
            }
        } catch (error) {
            logTerminal('Failed to communicate with engine backend on port 5001.', 'err');
        } finally {
            // Restore UI
            setTimeout(() => {
                radarOverlay.classList.add('hidden');
                btnText.textContent = 'INITIALIZE SCAN';
                scanBtn.disabled = false;
                scanIcon.classList.remove('fa-spin');
            }, 500);
        }
    });

    function renderProcesses(data) {
        document.getElementById('scan-stats').classList.remove('hidden');
        animateValue(document.getElementById('stat-total'), 0, data.total_processes, 800);
        animateValue(document.getElementById('stat-threats'), 0, data.suspicious_found, 800);

        tableBody.innerHTML = '';

        if (data.processes.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" class="empty-state">No active processes found.</td></tr>';
            return;
        }

        data.processes.forEach(proc => {
            const tr = document.createElement('tr');
            
            const badgeClass = proc.is_suspicious ? 'badge-alert' : 'badge-clean';
            const statusText = proc.is_suspicious ? 'SUSPICIOUS' : 'VERIFIED';
            const actionHTML = proc.is_suspicious 
                ? `<span class="action-link" onclick="openThreatModal(${proc.pid}, '${proc.name}', '${proc.exe.replace(/\\/g, '\\\\')}', '${proc.reason}')">INVESTIGATE</span>` 
                : `<span style="color: var(--text-muted)">-</span>`;

            tr.innerHTML = `
                <td>${proc.pid}</td>
                <td><i class="fa-solid ${proc.is_suspicious ? 'fa-biohazard text-red' : 'fa-cube text-muted'}" style="margin-right: 8px;"></i> ${proc.name}</td>
                <td title="${proc.exe}" class="text-muted">${truncatePath(proc.exe)}</td>
                <td><span class="badge ${badgeClass}">${statusText}</span></td>
                <td>${actionHTML}</td>
            `;
            tableBody.appendChild(tr);
        });
    }

    function truncatePath(path) {
        if (!path || path === 'Unknown') return 'Unknown';
        if (path.length > 35) {
            return '...' + path.substring(path.length - 32);
        }
        return path;
    }

    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }

    // Modal Logic
    const modal = document.getElementById('threat-modal');
    const modalTerminateBtn = document.getElementById('modal-terminate');

    window.openThreatModal = function(pid, name, path, reason) {
        document.getElementById('modal-pid').textContent = pid;
        document.getElementById('modal-process-name').textContent = name;
        document.getElementById('modal-path').textContent = path;
        document.getElementById('modal-reason').textContent = reason;
        modal.classList.remove('hidden');
        logTerminal(`Investigating process ${name} [PID: ${pid}]...`, 'warn');
    }

    function closeModal() {
        modal.classList.add('hidden');
    }

    document.querySelector('.close-btn').addEventListener('click', closeModal);
    document.getElementById('modal-ignore').addEventListener('click', () => {
        logTerminal(`Ignored threat flag for process.`, 'sys');
        closeModal();
    });
    
    modalTerminateBtn.addEventListener('click', async () => {
        const pid = document.getElementById('modal-pid').textContent;
        const name = document.getElementById('modal-process-name').textContent;
        const btnOriginalText = modalTerminateBtn.innerHTML;
        modalTerminateBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> TERMINATING...';
        modalTerminateBtn.disabled = true;

        logTerminal(`Executing termination sequence for PID: ${pid}...`, 'warn');

        try {
            const response = await fetch(`http://localhost:5001/api/terminate/${pid}`, { method: 'POST' });
            const result = await response.json();
            
            if (result.status === 'success') {
                logTerminal(`SUCCESS: Terminated ${name}.`, 'ok');
                closeModal();
                scanBtn.click(); // Refresh
            } else {
                logTerminal(`FAILED to terminate ${name}: ${result.message}`, 'err');
                alert('Termination Failed: ' + result.message);
            }
        } catch (error) {
            logTerminal('Error communicating with backend to terminate process.', 'err');
        } finally {
            modalTerminateBtn.innerHTML = btnOriginalText;
            modalTerminateBtn.disabled = false;
        }
    });

    window.onclick = function(event) {
        if (event.target == document.querySelector('.modal-glass')) {
            closeModal();
        }
    }
});
