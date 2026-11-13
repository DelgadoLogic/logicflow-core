/**
 * LogicFlow Dashboard Redesign — Interactive Frontend Controller
 * DelgadoLogic Systems LLC
 * 
 * Implements a high-fidelity state machine to simulate local PC intelligence operations
 * (Junk Cleaner, Turbo Mode, Sentinel Network Audit, Registry Surgeon, Lazarus Recovery).
 */

document.addEventListener('DOMContentLoaded', () => {
  
  // ==========================================================================
  // STATE MANAGEMENT & STATE VARIABLES
  // ==========================================================================
  const state = {
    activeTab: 'overview',
    cpuUsage: 12,
    ramUsage: 44,
    sysTemp: 48,
    isTurboActive: false,
    
    // Junk Cleaner State
    junkScanRun: false,
    junkScanning: false,
    junkProgress: 0,
    junkItemsChecked: [],
    junkTotalBytesCleaned: 0,
    
    // Network Scanner State
    networkScanRun: false,
    networkScanning: false,
    networkProgress: 0,
    
    // Registry Surgeon State
    registryScanRun: false,
    registryScanning: false,
    registryProgress: 0,
    registryFixed: false,
    
    // Lazarus Recovery State
    selectedRecoveryBlock: '411',
    lazarusRestoring: false
  };

  // ==========================================================================
  // LIVE TELEMETRY SIMULATOR
  // ==========================================================================
  function updateSystemTelemetry() {
    if (state.junkScanning || state.networkScanning || state.registryScanning || state.lazarusRestoring) {
      // Elevate stats during active scans/restores
      state.cpuUsage = Math.min(95, Math.max(70, Math.floor(Math.random() * 25) + 70));
      state.ramUsage = Math.min(85, Math.max(50, state.ramUsage + (Math.random() > 0.5 ? 1 : -1)));
      state.sysTemp = Math.min(78, Math.max(60, state.sysTemp + (Math.random() > 0.5 ? 1 : 0)));
    } else if (state.isTurboActive) {
      // Turbo Mode: Idle CPU is lower, RAM is lower, but clock profile might run slightly warmer
      state.cpuUsage = Math.min(25, Math.max(4, Math.floor(Math.random() * 6) + 4));
      state.ramUsage = Math.min(32, Math.max(26, state.ramUsage + (Math.random() > 0.5 ? 0.2 : -0.2)));
      state.sysTemp = Math.min(54, Math.max(45, state.sysTemp + (Math.random() > 0.7 ? 1 : -1)));
    } else {
      // Normal Idle State
      state.cpuUsage = Math.min(35, Math.max(6, Math.floor(Math.random() * 10) + 6));
      state.ramUsage = Math.min(50, Math.max(40, state.ramUsage + (Math.random() > 0.5 ? 0.1 : -0.1)));
      state.sysTemp = Math.min(52, Math.max(44, state.sysTemp + (Math.random() > 0.5 ? 0.5 : -0.5)));
    }
    
    // Render Telemetry
    const cpuVal = Math.round(state.cpuUsage);
    const ramVal = Math.round(state.ramUsage);
    const tempVal = Math.round(state.sysTemp);
    
    document.getElementById('stat-cpu').textContent = `${cpuVal}%`;
    document.getElementById('fill-cpu').style.width = `${cpuVal}%`;
    
    document.getElementById('stat-ram').textContent = `${ramVal}%`;
    document.getElementById('fill-ram').style.width = `${ramVal}%`;
    
    document.getElementById('stat-temp').textContent = `${tempVal}°C`;
    document.getElementById('fill-temp').style.width = `${tempVal}%`;
  }
  
  // Fluctuates metrics every 2 seconds
  setInterval(updateSystemTelemetry, 2000);

  // ==========================================================================
  // TAB NAVIGATION
  // ==========================================================================
  const tabInfo = {
    overview: {
      title: 'Overview',
      desc: 'Dynamic system diagnostics and local AI insights.'
    },
    junk: {
      title: 'Junk Cleaner',
      desc: 'Safely sweep cache directories and temporary files with concurrency.'
    },
    turbo: {
      title: 'Turbo Mode',
      desc: 'High-performance CPU, service, and power management overrides.'
    },
    network: {
      title: 'Network Scanner',
      desc: 'Audit loopback connections, ARP records, and firewall parameters.'
    },
    registry: {
      title: 'Registry Surgeon',
      desc: 'Safely scan, repair, and clean orphaned registry structures.'
    },
    lazarus: {
      title: 'Lazarus Recovery',
      desc: 'Local recovery points and cryptographic sector verification.'
    }
  };

  const navBtns = document.querySelectorAll('.nav-btn');
  const panes = document.querySelectorAll('.tab-pane');
  const tabTitleEl = document.getElementById('current-tab-title');
  const tabDescEl = document.getElementById('current-tab-desc');

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-target');
      
      // Update sidebar nav active states
      navBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      // Update viewport panes
      panes.forEach(pane => pane.classList.remove('active'));
      document.getElementById(`pane-${target}`).classList.add('active');
      
      // Update header labels
      tabTitleEl.textContent = tabInfo[target].title;
      tabDescEl.textContent = tabInfo[target].desc;
      
      state.activeTab = target;
    });
  });

  // ==========================================================================
  // JUNK CLEANER ENGINE
  // ==========================================================================
  const btnJunkScan = document.getElementById('btn-junk-scan');
  const btnJunkClear = document.getElementById('btn-junk-clear');
  const junkProgressContainer = document.getElementById('junk-progress-container');
  const junkProgressFill = document.getElementById('junk-progress-fill');
  const junkProgressPct = document.getElementById('junk-progress-pct');
  const junkStatusText = document.getElementById('junk-status-text');
  const junkDetailsEmpty = document.getElementById('junk-details-empty');
  const junkDetailsList = document.getElementById('junk-details-list');
  const junkSummaryCount = document.getElementById('junk-summary-count');
  const junkLogConsole = document.getElementById('junk-log-console');
  
  // Real paths scanned during simulated execution (Zero placeholders)
  const junkFilePaths = [
    { path: 'C:\\Windows\\Temp\\~DF342A098C.tmp', size: '242 MB', type: 'WindowsTemp' },
    { path: 'C:\\Windows\\Temp\\mfevt561.log', size: '120 MB', type: 'WindowsTemp' },
    { path: 'C:\\Windows\\Temp\\Cab_408_12.tmp', size: '1.06 GB', type: 'WindowsTemp' },
    { path: 'C:\\Users\\Manuel\\AppData\\Local\\Temp\\npm-1025-a8f2\\package.json', size: '820 KB', type: 'UserTemp' },
    { path: 'C:\\Users\\Manuel\\AppData\\Local\\Temp\\discord-update.log', size: '42 MB', type: 'UserTemp' },
    { path: 'C:\\Users\\Manuel\\AppData\\Local\\Temp\\v8-compile-cache-1000\\', size: '2.11 GB', type: 'UserTemp' },
    { path: 'C:\\Users\\Manuel\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\data_0', size: '450 MB', type: 'BrowserCache' },
    { path: 'C:\\Users\\Manuel\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache\\f_0038', size: '462 MB', type: 'BrowserCache' },
    { path: 'C:\\Windows\\Minidump\\Mini060526-01.dmp', size: '124 MB', type: 'CrashDumps' },
    { path: 'C:\\Windows\\Minidump\\MEMORY.DMP', size: '224 MB', type: 'CrashDumps' },
    { path: 'C:\\Users\\Manuel\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_256.db', size: '48 MB', type: 'ThumbnailCache' },
    { path: 'C:\\Users\\Manuel\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_idx.db', size: '40 MB', type: 'ThumbnailCache' }
  ];

  function addJunkLog(text, type = 'info') {
    const span = document.createElement('span');
    span.className = `log-${type}`;
    span.textContent = `[${new Date().toLocaleTimeString('en-US', {hour12:false})}] ${text}`;
    junkLogConsole.appendChild(span);
    junkLogConsole.scrollTop = junkLogConsole.scrollHeight;
  }

  btnJunkScan.addEventListener('click', () => {
    if (state.junkScanning) return;
    
    state.junkScanning = true;
    state.junkProgress = 0;
    
    // UI adjustments
    btnJunkScan.querySelector('svg').classList.add('spinning');
    btnJunkScan.disabled = true;
    btnJunkClear.classList.add('hidden');
    junkProgressContainer.classList.remove('hidden');
    junkDetailsList.classList.add('hidden');
    junkDetailsEmpty.classList.add('hidden');
    
    addJunkLog('Initializing Junk Cleaner Scan (Parallelized task-pool)...', 'info');
    
    const interval = setInterval(() => {
      state.junkProgress += 2;
      junkProgressFill.style.width = `${state.junkProgress}%`;
      junkProgressPct.textContent = `${state.junkProgress}%`;
      
      // Dynamic scanning paths in log terminal
      const pathIdx = Math.floor((state.junkProgress / 100) * junkFilePaths.length);
      if (pathIdx < junkFilePaths.length && state.junkProgress % 10 === 0) {
        const item = junkFilePaths[pathIdx];
        junkStatusText.textContent = `Scanning: ${item.path.substring(0, 32)}...`;
        addJunkLog(`Checking index lock on: ${item.path}`, 'info');
        
        // Simulate checking file locks dynamically to mirror logic of preventing exceptions
        if (Math.random() > 0.8) {
          addJunkLog(`[Lock Guard] Handle locked on: ${item.path.split('\\').pop()} - Skipping safely.`, 'warn');
        } else {
          addJunkLog(`[Ready] Handle accessible: ${item.path.split('\\').pop()}`, 'info');
        }
      }
      
      if (state.junkProgress >= 100) {
        clearInterval(interval);
        state.junkScanning = false;
        state.junkScanRun = true;
        
        btnJunkScan.querySelector('svg').classList.remove('spinning');
        btnJunkScan.disabled = false;
        btnJunkScan.classList.add('hidden');
        btnJunkClear.classList.remove('hidden');
        junkProgressContainer.classList.add('hidden');
        
        // Render scanned categories
        junkDetailsList.classList.remove('hidden');
        junkSummaryCount.innerHTML = `Scan complete. Found <strong>4.90 GB</strong> of temporary system and application files.`;
        
        addJunkLog('Directory scan complete. 4.90 GB identified for safe purge.', 'success');
        addJunkLog('Ready for secure local deletion sweep.', 'info');
        
        // Update Overview Ring
        document.getElementById('health-ring').style.strokeDashoffset = '145'; // Lowers health to show issues found
        document.getElementById('health-percentage').textContent = '45%';
      }
    }, 60);
  });

  btnJunkClear.addEventListener('click', () => {
    if (state.junkScanning) return;
    
    btnJunkClear.disabled = true;
    junkProgressContainer.classList.remove('hidden');
    junkProgressFill.style.width = '0%';
    junkProgressPct.textContent = '0%';
    junkStatusText.textContent = 'Purging files...';
    
    addJunkLog('Executing thread-safe parallel file deletions...', 'info');
    
    let clearPct = 0;
    const interval = setInterval(() => {
      clearPct += 4;
      junkProgressFill.style.width = `${clearPct}%`;
      junkProgressPct.textContent = `${clearPct}%`;
      
      const pathIdx = Math.floor((clearPct / 100) * junkFilePaths.length);
      if (pathIdx < junkFilePaths.length && clearPct % 12 === 0) {
        const item = junkFilePaths[pathIdx];
        junkStatusText.textContent = `Deleting: ${item.path.substring(0, 32)}...`;
        addJunkLog(`[IO] Calling File.Delete on ${item.path.split('\\').pop()}`, 'info');
      }
      
      if (clearPct >= 100) {
        clearInterval(interval);
        
        btnJunkClear.disabled = false;
        btnJunkClear.classList.add('hidden');
        btnJunkScan.classList.remove('hidden');
        junkProgressContainer.classList.add('hidden');
        junkDetailsList.classList.add('hidden');
        junkDetailsEmpty.classList.remove('hidden');
        
        junkSummaryCount.textContent = 'Purge completed successfully. 4.90 GB storage reclaimed.';
        addJunkLog('File cleanup finished. Zero cloud sync performed. Integrity clean.', 'success');
        addJunkLog('System resources reclaimed successfully.', 'success');
        
        // Reset Health Ring
        document.getElementById('health-ring').style.strokeDashoffset = '40';
        document.getElementById('health-percentage').textContent = '95%';
      }
    }, 80);
  });

  // ==========================================================================
  // TURBO ACCELERATION MODE (Theme & Settings Toggle)
  // ==========================================================================
  const btnTurboToggle = document.getElementById('btn-turbo-toggle');
  const turboStateBadge = document.getElementById('turbo-state-badge');
  const turboPowercfg = document.getElementById('turbo-powercfg');
  const turboRegTweak = document.getElementById('turbo-reg-tweak');
  const turboThreadPriority = document.getElementById('turbo-thread-priority');
  const turboCores = document.getElementById('turbo-cores');
  
  // Services & Processes elements to modify
  const srvSysmain = document.getElementById('srv-sysmain');
  const srvSearch = document.getElementById('srv-search');
  const srvSpooler = document.getElementById('srv-spooler');
  const srvBluetooth = document.getElementById('srv-bluetooth');
  const srvDiagtrack = document.getElementById('srv-diagtrack');
  
  const prcDiscord = document.getElementById('prc-discord');
  const prcSteam = document.getElementById('prc-steam');
  const prcSpotify = document.getElementById('prc-spotify');
  const prcEpic = document.getElementById('prc-epic');

  btnTurboToggle.addEventListener('click', () => {
    state.isTurboActive = !state.isTurboActive;
    
    // Toggle class on body for HSL variable redesign
    document.body.classList.toggle('turbo-active', state.isTurboActive);
    
    // Console log updates on Junk Cleaner console (showing system events link)
    addJunkLog(state.isTurboActive ? 'System entering Turbo Acceleration Mode.' : 'System returning to Standard Mode.', state.isTurboActive ? 'warn' : 'info');
    
    if (state.isTurboActive) {
      // Switch elements text/color
      btnTurboToggle.textContent = 'Disable Turbo Mode';
      btnTurboToggle.classList.remove('btn-secondary');
      btnTurboToggle.classList.add('btn-primary');
      
      turboStateBadge.textContent = 'TURBO ACCELERATION ACTIVE';
      turboStateBadge.className = 'turbo-status-val text-danger';
      
      // Apply profile stats
      turboPowercfg.textContent = 'Ultimate Performance Profile {e9a42b02}';
      turboRegTweak.textContent = 'Responsiveness: 0 | GPU Priority: 8';
      turboRegTweak.classList.remove('text-muted');
      turboRegTweak.classList.add('text-danger');
      turboThreadPriority.textContent = 'High Scheduling Priority (Real-time)';
      turboCores.textContent = 'Core Parking Disabled (All Cores Active)';
      
      // Update Services status to Stopped
      srvSysmain.textContent = 'Stopped';
      srvSysmain.className = 'service-pill stopped';
      srvSearch.textContent = 'Stopped';
      srvSearch.className = 'service-pill stopped';
      srvSpooler.textContent = 'Stopped';
      srvSpooler.className = 'service-pill stopped';
      srvBluetooth.textContent = 'Stopped';
      srvBluetooth.className = 'service-pill stopped';
      srvDiagtrack.textContent = 'Suspended';
      srvDiagtrack.className = 'service-pill stopped';
      
      // Update processes status to Suspended
      prcDiscord.textContent = 'Suspended';
      prcDiscord.className = 'process-state-pill suspended';
      prcSteam.textContent = 'Suspended';
      prcSteam.className = 'process-state-pill suspended';
      prcSpotify.textContent = 'Suspended';
      prcSpotify.className = 'process-state-pill suspended';
      prcEpic.textContent = 'Suspended';
      prcEpic.className = 'process-state-pill suspended';
      
      // Change Diagnostic Card details in overview dynamically
      document.getElementById('pulse-diagnostic-box').innerHTML = `
        <span class="terminal-prompt">&gt; Turbo Acceleration profile applied successfully.</span>
        <p class="ai-paragraph"><strong>PULSE ANALYSIS:</strong> 5 non-essential services stopped (SysMain, Search, Spooler, Bluetooth, Telemetry). 4 background task pools suspended. Overall CPU interrupt frequency reduced. RAM overhead dropped by 1.2 GB. System responsiveness optimization applied in registry (Multimedia Class Scheduler tasks).</p>
      `;
      
      addJunkLog('Ultimate Performance power plan activated. CPU governor core parking bypassed.', 'success');
      
    } else {
      // Return to Standard Mode
      btnTurboToggle.textContent = 'Toggle Turbo Mode';
      btnTurboToggle.classList.remove('btn-primary');
      btnTurboToggle.classList.add('btn-secondary');
      
      turboStateBadge.textContent = 'Standard Balanced';
      turboStateBadge.className = 'turbo-status-val text-muted';
      
      turboPowercfg.textContent = 'Dell Balanced Plan';
      turboRegTweak.textContent = 'Default Responsiveness';
      turboRegTweak.className = 'p-value font-mono text-muted';
      turboThreadPriority.textContent = 'Normal Scheduling';
      turboCores.textContent = 'Standard Windows Managed';
      
      // Reset services to Active
      srvSysmain.textContent = 'Active';
      srvSysmain.className = 'service-pill';
      srvSearch.textContent = 'Active';
      srvSearch.className = 'service-pill';
      srvSpooler.textContent = 'Active';
      srvSpooler.className = 'service-pill';
      srvBluetooth.textContent = 'Active';
      srvBluetooth.className = 'service-pill';
      srvDiagtrack.textContent = 'Active';
      srvDiagtrack.className = 'service-pill';
      
      // Reset processes to Running
      prcDiscord.textContent = 'Running';
      prcDiscord.className = 'process-state-pill';
      prcSteam.textContent = 'Running';
      prcSteam.className = 'process-state-pill';
      prcSpotify.textContent = 'Running';
      prcSpotify.className = 'process-state-pill';
      prcEpic.textContent = 'Running';
      prcEpic.className = 'process-state-pill';
      
      // Change Diagnostic Card details
      document.getElementById('pulse-diagnostic-box').innerHTML = `
        <span class="terminal-prompt">&gt; Returning to standard power profiles.</span>
        <p class="ai-paragraph"><strong>PULSE ANALYSIS:</strong> Services resumed. Power profiles reverted. Background launcher threads reactivated. System telemetry (DiagTrack) remains restricted in local configuration database.</p>
      `;
      
      addJunkLog('Power profiles reverted to OS defaults. Thread scheduling returned to standard queues.', 'info');
    }
  });

  // ==========================================================================
  // SENTINEL NETWORK SECURITY AUDIT
  // ==========================================================================
  const btnNetScan = document.getElementById('btn-net-scan');
  const netProgressContainer = document.getElementById('net-progress-container');
  const netProgressFill = document.getElementById('net-progress-fill');
  const netProgressPct = document.getElementById('net-progress-pct');
  const netStatusText = document.getElementById('net-status-text');
  const netDetailsEmpty = document.getElementById('net-details-empty');
  const netPortsTable = document.getElementById('net-ports-table');

  btnNetScan.addEventListener('click', () => {
    if (state.networkScanning) return;
    
    state.networkScanning = true;
    state.networkProgress = 0;
    
    btnNetScan.querySelector('svg').classList.add('spinning');
    btnNetScan.disabled = true;
    netProgressContainer.classList.remove('hidden');
    netPortsTable.classList.add('hidden');
    netDetailsEmpty.classList.add('hidden');
    
    addJunkLog('[Sentinel] Initiating Localhost Adapter Audit...', 'info');
    
    const interval = setInterval(() => {
      state.networkProgress += 5;
      netProgressFill.style.width = `${state.networkProgress}%`;
      netProgressPct.textContent = `${state.networkProgress}%`;
      
      if (state.networkProgress === 20) {
        netStatusText.textContent = 'Checking Active SSID profiles...';
        addJunkLog('[Sentinel] Querying SSID interfaces (netsh wlan show)...', 'info');
      } else if (state.networkProgress === 40) {
        netStatusText.textContent = 'Running DNS Leak check...';
        addJunkLog('[Sentinel] Auditing DNS leak nodes (Local resolver validated)...', 'info');
      } else if (state.networkProgress === 60) {
        netStatusText.textContent = 'Scanning loopback ports (135, 139, 445, 3389)...';
        addJunkLog('[Sentinel] Scanning loopback endpoints...', 'info');
      } else if (state.networkProgress === 80) {
        netStatusText.textContent = 'Auditing Firewall Public profiles...';
        addJunkLog('[Sentinel] Windows Firewall policy verified.', 'info');
      }
      
      if (state.networkProgress >= 100) {
        clearInterval(interval);
        state.networkScanning = false;
        state.networkScanRun = true;
        
        btnNetScan.querySelector('svg').classList.remove('spinning');
        btnNetScan.disabled = false;
        netProgressContainer.classList.add('hidden');
        netPortsTable.classList.remove('hidden');
        
        addJunkLog('[Sentinel] Network security audit complete. Exposed port detected: 3389.', 'warn');
        
        // Overview diagnostic update
        document.getElementById('pulse-diagnostic-box').innerHTML = `
          <span class="terminal-prompt">&gt; Network scan completed. RDP vulnerability verified.</span>
          <p class="ai-paragraph"><strong>PULSE ANALYSIS:</strong> Local security audit detects Port 3389 (RDP) listening. If your router has WAN port forwarding active or DMZ enabled, this exposes your Windows machine to brute-force credential attacks. Local Wi-Fi utilizes WPA3 encryption, which is safe.</p>
        `;
      }
    }, 100);
  });

  // ==========================================================================
  // REGISTRY SURGEON
  // ==========================================================================
  const btnRegScan = document.getElementById('btn-reg-scan');
  const btnRegFix = document.getElementById('btn-reg-fix');
  const regProgressContainer = document.getElementById('reg-progress-container');
  const regProgressFill = document.getElementById('reg-progress-fill');
  const regProgressPct = document.getElementById('reg-progress-pct');
  const regStatusText = document.getElementById('reg-status-text');
  const regDetailsEmpty = document.getElementById('reg-details-empty');
  const regIssuesTable = document.getElementById('reg-issues-table');
  const regCountSub = document.getElementById('reg-count-sub');
  const regLogConsole = document.getElementById('reg-log-console');

  function addRegLog(text, type = 'info') {
    const span = document.createElement('span');
    span.className = `log-${type}`;
    span.textContent = `[${new Date().toLocaleTimeString('en-US', {hour12:false})}] ${text}`;
    regLogConsole.appendChild(span);
    regLogConsole.scrollTop = regLogConsole.scrollHeight;
  }

  btnRegScan.addEventListener('click', () => {
    if (state.registryScanning) return;
    
    state.registryScanning = true;
    state.registryProgress = 0;
    
    btnRegScan.querySelector('svg').classList.add('spinning');
    btnRegScan.disabled = true;
    btnRegFix.classList.add('hidden');
    regProgressContainer.classList.remove('hidden');
    regIssuesTable.classList.add('hidden');
    regDetailsEmpty.classList.add('hidden');
    
    addRegLog('Registry scan initialized (Reading HKCU / HKLM hives)...', 'info');
    
    const interval = setInterval(() => {
      state.registryProgress += 4;
      regProgressFill.style.width = `${state.registryProgress}%`;
      regProgressPct.textContent = `${state.registryProgress}%`;
      
      if (state.registryProgress === 20) {
        regStatusText.textContent = 'Reading HKCU\\Software\\Classes\\CLSID...';
        addRegLog('Scanning ActiveX and COM classes...', 'info');
      } else if (state.registryProgress === 50) {
        regStatusText.textContent = 'Auditing Shared DLL keys...';
        addRegLog('Verifying DLL paths against system filesystem...', 'info');
      } else if (state.registryProgress === 80) {
        regStatusText.textContent = 'Checking application paths...';
        addRegLog('Resolving App Paths executables...', 'info');
      }
      
      if (state.registryProgress >= 100) {
        clearInterval(interval);
        state.registryScanning = false;
        state.registryScanRun = true;
        
        btnRegScan.querySelector('svg').classList.remove('spinning');
        btnRegScan.disabled = false;
        btnRegScan.classList.add('hidden');
        btnRegFix.classList.remove('hidden');
        regProgressContainer.classList.add('hidden');
        regIssuesTable.classList.remove('hidden');
        
        regCountSub.textContent = 'Scan complete. Found 30 integrity infractions across 4 hives.';
        addRegLog('Scan completed. 30 orphan registry references found.', 'warn');
        addRegLog('Safe-edit hook loaded. Keys are queued for safe removal.', 'info');
      }
    }, 80);
  });

  btnRegFix.addEventListener('click', () => {
    if (state.registryScanning) return;
    
    btnRegFix.disabled = true;
    regProgressContainer.classList.remove('hidden');
    regProgressFill.style.width = '0%';
    regProgressPct.textContent = '0%';
    regStatusText.textContent = 'Repairing keys...';
    
    addRegLog('Beginning safe registry surgery reconstruction...', 'info');
    
    let fixPct = 0;
    const interval = setInterval(() => {
      fixPct += 10;
      regProgressFill.style.width = `${fixPct}%`;
      regProgressPct.textContent = `${fixPct}%`;
      
      if (fixPct === 30) {
        addRegLog('Purging 14 orphaned CLSID references.', 'info');
      } else if (fixPct === 60) {
        addRegLog('Reconstructing 8 Shared DLL system path records.', 'info');
      } else if (fixPct === 90) {
        addRegLog('Repairing installer references.', 'info');
      }
      
      if (fixPct >= 100) {
        clearInterval(interval);
        
        btnRegFix.disabled = false;
        btnRegFix.classList.add('hidden');
        btnRegScan.classList.remove('hidden');
        regProgressContainer.classList.add('hidden');
        regIssuesTable.classList.add('hidden');
        regDetailsEmpty.classList.remove('hidden');
        
        regCountSub.textContent = 'Registry successfully repaired. Zero active errors.';
        addRegLog('Registry surgery complete. System structures optimized.', 'success');
        addRegLog('Rebuild verified. Thread lock check completed successfully.', 'success');
      }
    }, 150);
  });

  // ==========================================================================
  // LAZARUS RECOVERY
  // ==========================================================================
  const recoveryRows = document.querySelectorAll('.table-row-selectable');
  const btnLzSnapshot = document.getElementById('btn-lz-snapshot');
  const btnLzVerify = document.getElementById('btn-lz-verify');
  const btnLzRestore = document.getElementById('btn-lz-restore');
  const lazarusLogText = document.getElementById('lazarus-log-text');

  recoveryRows.forEach(row => {
    row.addEventListener('click', () => {
      recoveryRows.forEach(r => r.classList.remove('active'));
      row.classList.add('active');
      state.selectedRecoveryBlock = row.getAttribute('data-block-id');
      lazarusLogText.textContent = `Lazarus Recovery Block #${state.selectedRecoveryBlock} selected. Ready to roll back.`;
      lazarusLogText.className = 'text-main font-mono';
    });
  });

  btnLzSnapshot.addEventListener('click', () => {
    lazarusLogText.textContent = 'Creating sector system snapshot... Please hold.';
    lazarusLogText.className = 'text-warning font-mono';
    
    setTimeout(() => {
      lazarusLogText.textContent = 'Snapshot Block #412 created. Cryptographically signed with local SHA-256 (DelgadoLogic Key).';
      lazarusLogText.className = 'text-success font-mono';
      addJunkLog('[Lazarus] Automatic differential snapshot created locally.', 'success');
    }, 1500);
  });

  btnLzVerify.addEventListener('click', () => {
    lazarusLogText.textContent = 'Running WinSXS baseline hash verification...';
    lazarusLogText.className = 'text-warning font-mono';
    
    setTimeout(() => {
      lazarusLogText.textContent = 'Sector integrity verified. 100% hashes match the local baseline shadow store. Zero corruptions.';
      lazarusLogText.className = 'text-success font-mono';
      addJunkLog('[Lazarus] Local filesystem hash validation completed: 100% OK.', 'success');
    }, 1500);
  });

  btnLzRestore.addEventListener('click', () => {
    if (state.lazarusRestoring) return;
    
    state.lazarusRestoring = true;
    lazarusLogText.textContent = `CRITICAL WARNING: Reconstructing registry and files back to Block #${state.selectedRecoveryBlock}. Initializing sector write in 3 seconds...`;
    lazarusLogText.className = 'text-danger font-mono';
    
    let countdown = 3;
    const interval = setInterval(() => {
      countdown--;
      if (countdown > 0) {
        lazarusLogText.textContent = `CRITICAL WARNING: Rollback starting in ${countdown}s. Do not restart.`;
      } else {
        clearInterval(interval);
        lazarusLogText.textContent = 'Restoring registry hives, boot flags, and system shadows...';
        
        setTimeout(() => {
          lazarusLogText.textContent = `System rollback successfully completed to Block #${state.selectedRecoveryBlock}. Reboot not required due to local state injection.`;
          lazarusLogText.className = 'text-success font-mono';
          state.lazarusRestoring = false;
          addJunkLog(`[Lazarus] System rolled back safely to state #${state.selectedRecoveryBlock}.`, 'success');
        }, 2000);
      }
    }, 1000);
  });
  
  // Quick actions hooks from overview
  document.getElementById('action-quick-scan').addEventListener('click', () => {
    // Switch to Junk Tab and scan
    document.querySelector('[data-target="junk"]').click();
    setTimeout(() => {
      btnJunkScan.click();
    }, 300);
  });
  
  document.getElementById('action-optimize-ram').addEventListener('click', () => {
    // Toggle Turbo Mode
    document.querySelector('[data-target="turbo"]').click();
    setTimeout(() => {
      btnTurboToggle.click();
    }, 300);
  });

  document.getElementById('action-rebuild-lazarus').addEventListener('click', () => {
    // Switch to Lazarus Tab and verify
    document.querySelector('[data-target="lazarus"]').click();
    setTimeout(() => {
      btnLzVerify.click();
    }, 300);
  });
  
  // Set up input behavior for local AI interface
  const pulseInput = document.getElementById('pulse-input');
  const btnPulseAsk = document.getElementById('btn-pulse-ask');
  
  // Let the AI input become active once the page is fully initialized
  setTimeout(() => {
    pulseInput.disabled = false;
    btnPulseAsk.disabled = false;
  }, 1000);
  
  function handlePulseQuery() {
    const query = pulseInput.value.trim();
    if (!query) return;
    
    pulseInput.value = '';
    pulseInput.disabled = true;
    btnPulseAsk.disabled = true;
    
    const diagnosticBox = document.getElementById('pulse-diagnostic-box');
    diagnosticBox.innerHTML += `
      <p style="margin-top: 0.75rem; color: var(--highlight);" class="font-mono">&gt; User: ${query}</p>
      <p style="color: var(--text-muted);" id="pulse-thinking" class="font-mono">Pulse is thinking...</p>
    `;
    diagnosticBox.scrollTop = diagnosticBox.scrollHeight;
    
    setTimeout(() => {
      const thinkingEl = document.getElementById('pulse-thinking');
      if (thinkingEl) thinkingEl.remove();
      
      let response = '';
      const lowercaseQuery = query.toLowerCase();
      
      if (lowercaseQuery.includes('latency') || lowercaseQuery.includes('performance') || lowercaseQuery.includes('slow')) {
        response = "<strong>PULSE RESPONSE:</strong> To lower latency, enable <strong>Turbo Mode</strong>. This suspends high-overhead background processes like discord.exe (PID 8956) and steam.exe (PID 10532), disables CPU core parking, and applies a low-latency registry tweak HKLM\\...\\SystemProfile\\SystemResponsiveness to 0.";
      } else if (lowercaseQuery.includes('rdp') || lowercaseQuery.includes('port') || lowercaseQuery.includes('security')) {
        response = "<strong>PULSE RESPONSE:</strong> Port 3389 (RDP) is currently open on localhost. This represents a potential vulnerability. If your gateway router has port 3389 exposed to WAN, external attackers can attempt RDP password guessing. Recommendation: Close RDP or restrict source IPs using Windows Defender Firewall.";
      } else if (lowercaseQuery.includes('junk') || lowercaseQuery.includes('clean') || lowercaseQuery.includes('temp')) {
        response = "<strong>PULSE RESPONSE:</strong> System Temp has 1.42 GB of cache, and User Temp has 2.15 GB of storage. Total scrap is 4.90 GB. You can safely clear this using the <strong>Junk Cleaner</strong> panel. File locks are automatically analyzed to prevent app crashes.";
      } else {
        response = "<strong>PULSE RESPONSE:</strong> I have analyzed your system specifications (Ryzen 9 5900X, 32GB RAM). Your sector health is 100%. To reduce resource usage, use <strong>Junk Cleaner</strong> to purge cache files or toggle <strong>Turbo Mode</strong> for real-time thread priority configurations.";
      }
      
      diagnosticBox.innerHTML += `
        <p style="margin-top: 0.5rem;" class="ai-paragraph">${response}</p>
      `;
      diagnosticBox.scrollTop = diagnosticBox.scrollHeight;
      
      pulseInput.disabled = false;
      btnPulseAsk.disabled = false;
      pulseInput.focus();
    }, 1200);
  }
  
  btnPulseAsk.addEventListener('click', handlePulseQuery);
  pulseInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      handlePulseQuery();
    }
  });

});
