/**
 * @fileoverview WiFi Monitor Dashboard — Frontend Logic
 *
 * File ini menangani semua interaksi UI di dashboard WiFi Monitor.
 * Komunikasi real-time dengan server Flask menggunakan Socket.IO WebSocket.
 *
 * Fitur utama:
 * - Koneksi WebSocket ke server Flask via Socket.IO
 * - Auto-scan perangkat jaringan setiap 5 detik (2 detik saat serangan aktif)
 * - Render tabel perangkat (desktop) dan kartu (mobile) secara dinamis
 * - Tampilkan alert keamanan dengan filter severity
 * - Modal mitigasi serangan dengan preview command
 * - Modal ARP Spoof simulator dengan target IP selector
 * - Grafik analytics (Chart.js): severity, attack types, timeline
 * - Toast notification dan corner notification untuk alert baru
 * - Attack banner merah saat ada serangan aktif
 *
 * Alur data:
 * Server → Socket.IO → updateDevices() / updateAlerts() → render ke DOM
 *
 * ---
 *
 * @fileoverview WiFi Monitor Dashboard — Frontend Logic
 *
 * This file handles all UI interactions in the WiFi Monitor dashboard.
 * Real-time communication with the Flask server uses Socket.IO WebSocket.
 *
 * Main features:
 * - WebSocket connection to Flask server via Socket.IO
 * - Auto-scan network devices every 5s (2s during active attacks)
 * - Dynamically render device table (desktop) and cards (mobile)
 * - Display security alerts with severity filtering
 * - Attack mitigation modal with command preview
 * - ARP Spoof simulator modal with target IP selector
 * - Analytics charts (Chart.js): severity, attack types, timeline
 * - Toast and corner notifications for new alerts
 * - Red attack banner when active attacks are detected
 *
 * Data flow:
 * Server → Socket.IO → updateDevices() / updateAlerts() → render to DOM
 */

// ── State ──────────────────────────────────────────────────────────────────
let socket       = null;
let allDevices   = [];
let allAlerts    = [];
let seenAlertIds = new Set();
let currentTab   = 'devices';
let alertsPanelOpen = false;
let charts       = {};
let sidebarOpen  = false;

// Mitigation modal state
let mitigateAlertId   = null;
let mitigateAlertData = null;
let mitigating        = false;

// Corner notif timer
let cornerNotifTimer = null;

// Toast queue (max 3 visible)
const MAX_TOASTS = 3;

// Auto-scan state
let autoScanInterval  = null;
let scanCountdown     = 5;
let scanCountdownTimer = null;
let attackActive      = false;
const NORMAL_SCAN_INTERVAL  = 5000;   // 5 detik normal
const ATTACK_SCAN_INTERVAL  = 2000;   // 2 detik saat serangan aktif

// ── Init ───────────────────────────────────────────────────────────────────
/**
 * Entry point — dijalankan setelah DOM selesai dimuat.
 * Inisialisasi koneksi WebSocket, chart, dan auto-scan loop.
 *
 * Entry point — runs after DOM is fully loaded.
 * Initializes WebSocket connection, charts, and auto-scan loop.
 */
document.addEventListener('DOMContentLoaded', () => {
  initSocket();
  initCharts();
  startAutoScan(NORMAL_SCAN_INTERVAL);
  startScanCountdown(5);
  document.getElementById('scan-indicator').classList.remove('hidden');
  document.getElementById('scan-indicator').classList.add('flex');
});

// ── Auto-Scan ──────────────────────────────────────────────────────────────
/**
 * Mulai interval auto-scan perangkat jaringan.
 * Kalau WebSocket tersambung, pakai emit 'request_scan'.
 * Kalau tidak, fallback ke fetch /api/devices langsung.
 *
 * @param {number} interval - Interval dalam milidetik (5000 normal, 2000 attack mode)
 *
 * ---
 * Start the network device auto-scan interval.
 * If WebSocket is connected, uses emit 'request_scan'.
 * Otherwise falls back to direct fetch /api/devices.
 *
 * @param {number} interval - Interval in milliseconds (5000 normal, 2000 attack mode)
 */
function startAutoScan(interval) {
  clearInterval(autoScanInterval);
  autoScanInterval = setInterval(() => {
    if (socket && socket.connected) {
      socket.emit('request_scan');
    } else {
      fetch('/api/devices').then(r => r.json()).then(d => {
        if (d.devices) updateDevices(d.devices);
      }).catch(() => {});
    }
    // Also refresh stats
    refreshStats();
  }, interval);
}

function startScanCountdown(seconds) {
  clearInterval(scanCountdownTimer);
  scanCountdown = seconds;
  updateCountdownUI(seconds);

  scanCountdownTimer = setInterval(() => {
    scanCountdown--;
    if (scanCountdown <= 0) {
      scanCountdown = attackActive ? 2 : 5;
    }
    updateCountdownUI(scanCountdown);
  }, 1000);
}

function updateCountdownUI(sec) {
  const el = document.getElementById('scan-countdown');
  if (el) el.textContent = sec + 's';

  // Update autoscan progress bar
  const bar = document.getElementById('autoscan-bar');
  const total = attackActive ? 2 : 5;
  if (bar) {
    const pct = (sec / total) * 100;
    bar.style.width = pct + '%';
    bar.style.background = attackActive ? '#ef4444' : '#06b6d4';
  }

  // Update autoscan status text
  const status = document.getElementById('autoscan-status');
  if (status) {
    status.textContent = attackActive ? `${total}s (ATTACK MODE)` : `${total}s interval`;
    status.className = attackActive
      ? 'text-xs font-mono text-red-400'
      : 'text-xs font-mono text-cyan-400';
  }
}

/**
 * Aktifkan atau nonaktifkan "attack mode".
 * Saat attack mode aktif, interval scan dipercepat dari 5s ke 2s
 * agar dashboard lebih responsif terhadap perubahan jaringan.
 *
 * @param {boolean} active - true = aktifkan attack mode, false = kembali normal
 *
 * ---
 * Activate or deactivate "attack mode".
 * When active, scan interval speeds up from 5s to 2s
 * so the dashboard responds faster to network changes.
 *
 * @param {boolean} active - true = enable attack mode, false = return to normal
 */
function setAttackMode(active) {
  if (attackActive === active) return;
  attackActive = active;

  if (active) {
    startAutoScan(ATTACK_SCAN_INTERVAL);
    startScanCountdown(2);
  } else {
    startAutoScan(NORMAL_SCAN_INTERVAL);
    startScanCountdown(5);
  }
}

// ── Attack Banner ──────────────────────────────────────────────────────────
function updateAttackBanner() {
  const activeAttacks = allAlerts.filter(a => !a.mitigated &&
    ['CRITICAL', 'HIGH'].includes(a.severity));
  const banner = document.getElementById('attack-banner');
  const countEl = document.getElementById('attack-banner-count');
  const textEl  = document.getElementById('attack-banner-text');

  if (activeAttacks.length > 0) {
    banner.classList.remove('hidden');
    countEl.textContent = activeAttacks.length;
    const latest = activeAttacks[0];
    textEl.textContent = `⚠️ SERANGAN AKTIF: ${latest.attack_type || latest.type}`;
    setAttackMode(true);
  } else {
    banner.classList.add('hidden');
    setAttackMode(false);
  }
}

// ── SocketIO ───────────────────────────────────────────────────────────────
/**
 * Inisialisasi koneksi Socket.IO dan daftarkan semua event handler.
 *
 * Events yang didengarkan dari server:
 * - connect          : koneksi berhasil → update status indicator
 * - disconnect       : koneksi putus → update status indicator
 * - initial_data     : data awal saat pertama connect (devices, alerts, stats)
 * - devices_update   : update daftar perangkat dari auto-scan
 * - new_alert        : alert baru dari monitor → tampilkan toast + corner notif
 * - stats_update     : update statistik dashboard
 * - alerts_cleared   : semua alert dihapus → bersihkan UI
 * - alert_mitigated  : alert berhasil dimitigasi → update badge
 * - scan_started     : scan dimulai → flash pulse indicator
 * - device_restored  : internet perangkat dipulihkan → toast sukses
 *
 * ---
 * Initialize Socket.IO connection and register all event handlers.
 *
 * Events listened from server:
 * - connect          : connection established → update status indicator
 * - disconnect       : connection lost → update status indicator
 * - initial_data     : initial data on first connect (devices, alerts, stats)
 * - devices_update   : device list update from auto-scan
 * - new_alert        : new alert from monitor → show toast + corner notif
 * - stats_update     : dashboard statistics update
 * - alerts_cleared   : all alerts cleared → clean up UI
 * - alert_mitigated  : alert successfully mitigated → update badge
 * - scan_started     : scan started → flash pulse indicator
 * - device_restored  : device internet restored → success toast
 */
function initSocket() {
  socket = io({ transports: ['websocket', 'polling'] });

  socket.on('connect', () => {
    setConnStatus(true);
  });

  socket.on('disconnect', () => {
    setConnStatus(false);
  });

  socket.on('initial_data', (data) => {
    if (data.demo_mode) document.getElementById('demo-badge').classList.remove('hidden');
    if (data.devices) updateDevices(data.devices);
    if (data.alerts)  updateAlerts(data.alerts);
    if (data.stats)   updateStats(data.stats);
  });

  socket.on('devices_update', (data) => {
    if (data.devices) {
      updateDevices(data.devices);
      // Flash scan pulse
      flashScanPulse();
    }
  });

  socket.on('new_alert', (alert) => {
    if (seenAlertIds.has(alert.id)) return;
    seenAlertIds.add(alert.id);

    allAlerts.unshift(alert);
    renderAlerts();
    renderSideAlerts();
    updateAlertBadge();
    updateTabAlertCount();
    updateAttackBanner();

    showCornerNotif(alert);
    showToast(alert);
    updateCharts();
  });

  socket.on('stats_update', (stats) => {
    updateStats(stats);
  });

  socket.on('alerts_cleared', () => {
    allAlerts = [];
    seenAlertIds.clear();
    renderAlerts();
    renderSideAlerts();
    updateAlertBadge();
    updateTabAlertCount();
    updateAttackBanner();
  });

  socket.on('alert_mitigated', (data) => {
    const idx = allAlerts.findIndex(a => a.id === data.alert_id);
    if (idx !== -1) {
      allAlerts[idx].mitigated = true;
      allAlerts[idx].mitigation_result = data.result;
      renderAlerts();
      renderSideAlerts();
      updateAttackBanner();
    }
    showToastMsg('success', '🛡️ Mitigated', `Attack from ${data.source_ip} has been mitigated`);
  });

  socket.on('scan_started', () => {
    flashScanPulse();
  });

  socket.on('device_restored', (data) => {
    showToastMsg('success', '🌐 Internet Restored', `Akses internet ${data.ip} dipulihkan`);
    if (socket && socket.connected) socket.emit('request_scan');
  });

  // ESP events
  socket.on('esp_status_update', (data) => {
    if (data.devices) {
      espDevices = data.devices;
      if (currentTab === 'esp') renderEspList();
      const badge = document.getElementById('tab-esp-count');
      if (espDevices.length > 0) {
        badge.classList.remove('hidden');
        badge.textContent = espDevices.length;
      }
    }
  });

  socket.on('esp_wifi_scan', (data) => {
    if (data.networks && currentTab === 'esp') {
      renderWifiScanResults(data.esp_id, data.networks);
    }
  });

  socket.on('esp_connecting', (data) => {
    showToastMsg('info', '📶 Connecting', `ESP ${data.esp_id} → ${data.ssid}`);
  });
}

function flashScanPulse() {
  const pulse = document.getElementById('scan-pulse');
  if (!pulse) return;
  pulse.classList.remove('hidden');
  setTimeout(() => pulse.classList.add('hidden'), 800);
}

function setConnStatus(connected) {
  const dot  = document.getElementById('conn-dot');
  const text = document.getElementById('conn-text');
  if (connected) {
    dot.className    = 'w-2 h-2 rounded-full bg-green-400';
    text.textContent = 'Connected';
    text.className   = 'text-green-400';
  } else {
    dot.className    = 'w-2 h-2 rounded-full bg-red-400 animate-pulse';
    text.textContent = 'Disconnected';
    text.className   = 'text-red-400';
  }
}

// ── Sidebar (mobile) ───────────────────────────────────────────────────────
function toggleSidebar() {
  sidebarOpen ? closeSidebar() : openSidebar();
}

function openSidebar() {
  sidebarOpen = true;
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebar-overlay').classList.remove('hidden');
}

function closeSidebar() {
  sidebarOpen = false;
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.add('hidden');
}

// ── Devices ────────────────────────────────────────────────────────────────
/**
 * Update state perangkat dan re-render tabel/kartu.
 *
 * @param {Array<Object>} devices - Array device dari server
 *
 * ---
 * Update device state and re-render table/cards.
 *
 * @param {Array<Object>} devices - Device array from server
 */
function updateDevices(devices) {
  allDevices = devices;
  renderDevices();
  document.getElementById('device-count-label').textContent = `${devices.length} devices`;
}

/**
 * Render daftar perangkat ke tabel (desktop) dan kartu (mobile).
 * Terapkan filter pencarian teks dan filter status/threat.
 * Dipanggil setiap kali allDevices berubah atau filter diubah user.
 *
 * ---
 * Render device list to table (desktop) and cards (mobile).
 * Applies text search filter and status/threat filter.
 * Called whenever allDevices changes or user changes filters.
 */
function renderDevices() {
  const search = document.getElementById('device-search').value.toLowerCase();
  const filter = document.getElementById('device-filter').value;

  const filtered = allDevices.filter(d => {
    const matchSearch = !search ||
      d.ip.includes(search) ||
      (d.mac || '').toLowerCase().includes(search) ||
      (d.hostname || '').toLowerCase().includes(search) ||
      (d.vendor || '').toLowerCase().includes(search);
    const matchFilter =
      filter === 'all'     ? true :
      filter === 'online'  ? d.status === 'online' :
      filter === 'offline' ? d.status === 'offline' :
      filter === 'threat'  ? d.threat_level !== 'safe' : true;
    return matchSearch && matchFilter;
  });

  // Desktop table
  const tbody = document.getElementById('device-table-body');
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-gray-500 text-sm">No devices found</td></tr>`;
  } else {
    tbody.innerHTML = filtered.map(d => renderDeviceRow(d)).join('');
  }

  // Mobile cards
  const cards = document.getElementById('device-cards');
  if (filtered.length === 0) {
    cards.innerHTML = `<div class="text-center py-8 text-gray-500 text-sm">No devices found</div>`;
  } else {
    cards.innerHTML = filtered.map(d => renderDeviceCard(d)).join('');
  }
}

function renderDeviceRow(d) {
  const statusClass =
    d.status === 'online' ? 'status-online' :
    d.threat_level !== 'safe' ? 'status-threat' : 'status-offline';
  const threatClass =
    d.threat_level === 'critical' ? 'threat-critical' :
    d.threat_level === 'danger'   ? 'threat-danger' :
    d.threat_level === 'warning'  ? 'threat-warning' : 'threat-safe';
  const threatLabel =
    d.threat_level === 'critical' ? '🔴 Critical' :
    d.threat_level === 'danger'   ? '🟠 Danger' :
    d.threat_level === 'warning'  ? '🟡 Warning' : '🟢 Safe';

  const deviceAlerts = allAlerts.filter(a => a.source_ip === d.ip && !a.mitigated);
  const mitigateBtn = deviceAlerts.length > 0
    ? `<button onclick="openMitigateFromDevice('${d.ip}')"
         class="px-2 py-1 bg-green-700 hover:bg-green-600 text-white text-xs rounded-lg transition font-medium">
         🛡️ Mitigate
       </button>`
    : '';

  // Encode device data for ARP spoof modal
  const devData = encodeURIComponent(JSON.stringify({ ip: d.ip, mac: d.mac, hostname: d.hostname, vendor: d.vendor }));

  return `
    <tr>
      <td class="px-4 py-3">
        <div class="flex items-center gap-2">
          <span class="w-2.5 h-2.5 rounded-full ${statusClass}"></span>
          <span class="text-xs text-gray-400 capitalize">${d.status}</span>
        </div>
      </td>
      <td class="px-4 py-3 font-mono text-cyan-400 text-xs">${d.ip}</td>
      <td class="px-4 py-3 font-mono text-gray-400 text-xs">${d.mac || 'N/A'}</td>
      <td class="px-4 py-3 text-gray-300 text-xs">${d.hostname || d.ip}</td>
      <td class="px-4 py-3 text-xs">
        <span class="text-gray-300">${d.vendor && d.vendor !== 'Unknown' ? d.vendor : '<span class="text-gray-600">Unknown</span>'}</span>
      </td>
      <td class="px-4 py-3 text-xs">
        <span class="${threatClass} font-medium">${threatLabel}</span>
      </td>
      <td class="px-4 py-3 text-gray-500 text-xs font-mono">${d.last_seen || '-'}</td>
      <td class="px-4 py-3 text-xs">
        <div class="flex items-center gap-1.5">
          <button onclick="openArpSpoofModal('${d.ip}')"
            class="px-2 py-1 bg-red-900/40 hover:bg-red-800/60 border border-red-800/50 text-red-300 text-xs rounded-lg transition font-medium whitespace-nowrap">
            ⚠️ ARP
          </button>
          ${mitigateBtn}
        </div>
      </td>
    </tr>
  `;
}

function renderDeviceCard(d) {
  const statusClass =
    d.status === 'online' ? 'status-online' :
    d.threat_level !== 'safe' ? 'status-threat' : 'status-offline';
  const threatClass =
    d.threat_level === 'critical' ? 'threat-critical' :
    d.threat_level === 'danger'   ? 'threat-danger' :
    d.threat_level === 'warning'  ? 'threat-warning' : 'threat-safe';
  const threatLabel =
    d.threat_level === 'critical' ? '🔴 Critical' :
    d.threat_level === 'danger'   ? '🟠 Danger' :
    d.threat_level === 'warning'  ? '🟡 Warning' : '🟢 Safe';

  const deviceAlerts = allAlerts.filter(a => a.source_ip === d.ip && !a.mitigated);
  const cardClass = d.threat_level === 'critical' ? 'device-card threat-critical-active' :
                    d.threat_level !== 'safe' ? 'device-card threat-active' : 'device-card';

  return `
    <div class="${cardClass}">
      <div class="flex items-start justify-between gap-2">
        <div class="flex items-center gap-2 flex-1 min-w-0">
          <span class="w-2.5 h-2.5 rounded-full flex-shrink-0 ${statusClass}"></span>
          <div class="min-w-0">
            <p class="text-cyan-400 font-mono text-sm font-medium">${d.ip}</p>
            <p class="text-gray-400 text-xs truncate">${d.hostname || d.ip}</p>
          </div>
        </div>
        <span class="${threatClass} text-xs font-medium flex-shrink-0">${threatLabel}</span>
      </div>
      <div class="mt-2 grid grid-cols-2 gap-x-4 gap-y-1">
        <div>
          <p class="text-gray-500 text-xs">MAC</p>
          <p class="text-gray-300 font-mono text-xs truncate">${d.mac || 'N/A'}</p>
        </div>
        <div>
          <p class="text-gray-500 text-xs">Vendor</p>
          <p class="text-gray-300 text-xs truncate">${d.vendor || 'Unknown'}</p>
        </div>
        <div>
          <p class="text-gray-500 text-xs">Status</p>
          <p class="text-gray-300 text-xs capitalize">${d.status}</p>
        </div>
        <div>
          <p class="text-gray-500 text-xs">Last Seen</p>
          <p class="text-gray-300 font-mono text-xs">${d.last_seen || '-'}</p>
        </div>
      </div>
      <div class="mt-2 pt-2 border-t border-gray-800 flex gap-2">
        <button onclick="openArpSpoofModal('${d.ip}')"
          class="flex-1 px-3 py-1.5 bg-red-900/40 hover:bg-red-800/60 border border-red-800/50 text-red-300 text-xs rounded-lg transition font-medium text-center">
          ⚠️ ARP Spoof
        </button>
        ${deviceAlerts.length > 0 ? `
          <button onclick="openMitigateFromDevice('${d.ip}')"
            class="flex-1 px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded-lg transition font-medium text-center">
            🛡️ Mitigate
          </button>
        ` : ''}
      </div>
    </div>
  `;
}

function filterDevices() { renderDevices(); }

// ── Alerts ─────────────────────────────────────────────────────────────────
function updateAlerts(alerts) {
  allAlerts = alerts;
  alerts.forEach(a => seenAlertIds.add(a.id));
  renderAlerts();
  renderSideAlerts();
  updateAlertBadge();
  updateTabAlertCount();
  updateAttackBanner();
}

function renderAlerts() {
  const filter = document.getElementById('alert-filter').value;
  const filtered = filter === 'all' ? allAlerts : allAlerts.filter(a => a.severity === filter);
  const container = document.getElementById('alert-list');

  if (filtered.length === 0) {
    container.innerHTML = `<div class="text-center py-8 text-gray-500 text-sm">No alerts yet. Network is clean! ✅</div>`;
    return;
  }
  container.innerHTML = filtered.map(a => renderAlertCard(a)).join('');
}

function renderAlertCard(a) {
  const sev = (a.severity || 'low').toLowerCase();
  const mitigatedBadge = a.mitigated
    ? `<span class="px-2 py-0.5 bg-green-900/50 border border-green-700 text-green-400 text-xs rounded-full font-medium">✅ Mitigated</span>`
    : '';

  const mitigateBtn = !a.mitigated
    ? `<button onclick="openMitigateModal(${a.id})"
         class="mitigate-btn">
         🛡️ Mitigate
       </button>`
    : `<button onclick="showMitigationResult(${a.id})"
         class="mitigate-btn mitigated">
         📋 View Result
       </button>`;

  return `
    <div class="alert-card ${sev}" id="alert-card-${a.id}">
      <div class="flex items-start justify-between gap-3">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1 flex-wrap">
            <span class="badge-${sev} text-xs px-2 py-0.5 rounded-full font-medium">${a.severity}</span>
            <span class="text-gray-400 text-xs font-mono">${a.attack_type || a.type}</span>
            ${mitigatedBadge}
          </div>
          <p class="text-white text-sm font-medium">${a.title}</p>
          <p class="text-gray-400 text-xs mt-1 leading-relaxed">${a.message}</p>
          <div class="flex items-center gap-3 mt-2 flex-wrap">
            ${a.source_ip && a.source_ip !== 'N/A'
              ? `<span class="text-cyan-500 text-xs font-mono">📍 ${a.source_ip}</span>`
              : ''}
            <span class="text-gray-600 text-xs font-mono">${a.timestamp}</span>
          </div>
        </div>
        <div class="flex-shrink-0">
          ${mitigateBtn}
        </div>
      </div>
    </div>
  `;
}

function renderSideAlerts() {
  const container = document.getElementById('side-alert-list');
  const recent = allAlerts.slice(0, 10);
  if (recent.length === 0) {
    container.innerHTML = `<p class="text-gray-500 text-xs text-center py-4">No alerts yet</p>`;
    return;
  }
  container.innerHTML = recent.map(a => {
    const sev = (a.severity || 'low').toLowerCase();
    return `
      <div class="alert-card ${sev} !p-2.5 cursor-pointer" onclick="switchTab('alerts')">
        <div class="flex items-start gap-2">
          <div class="flex-1 min-w-0">
            <p class="text-white text-xs font-medium truncate">${a.title}</p>
            <p class="text-gray-400 text-xs mt-0.5 line-clamp-2">${a.message}</p>
            <p class="text-gray-600 text-xs font-mono mt-1">${a.timestamp}</p>
          </div>
          ${a.mitigated ? '<span class="text-green-400 text-xs flex-shrink-0">✅</span>' : ''}
        </div>
      </div>
    `;
  }).join('');
}

function filterAlerts() { renderAlerts(); }

function updateAlertBadge() {
  const unread = allAlerts.filter(a => !a.read).length;
  const badge = document.getElementById('alert-badge');
  if (unread > 0) {
    badge.classList.remove('hidden');
    badge.textContent = unread > 99 ? '99+' : unread;
  } else {
    badge.classList.add('hidden');
  }
}

function updateTabAlertCount() {
  const count = allAlerts.filter(a => !a.read).length;
  const el = document.getElementById('tab-alert-count');
  if (count > 0) {
    el.classList.remove('hidden');
    el.textContent = count > 99 ? '99+' : count;
  } else {
    el.classList.add('hidden');
  }
}

// ── Stats ──────────────────────────────────────────────────────────────────
function updateStats(stats) {
  if (!stats) return;
  document.getElementById('stat-devices').textContent = stats.total_devices || 0;
  document.getElementById('stat-online').textContent  = `${stats.online_devices || 0} online`;
  document.getElementById('stat-alerts').textContent  = stats.total_alerts || 0;
  document.getElementById('stat-unread').textContent  = `${stats.unread_alerts || 0} unread`;
  document.getElementById('stat-uptime').textContent  = stats.uptime || '00:00:00';

  const sev = stats.severity_counts || {};
  document.getElementById('sev-critical').textContent = sev.CRITICAL || 0;
  document.getElementById('sev-high').textContent     = sev.HIGH || 0;
  document.getElementById('sev-medium').textContent   = sev.MEDIUM || 0;
  document.getElementById('sev-low').textContent      = sev.LOW || 0;

  const atk = stats.attack_counts || {};
  document.getElementById('atk-arp').textContent    = atk.arp || 0;
  document.getElementById('atk-deauth').textContent = atk.deauth || 0;
  document.getElementById('atk-dns').textContent    = atk.dns || 0;
  document.getElementById('atk-dhcp').textContent   = atk.dhcp || 0;
  document.getElementById('atk-port').textContent   = atk.port || 0;

  updateCharts(stats);
}

async function refreshStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    updateStats(data);
  } catch (e) {}
}

// ── Charts ─────────────────────────────────────────────────────────────────
function initCharts() {
  Chart.defaults.color = '#9ca3af';
  Chart.defaults.borderColor = '#1f2937';

  charts.severity = new Chart(document.getElementById('chart-severity'), {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{ data: [0,0,0,0], backgroundColor: ['#7c3aed','#ef4444','#f59e0b','#3b82f6'], borderWidth: 0 }]
    },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { padding: 12, font: { size: 11 } } } } }
  });

  charts.attacks = new Chart(document.getElementById('chart-attacks'), {
    type: 'bar',
    data: {
      labels: ['ARP', 'Deauth', 'DNS', 'DHCP', 'Port Scan'],
      datasets: [{ label: 'Attacks', data: [0,0,0,0,0], backgroundColor: ['#7c3aed','#ef4444','#f59e0b','#3b82f6','#10b981'], borderRadius: 6, borderWidth: 0 }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, grid: { color: '#1f2937' }, ticks: { stepSize: 1 } }, x: { grid: { display: false } } }
    }
  });

  charts.timeline = new Chart(document.getElementById('chart-timeline'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [{ label: 'Alerts', data: [], borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,0.1)', fill: true, tension: 0.4, pointRadius: 3, pointBackgroundColor: '#06b6d4' }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, grid: { color: '#1f2937' }, ticks: { stepSize: 1 } }, x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } } }
    }
  });
}

function updateCharts(stats) {
  if (!charts.severity) return;
  if (stats && stats.severity_counts) {
    const sev = stats.severity_counts;
    charts.severity.data.datasets[0].data = [sev.CRITICAL||0, sev.HIGH||0, sev.MEDIUM||0, sev.LOW||0];
    charts.severity.update('none');
  }
  if (stats && stats.attack_counts) {
    const atk = stats.attack_counts;
    charts.attacks.data.datasets[0].data = [atk.arp||0, atk.deauth||0, atk.dns||0, atk.dhcp||0, atk.port||0];
    charts.attacks.update('none');
  }
  const recent = allAlerts.slice(0, 20).reverse();
  charts.timeline.data.labels = recent.map(a => (a.timestamp || '').split(' ')[1] || a.timestamp);
  charts.timeline.data.datasets[0].data = recent.map((_, i) => i + 1);
  charts.timeline.update('none');
}

// ── UI Actions ─────────────────────────────────────────────────────────────
function switchTab(tab) {
  currentTab = tab;
  ['devices', 'alerts', 'esp', 'chart'].forEach(t => {
    document.getElementById(`panel-${t}`)?.classList.toggle('hidden', t !== tab);
    document.getElementById(`tab-${t}`)?.classList.toggle('active', t === tab);
  });
  if (tab === 'chart') updateCharts();
  if (tab === 'esp')   refreshEspList();
  if (tab === 'alerts') {
    fetch('/api/alerts/read-all', { method: 'POST' }).catch(() => {});
    allAlerts.forEach(a => a.read = true);
    updateAlertBadge();
    updateTabAlertCount();
  }
  if (window.innerWidth < 768) closeSidebar();
}

function toggleAlertsPanel() {
  alertsPanelOpen = !alertsPanelOpen;
  document.getElementById('alerts-panel').classList.toggle('hidden', !alertsPanelOpen);
}

function triggerScan() {
  const btn = document.getElementById('scan-btn');
  btn.classList.add('scanning');
  btn.disabled = true;
  if (socket && socket.connected) {
    socket.emit('request_scan');
  } else {
    fetch('/api/scan', { method: 'POST' });
  }
  flashScanPulse();
  setTimeout(() => { btn.classList.remove('scanning'); btn.disabled = false; }, 3000);
}

function clearAlerts() {
  fetch('/api/alerts/clear', { method: 'POST' });
}

async function simulate(type) {
  try {
    const ip = '192.168.1.' + (Math.floor(Math.random() * 200) + 10);
    const res = await fetch(`/api/simulate/${type}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ src_ip: ip })
    });
    const data = await res.json();
    if (data.status === 'ok') {
      showToastMsg('success', '✅ Simulated', `${type} attack from ${ip}`);
    }
  } catch (e) {
    showToastMsg('error', '❌ Error', 'Failed to simulate');
  }
}

// ── Corner Notification ────────────────────────────────────────────────────
const SEVERITY_ICONS = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };

function showCornerNotif(alert) {
  clearTimeout(cornerNotifTimer);
  const el    = document.getElementById('corner-notif');
  const inner = document.getElementById('corner-notif-inner');
  const sev   = (alert.severity || 'LOW').toLowerCase();

  document.getElementById('corner-notif-icon').textContent  = SEVERITY_ICONS[alert.severity] || '⚠️';
  document.getElementById('corner-notif-title').textContent = alert.title;
  document.getElementById('corner-notif-ip').textContent    = alert.source_ip && alert.source_ip !== 'N/A'
    ? `📍 ${alert.source_ip}` : '';

  inner.className = `corner-notif-card ${sev}`;
  el.classList.remove('hidden');
  el.classList.add('corner-notif-enter');

  cornerNotifTimer = setTimeout(() => closeCornerNotif(), 5000);
}

function closeCornerNotif() {
  const el = document.getElementById('corner-notif');
  el.classList.add('hidden');
  el.classList.remove('corner-notif-enter');
}

// ── Toast ──────────────────────────────────────────────────────────────────
function showToast(alert) {
  const container = document.getElementById('toast-container');

  while (container.children.length >= MAX_TOASTS) {
    container.removeChild(container.firstChild);
  }

  const sev = (alert.severity || 'low').toLowerCase();
  const id  = 'toast-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);

  const toast = document.createElement('div');
  toast.id = id;
  toast.className = `toast ${sev} pointer-events-auto`;
  toast.innerHTML = `
    <div class="flex-1 min-w-0">
      <p class="text-white text-xs font-semibold truncate">${alert.title}</p>
      <p class="text-gray-400 text-xs mt-0.5 line-clamp-1">${alert.message}</p>
    </div>
    <button onclick="this.closest('.toast').remove()" class="text-gray-500 hover:text-white text-base leading-none ml-2 flex-shrink-0">×</button>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    if (document.getElementById(id)) {
      toast.style.animation = 'fadeOut 0.3s ease forwards';
      setTimeout(() => toast.remove(), 300);
    }
  }, 4000);
}

function showToastMsg(type, title, msg) {
  const sevMap = { success: 'LOW', error: 'HIGH', info: 'MEDIUM', warning: 'MEDIUM' };
  showToast({ severity: sevMap[type] || 'LOW', title, message: msg });
}

// ── Mitigation Modal ───────────────────────────────────────────────────────
/**
 * Buka modal mitigasi untuk alert tertentu.
 * Fetch preview command dari server lalu tampilkan di modal.
 *
 * @param {number} alertId - ID alert yang mau dimitigasi
 *
 * ---
 * Open the mitigation modal for a specific alert.
 * Fetches command preview from server then displays in modal.
 *
 * @param {number} alertId - ID of the alert to mitigate
 */
async function openMitigateModal(alertId) {
  const alert = allAlerts.find(a => a.id === alertId);
  if (!alert) return;

  mitigateAlertId   = alertId;
  mitigateAlertData = alert;
  mitigating        = false;

  document.getElementById('modal-subtitle').textContent    = alert.title;
  document.getElementById('modal-attack-type').textContent = alert.attack_type || alert.type;
  document.getElementById('modal-source-ip').textContent   = alert.source_ip || 'N/A';

  const sevEl = document.getElementById('modal-severity');
  sevEl.textContent = alert.severity;
  sevEl.className   = `font-medium badge-${(alert.severity||'low').toLowerCase()} text-xs px-2 py-0.5 rounded-full`;

  document.getElementById('modal-result').classList.add('hidden');
  document.getElementById('restore-internet-section').classList.add('hidden');
  document.getElementById('modal-result-steps').innerHTML = '';
  document.getElementById('modal-result-summary').textContent = '';

  const confirmBtn = document.getElementById('modal-confirm-btn');
  const cancelBtn  = document.getElementById('modal-cancel-btn');
  confirmBtn.innerHTML = '<span>🛡️ Run Mitigation</span>';
  confirmBtn.disabled  = false;
  cancelBtn.textContent = 'Cancel';
  cancelBtn.disabled = false;

  document.getElementById('modal-commands').innerHTML = '<span class="text-gray-500">Loading...</span>';

  try {
    const res = await fetch('/api/mitigate/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: alert.type, source_ip: alert.source_ip })
    });
    const data = await res.json();
    document.getElementById('modal-commands').innerHTML = (data.commands || [])
      .map(cmd => `<div class="text-green-400 py-0.5">${escapeHtml(cmd)}</div>`)
      .join('');
  } catch (e) {
    document.getElementById('modal-commands').innerHTML = '<span class="text-red-400">Failed to load preview</span>';
  }

  document.getElementById('mitigate-modal').classList.remove('hidden');
}

async function openMitigateFromDevice(ip) {
  const alert = allAlerts.find(a => a.source_ip === ip && !a.mitigated);
  if (alert) {
    openMitigateModal(alert.id);
  } else {
    showToastMsg('info', 'ℹ️ No Active Threats', `No unmitigated alerts for ${ip}`);
  }
}

function closeMitigateModal() {
  if (mitigating) return;
  document.getElementById('mitigate-modal').classList.add('hidden');
  mitigateAlertId   = null;
  mitigateAlertData = null;
}

/**
 * Eksekusi mitigasi setelah user konfirmasi di modal.
 * Kirim POST ke /api/mitigate/:id, tampilkan hasil di modal,
 * dan update state alert di allAlerts.
 *
 * ---
 * Execute mitigation after user confirms in modal.
 * Sends POST to /api/mitigate/:id, displays result in modal,
 * and updates alert state in allAlerts.
 */
async function confirmMitigate() {
  if (!mitigateAlertId || mitigating) return;
  mitigating = true;

  const confirmBtn = document.getElementById('modal-confirm-btn');
  const cancelBtn  = document.getElementById('modal-cancel-btn');
  confirmBtn.innerHTML = '<div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div><span>Running...</span>';
  confirmBtn.disabled  = true;
  cancelBtn.disabled   = true;

  try {
    const res = await fetch(`/api/mitigate/${mitigateAlertId}`, { method: 'POST' });
    const data = await res.json();

    if (data.status === 'ok' || data.status === 'already_mitigated') {
      const result = data.result;
      showMitigationResultInModal(result);

      const idx = allAlerts.findIndex(a => a.id === mitigateAlertId);
      if (idx !== -1) {
        allAlerts[idx].mitigated = true;
        allAlerts[idx].mitigation_result = result;
        renderAlerts();
        renderSideAlerts();
        renderDevices();
        updateAttackBanner();
      }

      // Show restore internet button if source IP was blocked
      const sourceIp = mitigateAlertData && mitigateAlertData.source_ip;
      if (sourceIp && sourceIp !== 'N/A') {
        document.getElementById('restore-internet-section').classList.remove('hidden');
        document.getElementById('restore-internet-btn').dataset.ip = sourceIp;
      }
    } else {
      showMitigationResultInModal({ success: false, summary: data.message || 'Mitigation failed', steps: [] });
    }
  } catch (e) {
    showMitigationResultInModal({ success: false, summary: 'Network error: ' + e.message, steps: [] });
  } finally {
    mitigating = false;
    confirmBtn.innerHTML = '✅ Done';
    cancelBtn.textContent = 'Close';
    cancelBtn.disabled = false;
  }
}

function showMitigationResultInModal(result) {
  const resultEl   = document.getElementById('modal-result');
  const stepsEl    = document.getElementById('modal-result-steps');
  const summaryEl  = document.getElementById('modal-result-summary');

  resultEl.classList.remove('hidden');

  stepsEl.innerHTML = (result.steps || []).map(step => `
    <div class="flex items-start gap-2 p-2 rounded-lg ${step.success ? 'bg-green-900/20 border border-green-800/40' : 'bg-red-900/20 border border-red-800/40'}">
      <span class="flex-shrink-0 text-sm">${step.success ? '✅' : '❌'}</span>
      <div class="flex-1 min-w-0">
        <p class="text-xs font-medium ${step.success ? 'text-green-300' : 'text-red-300'}">${escapeHtml(step.action)}</p>
        <code class="text-xs text-gray-500 font-mono block mt-0.5 truncate">${escapeHtml(step.command)}</code>
        ${step.output ? `<p class="text-xs text-gray-400 mt-0.5">${escapeHtml(step.output)}</p>` : ''}
      </div>
    </div>
  `).join('');

  summaryEl.innerHTML = `
    <span class="${result.success ? 'text-green-400' : 'text-yellow-400'}">${result.success ? '✅' : '⚠️'}</span>
    <span class="ml-1">${escapeHtml(result.summary || '')}</span>
    ${!result.is_root ? '<br><span class="text-yellow-500 text-xs">💡 Run as root for full mitigation</span>' : ''}
  `;
}

function showMitigationResult(alertId) {
  const alert = allAlerts.find(a => a.id === alertId);
  if (!alert || !alert.mitigation_result) return;
  openMitigateModal(alertId).then(() => {
    showMitigationResultInModal(alert.mitigation_result);
    document.getElementById('modal-confirm-btn').innerHTML = '✅ Already Mitigated';
    document.getElementById('modal-confirm-btn').disabled = true;
    // Show restore button
    if (alert.source_ip && alert.source_ip !== 'N/A') {
      document.getElementById('restore-internet-section').classList.remove('hidden');
      document.getElementById('restore-internet-btn').dataset.ip = alert.source_ip;
    }
  });
}

// ── Restore Internet ───────────────────────────────────────────────────────
async function restoreInternet() {
  const btn = document.getElementById('restore-internet-btn');
  const ip  = btn.dataset.ip;
  if (!ip) return;

  btn.innerHTML = '<div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div><span>Restoring...</span>';
  btn.disabled = true;

  try {
    const res = await fetch(`/api/restore/${ip}`, { method: 'POST' });
    const data = await res.json();
    if (data.status === 'ok') {
      btn.innerHTML = '✅ Internet Restored!';
      btn.className = btn.className.replace('bg-blue-700 hover:bg-blue-600', 'bg-green-700');
      showToastMsg('success', '🌐 Internet Restored', `Akses internet ${ip} berhasil dipulihkan`);
    } else {
      btn.innerHTML = '❌ Gagal — Coba Manual';
      btn.disabled = false;
      showToastMsg('error', '❌ Gagal', data.message || 'Restore internet gagal');
    }
  } catch (e) {
    btn.innerHTML = '❌ Error';
    btn.disabled = false;
    showToastMsg('error', '❌ Error', 'Network error: ' + e.message);
  }
}

// ── ESP Sensors Tab ───────────────────────────────────────────────────────

/** State ESP */
let espDevices       = [];
let activeEspId      = null;   // ESP yang sedang dipilih untuk scan/connect
let wifiConnectData  = null;   // Data WiFi yang mau dikonek {ssid, encryption, rssi, open}

/**
 * Refresh daftar ESP dari server dan render ke tab.
 */
async function refreshEspList() {
  try {
    const res  = await fetch('/api/esp/status');
    const data = await res.json();
    espDevices = data.devices || [];
    renderEspList();
    const badge = document.getElementById('tab-esp-count');
    if (espDevices.length > 0) {
      badge.classList.remove('hidden');
      badge.textContent = espDevices.length;
    } else {
      badge.classList.add('hidden');
    }
  } catch (e) {
    showToastMsg('error', '❌ Error', 'Gagal ambil data ESP');
  }
}

/**
 * Render kartu untuk setiap ESP yang terhubung.
 */
function renderEspList() {
  const container = document.getElementById('esp-list');
  if (!espDevices.length) {
    container.innerHTML = `
      <div class="text-center py-8 text-gray-500 text-sm">
        Belum ada ESP8266 yang terhubung.<br>
        <span class="text-xs text-gray-600">Flash kode ke ESP dan pastikan server Flask jalan.</span>
      </div>`;
    return;
  }

  container.innerHTML = espDevices.map(esp => {
    const rssiBar  = getRssiBar(esp.rssi);
    const uptime   = formatUptime(esp.uptime || 0);
    const ssid     = esp.connected_ssid || '—';
    const lastSeen = esp.last_seen || '—';

    return `
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3">
        <!-- Header -->
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-green-400 shadow-[0_0_6px_#4ade80]"></span>
            <span class="text-white font-mono text-sm font-semibold">${esp.esp_id}</span>
          </div>
          <span class="text-xs text-gray-500 font-mono">${lastSeen}</span>
        </div>

        <!-- Info grid -->
        <div class="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
          <div>
            <p class="text-gray-500">IP ESP</p>
            <p class="text-cyan-400 font-mono">${esp.esp_ip || esp.ip}</p>
          </div>
          <div>
            <p class="text-gray-500">WiFi Terhubung</p>
            <p class="text-green-400 font-mono truncate">${ssid}</p>
          </div>
          <div>
            <p class="text-gray-500">Signal</p>
            <p class="text-gray-300">${rssiBar} ${esp.rssi || 0} dBm</p>
          </div>
          <div>
            <p class="text-gray-500">Uptime</p>
            <p class="text-gray-300 font-mono">${uptime}</p>
          </div>
        </div>

        <!-- Tombol aksi -->
        <div class="flex gap-2 pt-1 border-t border-gray-800">
          <button onclick="espScanWifi('${esp.esp_id}')" id="scan-btn-${esp.esp_id}"
            class="flex-1 px-3 py-2 bg-cyan-800/50 hover:bg-cyan-700/60 border border-cyan-700/50 text-cyan-300 text-xs rounded-lg transition font-medium">
            📡 Scan WiFi Sekitar
          </button>
          <button onclick="espRefreshStatus('${esp.esp_id}')"
            class="px-3 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 text-xs rounded-lg transition">
            🔄
          </button>
        </div>
      </div>
    `;
  }).join('');
}

/**
 * Perintahkan ESP scan WiFi sekitar.
 * Hasil ditampilkan di panel bawah tab ESP.
 *
 * @param {string} espId - ID ESP yang mau disuruh scan
 */
async function espScanWifi(espId) {
  activeEspId = espId;
  const btn = document.getElementById(`scan-btn-${espId}`);
  if (btn) {
    btn.innerHTML = '<div class="w-3 h-3 border-2 border-cyan-300 border-t-transparent rounded-full animate-spin inline-block mr-1"></div> Scanning...';
    btn.disabled = true;
  }

  try {
    const res  = await fetch(`/api/esp/${espId}/scan`);
    const data = await res.json();

    if (data.error) {
      showToastMsg('error', '❌ Scan Gagal', data.error);
      return;
    }

    renderWifiScanResults(espId, data.networks || []);
    showToastMsg('success', '📡 Scan Selesai', `${(data.networks||[]).length} jaringan ditemukan`);
  } catch (e) {
    showToastMsg('error', '❌ Error', 'Gagal scan: ' + e.message);
  } finally {
    if (btn) {
      btn.innerHTML = '📡 Scan WiFi Sekitar';
      btn.disabled = false;
    }
  }
}

/**
 * Render daftar WiFi hasil scan ESP ke panel.
 *
 * @param {string} espId    - ID ESP sumber scan
 * @param {Array}  networks - Array jaringan WiFi
 */
function renderWifiScanResults(espId, networks) {
  const panel    = document.getElementById('esp-scan-panel');
  const listEl   = document.getElementById('esp-wifi-list');
  const sourceEl = document.getElementById('esp-scan-source');

  panel.classList.remove('hidden');
  sourceEl.textContent = `dari ${espId}`;

  if (!networks.length) {
    listEl.innerHTML = '<p class="text-gray-500 text-sm text-center py-4">Tidak ada jaringan ditemukan</p>';
    return;
  }

  // Urutkan dari sinyal terkuat
  networks.sort((a, b) => b.rssi - a.rssi);

  listEl.innerHTML = networks.map(net => {
    const bar      = getRssiBar(net.rssi);
    const encColor = net.open ? 'text-green-400' : 'text-yellow-400';
    const encLabel = net.open ? '🔓 Open' : `🔒 ${net.encryption}`;
    const ssidDisp = net.ssid || '<hidden>';

    return `
      <div class="bg-gray-900 border border-gray-800 hover:border-cyan-700/50 rounded-xl px-4 py-3
                  flex items-center justify-between gap-3 cursor-pointer transition group"
           onclick="openWifiConnectModal('${espId}', ${JSON.stringify(net).replace(/"/g, '&quot;')})">
        <div class="flex-1 min-w-0">
          <p class="text-white text-sm font-medium truncate">${ssidDisp}</p>
          <p class="text-gray-500 text-xs mt-0.5">ch${net.channel} · ${bar} ${net.rssi} dBm</p>
        </div>
        <div class="flex items-center gap-3 flex-shrink-0">
          <span class="${encColor} text-xs font-medium">${encLabel}</span>
          <span class="text-cyan-500 text-xs opacity-0 group-hover:opacity-100 transition">Konek →</span>
        </div>
      </div>
    `;
  }).join('');
}

/**
 * Refresh status satu ESP dari server langsung.
 *
 * @param {string} espId
 */
async function espRefreshStatus(espId) {
  try {
    const res  = await fetch(`/api/esp/${espId}/status`);
    const data = await res.json();
    // Update data di array lokal
    const idx = espDevices.findIndex(e => e.esp_id === espId);
    if (idx !== -1 && !data.error) {
      espDevices[idx] = { ...espDevices[idx], ...data };
      renderEspList();
    }
    showToastMsg('success', '🔄 Updated', `Status ${espId} diperbarui`);
  } catch (e) {
    showToastMsg('error', '❌ Error', e.message);
  }
}

// ── WiFi Connect Modal ────────────────────────────────────────────────────

/**
 * Buka modal untuk konek ESP ke WiFi yang dipilih.
 *
 * @param {string} espId  - ID ESP yang akan dikonek
 * @param {Object} netObj - Data jaringan WiFi {ssid, encryption, rssi, open}
 */
function openWifiConnectModal(espId, netObj) {
  activeEspId     = espId;
  wifiConnectData = netObj;

  document.getElementById('wifi-modal-ssid').textContent     = netObj.ssid || '';
  document.getElementById('wifi-modal-ssid-val').textContent = netObj.ssid || '';
  document.getElementById('wifi-modal-enc').textContent      = netObj.encryption || 'Unknown';
  document.getElementById('wifi-modal-rssi').textContent     = `${netObj.rssi} dBm`;
  document.getElementById('wifi-connect-password').value     = '';
  document.getElementById('wifi-connect-status').classList.add('hidden');

  const pwSection  = document.getElementById('wifi-password-section');
  const openNotice = document.getElementById('wifi-open-notice');
  if (netObj.open) {
    pwSection.classList.add('hidden');
    openNotice.classList.remove('hidden');
  } else {
    pwSection.classList.remove('hidden');
    openNotice.classList.add('hidden');
  }

  const btn = document.getElementById('wifi-connect-btn');
  btn.innerHTML = '<span>📶 Connect</span>';
  btn.disabled  = false;

  document.getElementById('wifi-connect-modal').classList.remove('hidden');
}

function closeWifiConnectModal() {
  document.getElementById('wifi-connect-modal').classList.add('hidden');
  wifiConnectData = null;
}

/**
 * Kirim perintah connect ke ESP via Flask proxy.
 */
async function confirmWifiConnect() {
  if (!activeEspId || !wifiConnectData) return;

  const password = wifiConnectData.open
    ? ''
    : document.getElementById('wifi-connect-password').value.trim();

  if (!wifiConnectData.open && !password) {
    showToastMsg('error', '❌ Error', 'Password tidak boleh kosong');
    return;
  }

  const btn    = document.getElementById('wifi-connect-btn');
  const status = document.getElementById('wifi-connect-status');
  btn.innerHTML = '<div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div><span>Connecting...</span>';
  btn.disabled  = true;
  status.textContent = '⏳ Mengirim perintah ke ESP...';
  status.classList.remove('hidden');

  try {
    const res  = await fetch(`/api/esp/${activeEspId}/connect`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ ssid: wifiConnectData.ssid, password })
    });
    const data = await res.json();

    if (data.error) {
      status.textContent = '❌ ' + data.error;
      btn.innerHTML = '<span>📶 Connect</span>';
      btn.disabled  = false;
      return;
    }

    status.textContent = `✅ Perintah terkirim! ESP sedang konek ke "${wifiConnectData.ssid}"...`;
    status.className   = 'bg-green-900/20 border border-green-700/40 rounded-xl p-3 text-xs text-green-300 text-center';
    status.classList.remove('hidden');

    showToastMsg('success', '📶 Connecting', `ESP ${activeEspId} sedang konek ke ${wifiConnectData.ssid}`);

    btn.innerHTML = '✅ Terkirim';

    // Refresh status ESP setelah 12 detik (beri waktu ESP konek)
    setTimeout(() => {
      refreshEspList();
      closeWifiConnectModal();
    }, 12000);

  } catch (e) {
    status.textContent = '❌ Error: ' + e.message;
    btn.innerHTML = '<span>📶 Connect</span>';
    btn.disabled  = false;
  }
}

// ── Helper ESP ────────────────────────────────────────────────────────────

/**
 * Konversi nilai RSSI ke bar sinyal emoji.
 * @param {number} rssi
 * @returns {string}
 */
function getRssiBar(rssi) {
  if (rssi >= -50) return '▂▄▆█';
  if (rssi >= -65) return '▂▄▆░';
  if (rssi >= -75) return '▂▄░░';
  return '▂░░░';
}

/**
 * Format detik ke string HH:MM:SS.
 * @param {number} seconds
 * @returns {string}
 */
function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

// ── ARP Spoof Modal ───────────────────────────────────────────────────────
/**
 * Buka modal simulator ARP Spoofing.
 * Populate dropdown dengan daftar perangkat online saat ini.
 * Kalau preselectedIp diberikan, langsung pilih IP itu di dropdown.
 *
 * @param {string} [preselectedIp] - IP yang langsung dipilih saat modal dibuka
 *
 * ---
 * Open the ARP Spoofing simulator modal.
 * Populates dropdown with currently online devices.
 * If preselectedIp is provided, pre-selects that IP in the dropdown.
 *
 * @param {string} [preselectedIp] - IP to pre-select when modal opens
 */
function openArpSpoofModal(preselectedIp) {
  // Populate dropdown with current devices
  const select = document.getElementById('arp-target-ip');
  select.innerHTML = '<option value="">-- Pilih Target IP --</option>';

  const onlineDevices = allDevices.filter(d => d.status === 'online');
  const allDevList = onlineDevices.length > 0 ? onlineDevices : allDevices;

  allDevList.forEach(d => {
    const opt = document.createElement('option');
    opt.value = d.ip;
    const label = d.hostname && d.hostname !== d.ip
      ? `${d.ip} — ${d.hostname} (${d.vendor || 'Unknown'})`
      : `${d.ip} — ${d.vendor || 'Unknown'}`;
    opt.textContent = label;
    opt.dataset.mac      = d.mac || 'N/A';
    opt.dataset.hostname = d.hostname || d.ip;
    opt.dataset.vendor   = d.vendor || 'Unknown';
    select.appendChild(opt);
  });

  // Pre-select if IP provided
  if (preselectedIp) {
    select.value = preselectedIp;
    onArpTargetChange();
  } else {
    document.getElementById('arp-target-info').classList.add('hidden');
    document.getElementById('arp-preview-msg').textContent = 'Pilih target IP untuk melihat preview...';
    document.getElementById('arp-preview-msg').className = 'text-gray-500 text-xs font-mono italic';
  }

  document.getElementById('arp-attacker-ip').value = '';
  const btn = document.getElementById('arp-launch-btn');
  btn.innerHTML = '<span>⚠️ Launch ARP Spoof</span>';
  btn.disabled = false;

  document.getElementById('arp-spoof-modal').classList.remove('hidden');
}

function closeArpSpoofModal() {
  document.getElementById('arp-spoof-modal').classList.add('hidden');
}

function onArpTargetChange() {
  const select = document.getElementById('arp-target-ip');
  const ip = select.value;
  if (!ip) {
    document.getElementById('arp-target-info').classList.add('hidden');
    document.getElementById('arp-preview-msg').textContent = 'Pilih target IP untuk melihat preview...';
    document.getElementById('arp-preview-msg').className = 'text-gray-500 text-xs font-mono italic';
    return;
  }

  const opt = select.options[select.selectedIndex];
  const mac      = opt.dataset.mac || 'N/A';
  const hostname = opt.dataset.hostname || ip;
  const vendor   = opt.dataset.vendor || 'Unknown';

  document.getElementById('arp-info-ip').textContent       = ip;
  document.getElementById('arp-info-mac').textContent      = mac;
  document.getElementById('arp-info-hostname').textContent = hostname;
  document.getElementById('arp-info-vendor').textContent   = vendor;
  document.getElementById('arp-target-info').classList.remove('hidden');

  updateArpPreview();
}

function updateArpPreview() {
  const ip = document.getElementById('arp-target-ip').value;
  if (!ip) return;

  const select    = document.getElementById('arp-target-ip');
  const opt       = select.options[select.selectedIndex];
  const mac       = opt ? (opt.dataset.mac || 'aa:bb:cc:dd:ee:ff') : 'aa:bb:cc:dd:ee:ff';
  const attackerIp = document.getElementById('arp-attacker-ip').value.trim() || '<auto>';
  const fakeMac   = 'ff:ee:dd:cc:bb:aa';

  const preview = `IP ${ip} changed MAC from ${mac} to ${fakeMac}. Attacker: ${attackerIp} — Possible MITM!`;
  const el = document.getElementById('arp-preview-msg');
  el.textContent = preview;
  el.className = 'text-red-300 text-xs font-mono';
}

/**
 * Kirim request simulasi ARP Spoof ke server.
 * Ambil target IP dari dropdown dan attacker IP dari input (opsional).
 * Setelah berhasil, tutup modal dan pindah ke tab Alerts.
 *
 * ---
 * Send ARP Spoof simulation request to server.
 * Gets target IP from dropdown and attacker IP from input (optional).
 * On success, closes modal and switches to Alerts tab.
 */
async function launchArpSpoof() {
  const targetIp   = document.getElementById('arp-target-ip').value;
  const attackerIp = document.getElementById('arp-attacker-ip').value.trim();

  if (!targetIp) {
    showToastMsg('error', '❌ Error', 'Pilih target IP terlebih dahulu!');
    return;
  }

  const select = document.getElementById('arp-target-ip');
  const opt    = select.options[select.selectedIndex];
  const mac    = opt ? (opt.dataset.mac || '') : '';

  const btn = document.getElementById('arp-launch-btn');
  btn.innerHTML = '<div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div><span>Launching...</span>';
  btn.disabled = true;

  try {
    const res = await fetch('/api/arp-spoof', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_ip: targetIp, attacker_ip: attackerIp, target_mac: mac })
    });
    const data = await res.json();

    if (data.status === 'ok') {
      showToastMsg('success', '⚠️ ARP Spoof Launched', `Target: ${targetIp} | Attacker: ${data.attacker_ip}`);
      closeArpSpoofModal();
      // Switch to alerts tab to see the alert
      setTimeout(() => switchTab('alerts'), 500);
    } else {
      showToastMsg('error', '❌ Error', data.message || 'Failed to launch');
      btn.innerHTML = '<span>⚠️ Launch ARP Spoof</span>';
      btn.disabled = false;
    }
  } catch (e) {
    showToastMsg('error', '❌ Error', 'Network error: ' + e.message);
    btn.innerHTML = '<span>⚠️ Launch ARP Spoof</span>';
    btn.disabled = false;
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────
/**
 * Escape karakter HTML berbahaya untuk mencegah XSS.
 * Selalu pakai fungsi ini sebelum memasukkan string ke innerHTML.
 *
 * @param {string} str - String yang mau di-escape
 * @returns {string} String yang sudah aman untuk innerHTML
 *
 * ---
 * Escape dangerous HTML characters to prevent XSS.
 * Always use this before inserting strings into innerHTML.
 *
 * @param {string} str - String to escape
 * @returns {string} Safe string for innerHTML
 */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
