document.addEventListener('DOMContentLoaded', () => {
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const viewTitle = document.getElementById('view-title');
  const viewSubtitle = document.getElementById('view-subtitle');

  const titles = {
    dashboard: { title: 'System Dashboard', sub: 'Real-time local DNS monitoring and policy enforcement' },
    blocklist: { title: 'Blocklist Registry', sub: 'Exact-domain blacklist rules resolved to 0.0.0.0' },
    queries: { title: 'Query Log Feed', sub: 'Live audit log of processed and blocked DNS requests' },
    egress: { title: 'Egress & Network Audit', sub: 'Background network sockets and snapshot egress tracking' },
    settings: { title: 'Application Settings', sub: 'Autostart configuration and system proxy routing' }
  };

  navItems.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      navItems.forEach(i => i.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const pane = document.getElementById(`tab-${target}`);
      if (pane) pane.classList.add('active');

      if (titles[target]) {
        viewTitle.textContent = titles[target].title;
        viewSubtitle.textContent = titles[target].sub;
      }

      if (target === 'blocklist') loadBlocklist();
      if (target === 'queries' || target === 'dashboard') loadLogs();
      if (target === 'egress') loadEgress();
      if (target === 'settings') loadSettings();
    });
  });

  const jumpQueriesBtn = document.getElementById('btn-jump-queries');
  if (jumpQueriesBtn) {
    jumpQueriesBtn.addEventListener('click', () => {
      const qTab = document.querySelector('[data-tab="queries"]');
      if (qTab) qTab.click();
    });
  }

  // Server Management
  const btnToggleServer = document.getElementById('btn-toggle-server');
  const serverStatusDot = document.getElementById('server-status-dot');
  const serverStatusText = document.getElementById('server-status-text');
  const btnServerLabel = document.getElementById('btn-server-label');
  const valEngineStatus = document.getElementById('val-engine-status');
  const valEngineDetail = document.getElementById('val-engine-detail');
  const valListen = document.getElementById('val-listen');
  const valUpstream = document.getElementById('val-upstream');
  let isRunning = false;

  function renderServerState(state) {
    if (!state) return;
    isRunning = !!state.running;

    if (valListen && state.listen) {
      valListen.textContent = `${state.listen}:${state.port || 53}`;
    }
    if (valUpstream && state.upstreams && state.upstreams.length) {
      valUpstream.textContent = state.upstreams.join(', ');
    }

    if (isRunning) {
      serverStatusDot.className = 'status-dot running';
      serverStatusText.textContent = `Active (PID ${state.pid || 'OK'})`;
      btnServerLabel.textContent = 'Stop Proxy';
      btnToggleServer.className = 'btn btn-danger';
      valEngineStatus.textContent = 'Online';
      valEngineStatus.className = 'metric-value text-accent';
      valEngineDetail.textContent = `Serving on ${state.listen || '127.0.0.1'}:${state.port || 53}`;
    } else {
      serverStatusDot.className = 'status-dot stopped';
      serverStatusText.textContent = 'Stopped';
      btnServerLabel.textContent = 'Start Proxy';
      btnToggleServer.className = 'btn btn-primary';
      valEngineStatus.textContent = 'Offline';
      valEngineStatus.className = 'metric-value';
      if (state.privilegeError) {
        valEngineDetail.textContent = 'Port 53 requires Administrator rights';
        valEngineStatus.className = 'metric-value text-warning';
      } else if (state.lastError) {
        valEngineDetail.textContent = state.lastError.substring(0, 45);
      } else {
        valEngineDetail.textContent = 'Proxy server idle';
      }
    }
  }

  async function updateStatus() {
    if (!window.dnsentinel?.server) return;
    try {
      const state = await window.dnsentinel.server.getStatus();
      renderServerState(state);
    } catch (err) {
      console.error('Status fetch error:', err);
    }
  }

  // Subscribe to real-time status push from main process
  if (window.dnsentinel?.server?.onStatusChanged) {
    window.dnsentinel.server.onStatusChanged((state) => {
      renderServerState(state);
    });
  }

  btnToggleServer.addEventListener('click', async () => {
    btnToggleServer.disabled = true;
    try {
      if (isRunning) {
        const res = await window.dnsentinel.server.stop();
        if (res?.state) renderServerState(res.state);
      } else {
        const res = await window.dnsentinel.server.start();
        if (res?.state) renderServerState(res.state);
        if (!res.ok) {
          alert('Failed to start DNS Proxy:\n' + (res.error || 'Port 53 binding failure. Run application as Administrator.'));
        }
      }
    } catch (err) {
      alert('Error toggling server: ' + err.message);
    } finally {
      setTimeout(async () => {
        await updateStatus();
        btnToggleServer.disabled = false;
      }, 500);
    }
  });

  // Blocklist Registry
  const listBlockItems = document.getElementById('list-block-items');
  const valBlockCount = document.getElementById('val-block-count');
  const inputSearch = document.getElementById('input-search-blocklist');
  const inputAddDomain = document.getElementById('input-add-domain');
  const btnAddDomain = document.getElementById('btn-add-domain');

  async function loadBlocklist() {
    if (!window.dnsentinel?.blocklist) return;
    try {
      const q = inputSearch ? inputSearch.value.trim() : '';
      const res = await window.dnsentinel.blocklist.list(q);
      const items = res?.domains || [];
      if (valBlockCount) valBlockCount.textContent = res?.total || items.length;

      if (!items.length) {
        listBlockItems.innerHTML = '<li class="empty-state">No blocked domains registered</li>';
        return;
      }

      listBlockItems.innerHTML = items.map(domain => `
        <li class="block-item">
          <span><code>${domain}</code></span>
          <button class="btn btn-sm btn-outline text-warning btn-remove-rule" data-domain="${domain}">Remove</button>
        </li>
      `).join('');

      document.querySelectorAll('.btn-remove-rule').forEach(btn => {
        btn.addEventListener('click', async () => {
          const d = btn.dataset.domain;
          btn.disabled = true;
          await window.dnsentinel.blocklist.remove(d);
          loadBlocklist();
        });
      });
    } catch (err) {
      console.error('Failed to load blocklist:', err);
    }
  }

  if (inputSearch) {
    let searchTimer = null;
    inputSearch.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(loadBlocklist, 200);
    });
  }

  if (btnAddDomain) {
    btnAddDomain.addEventListener('click', async () => {
      const d = inputAddDomain.value.trim();
      if (!d) return;
      btnAddDomain.disabled = true;
      try {
        const res = await window.dnsentinel.blocklist.add(d);
        if (res.ok) {
          inputAddDomain.value = '';
          loadBlocklist();
        } else {
          alert('Error adding domain: ' + (res.error || 'Unknown'));
        }
      } finally {
        btnAddDomain.disabled = false;
      }
    });

    inputAddDomain.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') btnAddDomain.click();
    });
  }

  // Logs & Query Feeds
  const preDnsLogs = document.getElementById('pre-dns-logs');
  const tbodyDashboardQueries = document.getElementById('tbody-dashboard-queries');
  const btnClearQueries = document.getElementById('btn-clear-queries');

  function renderDnsEntries(entries) {
    if (!entries || !entries.length) return;

    if (preDnsLogs) {
      const formattedLines = entries.map(item => {
        if (item.raw) return item.raw;
        return `[${item.ts || ''}] ${item.client || ''} -> ${item.domain || item.qname || ''} (${item.qtype || 'A'}) [${(item.action || '').toUpperCase()}] ${item.latency_ms || 0}ms`;
      });
      preDnsLogs.textContent = formattedLines.join('\n');
      preDnsLogs.scrollTop = preDnsLogs.scrollHeight;
    }

    if (tbodyDashboardQueries) {
      const recent = entries.slice(-10).reverse();
      const rows = recent.map(data => {
        if (data.raw) {
          return `<tr><td colspan="5" class="text-muted text-sm">${data.raw}</td></tr>`;
        }
        const isBlocked = data.action === 'blocked' || data.blocked;
        const badge = isBlocked 
          ? '<span class="badge-tag badge-block">BLOCKED</span>' 
          : '<span class="badge-tag badge-pass">FORWARDED</span>';
        const tsFormatted = data.ts ? data.ts.substring(11, 19) : '-';
        return `
          <tr>
            <td>${tsFormatted}</td>
            <td>${data.client || '127.0.0.1'}</td>
            <td><strong>${data.domain || data.qname || '-'}</strong></td>
            <td><code>${data.qtype || 'A'}</code></td>
            <td>${badge}</td>
          </tr>
        `;
      });
      tbodyDashboardQueries.innerHTML = rows.join('');
    }
  }

  async function loadLogs() {
    if (!window.dnsentinel?.logs) return;
    try {
      const res = await window.dnsentinel.logs.tail('dns', 80);
      if (res?.ok && res.entries?.length) {
        renderDnsEntries(res.entries);
      } else if (preDnsLogs && !preDnsLogs.textContent.includes('[')) {
        preDnsLogs.textContent = '(dns.log is empty or waiting for queries)';
      }
    } catch (err) {
      console.error('Failed to load logs:', err);
    }
  }

  // Subscribe to real-time stream push if available
  if (window.dnsentinel?.logs?.onDnsStream) {
    window.dnsentinel.logs.onDnsStream((newEntries) => {
      if (newEntries?.length) {
        loadLogs();
      }
    });
  }

  if (btnClearQueries) {
    btnClearQueries.addEventListener('click', async () => {
      if (window.dnsentinel?.logs) {
        await window.dnsentinel.logs.clear();
      }
      if (preDnsLogs) preDnsLogs.textContent = '(logs cleared)';
      if (tbodyDashboardQueries) {
        tbodyDashboardQueries.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No query records captured yet</td></tr>';
      }
    });
  }

  // Egress & NetTrack
  const preEgressLogs = document.getElementById('pre-egress-logs');
  const preNettrackLogs = document.getElementById('pre-nettrack-logs');
  const btnRefreshEgress = document.getElementById('btn-refresh-egress');

  async function loadEgress() {
    if (!window.dnsentinel?.logs) return;
    try {
      const resEgress = await window.dnsentinel.logs.tail('egress', 30);
      if (preEgressLogs) {
        if (resEgress?.ok && resEgress.entries?.length) {
          preEgressLogs.textContent = resEgress.entries.map(e => JSON.stringify(e, null, 2)).join('\n---\n');
        } else {
          preEgressLogs.textContent = '(egress.log empty)';
        }
      }

      if (window.dnsentinel?.nettrack) {
        const netRes = await window.dnsentinel.nettrack.snapshot();
        if (preNettrackLogs) {
          if (netRes?.ok && netRes.latest_record) {
            preNettrackLogs.textContent = JSON.stringify(netRes.latest_record, null, 2);
          } else {
            preNettrackLogs.textContent = '(nettrack snapshot empty or idle)';
          }
        }
      }
    } catch (err) {
      console.error('Failed to load egress:', err);
    }
  }

  if (btnRefreshEgress) {
    btnRefreshEgress.addEventListener('click', loadEgress);
  }

  // Settings
  const checkAutostart = document.getElementById('check-autostart');
  const btnOpenLogs1 = document.getElementById('btn-open-logs-1');
  const btnOpenLogs2 = document.getElementById('btn-open-logs-2');

  async function loadSettings() {
    if (!window.dnsentinel?.autostart) return;
    try {
      const res = await window.dnsentinel.autostart.status();
      if (res?.ok && checkAutostart) {
        checkAutostart.checked = !!res.enabled;
        if (!res.supported) {
          checkAutostart.disabled = true;
          checkAutostart.title = res.message || 'Registry autostart available on Windows host';
        }
      }
    } catch (err) {
      console.error('Failed to load autostart:', err);
    }
  }

  if (checkAutostart) {
    checkAutostart.addEventListener('change', async () => {
      if (!window.dnsentinel?.autostart) return;
      try {
        await window.dnsentinel.autostart.toggle(checkAutostart.checked);
      } catch (err) {
        alert('Autostart toggle error: ' + err.message);
      }
    });
  }

  const handleOpenFolder = async () => {
    if (window.dnsentinel?.logs) {
      await window.dnsentinel.logs.openDir();
    }
  };
  if (btnOpenLogs1) btnOpenLogs1.addEventListener('click', handleOpenFolder);
  if (btnOpenLogs2) btnOpenLogs2.addEventListener('click', handleOpenFolder);

  // Initialize
  updateStatus();
  loadBlocklist();
  loadLogs();

  setInterval(() => {
    updateStatus();
    loadLogs();
  }, 2500);
});
