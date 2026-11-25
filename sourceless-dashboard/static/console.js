(function () {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  const bodyEl = document.body;
  const userRole = bodyEl?.getAttribute('data-role') || 'support';
  const isAdmin = userRole === 'admin';

  let fleetData = {
    clienti: {},
    stats: { total: 0, online: 0, secure: 0, compromised: 0, pending_updates: 0, yara_alerts: 0 },
    yara_alerts: []
  };
  let activeView = 'fleet';
  let activeFilter = 'all';
  let activeOrgFilter = '';
  let searchQuery = '';
  let auditHwidFilter = '';
  let inspectedHwid = null;
  let pendingModalCfg = null;
  let auditDebounce = null;
  let lastAuditKey = '';
  const selectedHwids = new Set();
  const rejectedTimers = {};
  const displayedCounters = { total: 0, online: 0, secure: 0, updates: 0, alerts: 0 };
  let soundEnabled = localStorage.getItem('sl_sound_alerts') !== 'off';
  let hasInitialLoad = false;
  let prevSupportStates = {};
  let prevStatuses = {};
  let prevYaraCount = 0;
  const baseDocTitle = document.title;
  let titleFlashTimer = null;
  let audioCtx = null;

  function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function showToast(msg, isError) {
    const stack = document.getElementById('toastStack');
    if (!stack) return;
    const el = document.createElement('div');
    el.className = 'toast';
    if (isError) el.style.borderColor = 'rgba(242, 84, 109, 0.55)';
    el.textContent = msg;
    stack.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(8px)';
      el.style.transition = 'opacity 0.2s, transform 0.2s';
      setTimeout(() => el.remove(), 220);
    }, 2800);
  }

  function updateSoundToggleBtn() {
    const btn = document.getElementById('soundToggleBtn');
    if (!btn) return;
    btn.textContent = soundEnabled ? 'Alerts: On' : 'Alerts: Muted';
    btn.classList.toggle('muted', !soundEnabled);
  }

  function playAlertTone(kind) {
    if (!soundEnabled) return;
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      if (!audioCtx) audioCtx = new Ctx();
      if (audioCtx.state === 'suspended') audioCtx.resume().catch(() => {});
      const now = audioCtx.currentTime;
      const notes = kind === 'alert' ? [440, 330] : [587.33, 880];
      notes.forEach((freq, idx) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = kind === 'alert' ? 'triangle' : 'sine';
        osc.frequency.setValueAtTime(freq, now + idx * 0.13);
        gain.gain.setValueAtTime(0.001, now + idx * 0.13);
        gain.gain.exponentialRampToValueAtTime(kind === 'alert' ? 0.07 : 0.06, now + idx * 0.13 + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.13 + 0.18);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start(now + idx * 0.13);
        osc.stop(now + idx * 0.13 + 0.2);
      });
    } catch (_) { }
  }

  function stopTitleFlash() {
    if (titleFlashTimer) {
      clearInterval(titleFlashTimer);
      titleFlashTimer = null;
    }
    document.title = baseDocTitle;
  }

  function flashTabTitle(label) {
    stopTitleFlash();
    let tick = 0;
    document.title = label;
    titleFlashTimer = setInterval(() => {
      tick += 1;
      document.title = tick % 2 === 1 ? baseDocTitle : label;
      if (tick >= 16) stopTitleFlash();
    }, 900);
  }

  window.addEventListener('focus', stopTitleFlash);
  updateSoundToggleBtn();

  async function copyText(text, label, btnEl) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    if (btnEl) {
      btnEl.classList.add('copied-flash');
      setTimeout(() => btnEl.classList.remove('copied-flash'), 650);
    }
    showToast((label || 'Value') + ' copied to clipboard');
  }

  function animateCounter(elId, key, targetVal) {
    const el = document.getElementById(elId);
    if (!el) return;
    const startVal = displayedCounters[key] || 0;
    if (startVal === targetVal) {
      el.textContent = String(targetVal);
      return;
    }
    displayedCounters[key] = targetVal;
    const t0 = performance.now();
    const dur = 360;
    function step(now) {
      const p = Math.min(1, (now - t0) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = String(Math.round(startVal + (targetVal - startVal) * eased));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function formatRelative(ts) {
    if (!ts) return 'never';
    const diff = Math.max(0, Math.floor((Date.now() / 1000) - ts));
    if (diff < 5) return 'just now';
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  function formatUpdateBadge(info) {
    const st = (info.update_status || '').toLowerCase();
    if (st === 'pending_restart') return '<span class="badge badge-waiting">Restart Pending</span>';
    if (st === 'downloading' || st === 'checking') return '<span class="badge badge-indigo"><span class="spin-ring"></span>Updating</span>';
    if (st === 'error') return '<span class="badge badge-alert">Update Error</span>';
    if (st === 'up_to_date') return '<span class="badge badge-secure">Up to Date</span>';
    return '<span class="badge badge-muted">Legacy Agent</span>';
  }

  async function postAdmin(url, bodyObj) {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: bodyObj ? JSON.stringify(bodyObj) : '{}'
    });
    if (res.status === 401) {
      window.location.reload();
      return null;
    }
    if (!res.ok) {
      let errText = 'Action failed';
      try {
        const j = await res.json();
        if (j && j.error) errText = j.error;
      } catch (_) { }
      showToast(errText, true);
      return null;
    }
    return res;
  }

  function validateModalState() {
    if (!pendingModalCfg) return;
    const reasonEl = document.getElementById('modalReasonInput');
    const hintEl = document.getElementById('modalReasonHint');
    const pwEl = document.getElementById('modalPasswordInput');
    const confirmBtn = document.getElementById('modalConfirm');

    const reasonVal = (reasonEl.value || '').trim();
    const needReason = pendingModalCfg.requireReason !== false;
    const reasonOk = !needReason || reasonVal.length >= 6;
    const needPw = !!pendingModalCfg.askPassword;
    const pwOk = !needPw || (pwEl.value || '').length >= 8;

    if (needReason) {
      hintEl.textContent = reasonOk
        ? `Justification ready (${reasonVal.length}/400 characters)`
        : `Minimum 6 characters required (${reasonVal.length}/6)`;
      hintEl.classList.toggle('ok', reasonOk);
    }
    confirmBtn.disabled = !(reasonOk && pwOk);
  }

  function openActionModal(cfg) {
    pendingModalCfg = cfg;
    document.getElementById('modalTitle').textContent = cfg.title || 'Confirm Action';
    document.getElementById('modalMsg').textContent = cfg.message || '';
    const reasonWrap = document.getElementById('modalReasonWrap');
    const reasonInput = document.getElementById('modalReasonInput');
    const pwWrap = document.getElementById('modalPasswordWrap');
    const pwInput = document.getElementById('modalPasswordInput');
    const confirmBtn = document.getElementById('modalConfirm');

    reasonWrap.style.display = cfg.requireReason === false ? 'none' : 'block';
    reasonInput.value = '';
    reasonInput.placeholder = cfg.placeholder || 'Provide reason (ticket #, client request, incident reference)...';

    pwWrap.style.display = cfg.askPassword ? 'block' : 'none';
    pwInput.value = '';

    confirmBtn.textContent = cfg.confirmLabel || 'Confirm';
    confirmBtn.className = 'btn ' + (cfg.danger ? 'btn-danger' : 'btn-primary');

    document.getElementById('backdrop').classList.add('open');
    document.getElementById('confirmModal').classList.add('open');
    validateModalState();
    setTimeout(() => (cfg.askPassword ? pwInput : reasonInput).focus(), 60);
  }

  function closeAllOverlays() {
    document.getElementById('backdrop').classList.remove('open');
    document.getElementById('deviceDrawer').classList.remove('open');
    document.getElementById('confirmModal').classList.remove('open');
    pendingModalCfg = null;
  }

  function switchView(viewName) {
    activeView = viewName;
    document.querySelectorAll('.nav-tab').forEach((t) => {
      t.classList.toggle('active', t.getAttribute('data-view') === viewName);
    });
    document.querySelectorAll('.view-panel').forEach((p) => {
      const shouldHide = p.id !== 'view-' + viewName;
      p.classList.toggle('hidden', shouldHide);
      p.hidden = shouldHide;
    });
    if (viewName === 'audit') fetchAuditLog();
    if (viewName === 'threats') renderThreatsTable();
    if (viewName === 'team' && isAdmin) fetchTeamMembers();
  }

  async function fetchDeviceTimeline(hwid) {
    const box = document.getElementById('drawerTimeline');
    if (!box || !hwid) return;
    box.innerHTML = '<div class="timeline-empty">Loading recent activity...</div>';
    try {
      const res = await fetch('/api/audit?hwid=' + encodeURIComponent(hwid) + '&limit=10', {
        headers: { 'Accept': 'application/json' }
      });
      if (!res.ok) {
        box.innerHTML = '<div class="timeline-empty">Unable to load device timeline.</div>';
        return;
      }
      const data = await res.json();
      const entries = data.entries || [];
      if (!entries.length) {
        box.innerHTML = '<div class="timeline-empty">No recent audit events recorded for this device.</div>';
        return;
      }
      box.innerHTML = entries.map((ev) => {
        const sev = (ev.severity || 'info').toLowerCase();
        const sevCls = sev === 'critical' ? 'sev-critical' : (sev === 'ok' ? 'sev-ok' : (sev === 'warn' ? 'sev-warn' : ''));
        return `
          <div class="audit-item ${sevCls}">
            <div class="audit-top">
              <span><strong>${escapeHtml(ev.actor_name || ev.actor)}</strong> • ${escapeHtml(ev.type || 'event')}</span>
              <span>${escapeHtml(ev.time || '')}</span>
            </div>
            <div class="audit-msg">${escapeHtml(ev.detail || '')}</div>
            ${ev.reason ? `<div class="audit-sub">Reason: ${escapeHtml(ev.reason)}</div>` : ''}
          </div>
        `;
      }).join('');
    } catch (_) {
      box.innerHTML = '<div class="timeline-empty">Unable to load device timeline.</div>';
    }
  }

  function openDeviceDrawer(hwid) {
    const info = fleetData.clienti[hwid];
    if (!info) return;
    inspectedHwid = hwid;
    document.getElementById('drawerTitle').textContent = info.client_name || info.hostname || hwid;
    document.getElementById('metaClientName').value = info.client_name || '';
    const orgEl = document.getElementById('metaOrganization');
    if (orgEl) orgEl.value = info.organization || '';
    document.getElementById('metaNotes').value = info.notes || '';
    renderDrawerMeta(hwid, info);
    fetchDeviceTimeline(hwid);
    document.getElementById('backdrop').classList.add('open');
    document.getElementById('deviceDrawer').classList.add('open');
  }

  function renderDrawerMeta(hwid, info) {
    const box = document.getElementById('drawerMeta');
    if (!box || !info) return;
    const revBtn = document.getElementById('toggleRevokeBtn');
    if (revBtn) {
      revBtn.textContent = info.revoked ? 'Restore Device Access' : 'Revoke Device Access';
      revBtn.className = info.revoked ? 'btn btn-support' : 'btn btn-warn';
    }
    const statusLabel = info.revoked ? 'Revoked' : (info.status === 'Integru' ? 'Intact' : (info.status === 'Inscris' ? 'Enrolled' : info.status || 'Unknown'));
    box.innerHTML = `
      <span class="mk">HWID</span><span class="mv">${escapeHtml(hwid)}</span>
      <span class="mk">Hostname</span><span class="mv">${escapeHtml(info.hostname || '—')}</span>
      <span class="mk">Organization</span><span class="mv">${escapeHtml(info.organization || 'Unassigned')}</span>
      <span class="mk">IP Address</span><span class="mv">${escapeHtml(info.ip || '—')}</span>
      <span class="mk">Presence</span><span class="mv">${info.online ? 'Online' : 'Offline'} (${formatRelative(info.last_seen_ts)})</span>
      <span class="mk">OS Build</span><span class="mv">${escapeHtml(info.os_version || 'Legacy')} (${escapeHtml(info.update_channel || 'stable')})</span>
      <span class="mk">Update</span><span class="mv">${escapeHtml(info.update_status || 'unknown')}</span>
      <span class="mk">Security</span><span class="mv">SELinux: ${escapeHtml(info.selinux || '—')} • Lockdown: ${escapeHtml(info.lockdown || '—')}</span>
      <span class="mk">Resources</span><span class="mv">RAM ${escapeHtml(info.ram_percent ?? '—')}% • Disk ${escapeHtml(info.disk_percent ?? '—')}% • Up ${escapeHtml(info.uptime || '—')}</span>
      <span class="mk">Integrity</span><span class="mv">${escapeHtml(statusLabel)}</span>
      <span class="mk">Re-enroll</span><span class="mv">${info.allow_reenroll ? 'Approved (Waiting)' : 'Locked'}</span>
    `;
  }

  function matchesFilter(hwid, info) {
    if (activeFilter === 'online' && !info.online) return false;
    if (activeFilter === 'offline' && info.online) return false;
    if (activeFilter === 'modified' && info.status === 'Integru') return false;
    if (activeFilter === 'pending_update' && info.update_status !== 'pending_restart') return false;
    if (activeFilter === 'support' && info.support_state !== 'waiting' && info.support_state !== 'approved') return false;
    if (activeFilter === 'live_iso' && !info.is_live_iso) return false;
    if (activeFilter === 'revoked' && !info.revoked) return false;
    if (activeOrgFilter && (info.organization || '').trim() !== activeOrgFilter) return false;
    if (searchQuery) {
      const hay = [
        hwid, info.client_name, info.organization, info.hostname, info.ip, info.notes,
        info.status, info.os_version, info.update_channel, info.update_status
      ].filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  }

  function updateBulkBar(visibleHwids) {
    const bar = document.getElementById('bulkBar');
    const countEl = document.getElementById('bulkCount');
    const selectAllEl = document.getElementById('selectAllFleet');
    if (countEl) countEl.textContent = String(selectedHwids.size);
    if (bar) bar.hidden = selectedHwids.size === 0;
    if (selectAllEl) {
      const list = visibleHwids || [];
      if (!list.length) {
        selectAllEl.checked = false;
        selectAllEl.indeterminate = false;
      } else {
        const matched = list.filter((h) => selectedHwids.has(h)).length;
        selectAllEl.checked = matched === list.length;
        selectAllEl.indeterminate = matched > 0 && matched < list.length;
      }
    }
  }

  function renderFleetTable() {
    const tbody = document.getElementById('clients-tbody');
    if (!tbody) return;
    const entries = Object.entries(fleetData.clienti || {});
    entries.sort((a, b) => {
      if (!!b[1].online !== !!a[1].online) return b[1].online ? 1 : -1;
      const nameA = (a[1].client_name || a[1].hostname || a[0]).toLowerCase();
      const nameB = (b[1].client_name || b[1].hostname || b[0]).toLowerCase();
      const cmp = nameA.localeCompare(nameB, undefined, { numeric: true, sensitivity: 'base' });
      return cmp !== 0 ? cmp : a[0].localeCompare(b[0]);
    });

    const filtered = entries.filter(([hwid, info]) => matchesFilter(hwid, info));
    updateBulkBar(filtered.map(([h]) => h));
    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state">${entries.length ? 'No MiniPCs match the active search or filter.' : 'No enrolled SourceLess MiniPCs yet.'}</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(([hwid, info]) => {
      const safeHwid = escapeHtml(hwid);
      const isOnline = !!info.online;
      const isRevoked = !!info.revoked;
      const isSecure = !isRevoked && info.status === 'Integru';
      const displayName = info.client_name || info.hostname || 'Unassigned Device';
      const subHost = info.client_name && info.hostname ? info.hostname : (info.notes ? info.notes.slice(0, 38) : 'Standard Node');
      const orgBadge = info.organization ? `<span class="micro-tag org-tag">${escapeHtml(info.organization)}</span>` : '';
      const liveBadge = info.is_live_iso ? '<span class="micro-tag live-iso">Live ISO</span>' : '';

      const presenceHtml = isOnline
        ? '<span class="presence on"><span class="radar-dot"></span>Online</span>'
        : '<span class="presence off"><span class="radar-dot"></span>Offline</span>';

      let statusHtml = '<span class="badge badge-secure">Intact</span>';
      if (isRevoked) statusHtml = '<span class="badge badge-alert">Revoked</span>';
      else if (info.status === 'Inscris') statusHtml = '<span class="badge badge-muted">Enrolled</span>';
      else if (!isSecure) statusHtml = '<span class="badge badge-alert">Modified</span>';

      const seOk = (info.selinux || '').toLowerCase() === 'enforcing';
      const ldOk = (info.lockdown || '').toLowerCase() === 'integrity' || (info.lockdown || '').toLowerCase() === 'confidentiality';
      const ramPct = Math.max(0, Math.min(100, Number(info.ram_percent || 0)));
      const diskPct = Math.max(0, Math.min(100, Number(info.disk_percent || 0)));
      const hasRes = info.ram_percent !== undefined && info.ram_percent !== null;

      const healthHtml = `
        <div class="telemetry-stack">
          <div class="mini-tags">
            ${statusHtml}
            ${info.selinux ? `<span class="micro-tag ${seOk ? 'ok' : 'bad'}">SE:${escapeHtml(info.selinux)}</span>` : ''}
            ${info.lockdown ? `<span class="micro-tag ${ldOk ? 'ok' : 'bad'}">LD:${escapeHtml(info.lockdown)}</span>` : ''}
          </div>
          ${hasRes ? `
            <div class="meter-row">
              <span>RAM</span><div class="meter-bar"><div class="meter-fill" style="width:${ramPct}%"></div></div><span>${ramPct}%</span>
              <span style="margin-left:4px;">DSK</span><span>${diskPct}%</span>
            </div>` : ''}
        </div>
      `;

      const osHtml = `
        <div class="telemetry-stack">
          <div class="mini-tags">
            <span class="micro-tag">${escapeHtml(info.os_version || 'Base Build')}</span>
            <span class="micro-tag">${escapeHtml(info.update_channel || 'stable')}</span>
          </div>
          <div>${formatUpdateBadge(info)}</div>
        </div>
      `;

      let credsHtml = '<span style="color: var(--muted);">—</span>';
      if (info.support_state === 'approved' && info.rustdesk_id && info.rustdesk_id !== 'N/A') {
        credsHtml = `
          <button class="cred-chip" type="button" data-copy="${escapeHtml(info.rustdesk_id)}" data-label="RustDesk ID">ID: ${escapeHtml(info.rustdesk_id)}</button>
          <button class="cred-chip" type="button" data-copy="${escapeHtml(info.rustdesk_pw)}" data-label="RustDesk Password">PW: ${escapeHtml(info.rustdesk_pw)}</button>
        `;
      } else if (info.support_state === 'rejected') {
        credsHtml = '<span class="badge badge-alert">Access Denied</span>';
      } else if (info.support_state === 'waiting') {
        credsHtml = '<span class="badge badge-waiting"><span class="spin-ring"></span>Waiting Approval</span>';
      }

      let btns = '';
      if (!isSecure && !isRevoked) {
        btns += `<button class="btn btn-primary" type="button" data-action="reinstate" data-hwid="${safeHwid}">Reinstate</button>`;
      }
      if (info.support_state === 'waiting') {
        btns += `<button class="btn btn-danger" type="button" data-action="stop_support" data-hwid="${safeHwid}">Cancel</button>`;
      } else if (info.support_state === 'approved') {
        btns += `<button class="btn btn-danger" type="button" data-action="stop_support" data-hwid="${safeHwid}">Stop Support</button>`;
      } else {
        btns += `<button class="btn btn-support" type="button" data-action="request_support" data-hwid="${safeHwid}" ${isOnline && !isRevoked ? '' : 'disabled title="Device is offline or revoked"'}>Request Access</button>`;
      }
      btns += `<button class="btn btn-ghost" type="button" data-action="inspect" data-hwid="${safeHwid}">Details</button>`;

      return `
        <tr data-hwid="${safeHwid}">
          <td class="col-check"><input type="checkbox" class="row-check" data-select-hwid="${safeHwid}" ${selectedHwids.has(hwid) ? 'checked' : ''} aria-label="Select ${escapeHtml(displayName)}"></td>
          <td>${presenceHtml}</td>
          <td>
            <div class="device-cell">
              <span class="client-name">${escapeHtml(displayName)}</span>
              ${(orgBadge || liveBadge) ? `<span class="mini-tags">${orgBadge}${liveBadge}</span>` : ''}
              <span class="host-sub">${escapeHtml(subHost)}</span>
              <button class="hwid-btn" type="button" data-copy="${safeHwid}" data-label="HWID" title="Click to copy ${safeHwid}">
                <span class="hwid-txt">${safeHwid}</span>
              </button>
            </div>
          </td>
          <td>${osHtml}</td>
          <td>${healthHtml}</td>
          <td>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.81rem;">${escapeHtml(info.ip || '—')}</div>
            <div style="font-size: 0.74rem; color: var(--muted);" title="${escapeHtml(info.last_seen || '')}">${formatRelative(info.last_seen_ts)}</div>
          </td>
          <td>${credsHtml}</td>
          <td><div class="actions-row">${btns}</div></td>
        </tr>
      `;
    }).join('');
  }

  function renderThreatsTable() {
    const tbody = document.getElementById('threats-tbody');
    if (!tbody) return;
    const items = fleetData.yara_alerts || [];
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No YARA threats detected across the fleet.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map((al) => `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;">${escapeHtml(al.time || '')}</td>
        <td>
          <div class="device-cell">
            <span class="client-name">${escapeHtml(al.client_label || al.hostname || al.hwid)}</span>
            <span class="host-sub">${escapeHtml(al.hwid || '')}</span>
          </div>
        </td>
        <td><span class="badge badge-alert">${escapeHtml(al.rule || 'Unknown')}</span></td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:0.81rem;color:#fff;">${escapeHtml(al.filename || '')}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--muted);">
          <div>Src: ${escapeHtml(al.path || '—')}</div>
          <div>Vault: ${escapeHtml(al.quarantine_path || '—')}</div>
        </td>
      </tr>
    `).join('');
  }

  function buildAuditParams() {
    const params = new URLSearchParams();
    const q = document.getElementById('auditSearch')?.value.trim() || '';
    const actor = document.getElementById('auditActorFilter')?.value || '';
    const cat = document.getElementById('auditCategoryFilter')?.value || '';
    const sev = document.getElementById('auditSeverityFilter')?.value || '';
    const days = document.getElementById('auditDaysFilter')?.value || '';
    if (q) params.set('q', q);
    if (actor) params.set('actor', actor);
    if (cat) params.set('category', cat);
    if (sev) params.set('severity', sev);
    if (days) params.set('days', days);
    if (auditHwidFilter) params.set('hwid', auditHwidFilter);
    return params;
  }

  async function fetchAuditLog() {
    const banner = document.getElementById('auditHwidBanner');
    const hwidLbl = document.getElementById('auditHwidLabel');
    if (banner && hwidLbl) {
      banner.style.display = auditHwidFilter ? 'block' : 'none';
      hwidLbl.textContent = auditHwidFilter;
    }
    const params = buildAuditParams();
    try {
      const res = await fetch('/api/audit?' + params.toString(), { headers: { 'Accept': 'application/json' } });
      if (res.status === 401) {
        window.location.reload();
        return;
      }
      const data = await res.json();
      const actorSel = document.getElementById('auditActorFilter');
      if (actorSel && Array.isArray(data.actors)) {
        const cur = actorSel.value;
        actorSel.innerHTML = '<option value="">All Operators &amp; Sources</option>' +
          data.actors.map((a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join('');
        actorSel.value = cur;
      }
      const tbody = document.getElementById('audit-tbody');
      if (!tbody) return;
      const entries = data.entries || [];
      const curKey = JSON.stringify(entries);
      if (curKey === lastAuditKey) return;
      lastAuditKey = curKey;
      if (!entries.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No audit records match the selected filters.</td></tr>';
        return;
      }
      tbody.innerHTML = entries.map((ev) => {
        const sev = ev.severity || 'info';
        const sevClass = sev === 'critical' ? 'badge-alert' : (sev === 'ok' ? 'badge-secure' : (sev === 'warn' ? 'badge-waiting' : 'badge-muted'));
        const role = (ev.actor_role || 'system').toLowerCase();
        return `
          <tr>
            <td style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;white-space:nowrap;">${escapeHtml(ev.time || '')}</td>
            <td>
              <div class="device-cell">
                <span class="client-name">${escapeHtml(ev.actor_name || ev.actor)}</span>
                <span class="mini-tags"><span class="role-tag ${escapeHtml(role)}">${escapeHtml(role)}</span> <span class="host-sub">${escapeHtml(ev.actor)}</span></span>
              </div>
            </td>
            <td>
              <div class="telemetry-stack">
                <span class="badge ${sevClass}">${escapeHtml(ev.type || 'event')}</span>
                <span class="host-sub">${escapeHtml(ev.category || 'system')}</span>
              </div>
            </td>
            <td>
              <div class="device-cell">
                <span style="font-weight:600;">${escapeHtml(ev.client_label || ev.hostname || 'Console')}</span>
                <span class="host-sub" style="font-family:'JetBrains Mono',monospace;">${escapeHtml(ev.hwid || '')}</span>
              </div>
            </td>
            <td>
              <div style="line-height:1.4;">${escapeHtml(ev.detail || '')}</div>
              ${ev.reason ? `<div class="reason-box"><strong>Reason:</strong> ${escapeHtml(ev.reason)}</div>` : ''}
            </td>
            <td style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:var(--muted);">${escapeHtml(ev.ip || '')}</td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to fetch audit log:', err);
    }
  }

  async function fetchTeamMembers() {
    if (!isAdmin) return;
    const tbody = document.getElementById('team-tbody');
    if (!tbody) return;
    try {
      const res = await fetch('/api/team', { headers: { 'Accept': 'application/json' } });
      if (!res.ok) return;
      const data = await res.json();
      const members = data.members || [];
      tbody.innerHTML = members.map((m) => `
        <tr>
          <td>
            <div class="device-cell">
              <span class="client-name">${escapeHtml(m.full_name || m.username)}</span>
              <span class="host-sub" style="font-family:'JetBrains Mono',monospace;">@${escapeHtml(m.username)}</span>
            </div>
          </td>
          <td><span class="role-tag ${escapeHtml(m.role)}">${escapeHtml(m.role)}</span></td>
          <td>${m.active ? '<span class="badge badge-secure">Active</span>' : '<span class="badge badge-alert">Disabled</span>'}</td>
          <td style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:var(--muted);">${escapeHtml(m.last_login || 'Never')}</td>
          <td>
            <div class="actions-row">
              ${m.protected ? '<span class="host-sub">Primary Env Admin</span>' : `
                <button class="btn btn-warn" type="button" data-team-action="toggle" data-user="${escapeHtml(m.username)}">${m.active ? 'Disable' : 'Enable'}</button>
                <button class="btn btn-ghost" type="button" data-team-action="reset_pw" data-user="${escapeHtml(m.username)}">Reset Password</button>
                <button class="btn btn-danger" type="button" data-team-action="delete" data-user="${escapeHtml(m.username)}">Delete</button>
              `}
            </div>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Failed to load team:', err);
    }
  }

  async function refreshDashboard() {
    try {
      const res = await fetch('/api/data', { headers: { 'Accept': 'application/json' } });
      if (res.status === 401) {
        window.location.reload();
        return;
      }
      const data = await res.json();
      fleetData = data;

      for (const [hwid, info] of Object.entries(data.clienti || {})) {
        if (info.support_state === 'rejected') {
          if (!rejectedTimers[hwid]) {
            rejectedTimers[hwid] = setTimeout(async () => {
              await postAdmin('/stop_support/' + encodeURIComponent(hwid), { reason: 'Auto-reset after 10s access denial' });
              delete rejectedTimers[hwid];
              refreshDashboard();
            }, 10000);
          }
        } else if (rejectedTimers[hwid]) {
          clearTimeout(rejectedTimers[hwid]);
          delete rejectedTimers[hwid];
        }
      }

      const st = data.stats || {};
      const yaraCount = st.yara_alerts || 0;
      const totalAlerts = (st.compromised || 0) + yaraCount;
      const clientsObj = data.clienti || {};

      for (const hwid of Array.from(selectedHwids)) {
        if (!clientsObj[hwid]) selectedHwids.delete(hwid);
      }

      const orgSel = document.getElementById('orgFilter');
      const orgList = Array.isArray(data.organizations) ? data.organizations : [];
      if (orgSel) {
        const curOrg = orgSel.value;
        orgSel.innerHTML = '<option value="">All Organizations</option>' +
          orgList.map((o) => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join('');
        if (orgList.includes(curOrg)) {
          orgSel.value = curOrg;
        } else if (activeOrgFilter) {
          activeOrgFilter = '';
          orgSel.value = '';
        }
      }
      const dl = document.getElementById('orgDatalist');
      if (dl) {
        dl.innerHTML = orgList.map((o) => `<option value="${escapeHtml(o)}">`).join('');
      }

      const cleanupBtn = document.getElementById('cleanupLiveIsoBtn');
      if (cleanupBtn) {
        const offlineLive = st.offline_live_iso || 0;
        cleanupBtn.hidden = offlineLive <= 0;
        cleanupBtn.textContent = `Clean Offline Live ISOs (${offlineLive})`;
      }

      const nextSupportStates = {};
      const nextStatuses = {};
      for (const [hwid, info] of Object.entries(clientsObj)) {
        nextSupportStates[hwid] = info.support_state || 'idle';
        nextStatuses[hwid] = info.status || '';
        if (hasInitialLoad) {
          if (prevSupportStates[hwid] !== 'approved' && info.support_state === 'approved') {
            const label = info.client_name || info.hostname || hwid;
            playAlertTone('support');
            showToast(`Remote support approved on ${label}`);
            flashTabTitle(`Support Approved — ${baseDocTitle}`);
          }
          if (prevStatuses[hwid] === 'Integru' && info.status && info.status !== 'Integru') {
            const label = info.client_name || info.hostname || hwid;
            playAlertTone('alert');
            showToast(`Integrity tamper alert on ${label}`, true);
            flashTabTitle(`⚠ Security Alert — ${baseDocTitle}`);
          }
        }
      }
      if (hasInitialLoad && yaraCount > prevYaraCount) {
        playAlertTone('alert');
        showToast('New YARA threat quarantined!', true);
        flashTabTitle(`⚠ YARA Alert — ${baseDocTitle}`);
      }
      prevSupportStates = nextSupportStates;
      prevStatuses = nextStatuses;
      prevYaraCount = yaraCount;
      hasInitialLoad = true;

      animateCounter('stat-total', 'total', st.total || 0);
      animateCounter('stat-online', 'online', st.online || 0);
      animateCounter('stat-secure', 'secure', st.secure || 0);
      animateCounter('stat-updates', 'updates', st.pending_updates || 0);
      animateCounter('stat-alerts', 'alerts', totalAlerts);

      const badge = document.getElementById('threatsBadge');
      if (badge) {
        badge.textContent = String(yaraCount);
        badge.classList.toggle('has-alerts', yaraCount > 0);
      }

      renderFleetTable();
      if (activeView === 'threats') renderThreatsTable();
      if (inspectedHwid && data.clienti[inspectedHwid] && document.getElementById('deviceDrawer').classList.contains('open')) {
        renderDrawerMeta(inspectedHwid, data.clienti[inspectedHwid]);
      }
    } catch (err) {
      console.error('Telemetry refresh failed:', err);
    }
  }

  // Navigation Tabs
  document.getElementById('navTabs')?.addEventListener('click', (e) => {
    const tab = e.target.closest('.nav-tab');
    if (!tab) return;
    switchView(tab.getAttribute('data-view') || 'fleet');
  });

  document.getElementById('copyKeyBtn')?.addEventListener('click', (e) => {
    copyText(document.getElementById('supportKeyVal').textContent.trim(), 'Support Key', e.currentTarget);
  });

  document.getElementById('soundToggleBtn')?.addEventListener('click', () => {
    soundEnabled = !soundEnabled;
    localStorage.setItem('sl_sound_alerts', soundEnabled ? 'on' : 'off');
    updateSoundToggleBtn();
    if (soundEnabled) playAlertTone('support');
  });

  // Fleet search & filter
  document.getElementById('searchInput')?.addEventListener('input', (e) => {
    searchQuery = e.target.value.trim().toLowerCase();
    renderFleetTable();
  });

  document.getElementById('orgFilter')?.addEventListener('change', (e) => {
    activeOrgFilter = e.target.value || '';
    renderFleetTable();
  });

  document.getElementById('filterPills')?.addEventListener('click', (e) => {
    const pill = e.target.closest('.filter-pill');
    if (!pill) return;
    document.querySelectorAll('.filter-pill').forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');
    activeFilter = pill.getAttribute('data-filter') || 'all';
    renderFleetTable();
  });

  document.getElementById('cleanupLiveIsoBtn')?.addEventListener('click', () => {
    if (!isAdmin) return;
    openActionModal({
      title: 'Clean Offline Live ISO Nodes',
      message: 'Remove all offline temporary Live ISO boot records from the fleet table.',
      confirmLabel: 'Remove Offline Live ISOs',
      onSubmit: async (reason) => {
        const res = await postAdmin('/api/cleanup_live_iso', { reason });
        if (res) {
          const payload = await res.json();
          showToast(`Removed ${payload.removed || 0} offline Live ISO record(s)`);
          refreshDashboard();
        }
      }
    });
  });

  // Multi-select & Bulk Actions
  document.getElementById('clients-tbody')?.addEventListener('change', (e) => {
    const chk = e.target.closest('[data-select-hwid]');
    if (!chk) return;
    const hwid = chk.getAttribute('data-select-hwid');
    if (!hwid) return;
    if (chk.checked) selectedHwids.add(hwid);
    else selectedHwids.delete(hwid);
    const visible = Array.from(document.querySelectorAll('#clients-tbody [data-select-hwid]'))
      .map((el) => el.getAttribute('data-select-hwid'));
    updateBulkBar(visible);
  });

  document.getElementById('selectAllFleet')?.addEventListener('change', (e) => {
    const checked = !!e.target.checked;
    document.querySelectorAll('#clients-tbody [data-select-hwid]').forEach((chk) => {
      const hwid = chk.getAttribute('data-select-hwid');
      chk.checked = checked;
      if (hwid) {
        if (checked) selectedHwids.add(hwid);
        else selectedHwids.delete(hwid);
      }
    });
    const visible = Array.from(document.querySelectorAll('#clients-tbody [data-select-hwid]'))
      .map((el) => el.getAttribute('data-select-hwid'));
    updateBulkBar(visible);
  });

  document.getElementById('bulkClearBtn')?.addEventListener('click', () => {
    selectedHwids.clear();
    renderFleetTable();
  });

  document.getElementById('bulkBar')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-bulk-cmd]');
    if (!btn || !selectedHwids.size) return;
    const cmd = btn.getAttribute('data-bulk-cmd');
    const hwids = Array.from(selectedHwids);
    const labels = {
      check_update: 'Check for OS Updates',
      set_channel_stable: 'Switch to Stable Channel',
      set_channel_testing: 'Switch to Testing Channel',
      reboot_device: 'Reboot Devices'
    };
    openActionModal({
      title: `Bulk Action: ${labels[cmd] || cmd}`,
      message: `Queue '${labels[cmd] || cmd}' across ${hwids.length} selected device(s). One justification entry will be logged per device.`,
      confirmLabel: `Run on ${hwids.length} Device(s)`,
      danger: cmd === 'reboot_device',
      onSubmit: async (reason) => {
        const res = await postAdmin('/api/bulk_cmd', { hwids, cmd, reason });
        if (res) {
          const payload = await res.json();
          selectedHwids.clear();
          showToast(`Queued on ${payload.queued || 0} device(s)` + (payload.skipped ? ` (${payload.skipped} skipped)` : ''));
          refreshDashboard();
        }
      }
    });
  });

  // Fleet table actions
  document.getElementById('clients-tbody')?.addEventListener('click', async (e) => {
    const copyBtn = e.target.closest('[data-copy]');
    if (copyBtn) {
      copyText(copyBtn.getAttribute('data-copy'), copyBtn.getAttribute('data-label'), copyBtn);
      return;
    }
    const actBtn = e.target.closest('[data-action]');
    if (!actBtn) return;
    const action = actBtn.getAttribute('data-action');
    const hwid = actBtn.getAttribute('data-hwid');
    if (!hwid) return;

    if (action === 'inspect') {
      openDeviceDrawer(hwid);
    } else if (action === 'reinstate') {
      openActionModal({
        title: 'Reinstate Tamper Seal',
        message: `Clear integrity warning on ${hwid}? Explain what verified the system state.`,
        confirmLabel: 'Reinstate Device',
        onSubmit: async (reason) => {
          const ok = await postAdmin('/reinstate/' + encodeURIComponent(hwid), { reason });
          if (ok) { showToast('Tamper seal reinstated'); refreshDashboard(); }
        }
      });
    } else if (action === 'request_support') {
      openActionModal({
        title: 'Request Remote Support Session',
        message: `Send an authorization prompt to ${hwid}. State the support ticket or reason visible to your audit team.`,
        confirmLabel: 'Send Request',
        onSubmit: async (reason) => {
          const ok = await postAdmin('/request_support/' + encodeURIComponent(hwid), { reason });
          if (ok) { showToast('Support prompt dispatched'); refreshDashboard(); }
        }
      });
    } else if (action === 'stop_support') {
      await postAdmin('/stop_support/' + encodeURIComponent(hwid), { reason: 'Operator closed remote support session' });
      showToast('Support session stopped');
      refreshDashboard();
    }
  });

  // Device Drawer Controls
  document.getElementById('viewDeviceAuditBtn')?.addEventListener('click', () => {
    if (!inspectedHwid) return;
    auditHwidFilter = inspectedHwid;
    closeAllOverlays();
    switchView('audit');
  });

  document.getElementById('cmdCheckUpdateBtn')?.addEventListener('click', async () => {
    if (!inspectedHwid) return;
    const ok = await postAdmin('/device_cmd/' + encodeURIComponent(inspectedHwid), { cmd: 'check_update' });
    if (ok) {
      showToast('Update check command queued');
      refreshDashboard();
      fetchDeviceTimeline(inspectedHwid);
    }
  });

  document.getElementById('cmdStableBtn')?.addEventListener('click', () => {
    if (!inspectedHwid) return;
    const target = inspectedHwid;
    openActionModal({
      title: 'Switch Device to Stable Channel',
      message: `Move ${target} to the production :stable release stream.`,
      confirmLabel: 'Switch to Stable',
      onSubmit: async (reason) => {
        const ok = await postAdmin('/device_cmd/' + encodeURIComponent(target), { cmd: 'set_channel_stable', reason });
        if (ok) { showToast('Channel switch queued'); refreshDashboard(); }
      }
    });
  });

  document.getElementById('cmdTestingBtn')?.addEventListener('click', () => {
    if (!inspectedHwid) return;
    const target = inspectedHwid;
    openActionModal({
      title: 'Switch Device to Testing Channel',
      message: `Move ${target} to pre-release :testing builds.`,
      confirmLabel: 'Switch to Testing',
      onSubmit: async (reason) => {
        const ok = await postAdmin('/device_cmd/' + encodeURIComponent(target), { cmd: 'set_channel_testing', reason });
        if (ok) { showToast('Channel switch queued'); refreshDashboard(); }
      }
    });
  });

  document.getElementById('cmdRebootBtn')?.addEventListener('click', () => {
    if (!inspectedHwid) return;
    const target = inspectedHwid;
    openActionModal({
      title: 'Reboot Remote MiniPC',
      message: `Queue immediate reboot on ${target}. Any staged OS update will install during restart.`,
      confirmLabel: 'Queue Reboot',
      danger: true,
      onSubmit: async (reason) => {
        const ok = await postAdmin('/device_cmd/' + encodeURIComponent(target), { cmd: 'reboot_device', reason });
        if (ok) { showToast('Reboot command queued'); refreshDashboard(); }
      }
    });
  });

  document.getElementById('saveMetaBtn')?.addEventListener('click', async () => {
    if (!inspectedHwid) return;
    const clientName = document.getElementById('metaClientName').value.trim();
    const organization = (document.getElementById('metaOrganization')?.value || '').trim();
    const notes = document.getElementById('metaNotes').value.trim();
    const ok = await postAdmin('/update_meta/' + encodeURIComponent(inspectedHwid), {
      client_name: clientName,
      organization,
      notes
    });
    if (ok) {
      showToast('Client details saved');
      refreshDashboard();
      fetchDeviceTimeline(inspectedHwid);
    }
  });

  document.getElementById('toggleRevokeBtn')?.addEventListener('click', () => {
    if (!inspectedHwid || !isAdmin) return;
    const target = inspectedHwid;
    const curRevoked = !!fleetData.clienti[target]?.revoked;
    openActionModal({
      title: curRevoked ? 'Restore Device Access' : 'Revoke Device Access',
      message: curRevoked ? `Re-enable fleet trust for ${target}.` : `Mark ${target} as revoked and block support requests.`,
      confirmLabel: curRevoked ? 'Restore Access' : 'Revoke Access',
      danger: !curRevoked,
      onSubmit: async (reason) => {
        const res = await postAdmin('/toggle_revoke/' + encodeURIComponent(target), { reason });
        if (res) {
          const payload = await res.json();
          showToast(payload.revoked ? 'Device access revoked' : 'Device access restored');
          refreshDashboard();
        }
      }
    });
  });

  document.getElementById('reenrollBtn')?.addEventListener('click', () => {
    if (!inspectedHwid || !isAdmin) return;
    const target = inspectedHwid;
    openActionModal({
      title: 'Approve One-Time Re-Enrollment',
      message: `Allow ${target} to receive a new certificate and telemetry token on next check-in.`,
      confirmLabel: 'Approve Re-Enrollment',
      onSubmit: async (reason) => {
        const ok = await postAdmin('/allow_reenroll/' + encodeURIComponent(target), { reason });
        if (ok) { showToast('Re-enrollment approved'); refreshDashboard(); }
      }
    });
  });

  document.getElementById('drawerDeleteBtn')?.addEventListener('click', () => {
    if (!inspectedHwid || !isAdmin) return;
    const target = inspectedHwid;
    openActionModal({
      title: 'Delete Device Record',
      message: `Permanently delete HWID ${target} from the fleet database.`,
      confirmLabel: 'Delete Permanently',
      danger: true,
      onSubmit: async (reason) => {
        const ok = await postAdmin('/delete_client/' + encodeURIComponent(target), { reason });
        if (ok) {
          inspectedHwid = null;
          showToast('Device deleted');
          refreshDashboard();
        }
      }
    });
  });

  // Threats view
  document.getElementById('clearThreatsBtn')?.addEventListener('click', () => {
    openActionModal({
      title: 'Clear All Threat Alerts',
      message: 'Remove all YARA alert notifications from the dashboard feed.',
      confirmLabel: 'Clear Alerts',
      danger: true,
      onSubmit: async (reason) => {
        const ok = await postAdmin('/clear_yara_alerts', { reason });
        if (ok) { showToast('Threat alerts cleared'); refreshDashboard(); }
      }
    });
  });

  // Audit filter & export listeners
  document.getElementById('auditSearch')?.addEventListener('input', () => {
    clearTimeout(auditDebounce);
    auditDebounce = setTimeout(fetchAuditLog, 200);
  });
  ['auditActorFilter', 'auditCategoryFilter', 'auditSeverityFilter', 'auditDaysFilter'].forEach((id) => {
    document.getElementById(id)?.addEventListener('change', fetchAuditLog);
  });
  document.getElementById('clearAuditHwidBtn')?.addEventListener('click', () => {
    auditHwidFilter = '';
    fetchAuditLog();
  });
  document.getElementById('auditClearBtn')?.addEventListener('click', () => {
    document.getElementById('auditSearch').value = '';
    document.getElementById('auditActorFilter').value = '';
    document.getElementById('auditCategoryFilter').value = '';
    document.getElementById('auditSeverityFilter').value = '';
    document.getElementById('auditDaysFilter').value = '';
    auditHwidFilter = '';
    fetchAuditLog();
  });
  document.getElementById('auditExportBtn')?.addEventListener('click', () => {
    const params = buildAuditParams();
    window.location.href = '/api/audit/export.csv?' + params.toString();
  });

  // Team management listeners
  document.getElementById('addOperatorBtn')?.addEventListener('click', () => {
    const username = document.getElementById('newOpUser').value.trim();
    const fullName = document.getElementById('newOpName').value.trim();
    const role = document.getElementById('newOpRole').value;
    const password = document.getElementById('newOpPass').value;
    if (!username || password.length < 8) {
      showToast('Enter a valid username and an 8+ character passphrase', true);
      return;
    }
    openActionModal({
      title: 'Create Operator Account',
      message: `Create '${username}' with '${role}' permissions.`,
      confirmLabel: 'Create Operator',
      onSubmit: async (reason) => {
        const ok = await postAdmin('/api/team/add', { username, full_name: fullName, role, password, reason });
        if (ok) {
          document.getElementById('newOpUser').value = '';
          document.getElementById('newOpName').value = '';
          document.getElementById('newOpPass').value = '';
          showToast('Operator account created');
          fetchTeamMembers();
        }
      }
    });
  });

  document.getElementById('team-tbody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-team-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-team-action');
    const targetUser = btn.getAttribute('data-user');
    if (!targetUser) return;

    if (action === 'toggle') {
      openActionModal({
        title: 'Toggle Operator Status',
        message: `Enable or disable console access for @${targetUser}.`,
        confirmLabel: 'Apply Change',
        onSubmit: async (reason) => {
          const ok = await postAdmin('/api/team/toggle/' + encodeURIComponent(targetUser), { reason });
          if (ok) { showToast('Operator status updated'); fetchTeamMembers(); }
        }
      });
    } else if (action === 'reset_pw') {
      openActionModal({
        title: `Reset Passphrase (@${targetUser})`,
        message: `Set a new passphrase for operator @${targetUser}.`,
        confirmLabel: 'Reset Passphrase',
        askPassword: true,
        onSubmit: async (reason, password) => {
          const ok = await postAdmin('/api/team/reset_password/' + encodeURIComponent(targetUser), { password, reason });
          if (ok) { showToast('Passphrase updated'); fetchTeamMembers(); }
        }
      });
    } else if (action === 'delete') {
      openActionModal({
        title: 'Delete Operator Account',
        message: `Permanently delete @${targetUser}. Historical audit log entries remain preserved.`,
        confirmLabel: 'Delete Operator',
        danger: true,
        onSubmit: async (reason) => {
          const ok = await postAdmin('/api/team/delete/' + encodeURIComponent(targetUser), { reason });
          if (ok) { showToast('Operator deleted'); fetchTeamMembers(); }
        }
      });
    }
  });

  // Modal & Backdrop wiring
  document.getElementById('backdrop')?.addEventListener('click', closeAllOverlays);
  document.getElementById('closeDeviceDrawer')?.addEventListener('click', closeAllOverlays);
  document.getElementById('modalCancel')?.addEventListener('click', closeAllOverlays);
  document.getElementById('modalReasonInput')?.addEventListener('input', validateModalState);
  document.getElementById('modalPasswordInput')?.addEventListener('input', validateModalState);
  document.getElementById('modalConfirm')?.addEventListener('click', async () => {
    if (!pendingModalCfg) return;
    const reason = (document.getElementById('modalReasonInput').value || '').trim();
    const password = document.getElementById('modalPasswordInput').value || '';
    const handler = pendingModalCfg.onSubmit;
    closeAllOverlays();
    if (handler) await handler(reason, password);
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAllOverlays();
  });

  setInterval(() => {
    refreshDashboard();
    if (activeView === 'audit') fetchAuditLog();
  }, 2000);
  refreshDashboard();
})();
