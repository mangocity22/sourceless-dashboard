(function () {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  let fleetData = {
    clienti: {},
    stats: { total: 0, online: 0, secure: 0, compromised: 0, pending_updates: 0, yara_alerts: 0 },
    audit_log: [],
    yara_alerts: []
  };
  let activeFilter = 'all';
  let searchQuery = '';
  let inspectedHwid = null;
  let pendingModalAction = null;
  const rejectedTimers = {};
  const displayedCounters = { total: 0, online: 0, secure: 0, updates: 0, alerts: 0 };

  function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function showToast(msg) {
    const stack = document.getElementById('toastStack');
    if (!stack) return;
    const el = document.createElement('div');
    el.className = 'toast';
    el.textContent = msg;
    stack.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(8px)';
      el.style.transition = 'opacity 0.2s, transform 0.2s';
      setTimeout(() => el.remove(), 220);
    }, 2600);
  }

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
    const st = (info.update_status || 'unknown').toLowerCase();
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
    return res;
  }

  function openConfirm(title, message, onConfirm) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalMsg').textContent = message;
    pendingModalAction = onConfirm;
    document.getElementById('backdrop').classList.add('open');
    document.getElementById('confirmModal').classList.add('open');
  }

  function closeAllOverlays() {
    document.getElementById('backdrop').classList.remove('open');
    document.getElementById('deviceDrawer').classList.remove('open');
    document.getElementById('threatsDrawer').classList.remove('open');
    document.getElementById('auditDrawer').classList.remove('open');
    document.getElementById('confirmModal').classList.remove('open');
    pendingModalAction = null;
  }

  function openDrawer(drawerId) {
    document.getElementById('backdrop').classList.add('open');
    ['deviceDrawer', 'threatsDrawer', 'auditDrawer'].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle('open', id === drawerId);
    });
  }

  function openDeviceDrawer(hwid) {
    const info = fleetData.clienti[hwid];
    if (!info) return;
    inspectedHwid = hwid;
    document.getElementById('drawerTitle').textContent = info.client_name || info.hostname || hwid;
    document.getElementById('metaClientName').value = info.client_name || '';
    document.getElementById('metaNotes').value = info.notes || '';
    renderDrawerMeta(hwid, info);
    openDrawer('deviceDrawer');
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

  function renderAuditDrawer() {
    const list = document.getElementById('auditList');
    const items = fleetData.audit_log || [];
    if (!items.length) {
      list.innerHTML = '<div class="empty-state">No audit events recorded yet.</div>';
      return;
    }
    list.innerHTML = items.map((ev) => `
      <div class="audit-item sev-${escapeHtml(ev.severity || 'info')}">
        <div class="audit-top">
          <strong>${escapeHtml(ev.hostname || 'System')} • ${escapeHtml(ev.type || 'event')}</strong>
          <span>${escapeHtml(ev.time || '')}</span>
        </div>
        <div class="audit-msg">${escapeHtml(ev.detail || '')}</div>
      </div>
    `).join('');
  }

  function renderThreatsDrawer() {
    const list = document.getElementById('threatsList');
    const items = fleetData.yara_alerts || [];
    if (!items.length) {
      list.innerHTML = '<div class="empty-state">No YARA threats detected across the fleet.</div>';
      return;
    }
    list.innerHTML = items.map((al) => `
      <div class="audit-item sev-critical">
        <div class="audit-top">
          <strong>${escapeHtml(al.client_label || al.hostname || al.hwid)}</strong>
          <span>${escapeHtml(al.time || '')}</span>
        </div>
        <div class="audit-msg">Rule <strong>${escapeHtml(al.rule || 'Unknown')}</strong> quarantined <code>${escapeHtml(al.filename || 'file')}</code></div>
        <div class="audit-sub">Source: ${escapeHtml(al.path || '—')}<br>Quarantine: ${escapeHtml(al.quarantine_path || '—')}</div>
      </div>
    `).join('');
  }

  function matchesFilter(hwid, info) {
    if (activeFilter === 'online' && !info.online) return false;
    if (activeFilter === 'offline' && info.online) return false;
    if (activeFilter === 'modified' && info.status === 'Integru') return false;
    if (activeFilter === 'pending_update' && info.update_status !== 'pending_restart') return false;
    if (activeFilter === 'support' && info.support_state !== 'waiting' && info.support_state !== 'approved') return false;
    if (activeFilter === 'revoked' && !info.revoked) return false;
    if (searchQuery) {
      const hay = [
        hwid, info.client_name, info.hostname, info.ip, info.notes,
        info.status, info.os_version, info.update_channel, info.update_status
      ].filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(searchQuery)) return false;
    }
    return true;
  }

  function renderTable() {
    const tbody = document.getElementById('clients-tbody');
    const entries = Object.entries(fleetData.clienti || {});
    entries.sort((a, b) => {
      if (!!b[1].online !== !!a[1].online) return b[1].online ? 1 : -1;
      return (b[1].last_seen_ts || 0) - (a[1].last_seen_ts || 0);
    });

    const filtered = entries.filter(([hwid, info]) => matchesFilter(hwid, info));
    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">${entries.length ? 'No MiniPCs match the active search or filter.' : 'No enrolled SourceLess MiniPCs yet.'}</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(([hwid, info]) => {
      const safeHwid = escapeHtml(hwid);
      const isOnline = !!info.online;
      const isRevoked = !!info.revoked;
      const isSecure = !isRevoked && info.status === 'Integru';
      const displayName = info.client_name || info.hostname || 'Unassigned Device';
      const subHost = info.client_name && info.hostname ? info.hostname : (info.notes ? info.notes.slice(0, 38) : 'Standard Node');

      const presenceHtml = isOnline
        ? '<span class="presence on"><span class="radar-dot"></span>Online</span>'
        : '<span class="presence off"><span class="radar-dot"></span>Offline</span>';

      let statusHtml = '<span class="badge badge-secure">Intact</span>';
      if (isRevoked) {
        statusHtml = '<span class="badge badge-alert">Revoked</span>';
      } else if (info.status === 'Inscris') {
        statusHtml = '<span class="badge badge-muted">Enrolled</span>';
      } else if (!isSecure) {
        statusHtml = '<span class="badge badge-alert">Modified</span>';
      }

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
          <td>${presenceHtml}</td>
          <td>
            <div class="device-cell">
              <span class="client-name">${escapeHtml(displayName)}</span>
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
              await postAdmin('/stop_support/' + encodeURIComponent(hwid));
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

      renderTable();
      if (inspectedHwid && data.clienti[inspectedHwid] && document.getElementById('deviceDrawer').classList.contains('open')) {
        renderDrawerMeta(inspectedHwid, data.clienti[inspectedHwid]);
      }
      if (document.getElementById('auditDrawer').classList.contains('open')) {
        renderAuditDrawer();
      }
      if (document.getElementById('threatsDrawer').classList.contains('open')) {
        renderThreatsDrawer();
      }
    } catch (err) {
      console.error('Telemetry refresh failed:', err);
    }
  }

  document.getElementById('copyKeyBtn')?.addEventListener('click', (e) => {
    copyText(document.getElementById('supportKeyVal').textContent.trim(), 'Support Key', e.currentTarget);
  });

  document.getElementById('openAuditBtn')?.addEventListener('click', () => {
    renderAuditDrawer();
    openDrawer('auditDrawer');
  });

  document.getElementById('openThreatsBtn')?.addEventListener('click', () => {
    renderThreatsDrawer();
    openDrawer('threatsDrawer');
  });

  document.getElementById('searchInput')?.addEventListener('input', (e) => {
    searchQuery = e.target.value.trim().toLowerCase();
    renderTable();
  });

  document.getElementById('filterPills')?.addEventListener('click', (e) => {
    const pill = e.target.closest('.filter-pill');
    if (!pill) return;
    document.querySelectorAll('.filter-pill').forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');
    activeFilter = pill.getAttribute('data-filter') || 'all';
    renderTable();
  });

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
    } else if (action === 'reinstate' || action === 'request_support' || action === 'stop_support') {
      await postAdmin('/' + action + '/' + encodeURIComponent(hwid));
      showToast(action === 'reinstate' ? 'Tamper seal reinstated' : (action === 'request_support' ? 'Support prompt dispatched' : 'Support session stopped'));
      refreshDashboard();
    }
  });

  async function sendDeviceCmd(cmd, toastText) {
    if (!inspectedHwid) return;
    const res = await postAdmin('/device_cmd/' + encodeURIComponent(inspectedHwid), { cmd });
    if (res && res.ok) {
      showToast(toastText);
      refreshDashboard();
    }
  }

  document.getElementById('cmdCheckUpdateBtn')?.addEventListener('click', () => sendDeviceCmd('check_update', 'Update check command queued'));
  document.getElementById('cmdStableBtn')?.addEventListener('click', () => sendDeviceCmd('set_channel_stable', 'Switched device to Stable channel'));
  document.getElementById('cmdTestingBtn')?.addEventListener('click', () => sendDeviceCmd('set_channel_testing', 'Switched device to Testing channel'));
  document.getElementById('cmdRebootBtn')?.addEventListener('click', () => {
    if (!inspectedHwid) return;
    openConfirm(
      'Reboot Remote MiniPC?',
      'Are you sure you want to reboot device ' + inspectedHwid + '? Any staged OS update will install automatically during restart.',
      async () => sendDeviceCmd('reboot_device', 'Reboot command queued for next heartbeat')
    );
  });

  document.getElementById('backdrop')?.addEventListener('click', closeAllOverlays);
  document.getElementById('closeDeviceDrawer')?.addEventListener('click', closeAllOverlays);
  document.getElementById('closeThreatsDrawer')?.addEventListener('click', closeAllOverlays);
  document.getElementById('closeAuditDrawer')?.addEventListener('click', closeAllOverlays);
  document.getElementById('modalCancel')?.addEventListener('click', closeAllOverlays);
  document.getElementById('modalConfirm')?.addEventListener('click', async () => {
    if (pendingModalAction) await pendingModalAction();
    closeAllOverlays();
  });

  document.getElementById('saveMetaBtn')?.addEventListener('click', async () => {
    if (!inspectedHwid) return;
    const clientName = document.getElementById('metaClientName').value.trim();
    const notes = document.getElementById('metaNotes').value.trim();
    const res = await postAdmin('/update_meta/' + encodeURIComponent(inspectedHwid), { client_name: clientName, notes });
    if (res && res.ok) {
      showToast('Client details saved');
      refreshDashboard();
    }
  });

  document.getElementById('toggleRevokeBtn')?.addEventListener('click', async () => {
    if (!inspectedHwid) return;
    const res = await postAdmin('/toggle_revoke/' + encodeURIComponent(inspectedHwid));
    if (res && res.ok) {
      const payload = await res.json();
      showToast(payload.revoked ? 'Device access revoked' : 'Device access restored');
      refreshDashboard();
    }
  });

  document.getElementById('reenrollBtn')?.addEventListener('click', () => {
    if (!inspectedHwid) return;
    const targetHwid = inspectedHwid;
    openConfirm(
      'Approve One-Time Re-Enrollment?',
      'This allows device ' + targetHwid + ' to re-register and receive a new certificate/token on its next boot or OS reinstall.',
      async () => {
        await postAdmin('/allow_reenroll/' + encodeURIComponent(targetHwid));
        showToast('Re-enrollment approved for next device check-in');
        refreshDashboard();
      }
    );
  });

  document.getElementById('drawerDeleteBtn')?.addEventListener('click', () => {
    if (!inspectedHwid) return;
    const targetHwid = inspectedHwid;
    openConfirm(
      'Delete Device Record?',
      'Remove HWID ' + targetHwid + ' from the fleet database? It will lose telemetry access until re-enrolled.',
      async () => {
        await postAdmin('/delete_client/' + encodeURIComponent(targetHwid));
        inspectedHwid = null;
        showToast('Device deleted');
        refreshDashboard();
      }
    );
  });

  document.getElementById('clearThreatsBtn')?.addEventListener('click', async () => {
    await postAdmin('/clear_yara_alerts');
    showToast('Threat alerts cleared');
    refreshDashboard();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAllOverlays();
  });

  setInterval(refreshDashboard, 2000);
  refreshDashboard();
})();
