/**
 * Credentials Tab — Crucible v2.0
 * Vault-backed credential management with encrypted storage,
 * spray configuration, bulk import, and real-time Socket.IO updates.
 *
 * Relies on globals from project.js:
 *   window._PROJECT_ID, window.toast(), window.esc()
 *
 * HTML lives in project.html under data-tab="credentials".
 */
(function () {
  'use strict';

  /* ── Inject component CSS ────────────────────────────────── */
  document.head.insertAdjacentHTML('beforeend', '<style>' + [
    /* Protocol risk border colours */
    '.cred-row-high{border-left:3px solid #e74c3c}',
    '.cred-row-medium{border-left:3px solid #f39c12}',
    '.cred-row-low{border-left:3px solid #f1c40f}',
    '.cred-row-default{border-left:3px solid var(--border-mid)}',

    /* Verified badges */
    '.cred-verified{color:#27ae60;font-weight:700;font-size:.9rem}',
    '.cred-unverified{color:#e74c3c;font-weight:700;font-size:.9rem}',

    /* Spray toggle */
    '.cred-spray-on{color:#27ae60;font-weight:600;font-size:.78rem}',
    '.cred-spray-off{color:var(--text-muted);font-size:.78rem}',

    /* Source badge */
    '.cred-source{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em}',
    '.cred-source-user{background:rgba(74,144,217,.15);color:#4a90d9}',
    '.cred-source-captured{background:rgba(231,76,60,.12);color:#e74c3c}',

    /* Type badge */
    '.cred-type-badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.72rem;font-weight:600;background:var(--bg-secondary);color:var(--text-secondary)}',

    /* OS tag */
    '.cred-os{display:inline-block;padding:1px 5px;border-radius:3px;font-size:.70rem;background:rgba(146,208,80,.12);color:#6aaa40}',

    /* Action buttons */
    '.cred-action{background:none;border:none;cursor:pointer;padding:4px;border-radius:var(--radius-sm,4px);color:var(--text-muted);transition:color .15s,background .15s}',
    '.cred-action:hover{background:var(--bg-hover);color:var(--text-primary)}',
    '.cred-action-danger:hover{color:#e74c3c}',

    /* Modal overlay */
    '.cred-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:1000;display:none;align-items:center;justify-content:center}',
    '.cred-modal-overlay.active{display:flex}',
    '.cred-modal{background:var(--bg-card);border:1px solid var(--border-mid);border-radius:8px;max-width:580px;width:92%;max-height:85vh;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,.3)}',
    '.cred-modal-header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border-mid)}',
    '.cred-modal-title{font-size:1rem;font-weight:700;color:var(--text-primary)}',
    '.cred-modal-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1.2rem;line-height:1}',
    '.cred-modal-body{padding:16px 20px}',
    '.cred-modal-footer{padding:12px 20px;border-top:1px solid var(--border-mid);display:flex;justify-content:flex-end;gap:8px}',

    /* Spray config grid */
    '.spray-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px}',
    '.spray-card{background:var(--bg-surface);border:1px solid var(--border-mid);border-radius:4px;padding:8px 10px;font-size:.8rem}',
    '.spray-card-label{font-weight:600;color:var(--text-primary);margin-bottom:4px;text-transform:uppercase;font-size:.72rem;letter-spacing:.03em}',
    '.spray-field{display:flex;justify-content:space-between;padding:2px 0;font-size:.78rem}',
    '.spray-field-label{color:var(--text-muted)}',
    '.spray-field-val{color:var(--text-primary);font-family:monospace}',

    /* Import results */
    '.cred-import-result{font-size:.82rem;padding:8px;background:var(--bg-surface);border-radius:4px;margin-top:8px;border:1px solid var(--border-mid)}',
  ].join('\n') + '</style>');


  /* ── Globals ──────────────────────────────────────────────── */
  var PID = (window._PROJECT_ID != null)
    ? window._PROJECT_ID
    : JSON.parse(document.getElementById('projectConfig').textContent).pid;

  var _creds = [];
  var _loaded = false;
  var _sprayConfig = null;

  /* ── Helpers ──────────────────────────────────────────────── */
  function _e(s) { return window.esc ? window.esc(s) : (s == null ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')); }
  function _toast(type, msg) { if (window.toast) window.toast(type, msg); }

  function _fmtIso(iso) {
    if (!iso) return '--';
    try {
      var d = new Date(iso);
      if (isNaN(d.getTime())) return '--';
      return d.toLocaleString(undefined, { year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', hour12:false });
    } catch (e) { return '--'; }
  }

  function _api(path, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
      opts.headers = Object.assign({'Content-Type':'application/json'}, opts.headers || {});
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(path, opts).then(function (r) {
      if (r.status === 401) { window.location.href = '/login'; }
      return r;
    });
  }

  /* ── Protocol risk mapping ───────────────────────────────── */
  var _PROTO_RISK = { rdp:'high', winrm:'high', ssh:'high', smb:'medium', ldap:'medium', kerberos:'medium', ftp:'low', http:'low', telnet:'low' };
  function _protoClass(proto) { return 'cred-row-' + (_PROTO_RISK[(proto||'').toLowerCase()] || 'default'); }

  /* ── Source badge ─────────────────────────────────────────── */
  function _srcBadge(src) {
    if (!src) return '';
    if (src === 'user_provided') return '<span class="cred-source cred-source-user">User</span>';
    if (src.indexOf('captured') === 0) return '<span class="cred-source cred-source-captured">' + _e(src.replace('captured_','').replace(/_/g,' ')) + '</span>';
    return '<span class="cred-source">' + _e(src) + '</span>';
  }


  /* ══════════════════════════════════════════════════════════════
     VAULT STATE
     ══════════════════════════════════════════════════════════════ */

  function checkVaultStatus() {
    _api('/api/credentials/' + PID + '/vault/status')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var badge   = document.getElementById('vaultStatusBadge');
        var unlock  = document.getElementById('vaultUnlockPanel');
        var create  = document.getElementById('vaultCreatePanel');
        var main    = document.getElementById('credentialsMainPanel');

        if (!d.exists) {
          if (badge)  { badge.textContent = 'No Vault'; badge.className = 'badge badge-muted'; }
          if (unlock) unlock.style.display = 'none';
          if (create) create.style.display = '';
          if (main)   main.style.display = 'none';
        } else if (!d.unlocked) {
          if (badge)  { badge.textContent = 'Locked'; badge.className = 'badge badge-muted'; }
          if (unlock) unlock.style.display = '';
          if (create) create.style.display = 'none';
          if (main)   main.style.display = 'none';
        } else {
          if (badge)  { badge.textContent = 'Unlocked (' + (d.credential_count||0) + ' creds)'; badge.className = 'badge badge-success'; }
          if (unlock) unlock.style.display = 'none';
          if (create) create.style.display = 'none';
          if (main)   main.style.display = '';
          loadCredentials();
          loadSprayConfig();
        }

        _updatePill(d.credential_count || 0);
      })
      .catch(function () {});
  }

  /* ── Vault create ────────────────────────────────────────── */
  function createVault() {
    var p1  = (document.getElementById('vaultNewPassphrase')     || {}).value || '';
    var p2  = (document.getElementById('vaultConfirmPassphrase') || {}).value || '';
    var err = document.getElementById('vaultCreateError');

    if (p1.length < 8) { if (err) { err.textContent = 'Passphrase must be at least 8 characters.'; err.style.display = ''; } return; }
    if (p1 !== p2)     { if (err) { err.textContent = 'Passphrases do not match.';                 err.style.display = ''; } return; }
    if (err) err.style.display = 'none';

    _api('/api/credentials/' + PID + '/vault/create', { method:'POST', body:{ passphrase:p1 } })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (res.ok) {
          var el1 = document.getElementById('vaultNewPassphrase');     if (el1) el1.value = '';
          var el2 = document.getElementById('vaultConfirmPassphrase'); if (el2) el2.value = '';
          _toast('success', 'Vault created and unlocked.');
          checkVaultStatus();
        } else {
          if (err) { err.textContent = res.data.error || 'Failed.'; err.style.display = ''; }
        }
      });
  }

  /* ── Vault unlock ────────────────────────────────────────── */
  function unlockVault() {
    var inp = document.getElementById('vaultPassphraseInput');
    var pw  = (inp || {}).value || '';
    var err = document.getElementById('vaultUnlockError');

    if (!pw) { if (err) { err.textContent = 'Enter passphrase.'; err.style.display = ''; } return; }
    if (err) err.style.display = 'none';

    _api('/api/credentials/' + PID + '/vault/unlock', { method:'POST', body:{ passphrase:pw } })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (res.ok) {
          if (inp) inp.value = '';
          _toast('success', 'Vault unlocked.');
          checkVaultStatus();
        } else {
          if (err) { err.textContent = res.data.error || 'Invalid passphrase.'; err.style.display = ''; }
        }
      });
  }

  /* ── Vault lock ──────────────────────────────────────────── */
  function lockVault() {
    _api('/api/credentials/' + PID + '/vault/lock', { method:'POST' })
      .then(function () {
        _creds = [];
        _loaded = false;
        _toast('info', 'Vault locked.');
        checkVaultStatus();
      });
  }


  /* ══════════════════════════════════════════════════════════════
     CREDENTIAL LISTING
     ══════════════════════════════════════════════════════════════ */

  function loadCredentials() {
    var src = (document.getElementById('credSourceFilter') || {}).value || '';
    var typ = (document.getElementById('credTypeFilter')   || {}).value || '';
    var params = [];
    if (src) params.push('source=' + encodeURIComponent(src));
    if (typ) params.push('cred_type=' + encodeURIComponent(typ));
    var url = '/api/credentials/' + PID + (params.length ? '?' + params.join('&') : '');

    _api(url)
      .then(function (r) { return r.json(); })
      .then(function (d) {
        _creds = d.credentials || [];
        _loaded = true;
        _renderTable();
        _updatePill(_creds.length);
      })
      .catch(function () { _creds = []; _renderTable(); });
  }

  function _renderTable() {
    var tbody = document.getElementById('credentialsBody');
    var empty = document.getElementById('credsEmpty');
    if (!tbody) return;

    if (!_creds.length) {
      tbody.innerHTML = '';
      if (empty) empty.style.display = '';
      return;
    }
    if (empty) empty.style.display = 'none';

    var html = '';
    for (var i = 0; i < _creds.length; i++) {
      var c = _creds[i];
      html += '<tr class="' + _protoClass(c.protocol) + '">';

      /* # */
      html += '<td><span class="badge badge-muted" style="font-size:.68rem">' + c.id + '</span></td>';

      /* Username */
      html += '<td><strong>' + _e(c.username) + '</strong></td>';

      /* Domain */
      html += '<td>' + _e(c.domain || '--') + '</td>';

      /* Type */
      html += '<td><span class="cred-type-badge">' + _e(c.cred_type || '--') + '</span></td>';

      /* OS Tag */
      html += '<td>' + (c.os_tag ? '<span class="cred-os">' + _e(c.os_tag) + '</span>' : '--') + '</td>';

      /* Protocol */
      html += '<td>' + _e(c.protocol || 'any') + '</td>';

      /* Source */
      html += '<td>' + _srcBadge(c.source) + '</td>';

      /* Target IP */
      html += '<td style="font-family:monospace;font-size:.82rem">' + _e(c.target_ip || 'global') + '</td>';

      /* Spray */
      html += '<td>';
      html += c.spray_eligible
        ? '<span class="cred-spray-on">ON</span>'
        : '<span class="cred-spray-off">OFF</span>';
      html += '</td>';

      /* Verified */
      html += '<td>';
      html += c.verified
        ? '<span class="cred-verified" title="Verified">&#10003;</span>'
        : '<span class="cred-unverified" title="Unverified">&#10007;</span>';
      html += '</td>';

      /* Actions */
      html += '<td>';
      html += '<button class="cred-action" title="View details" data-cred-view="' + c.id + '">'
            + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button> ';
      html += '<button class="cred-action" title="Edit" data-cred-edit="' + c.id + '">'
            + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button> ';
      html += '<button class="cred-action cred-action-danger" title="Delete" data-cred-del="' + c.id + '" data-cred-user="' + _e(c.username) + '">'
            + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg></button>';
      html += '</td>';

      html += '</tr>';
    }
    tbody.innerHTML = html;
  }

  function _updatePill(count) {
    var pill = document.getElementById('credentialsPill');
    if (pill) pill.textContent = count || '';
  }

  /* ── Table action delegation ─────────────────────────────── */
  (function () {
    var wrap = document.getElementById('credentialsBody');
    if (!wrap) return;
    wrap.parentElement.addEventListener('click', function (ev) {
      var btn;
      if ((btn = ev.target.closest('[data-cred-view]'))) { _openViewModal(parseInt(btn.getAttribute('data-cred-view'), 10)); return; }
      if ((btn = ev.target.closest('[data-cred-edit]'))) { _openEditModal(parseInt(btn.getAttribute('data-cred-edit'), 10)); return; }
      if ((btn = ev.target.closest('[data-cred-del]')))  { _deleteCred(parseInt(btn.getAttribute('data-cred-del'), 10), btn.getAttribute('data-cred-user')); return; }
    });
  })();


  /* ══════════════════════════════════════════════════════════════
     ADD CREDENTIAL MODAL
     ══════════════════════════════════════════════════════════════ */

  var _addModal = null;

  function _ensureAddModal() {
    if (_addModal) return _addModal;
    var ov = document.createElement('div');
    ov.className = 'cred-modal-overlay'; ov.id = 'credAddModal';
    ov.innerHTML =
      '<div class="cred-modal"><div class="cred-modal-header"><span class="cred-modal-title">Add Credential</span>'
      + '<button class="cred-modal-close" id="credAddClose">&times;</button></div>'
      + '<div class="cred-modal-body"><div class="form-grid" style="gap:10px">'
      + '<div class="form-group"><label class="form-label">Username *</label><input type="text" class="form-control" id="caUser"></div>'
      + '<div class="form-group"><label class="form-label">Secret / Password *</label><input type="password" class="form-control" id="caSecret"></div>'
      + '<div class="form-group"><label class="form-label">Type</label><select class="form-control" id="caType"><option value="password">Password</option><option value="ntlm_hash">NTLM Hash</option><option value="ssh_key">SSH Key</option><option value="kerberos_ticket">Kerberos Ticket</option></select></div>'
      + '<div class="form-group"><label class="form-label">Domain</label><input type="text" class="form-control" id="caDomain" placeholder="e.g. CORP"></div>'
      + '<div class="form-group"><label class="form-label">Protocol</label><select class="form-control" id="caProto"><option value="">--</option><option value="smb">SMB</option><option value="ssh">SSH</option><option value="rdp">RDP</option><option value="winrm">WinRM</option><option value="ldap">LDAP</option><option value="ftp">FTP</option><option value="http">HTTP</option><option value="mysql">MySQL</option><option value="mssql">MSSQL</option><option value="postgresql">PostgreSQL</option><option value="vnc">VNC</option><option value="redis">Redis</option><option value="telnet">Telnet</option><option value="kerberos">Kerberos</option></select></div>'
      + '<div class="form-group"><label class="form-label">Target IP</label><input type="text" class="form-control" id="caIP" placeholder="e.g. 10.0.0.5"></div>'
      + '<div class="form-group"><label class="form-label">OS Tag</label><select class="form-control" id="caOS"><option value="">--</option><option value="windows">Windows</option><option value="redhat">RedHat</option><option value="ubuntu">Ubuntu</option><option value="linux_other">Linux (Other)</option><option value="macos">macOS</option><option value="network_device">Network Device</option></select></div>'
      + '<div class="form-group" style="grid-column:1/-1"><label class="form-label">Notes</label><textarea class="form-control" id="caNotes" rows="2" style="font-size:.82rem"></textarea></div>'
      + '<div class="form-group"><label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:.82rem"><input type="checkbox" id="caSpray" checked> Spray Eligible</label></div>'
      + '</div><p id="caError" style="color:var(--danger);font-size:.82rem;margin-top:8px;display:none"></p></div>'
      + '<div class="cred-modal-footer"><button class="btn btn-ghost" id="caCancel">Cancel</button><button class="btn btn-primary" id="caSubmit">Add</button></div></div>';

    document.body.appendChild(ov);
    _addModal = ov;

    ov.querySelector('#credAddClose').onclick = function () { ov.classList.remove('active'); };
    ov.querySelector('#caCancel').onclick     = function () { ov.classList.remove('active'); };
    ov.querySelector('#caSubmit').onclick     = _submitAdd;
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.classList.remove('active'); });

    return ov;
  }

  function _openAddModal() {
    var m = _ensureAddModal();
    ['caUser','caSecret','caDomain','caIP','caNotes'].forEach(function (id) { var el = document.getElementById(id); if (el) el.value = ''; });
    var t = document.getElementById('caType'); if (t) t.value = 'password';
    var p = document.getElementById('caProto'); if (p) p.value = '';
    var o = document.getElementById('caOS'); if (o) o.value = '';
    var s = document.getElementById('caSpray'); if (s) s.checked = true;
    var e = document.getElementById('caError'); if (e) e.style.display = 'none';
    m.classList.add('active');
  }

  function _submitAdd() {
    var user   = (document.getElementById('caUser')   || {}).value || '';
    var secret = (document.getElementById('caSecret') || {}).value || '';
    var errEl  = document.getElementById('caError');

    if (!user.trim() || !secret) { if (errEl) { errEl.textContent = 'Username and secret are required.'; errEl.style.display = ''; } return; }
    if (errEl) errEl.style.display = 'none';

    var body = {
      username: user.trim(), secret: secret,
      cred_type:       (document.getElementById('caType')  || {}).value || 'password',
      domain:          (document.getElementById('caDomain')|| {}).value || '',
      protocol:        (document.getElementById('caProto') || {}).value || '',
      target_ip:       (document.getElementById('caIP')    || {}).value || '',
      os_tag:          (document.getElementById('caOS')    || {}).value || '',
      notes:           (document.getElementById('caNotes') || {}).value || '',
      spray_eligible: !!(document.getElementById('caSpray') || {}).checked,
      added_by: 'cred_tab',
    };

    var btn = document.getElementById('caSubmit'); if (btn) btn.disabled = true;
    _api('/api/credentials/' + PID, { method:'POST', body:body })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, s:r.status, data:d }; }); })
      .then(function (res) {
        if (btn) btn.disabled = false;
        if (res.ok) {
          _toast('success', 'Credential added.');
          _addModal.classList.remove('active');
          loadCredentials();
        } else {
          var msg = res.data.error || 'Failed.';
          if (res.s === 423) msg = 'Vault is locked. Unlock first.';
          if (errEl) { errEl.textContent = msg; errEl.style.display = ''; }
        }
      })
      .catch(function () { if (btn) btn.disabled = false; });
  }


  /* ══════════════════════════════════════════════════════════════
     VIEW CREDENTIAL MODAL
     ══════════════════════════════════════════════════════════════ */

  var _viewModal = null;

  function _ensureViewModal() {
    if (_viewModal) return _viewModal;
    var ov = document.createElement('div');
    ov.className = 'cred-modal-overlay'; ov.id = 'credViewModal';
    ov.innerHTML =
      '<div class="cred-modal"><div class="cred-modal-header"><span class="cred-modal-title">Credential Details</span>'
      + '<button class="cred-modal-close" id="cvClose">&times;</button></div>'
      + '<div class="cred-modal-body" id="cvBody"></div>'
      + '<div class="cred-modal-footer"><button class="btn btn-ghost" id="cvDone">Close</button></div></div>';
    document.body.appendChild(ov);
    _viewModal = ov;
    ov.querySelector('#cvClose').onclick = function () { ov.classList.remove('active'); };
    ov.querySelector('#cvDone').onclick  = function () { ov.classList.remove('active'); };
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.classList.remove('active'); });
    return ov;
  }

  function _openViewModal(credId) {
    var cred = null;
    for (var i = 0; i < _creds.length; i++) { if (_creds[i].id === credId) { cred = _creds[i]; break; } }
    if (!cred) return;

    var m = _ensureViewModal();
    var body = document.getElementById('cvBody');
    var rows = [
      ['Username', cred.username], ['Domain', cred.domain||'--'], ['Type', cred.cred_type],
      ['OS Tag', cred.os_tag||'--'], ['Protocol', cred.protocol||'--'],
      ['Target IP', cred.target_ip||'global'], ['Source', cred.source||'--'],
      ['Spray Eligible', cred.spray_eligible ? 'Yes':'No'], ['Verified', cred.verified ? 'Yes':'No'],
      ['Added By', cred.added_by||'--'], ['Created', _fmtIso(cred.created)], ['Notes', cred.notes||'--'],
    ];
    var html = '<table style="width:100%;border-collapse:collapse;font-size:.85rem">';
    for (var j = 0; j < rows.length; j++) {
      html += '<tr><td style="padding:4px 8px;color:var(--text-muted);white-space:nowrap;width:120px;vertical-align:top">' + rows[j][0] + '</td>'
            + '<td style="padding:4px 8px;color:var(--text-primary);word-break:break-word">' + _e(rows[j][1]) + '</td></tr>';
    }
    html += '</table>';
    html += '<p style="font-size:.78rem;color:var(--text-muted);margin-top:12px;font-style:italic">The secret is encrypted and cannot be displayed here. Use "Generate Cred File" to export for tools.</p>';
    body.innerHTML = html;
    m.classList.add('active');
  }


  /* ══════════════════════════════════════════════════════════════
     EDIT CREDENTIAL MODAL
     ══════════════════════════════════════════════════════════════ */

  var _editModal = null;
  var _editCredId = null;

  function _ensureEditModal() {
    if (_editModal) return _editModal;
    var ov = document.createElement('div');
    ov.className = 'cred-modal-overlay'; ov.id = 'credEditModal';
    ov.innerHTML =
      '<div class="cred-modal"><div class="cred-modal-header"><span class="cred-modal-title">Edit Credential</span>'
      + '<button class="cred-modal-close" id="ceClose">&times;</button></div>'
      + '<div class="cred-modal-body"><div class="form-grid" style="gap:10px">'
      + '<div class="form-group"><label class="form-label">New Secret (blank = keep)</label><input type="password" class="form-control" id="ceSecret"></div>'
      + '<div class="form-group"><label class="form-label">Domain</label><input type="text" class="form-control" id="ceDomain"></div>'
      + '<div class="form-group"><label class="form-label">Protocol</label><select class="form-control" id="ceProto"><option value="">--</option><option value="smb">SMB</option><option value="ssh">SSH</option><option value="rdp">RDP</option><option value="winrm">WinRM</option><option value="ldap">LDAP</option><option value="ftp">FTP</option><option value="http">HTTP</option><option value="mysql">MySQL</option><option value="mssql">MSSQL</option><option value="postgresql">PostgreSQL</option><option value="vnc">VNC</option><option value="redis">Redis</option><option value="telnet">Telnet</option><option value="kerberos">Kerberos</option></select></div>'
      + '<div class="form-group"><label class="form-label">Target IP</label><input type="text" class="form-control" id="ceIP"></div>'
      + '<div class="form-group"><label class="form-label">OS Tag</label><select class="form-control" id="ceOS"><option value="">--</option><option value="windows">Windows</option><option value="redhat">RedHat</option><option value="ubuntu">Ubuntu</option><option value="linux_other">Linux (Other)</option><option value="macos">macOS</option><option value="network_device">Network Device</option></select></div>'
      + '<div class="form-group" style="grid-column:1/-1"><label class="form-label">Notes</label><textarea class="form-control" id="ceNotes" rows="2" style="font-size:.82rem"></textarea></div>'
      + '<div class="form-group"><label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:.82rem"><input type="checkbox" id="ceSpray"> Spray Eligible</label></div>'
      + '</div><p id="ceError" style="color:var(--danger);font-size:.82rem;margin-top:8px;display:none"></p></div>'
      + '<div class="cred-modal-footer"><button class="btn btn-ghost" id="ceCancel">Cancel</button><button class="btn btn-primary" id="ceSubmit">Save</button></div></div>';

    document.body.appendChild(ov);
    _editModal = ov;
    ov.querySelector('#ceClose').onclick  = function () { ov.classList.remove('active'); };
    ov.querySelector('#ceCancel').onclick  = function () { ov.classList.remove('active'); };
    ov.querySelector('#ceSubmit').onclick  = _submitEdit;
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.classList.remove('active'); });
    return ov;
  }

  function _openEditModal(credId) {
    var cred = null;
    for (var i = 0; i < _creds.length; i++) { if (_creds[i].id === credId) { cred = _creds[i]; break; } }
    if (!cred) return;

    _editCredId = credId;
    var m = _ensureEditModal();

    document.getElementById('ceSecret').value = '';
    document.getElementById('ceDomain').value = cred.domain || '';
    document.getElementById('ceProto').value  = cred.protocol || '';
    document.getElementById('ceIP').value     = cred.target_ip || '';
    document.getElementById('ceOS').value     = cred.os_tag || '';
    document.getElementById('ceNotes').value  = cred.notes || '';
    document.getElementById('ceSpray').checked = !!cred.spray_eligible;
    var err = document.getElementById('ceError'); if (err) err.style.display = 'none';

    m.classList.add('active');
  }

  function _submitEdit() {
    if (!_editCredId) return;
    var body = {};
    var secret = (document.getElementById('ceSecret') || {}).value;
    if (secret) body.secret = secret;
    body.domain          = (document.getElementById('ceDomain') || {}).value || '';
    body.protocol        = (document.getElementById('ceProto')  || {}).value || '';
    body.target_ip       = (document.getElementById('ceIP')     || {}).value || '';
    body.os_tag          = (document.getElementById('ceOS')     || {}).value || '';
    body.notes           = (document.getElementById('ceNotes')  || {}).value || '';
    body.spray_eligible  = !!(document.getElementById('ceSpray') || {}).checked;

    var btn = document.getElementById('ceSubmit'); if (btn) btn.disabled = true;
    _api('/api/credentials/' + PID + '/' + _editCredId, { method:'PUT', body:body })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (btn) btn.disabled = false;
        if (res.ok) {
          _toast('success', 'Credential updated.');
          _editModal.classList.remove('active');
          loadCredentials();
        } else {
          var errEl = document.getElementById('ceError');
          if (errEl) { errEl.textContent = res.data.error || 'Update failed.'; errEl.style.display = ''; }
        }
      })
      .catch(function () { if (btn) btn.disabled = false; });
  }


  /* ══════════════════════════════════════════════════════════════
     DELETE CREDENTIAL
     ══════════════════════════════════════════════════════════════ */

  function _deleteCred(credId, username) {
    if (!confirm('Delete credential for "' + (username||'') + '"? This cannot be undone.')) return;
    _api('/api/credentials/' + PID + '/' + credId, { method:'DELETE' })
      .then(function (r) {
        if (r.ok) { _toast('success', 'Credential deleted.'); loadCredentials(); }
        else r.json().then(function (d) { _toast('error', d.error || 'Delete failed.'); });
      })
      .catch(function () { _toast('error', 'Delete request failed.'); });
  }


  /* ══════════════════════════════════════════════════════════════
     IMPORT CREDENTIALS
     ══════════════════════════════════════════════════════════════ */

  var _importModal = null;

  function _ensureImportModal() {
    if (_importModal) return _importModal;
    var ov = document.createElement('div');
    ov.className = 'cred-modal-overlay'; ov.id = 'credImportModal';
    ov.innerHTML =
      '<div class="cred-modal"><div class="cred-modal-header"><span class="cred-modal-title">Import Credentials</span>'
      + '<button class="cred-modal-close" id="ciClose">&times;</button></div>'
      + '<div class="cred-modal-body">'
      + '<p style="font-size:.85rem;color:var(--text-secondary);margin-bottom:12px">Upload a CSV or JSON file. The vault must be unlocked.</p>'
      + '<p style="font-size:.78rem;color:var(--text-muted);margin-bottom:12px">CSV columns: username, secret (or password / hash), cred_type, domain, os_tag, target_ip, protocol, notes, spray_eligible</p>'
      + '<input type="file" id="ciFile" accept=".csv,.json" style="font-size:.85rem">'
      + '<div id="ciResult" class="cred-import-result" style="display:none"></div>'
      + '</div>'
      + '<div class="cred-modal-footer"><button class="btn btn-ghost" id="ciCancel">Cancel</button><button class="btn btn-primary" id="ciSubmit">Upload &amp; Import</button></div></div>';

    document.body.appendChild(ov);
    _importModal = ov;
    ov.querySelector('#ciClose').onclick  = function () { ov.classList.remove('active'); };
    ov.querySelector('#ciCancel').onclick  = function () { ov.classList.remove('active'); };
    ov.querySelector('#ciSubmit').onclick  = _submitImport;
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.classList.remove('active'); });
    return ov;
  }

  function _openImportModal() {
    var m = _ensureImportModal();
    var f = document.getElementById('ciFile'); if (f) f.value = '';
    var r = document.getElementById('ciResult'); if (r) r.style.display = 'none';
    m.classList.add('active');
  }

  function _submitImport() {
    var fi = document.getElementById('ciFile');
    if (!fi || !fi.files.length) { _toast('error', 'Select a file.'); return; }

    var fd = new FormData();
    fd.append('file', fi.files[0]);

    var btn = document.getElementById('ciSubmit'); if (btn) btn.disabled = true;
    fetch('/api/credentials/' + PID + '/import', { method:'POST', credentials:'same-origin', body:fd })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (btn) btn.disabled = false;
        var result = document.getElementById('ciResult');
        if (result) {
          var h = '<strong>Imported:</strong> ' + (res.data.imported||0);
          if (res.data.errors && res.data.errors.length) {
            h += '<br><strong>Errors (' + res.data.errors.length + '):</strong><ul style="margin:4px 0 0 16px;font-size:.78rem">';
            res.data.errors.slice(0, 10).forEach(function (e) { h += '<li>' + _e(e) + '</li>'; });
            if (res.data.errors.length > 10) h += '<li>... and ' + (res.data.errors.length - 10) + ' more</li>';
            h += '</ul>';
          }
          result.innerHTML = h;
          result.style.display = '';
        }
        if (res.data.imported) { _toast('success', 'Imported ' + res.data.imported + ' credentials.'); loadCredentials(); }
      })
      .catch(function () { if (btn) btn.disabled = false; _toast('error', 'Import failed.'); });
  }


  /* ══════════════════════════════════════════════════════════════
     GENERATE CRED FILE
     ══════════════════════════════════════════════════════════════ */

  function _generateCredFile() {
    _api('/api/credentials/' + PID + '/generate-cred-file', { method:'POST' })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (res.ok) _toast('success', 'Cred file: ' + res.data.file_path + ' (' + res.data.cred_count + ' creds)');
        else _toast('error', res.data.error || 'Failed.');
      })
      .catch(function () { _toast('error', 'Request failed.'); });
  }


  /* ══════════════════════════════════════════════════════════════
     SPRAY CONFIGURATION
     ══════════════════════════════════════════════════════════════ */

  function loadSprayConfig() {
    _api('/api/credentials/' + PID + '/spray-config')
      .then(function (r) { return r.json(); })
      .then(function (cfg) {
        _sprayConfig = cfg;
        var en = document.getElementById('sprayEnabled');     if (en) en.checked = cfg.enabled !== false;
        var cr = document.getElementById('sprayCrossProtocol'); if (cr) cr.checked = cfg.cross_protocol !== false;
        _renderSprayConfig(cfg);
      })
      .catch(function () {});
  }

  function _renderSprayConfig(cfg) {
    var body = document.getElementById('sprayConfigBody');
    if (!body) return;
    var protos = cfg.protocols || {};
    var keys = Object.keys(protos).sort();
    if (!keys.length) { body.innerHTML = '<p class="text-xs text-muted">No spray protocols configured.</p>'; return; }

    var html = '<div class="spray-grid">';
    for (var i = 0; i < keys.length; i++) {
      var p = keys[i], s = protos[p];
      html += '<div class="spray-card"><div class="spray-card-label">' + _e(p) + '</div>'
            + '<div class="spray-field"><span class="spray-field-label">Max Attempts</span><span class="spray-field-val">' + (s.max_attempts||0) + '</span></div>'
            + '<div class="spray-field"><span class="spray-field-label">Delay (s)</span><span class="spray-field-val">' + (s.delay_seconds||0) + '</span></div>'
            + '<div class="spray-field"><span class="spray-field-label">Lockout (s)</span><span class="spray-field-val">' + (s.lockout_window||0) + '</span></div></div>';
    }
    html += '</div>';
    body.innerHTML = html;
  }

  function _saveSprayToggle() {
    if (!_sprayConfig) return;
    var en = document.getElementById('sprayEnabled');
    var cr = document.getElementById('sprayCrossProtocol');
    _api('/api/credentials/' + PID + '/spray-config', { method:'PUT', body:{
      enabled: !!(en && en.checked),
      cross_protocol: !!(cr && cr.checked),
    }})
    .then(function (r) { return r.json(); })
    .then(function (cfg) { _sprayConfig = cfg; _toast('success', 'Spray config updated.'); });
  }


  /* ══════════════════════════════════════════════════════════════
     SOCKET.IO REAL-TIME UPDATES
     ══════════════════════════════════════════════════════════════ */

  function _hookSocket() {
    try {
      if (typeof io === 'undefined') return;
      // project.js creates a local `socket` var. Access via io.managers.
      var managers = io.managers;
      if (!managers) return;
      var keys = Object.keys(managers);
      if (!keys.length) return;
      var mgr = managers[keys[0]];
      if (!mgr || !mgr.nsps || !mgr.nsps['/']) return;
      var sock = mgr.nsps['/'];

      sock.on('new_credential', function () { if (_loaded) loadCredentials(); });
      sock.on('credential_found', function () { if (_loaded) loadCredentials(); });
      sock.on('creds_harvested', function (data) {
        if (_loaded) loadCredentials();
        _toast('info', (data.count||0) + ' credentials harvested from ' + (data.source||'tool'));
      });
      sock.on('credential_verified', function () { if (_loaded) loadCredentials(); });
    } catch (e) { /* non-critical */ }
  }


  /* ══════════════════════════════════════════════════════════════
     INITIALIZATION & EVENT BINDINGS
     ══════════════════════════════════════════════════════════════ */

  /* Exposed for project.js tab-switch hook */
  window._initCredentials = function () {
    if (!_loaded) checkVaultStatus();
  };

  /* Bind vault buttons */
  var _btnCreate  = document.getElementById('btnVaultCreate');
  var _btnUnlock  = document.getElementById('btnVaultUnlock');
  var _btnLock    = document.getElementById('btnLockVault');
  if (_btnCreate) _btnCreate.addEventListener('click', createVault);
  if (_btnUnlock) _btnUnlock.addEventListener('click', unlockVault);
  if (_btnLock)   _btnLock.addEventListener('click', lockVault);

  /* Enter-key on passphrase inputs */
  var _passIn = document.getElementById('vaultPassphraseInput');
  if (_passIn) _passIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') unlockVault(); });
  var _newPassIn = document.getElementById('vaultNewPassphrase');
  if (_newPassIn) _newPassIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') { var c = document.getElementById('vaultConfirmPassphrase'); if (c) c.focus(); } });
  var _confPassIn = document.getElementById('vaultConfirmPassphrase');
  if (_confPassIn) _confPassIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') createVault(); });

  /* Credential toolbar buttons */
  var _btnAdd    = document.getElementById('btnAddCred');
  var _btnImport = document.getElementById('btnImportCreds');
  var _btnGen    = document.getElementById('btnGenerateCredFile');
  if (_btnAdd)    _btnAdd.addEventListener('click', _openAddModal);
  if (_btnImport) _btnImport.addEventListener('click', _openImportModal);
  if (_btnGen)    _btnGen.addEventListener('click', _generateCredFile);

  /* Filters */
  var _srcF = document.getElementById('credSourceFilter');
  var _typF = document.getElementById('credTypeFilter');
  if (_srcF) _srcF.addEventListener('change', loadCredentials);
  if (_typF) _typF.addEventListener('change', loadCredentials);

  /* Spray toggles */
  var _spEn = document.getElementById('sprayEnabled');
  var _spCr = document.getElementById('sprayCrossProtocol');
  if (_spEn) _spEn.addEventListener('change', _saveSprayToggle);
  if (_spCr) _spCr.addEventListener('change', _saveSprayToggle);

  /* Socket.IO */
  _hookSocket();

})();
