/**
 * PWNED Tab — Crucible v2.0
 * Tiered PWNED-system tracking with Impacket execution,
 * deployment management, and real-time Socket.IO updates.
 *
 * Relies on globals from project.js:
 *   window._PROJECT_ID, window.toast(), window.esc()
 *
 * HTML lives in project.html under data-tab="pwned".
 */
(function () {
  'use strict';

  /* ── Inject component CSS ────────────────────────────────── */
  document.head.insertAdjacentHTML('beforeend', '<style>' + [
    /* Tier row borders */
    '.pw-row-PWNED{border-left:3px solid #c0392b}',
    '.pw-row-AUTH{border-left:3px solid #e67e22}',
    '.pw-row-PARTIAL{border-left:3px solid #27ae60}',

    /* Tier badge */
    '.pw-tier{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em}',
    '.pw-tier-PWNED{background:rgba(192,57,43,.15);color:#c0392b}',
    '.pw-tier-AUTH{background:rgba(230,126,34,.15);color:#e67e22}',
    '.pw-tier-PARTIAL{background:rgba(39,174,96,.15);color:#27ae60}',

    /* Access level badge */
    '.pw-access{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em}',
    '.pw-access-SYSTEM{background:rgba(142,68,173,.15);color:#8e44ad}',
    '.pw-access-ROOT{background:rgba(192,57,43,.15);color:#c0392b}',
    '.pw-access-ADMIN{background:rgba(230,126,34,.15);color:#e67e22}',
    '.pw-access-USER{background:rgba(74,144,217,.15);color:#4a90d9}',
    '.pw-access-SERVICE{background:rgba(39,174,96,.15);color:#27ae60}',
    '.pw-access-default{background:var(--bg-secondary);color:var(--text-secondary)}',

    /* Action buttons */
    '.pw-action{background:none;border:none;cursor:pointer;padding:4px;border-radius:var(--radius-sm,4px);color:var(--text-muted);transition:color .15s,background .15s}',
    '.pw-action:hover{background:var(--bg-hover);color:var(--text-primary)}',
    '.pw-action-danger:hover{color:#e74c3c}',
    '.pw-action-warn:hover{color:#e67e22}',

    /* Impacket status badge */
    '.pw-ipk-status{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.72rem;font-weight:600;text-transform:uppercase}',
    '.pw-ipk-completed{background:rgba(39,174,96,.15);color:#27ae60}',
    '.pw-ipk-running{background:rgba(74,144,217,.15);color:#4a90d9}',
    '.pw-ipk-failed{background:rgba(231,76,60,.12);color:#e74c3c}',
    '.pw-ipk-queued{background:rgba(241,196,15,.15);color:#c29d0b}',
    '.pw-ipk-cancelled{background:var(--bg-secondary);color:var(--text-muted)}',

    /* Modal overlay (shared layout with cred modals) */
    '.pw-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:1000;display:none;align-items:center;justify-content:center}',
    '.pw-modal-overlay.active{display:flex}',
    '.pw-modal{background:var(--bg-card);border:1px solid var(--border-mid);border-radius:8px;max-width:600px;width:92%;max-height:85vh;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,.3)}',
    '.pw-modal-header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border-mid)}',
    '.pw-modal-title{font-size:1rem;font-weight:700;color:var(--text-primary)}',
    '.pw-modal-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1.2rem;line-height:1}',
    '.pw-modal-body{padding:16px 20px}',
    '.pw-modal-footer{padding:12px 20px;border-top:1px solid var(--border-mid);display:flex;justify-content:flex-end;gap:8px}',

    /* Detail row pairs */
    '.pw-detail-row{display:flex;justify-content:space-between;padding:4px 0;font-size:.82rem;border-bottom:1px solid var(--border-subtle,rgba(128,128,128,.1))}',
    '.pw-detail-label{color:var(--text-muted);min-width:120px}',
    '.pw-detail-val{color:var(--text-primary);text-align:right;word-break:break-word;font-family:monospace;font-size:.82rem}',

    /* Deploy / Impacket confirm section */
    '.pw-confirm-box{background:rgba(231,76,60,.06);border:1px solid rgba(231,76,60,.2);border-radius:4px;padding:12px;margin-top:8px;font-size:.85rem;color:var(--text-primary)}',
    '.pw-confirm-box p{margin-bottom:6px}',

    /* Note textarea */
    '.pw-note-area{width:100%;min-height:60px;resize:vertical;font-size:.85rem;font-family:inherit;padding:8px;border:1px solid var(--border-mid);border-radius:4px;background:var(--bg-surface);color:var(--text-primary)}',

    /* Expand row detail */
    '.pw-expand-row td{padding:8px 16px !important;background:var(--bg-surface)}',
    '.pw-expand-inner{display:grid;grid-template-columns:1fr 1fr;gap:8px 20px;font-size:.82rem}',

    /* Filter button active state */
    '.pwned-filter.active{background:var(--accent-primary);color:#fff}',
  ].join('\n') + '</style>');


  /* ── Globals ──────────────────────────────────────────────── */
  var PID = (window._PROJECT_ID != null)
    ? window._PROJECT_ID
    : JSON.parse(document.getElementById('projectConfig').textContent).pid;

  var _systems = [];
  var _loaded = false;
  var _currentTier = '';
  var _expandedId = null;

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

  /* ── Access level sort weight ────────────────────────────── */
  var _ACCESS_WEIGHT = { SYSTEM:0, ROOT:1, ADMIN:2, USER:3, SERVICE:4 };
  function _accessWeight(lvl) { return _ACCESS_WEIGHT[(lvl||'').toUpperCase()] !== undefined ? _ACCESS_WEIGHT[(lvl||'').toUpperCase()] : 99; }

  /* ── Access level badge ──────────────────────────────────── */
  function _accessBadge(lvl) {
    var up = (lvl || 'UNKNOWN').toUpperCase();
    var cls = 'pw-access-' + (['SYSTEM','ROOT','ADMIN','USER','SERVICE'].indexOf(up) >= 0 ? up : 'default');
    return '<span class="pw-access ' + cls + '">' + _e(up) + '</span>';
  }

  /* ── Tier badge ──────────────────────────────────────────── */
  function _tierBadge(tier) {
    var t = (tier || '').toUpperCase();
    return '<span class="pw-tier pw-tier-' + t + '">' + _e(t || '--') + '</span>';
  }

  /* ── Impacket status badge ───────────────────────────────── */
  function _ipkStatusBadge(status) {
    var s = (status || '').toLowerCase();
    var cls = 'pw-ipk-' + (['completed','running','failed','queued','cancelled'].indexOf(s)>=0 ? s : 'queued');
    return '<span class="pw-ipk-status ' + cls + '">' + _e(status || '--') + '</span>';
  }


  /* ══════════════════════════════════════════════════════════════
     STATS
     ══════════════════════════════════════════════════════════════ */

  function _loadStats() {
    var excl = (document.getElementById('pwnedExcludeUser') || {}).checked;
    _api('/api/pwned/' + PID + '/stats?exclude_user_provided=' + (excl !== false))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var elP = document.getElementById('pwnedCountPWNED');
        var elA = document.getElementById('pwnedCountAUTH');
        var elR = document.getElementById('pwnedCountPARTIAL');
        if (elP) elP.textContent = d.PWNED || 0;
        if (elA) elA.textContent = d.AUTH || 0;
        if (elR) elR.textContent = d.PARTIAL || 0;

        var total = (d.PWNED||0) + (d.AUTH||0) + (d.PARTIAL||0);
        _updatePill(total);
      })
      .catch(function () {});
  }

  function _updatePill(count) {
    var pill = document.getElementById('pwnedPill');
    if (pill) pill.textContent = count || '';
  }


  /* ══════════════════════════════════════════════════════════════
     PWNED LISTING
     ══════════════════════════════════════════════════════════════ */

  function loadPwned() {
    var excl = (document.getElementById('pwnedExcludeUser') || {}).checked;
    var params = ['exclude_user_provided=' + (excl !== false)];
    if (_currentTier) params.push('tier=' + encodeURIComponent(_currentTier));

    _api('/api/pwned/' + PID + '?' + params.join('&'))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        _systems = d.pwned_systems || [];
        /* Sort by access level weight (SYSTEM > ROOT > ADMIN > USER) */
        _systems.sort(function (a, b) { return _accessWeight(a.access_level) - _accessWeight(b.access_level); });
        _loaded = true;
        _renderTable();
      })
      .catch(function () { _systems = []; _renderTable(); });

    _loadStats();
  }

  function _renderTable() {
    var tbody = document.getElementById('pwnedBody');
    var empty = document.getElementById('pwnedEmpty');
    if (!tbody) return;

    if (!_systems.length) {
      tbody.innerHTML = '';
      if (empty) empty.style.display = '';
      return;
    }
    if (empty) empty.style.display = 'none';

    var html = '';
    for (var i = 0; i < _systems.length; i++) {
      var s = _systems[i];
      var expanded = _expandedId === s.id;

      html += '<tr class="pw-row-' + (s.tier||'').toUpperCase() + '" style="cursor:pointer" data-pw-toggle="' + s.id + '">';

      /* Expand chevron */
      html += '<td><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="transition:transform .15s;transform:rotate(' + (expanded?'90':'0') + 'deg)"><polyline points="9 18 15 12 9 6"/></svg></td>';

      /* IP */
      html += '<td style="font-family:monospace;font-size:.82rem;font-weight:600">' + _e(s.ip) + '</td>';

      /* Hostname */
      html += '<td>' + _e(s.hostname || '--') + '</td>';

      /* OS */
      html += '<td style="font-size:.82rem">' + _e(s.os || '--') + '</td>';

      /* Tier */
      html += '<td>' + _tierBadge(s.tier) + '</td>';

      /* Protocol */
      html += '<td>' + _e(s.protocol || '--') + '</td>';

      /* Access Level */
      html += '<td>' + _accessBadge(s.access_level) + '</td>';

      /* Credential */
      html += '<td style="font-size:.82rem">' + _e(s.credential_username || '--') + (s.credential_domain ? '\\' + _e(s.credential_domain) : '') + '</td>';

      /* Timestamp */
      html += '<td style="font-size:.78rem;color:var(--text-muted)">' + _fmtIso(s.created || s.timestamp) + '</td>';

      /* Actions */
      html += '<td>';
      html += '<button class="pw-action" title="Add note" data-pw-note="' + s.id + '">'
            + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button> ';
      if (s.tier === 'PWNED') {
        html += '<button class="pw-action pw-action-warn" title="Deploy tool" data-pw-deploy="' + s.id + '">'
              + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg></button> ';
        html += '<button class="pw-action pw-action-danger" title="Impacket" data-pw-impacket="' + s.id + '">'
              + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></button>';
      }
      html += '</td>';

      html += '</tr>';

      /* Expanded detail row */
      if (expanded) {
        html += '<tr class="pw-expand-row"><td colspan="10">';
        html += '<div class="pw-expand-inner">';
        html += '<div class="pw-detail-row"><span class="pw-detail-label">ID</span><span class="pw-detail-val">' + s.id + '</span></div>';
        html += '<div class="pw-detail-row"><span class="pw-detail-label">Method</span><span class="pw-detail-val">' + _e(s.method||'--') + '</span></div>';
        html += '<div class="pw-detail-row"><span class="pw-detail-label">Tool</span><span class="pw-detail-val">' + _e(s.tool||'--') + '</span></div>';
        html += '<div class="pw-detail-row"><span class="pw-detail-label">Port</span><span class="pw-detail-val">' + (s.port||'--') + '</span></div>';
        html += '<div class="pw-detail-row"><span class="pw-detail-label">Source</span><span class="pw-detail-val">' + _e(s.source||'--') + '</span></div>';
        html += '<div class="pw-detail-row"><span class="pw-detail-label">Credential ID</span><span class="pw-detail-val">' + (s.credential_id||'--') + '</span></div>';
        if (s.notes) {
          html += '<div class="pw-detail-row" style="grid-column:1/-1"><span class="pw-detail-label">Notes</span><span class="pw-detail-val" style="white-space:pre-wrap">' + _e(s.notes) + '</span></div>';
        }
        html += '</div></td></tr>';
      }
    }
    tbody.innerHTML = html;
  }


  /* ── Table event delegation ──────────────────────────────── */
  (function () {
    var wrap = document.getElementById('pwnedTable');
    if (!wrap) return;
    wrap.addEventListener('click', function (ev) {
      var btn;

      /* Toggle expand */
      var toggle = ev.target.closest('[data-pw-toggle]');
      if (toggle && !ev.target.closest('button')) {
        var id = parseInt(toggle.getAttribute('data-pw-toggle'), 10);
        _expandedId = (_expandedId === id) ? null : id;
        _renderTable();
        return;
      }

      if ((btn = ev.target.closest('[data-pw-note]')))     { _openNoteModal(parseInt(btn.getAttribute('data-pw-note'), 10)); ev.stopPropagation(); return; }
      if ((btn = ev.target.closest('[data-pw-deploy]')))    { _openDeployModal(parseInt(btn.getAttribute('data-pw-deploy'), 10)); ev.stopPropagation(); return; }
      if ((btn = ev.target.closest('[data-pw-impacket]')))  { _openImpacketModal(parseInt(btn.getAttribute('data-pw-impacket'), 10)); ev.stopPropagation(); return; }
    });
  })();


  /* ══════════════════════════════════════════════════════════════
     NOTE MODAL
     ══════════════════════════════════════════════════════════════ */

  var _noteModal = null;
  var _notePwnedId = null;

  function _ensureNoteModal() {
    if (_noteModal) return _noteModal;
    var ov = document.createElement('div');
    ov.className = 'pw-modal-overlay'; ov.id = 'pwNoteModal';
    ov.innerHTML =
      '<div class="pw-modal"><div class="pw-modal-header"><span class="pw-modal-title">Add Note</span>'
      + '<button class="pw-modal-close" id="pnClose">&times;</button></div>'
      + '<div class="pw-modal-body">'
      + '<label class="form-label" style="margin-bottom:8px;display:block">Note</label>'
      + '<textarea class="pw-note-area" id="pnText" placeholder="Enter a note about this system..."></textarea>'
      + '<p id="pnError" style="color:var(--danger);font-size:.82rem;margin-top:8px;display:none"></p>'
      + '</div>'
      + '<div class="pw-modal-footer"><button class="btn btn-ghost" id="pnCancel">Cancel</button><button class="btn btn-primary" id="pnSubmit">Save Note</button></div></div>';
    document.body.appendChild(ov);
    _noteModal = ov;
    ov.querySelector('#pnClose').onclick  = function () { ov.classList.remove('active'); };
    ov.querySelector('#pnCancel').onclick  = function () { ov.classList.remove('active'); };
    ov.querySelector('#pnSubmit').onclick  = _submitNote;
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.classList.remove('active'); });
    return ov;
  }

  function _openNoteModal(pwnedId) {
    _notePwnedId = pwnedId;
    var m = _ensureNoteModal();
    var txt = document.getElementById('pnText'); if (txt) txt.value = '';
    var err = document.getElementById('pnError'); if (err) err.style.display = 'none';
    m.classList.add('active');
    if (txt) txt.focus();
  }

  function _submitNote() {
    if (!_notePwnedId) return;
    var txt = (document.getElementById('pnText') || {}).value || '';
    var err = document.getElementById('pnError');
    if (!txt.trim()) { if (err) { err.textContent = 'Note cannot be empty.'; err.style.display = ''; } return; }
    if (err) err.style.display = 'none';

    var btn = document.getElementById('pnSubmit'); if (btn) btn.disabled = true;
    _api('/api/pwned/' + PID + '/' + _notePwnedId + '/note', { method:'POST', body:{ note: txt.trim() } })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (btn) btn.disabled = false;
        if (res.ok) {
          _toast('success', 'Note added.');
          _noteModal.classList.remove('active');
          loadPwned();
        } else {
          if (err) { err.textContent = res.data.error || 'Failed.'; err.style.display = ''; }
        }
      })
      .catch(function () { if (btn) btn.disabled = false; });
  }


  /* ══════════════════════════════════════════════════════════════
     DEPLOY TOOL MODAL
     ══════════════════════════════════════════════════════════════ */

  var _deployModal = null;
  var _deployPwnedId = null;

  function _ensureDeployModal() {
    if (_deployModal) return _deployModal;
    var ov = document.createElement('div');
    ov.className = 'pw-modal-overlay'; ov.id = 'pwDeployModal';
    ov.innerHTML =
      '<div class="pw-modal"><div class="pw-modal-header"><span class="pw-modal-title">Deploy Tool</span>'
      + '<button class="pw-modal-close" id="pdClose">&times;</button></div>'
      + '<div class="pw-modal-body">'
      + '<p style="font-size:.85rem;color:var(--text-secondary);margin-bottom:12px">Choose a tool to deploy against this PWNED system.</p>'
      + '<div class="form-group"><label class="form-label">Tool</label>'
      + '<select class="form-control" id="pdTool"><option value="dredge">Dredge (Credential Harvester)</option><option value="vault">Vault (Persistence Agent)</option></select></div>'
      + '<p id="pdError" style="color:var(--danger);font-size:.82rem;margin-top:8px;display:none"></p>'
      + '</div>'
      + '<div class="pw-modal-footer"><button class="btn btn-ghost" id="pdCancel">Cancel</button><button class="btn btn-primary" id="pdSubmit">Queue Deploy</button></div></div>';
    document.body.appendChild(ov);
    _deployModal = ov;
    ov.querySelector('#pdClose').onclick  = function () { ov.classList.remove('active'); };
    ov.querySelector('#pdCancel').onclick  = function () { ov.classList.remove('active'); };
    ov.querySelector('#pdSubmit').onclick  = _submitDeploy;
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.classList.remove('active'); });
    return ov;
  }

  function _openDeployModal(pwnedId) {
    _deployPwnedId = pwnedId;
    var m = _ensureDeployModal();
    var tool = document.getElementById('pdTool'); if (tool) tool.value = 'dredge';
    var err = document.getElementById('pdError'); if (err) err.style.display = 'none';
    m.classList.add('active');
  }

  function _submitDeploy() {
    if (!_deployPwnedId) return;
    var tool = (document.getElementById('pdTool') || {}).value || 'dredge';
    var err  = document.getElementById('pdError');
    if (err) err.style.display = 'none';

    var btn = document.getElementById('pdSubmit'); if (btn) btn.disabled = true;
    _api('/api/pwned/' + PID + '/' + _deployPwnedId + '/deploy', { method:'POST', body:{ tool:tool } })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (btn) btn.disabled = false;
        if (res.ok || res.data.deploy_id) {
          _toast('success', tool.charAt(0).toUpperCase() + tool.slice(1) + ' deployment queued.');
          _deployModal.classList.remove('active');
        } else {
          if (err) { err.textContent = res.data.error || 'Failed.'; err.style.display = ''; }
        }
      })
      .catch(function () { if (btn) btn.disabled = false; });
  }


  /* ══════════════════════════════════════════════════════════════
     IMPACKET EXECUTION MODAL
     ══════════════════════════════════════════════════════════════ */

  var _ipkModal = null;
  var _ipkPwnedId = null;

  function _ensureImpacketModal() {
    if (_ipkModal) return _ipkModal;
    var ov = document.createElement('div');
    ov.className = 'pw-modal-overlay'; ov.id = 'pwImpacketModal';
    ov.innerHTML =
      '<div class="pw-modal"><div class="pw-modal-header"><span class="pw-modal-title">Impacket Execution</span>'
      + '<button class="pw-modal-close" id="piClose">&times;</button></div>'
      + '<div class="pw-modal-body">'
      + '<div class="form-group"><label class="form-label">Impacket Tool</label>'
      + '<select class="form-control" id="piTool">'
      + '<option value="secretsdump">secretsdump - Extract Hashes (SAM/LSA/NTDS.dit)</option>'
      + '<option value="wmiexec">wmiexec - WMI Shell</option>'
      + '<option value="psexec">psexec - PsExec Shell (SYSTEM-level)</option>'
      + '<option value="smbexec">smbexec - SMB Shell (stealthier)</option>'
      + '</select></div>'
      + '<div class="form-group"><label class="form-label">Command (optional, for shell tools)</label>'
      + '<input type="text" class="form-control" id="piCmd" placeholder="e.g. whoami /all"></div>'
      + '<div class="pw-confirm-box" id="piConfirmBox" style="display:none">'
      + '<p id="piConfirmMsg" style="font-weight:600"></p>'
      + '<p style="font-size:.78rem;color:var(--text-muted)">This will execute an Impacket tool on the target. This action is logged and cannot be undone.</p>'
      + '</div>'
      + '<p id="piError" style="color:var(--danger);font-size:.82rem;margin-top:8px;display:none"></p>'
      + '</div>'
      + '<div class="pw-modal-footer"><button class="btn btn-ghost" id="piCancel">Cancel</button>'
      + '<button class="btn btn-primary" id="piPreview" style="background:var(--warning);border-color:var(--warning)">Preview</button>'
      + '<button class="btn btn-primary" id="piConfirm" style="display:none;background:var(--danger);border-color:var(--danger)">Confirm Execute</button></div></div>';
    document.body.appendChild(ov);
    _ipkModal = ov;
    ov.querySelector('#piClose').onclick   = function () { ov.classList.remove('active'); };
    ov.querySelector('#piCancel').onclick   = function () { ov.classList.remove('active'); };
    ov.querySelector('#piPreview').onclick  = _previewImpacket;
    ov.querySelector('#piConfirm').onclick  = _confirmImpacket;
    ov.addEventListener('click', function (e) { if (e.target === ov) ov.classList.remove('active'); });
    return ov;
  }

  function _openImpacketModal(pwnedId) {
    _ipkPwnedId = pwnedId;
    var m = _ensureImpacketModal();
    document.getElementById('piTool').value = 'secretsdump';
    document.getElementById('piCmd').value  = '';
    var box = document.getElementById('piConfirmBox'); if (box) box.style.display = 'none';
    var preview = document.getElementById('piPreview'); if (preview) preview.style.display = '';
    var confirm = document.getElementById('piConfirm'); if (confirm) confirm.style.display = 'none';
    var err = document.getElementById('piError'); if (err) err.style.display = 'none';
    m.classList.add('active');
  }

  function _previewImpacket() {
    if (!_ipkPwnedId) return;
    var tool = (document.getElementById('piTool') || {}).value || 'secretsdump';
    var err  = document.getElementById('piError');
    if (err) err.style.display = 'none';

    var btn = document.getElementById('piPreview'); if (btn) btn.disabled = true;
    _api('/api/pwned/' + PID + '/' + _ipkPwnedId + '/impacket', { method:'POST', body:{ tool:tool, confirmed:false } })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (btn) btn.disabled = false;
        if (res.data.status === 'awaiting_confirmation') {
          var msg = document.getElementById('piConfirmMsg');
          if (msg) msg.textContent = res.data.label + ' on ' + res.data.target + ' — ' + res.data.description;
          var box = document.getElementById('piConfirmBox'); if (box) box.style.display = '';
          if (btn) btn.style.display = 'none';
          var confirm = document.getElementById('piConfirm'); if (confirm) confirm.style.display = '';
        } else if (res.data.error) {
          if (err) { err.textContent = res.data.error; err.style.display = ''; }
        }
      })
      .catch(function () { if (btn) btn.disabled = false; });
  }

  function _confirmImpacket() {
    if (!_ipkPwnedId) return;
    var tool = (document.getElementById('piTool') || {}).value || 'secretsdump';
    var cmd  = (document.getElementById('piCmd') || {}).value || '';
    var err  = document.getElementById('piError');
    if (err) err.style.display = 'none';

    var btn = document.getElementById('piConfirm'); if (btn) btn.disabled = true;
    var body = { tool:tool, confirmed:true };
    if (cmd.trim()) body.command = cmd.trim();

    _api('/api/pwned/' + PID + '/' + _ipkPwnedId + '/impacket', { method:'POST', body:body })
      .then(function (r) { return r.json().then(function (d) { return { ok:r.ok, data:d }; }); })
      .then(function (res) {
        if (btn) btn.disabled = false;
        if (res.ok && res.data.deploy_id) {
          _toast('success', 'Impacket ' + tool + ' execution started (deploy #' + res.data.deploy_id + ').');
          _ipkModal.classList.remove('active');
          _loadImpacketHistory();
        } else {
          if (err) { err.textContent = res.data.error || 'Execution failed.'; err.style.display = ''; }
        }
      })
      .catch(function () { if (btn) btn.disabled = false; });
  }


  /* ══════════════════════════════════════════════════════════════
     IMPACKET HISTORY
     ══════════════════════════════════════════════════════════════ */

  function _loadImpacketHistory() {
    _api('/api/pwned/' + PID + '/impacket/history')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var history = d.history || [];
        var tbody = document.getElementById('impacketHistoryBody');
        var empty = document.getElementById('impacketEmpty');
        if (!tbody) return;

        if (!history.length) {
          tbody.innerHTML = '';
          if (empty) empty.style.display = '';
          return;
        }
        if (empty) empty.style.display = 'none';

        var html = '';
        for (var i = 0; i < history.length; i++) {
          var h = history[i];
          html += '<tr>';
          html += '<td><strong>' + _e(h.tool) + '</strong></td>';
          html += '<td style="font-family:monospace;font-size:.82rem">' + _e(h.ip) + (h.hostname ? ' (' + _e(h.hostname) + ')' : '') + '</td>';
          html += '<td>' + _ipkStatusBadge(h.status) + '</td>';
          html += '<td style="font-size:.78rem">' + _fmtIso(h.started) + '</td>';
          html += '<td style="font-size:.78rem">' + _fmtIso(h.completed) + '</td>';
          html += '<td style="font-size:.78rem;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + _e(h.notes||'--') + '</td>';
          html += '</tr>';
        }
        tbody.innerHTML = html;
      })
      .catch(function () {});
  }


  /* ══════════════════════════════════════════════════════════════
     TIER FILTER BUTTONS
     ══════════════════════════════════════════════════════════════ */

  document.querySelectorAll('.pwned-filter').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.pwned-filter').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      _currentTier = btn.getAttribute('data-tier') || '';
      loadPwned();
    });
  });

  /* Exclude user-provided toggle */
  var _exclToggle = document.getElementById('pwnedExcludeUser');
  if (_exclToggle) {
    _exclToggle.addEventListener('change', function () { loadPwned(); });
  }


  /* ══════════════════════════════════════════════════════════════
     SOCKET.IO REAL-TIME UPDATES
     ══════════════════════════════════════════════════════════════ */

  function _hookSocket() {
    try {
      if (typeof io === 'undefined') return;
      var managers = io.managers;
      if (!managers) return;
      var keys = Object.keys(managers);
      if (!keys.length) return;
      var mgr = managers[keys[0]];
      if (!mgr || !mgr.nsps || !mgr.nsps['/']) return;
      var sock = mgr.nsps['/'];

      sock.on('host_pwned', function () { if (_loaded) loadPwned(); });
      sock.on('system_pwned', function () { if (_loaded) loadPwned(); });
      sock.on('impacket_complete', function (data) {
        if (_loaded) {
          loadPwned();
          _loadImpacketHistory();
        }
        var msg = 'Impacket ' + (data.tool||'') + ' ' + (data.status||'completed');
        if (data.status === 'completed') _toast('success', msg);
        else if (data.status === 'failed') _toast('error', msg);
        else _toast('info', msg);
      });
      sock.on('deployment_queued', function () { if (_loaded) loadPwned(); });
      sock.on('creds_harvested', function (data) {
        if (_loaded) _loadImpacketHistory();
        _toast('info', (data.count||0) + ' credentials harvested from ' + (data.source||'tool'));
      });
    } catch (e) { /* non-critical */ }
  }


  /* ══════════════════════════════════════════════════════════════
     INITIALIZATION
     ══════════════════════════════════════════════════════════════ */

  window._initPwned = function () {
    if (!_loaded) {
      loadPwned();
      _loadImpacketHistory();
    }
  };

  _hookSocket();

})();
