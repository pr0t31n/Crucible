/* Burp XML Import Wizard — 3-step guided import with title normalization.
 *
 * Step 1: Upload & Scope — user picks file and selects scope
 * Step 2: Target Selection — filter hosts, toggle in/out of scope
 * Step 3: Finding Selection — review normalized findings, toggle each
 *
 * Depends on: project.js globals (projectId, loadFindings), socket
 */

(function () {
  'use strict';

  var _cfg = JSON.parse(document.getElementById('projectConfig').textContent);
  var projectId = _cfg.pid;

  var _bwState = {
    cacheKey: '',
    filename: '',
    totalIssues: 0,
    hosts: [],
    findings: [],
    applicableScopes: [],
    selectedScope: '',
    selectedHosts: {},
    selectedKeys: {},
    step: 0,
  };

  var _RISK_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  var _RISK_CLS = {
    CRITICAL: 'risk-critical', HIGH: 'risk-high',
    MEDIUM: 'risk-medium', LOW: 'risk-low', INFO: 'risk-info',
  };

  // ── Modal skeleton ─────────────────────────────────────────────────

  function _ensureModal() {
    if (document.getElementById('burpWizardModal')) return;
    var m = document.createElement('div');
    m.id = 'burpWizardModal';
    m.className = 'modal-overlay';
    m.style.display = 'none';
    m.innerHTML =
      '<div class="modal-dialog" style="max-width:900px;width:95vw;max-height:85vh;display:flex;flex-direction:column">' +
        '<div class="modal-header" style="flex-shrink:0">' +
          '<h3 id="bwTitle" style="margin:0;font-size:1rem">Burp Import Wizard</h3>' +
          '<button type="button" class="modal-close" onclick="window._burpWizardClose()">&times;</button>' +
        '</div>' +
        '<div id="bwBody" class="modal-body" style="flex:1;overflow-y:auto;padding:16px"></div>' +
        '<div id="bwFooter" class="modal-footer" style="flex-shrink:0;display:flex;justify-content:space-between;padding:12px 16px"></div>' +
      '</div>';
    document.body.appendChild(m);
    m.addEventListener('click', function (e) {
      if (e.target === m) window._burpWizardClose();
    });
  }

  function _show() {
    var m = document.getElementById('burpWizardModal');
    if (m) m.style.display = 'flex';
  }

  window._burpWizardClose = function () {
    var m = document.getElementById('burpWizardModal');
    if (m) m.style.display = 'none';
    _bwState.step = 0;
  };

  // ── Step 1: Upload & Scope ─────────────────────────────────────────

  function _renderStep1() {
    _bwState.step = 1;
    var body = document.getElementById('bwBody');
    var footer = document.getElementById('bwFooter');
    document.getElementById('bwTitle').textContent = 'Burp Import — Step 1: Upload XML';

    var html =
      '<div style="margin-bottom:16px">' +
        '<label class="form-label">Burp Suite XML Export File</label>' +
        '<div id="bwDropZone" class="ev-drop-zone" style="text-align:center;padding:32px">' +
          '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:8px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>' +
          '<div style="font-size:0.85rem;opacity:0.7">Drag & drop Burp XML file here, or click to browse</div>' +
          '<div id="bwFileName" style="font-size:0.8rem;margin-top:8px;color:var(--clr-high,#f59e0b);display:none"></div>' +
          '<input type="file" id="bwFileInput" hidden accept=".xml">' +
        '</div>' +
      '</div>' +
      '<div id="bwScopeSection" style="display:none">' +
        '<label class="form-label">Import Scope</label>' +
        '<select id="bwScopeSelect" class="form-control" style="max-width:300px">' +
          '<option value="">Select scope...</option>' +
        '</select>' +
      '</div>' +
      '<div id="bwPreviewStatus" style="margin-top:16px;font-size:0.8rem;opacity:0.6"></div>' +
      '<div id="bwError" style="margin-top:12px;color:var(--clr-critical,#ef4444);display:none;font-size:0.85rem"></div>';

    body.innerHTML = html;
    footer.innerHTML =
      '<div></div>' +
      '<button type="button" class="btn btn-primary btn-sm" id="bwNext1" disabled>Next: Select Targets</button>';

    var dropZone = document.getElementById('bwDropZone');
    var fileInput = document.getElementById('bwFileInput');

    dropZone.addEventListener('click', function () { fileInput.click(); });
    dropZone.addEventListener('dragover', function (e) {
      e.preventDefault();
      dropZone.classList.add('ev-drop-active');
    });
    dropZone.addEventListener('dragleave', function () {
      dropZone.classList.remove('ev-drop-active');
    });
    dropZone.addEventListener('drop', function (e) {
      e.preventDefault();
      dropZone.classList.remove('ev-drop-active');
      if (e.dataTransfer.files.length) _handleFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', function () {
      if (fileInput.files.length) _handleFile(fileInput.files[0]);
    });

    document.getElementById('bwNext1').addEventListener('click', function () {
      _renderStep2();
    });
  }

  function _handleFile(file) {
    if (!file.name.toLowerCase().endsWith('.xml')) {
      _showError('Please select a .xml file exported from Burp Suite.');
      return;
    }
    var nameEl = document.getElementById('bwFileName');
    nameEl.textContent = file.name;
    nameEl.style.display = '';

    var status = document.getElementById('bwPreviewStatus');
    status.textContent = 'Parsing Burp XML...';
    _hideError();

    var fd = new FormData();
    fd.append('file', file);

    fetch('/api/import/burp/' + projectId + '/preview', {
      method: 'POST',
      body: fd,
    })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
      .then(function (res) {
        if (!res.ok) {
          _showError(res.data.error || 'Failed to parse Burp XML');
          status.textContent = '';
          return;
        }
        var d = res.data;
        _bwState.cacheKey = d.cache_key;
        _bwState.filename = d.filename;
        _bwState.totalIssues = d.total_issues;
        _bwState.hosts = d.hosts;
        _bwState.findings = d.findings;
        _bwState.applicableScopes = d.applicable_scopes || [];

        _bwState.selectedHosts = {};
        for (var i = 0; i < d.hosts.length; i++) {
          if (d.hosts[i].in_scope) {
            _bwState.selectedHosts[d.hosts[i].host] = true;
          }
        }

        _bwState.selectedKeys = {};
        for (var j = 0; j < d.findings.length; j++) {
          _bwState.selectedKeys[d.findings[j].dedup_key] = true;
        }

        status.textContent = d.total_issues + ' issues parsed, ' +
          d.hosts.length + ' hosts, ' +
          d.findings.length + ' unique findings (after dedup).';

        var scopeSec = document.getElementById('bwScopeSection');
        var scopeSel = document.getElementById('bwScopeSelect');
        if (_bwState.applicableScopes.length) {
          scopeSec.style.display = '';
          scopeSel.innerHTML = '<option value="">Select scope...</option>';
          for (var s = 0; s < _bwState.applicableScopes.length; s++) {
            var o = document.createElement('option');
            o.value = _bwState.applicableScopes[s];
            o.textContent = _bwState.applicableScopes[s];
            scopeSel.appendChild(o);
          }
          scopeSel.addEventListener('change', function () {
            _bwState.selectedScope = scopeSel.value;
          });
          if (_bwState.applicableScopes.length === 1) {
            scopeSel.value = _bwState.applicableScopes[0];
            _bwState.selectedScope = _bwState.applicableScopes[0];
          }
        }

        document.getElementById('bwNext1').disabled = false;
      })
      .catch(function (err) {
        _showError('Network error: ' + err.message);
        status.textContent = '';
      });
  }

  // ── Step 2: Target Selection ───────────────────────────────────────

  function _renderStep2() {
    _bwState.step = 2;
    var body = document.getElementById('bwBody');
    var footer = document.getElementById('bwFooter');
    document.getElementById('bwTitle').textContent =
      'Burp Import — Step 2: Select Targets (' + _bwState.hosts.length + ' hosts)';

    var selectedCount = Object.keys(_bwState.selectedHosts).length;

    var html =
      '<div style="display:flex;gap:8px;margin-bottom:12px;align-items:center">' +
        '<button type="button" class="btn btn-xs btn-ghost" id="bwSelectAllHosts">Select All</button>' +
        '<button type="button" class="btn btn-xs btn-ghost" id="bwDeselectAllHosts">Deselect All</button>' +
        '<button type="button" class="btn btn-xs btn-ghost" id="bwSelectInScope">In-Scope Only</button>' +
        '<span style="margin-left:auto;font-size:0.8rem;opacity:0.6" id="bwHostCount">' +
          selectedCount + ' / ' + _bwState.hosts.length + ' selected</span>' +
      '</div>' +
      '<div class="table-responsive" style="max-height:55vh;overflow-y:auto">' +
        '<table class="data-table">' +
          '<thead><tr>' +
            '<th style="width:32px"></th>' +
            '<th>Host</th>' +
            '<th>IP</th>' +
            '<th style="width:80px">Findings</th>' +
            '<th style="width:80px">Scope</th>' +
          '</tr></thead>' +
          '<tbody id="bwHostBody"></tbody>' +
        '</table>' +
      '</div>';

    body.innerHTML = html;
    footer.innerHTML =
      '<button type="button" class="btn btn-ghost btn-sm" id="bwBack2">Back</button>' +
      '<button type="button" class="btn btn-primary btn-sm" id="bwNext2">Next: Select Findings</button>';

    _renderHostRows();

    document.getElementById('bwSelectAllHosts').addEventListener('click', function () {
      for (var i = 0; i < _bwState.hosts.length; i++)
        _bwState.selectedHosts[_bwState.hosts[i].host] = true;
      _renderHostRows();
    });
    document.getElementById('bwDeselectAllHosts').addEventListener('click', function () {
      _bwState.selectedHosts = {};
      _renderHostRows();
    });
    document.getElementById('bwSelectInScope').addEventListener('click', function () {
      _bwState.selectedHosts = {};
      for (var i = 0; i < _bwState.hosts.length; i++)
        if (_bwState.hosts[i].in_scope)
          _bwState.selectedHosts[_bwState.hosts[i].host] = true;
      _renderHostRows();
    });
    document.getElementById('bwBack2').addEventListener('click', function () { _renderStep1(); });
    document.getElementById('bwNext2').addEventListener('click', function () { _renderStep3(); });
  }

  function _renderHostRows() {
    var tbody = document.getElementById('bwHostBody');
    if (!tbody) return;
    var rows = '';
    for (var i = 0; i < _bwState.hosts.length; i++) {
      var h = _bwState.hosts[i];
      var checked = _bwState.selectedHosts[h.host] ? ' checked' : '';
      var scopeBadge = h.in_scope
        ? '<span class="badge badge-success" style="font-size:0.65rem">In Scope</span>'
        : '<span class="badge badge-ghost" style="font-size:0.65rem">Out</span>';
      rows +=
        '<tr>' +
          '<td><input type="checkbox" class="bw-host-chk" data-host="' + _esc(h.host) + '"' + checked + '></td>' +
          '<td style="font-size:0.8rem;word-break:break-all">' + _esc(h.host) + '</td>' +
          '<td style="font-size:0.8rem">' + _esc(h.ip || '') + '</td>' +
          '<td style="text-align:center">' + h.count + '</td>' +
          '<td>' + scopeBadge + '</td>' +
        '</tr>';
    }
    tbody.innerHTML = rows;

    var chks = tbody.querySelectorAll('.bw-host-chk');
    for (var j = 0; j < chks.length; j++) {
      chks[j].addEventListener('change', function () {
        if (this.checked) _bwState.selectedHosts[this.dataset.host] = true;
        else delete _bwState.selectedHosts[this.dataset.host];
        _updateHostCount();
      });
    }
    _updateHostCount();
  }

  function _updateHostCount() {
    var el = document.getElementById('bwHostCount');
    if (el) el.textContent = Object.keys(_bwState.selectedHosts).length +
      ' / ' + _bwState.hosts.length + ' selected';
  }

  // ── Step 3: Finding Selection ──────────────────────────────────────

  function _renderStep3() {
    _bwState.step = 3;
    var body = document.getElementById('bwBody');
    var footer = document.getElementById('bwFooter');
    document.getElementById('bwTitle').textContent =
      'Burp Import — Step 3: Select Findings (' + _bwState.findings.length + ' unique)';

    var selectedCount = Object.keys(_bwState.selectedKeys).length;

    var html =
      '<div style="display:flex;gap:8px;margin-bottom:12px;align-items:center;flex-wrap:wrap">' +
        '<button type="button" class="btn btn-xs btn-ghost" id="bwSelectAllFindings">Select All</button>' +
        '<button type="button" class="btn btn-xs btn-ghost" id="bwDeselectAllFindings">Deselect All</button>' +
        '<select id="bwRiskFilter" class="form-control" style="width:auto;font-size:0.78rem;padding:2px 8px">' +
          '<option value="">All Risks</option>' +
          '<option value="CRITICAL">Critical</option>' +
          '<option value="HIGH">High</option>' +
          '<option value="MEDIUM">Medium</option>' +
          '<option value="LOW">Low</option>' +
          '<option value="INFO">Info</option>' +
        '</select>' +
        '<input type="text" id="bwFindingSearch" class="form-control" placeholder="Search findings..." style="width:200px;font-size:0.78rem;padding:4px 8px">' +
        '<span style="margin-left:auto;font-size:0.8rem;opacity:0.6" id="bwFindingCount">' +
          selectedCount + ' / ' + _bwState.findings.length + ' selected</span>' +
      '</div>' +
      '<div class="table-responsive" style="max-height:55vh;overflow-y:auto">' +
        '<table class="data-table">' +
          '<thead><tr>' +
            '<th style="width:32px"></th>' +
            '<th>Finding</th>' +
            '<th style="width:60px">Risk</th>' +
            '<th style="width:50px">Dups</th>' +
            '<th>Host</th>' +
          '</tr></thead>' +
          '<tbody id="bwFindingBody"></tbody>' +
        '</table>' +
      '</div>';

    body.innerHTML = html;
    footer.innerHTML =
      '<button type="button" class="btn btn-ghost btn-sm" id="bwBack3">Back</button>' +
      '<button type="button" class="btn btn-primary btn-sm" id="bwCommit">Import ' + selectedCount + ' Findings</button>';

    _renderFindingRows();

    document.getElementById('bwSelectAllFindings').addEventListener('click', function () {
      for (var i = 0; i < _bwState.findings.length; i++)
        _bwState.selectedKeys[_bwState.findings[i].dedup_key] = true;
      _renderFindingRows();
    });
    document.getElementById('bwDeselectAllFindings').addEventListener('click', function () {
      _bwState.selectedKeys = {};
      _renderFindingRows();
    });
    document.getElementById('bwRiskFilter').addEventListener('change', function () {
      _renderFindingRows();
    });
    document.getElementById('bwFindingSearch').addEventListener('input', function () {
      _renderFindingRows();
    });
    document.getElementById('bwBack3').addEventListener('click', function () { _renderStep2(); });
    document.getElementById('bwCommit').addEventListener('click', _commitImport);
  }

  function _renderFindingRows() {
    var tbody = document.getElementById('bwFindingBody');
    if (!tbody) return;

    var riskFilter = (document.getElementById('bwRiskFilter') || {}).value || '';
    var search = ((document.getElementById('bwFindingSearch') || {}).value || '').toLowerCase();

    var rows = '';
    var visibleCount = 0;
    for (var i = 0; i < _bwState.findings.length; i++) {
      var f = _bwState.findings[i];
      if (riskFilter && f.risk !== riskFilter) continue;
      if (search && f.title.toLowerCase().indexOf(search) === -1 &&
          (f.burp_name || '').toLowerCase().indexOf(search) === -1) continue;

      visibleCount++;
      var checked = _bwState.selectedKeys[f.dedup_key] ? ' checked' : '';
      var riskCls = _RISK_CLS[f.risk] || 'risk-info';
      var titleHtml = _esc(f.title);
      if (f.burp_name && f.burp_name !== f.title) {
        titleHtml += '<div style="font-size:0.7rem;opacity:0.5;margin-top:2px">Burp: ' + _esc(f.burp_name) + '</div>';
      }
      rows +=
        '<tr>' +
          '<td><input type="checkbox" class="bw-finding-chk" data-key="' + _esc(f.dedup_key) + '"' + checked + '></td>' +
          '<td style="font-size:0.8rem">' + titleHtml + '</td>' +
          '<td><span class="badge ' + riskCls + '" style="font-size:0.65rem">' + f.risk + '</span></td>' +
          '<td style="text-align:center;font-size:0.8rem">' + (f.dup_count || 1) + '</td>' +
          '<td style="font-size:0.75rem;max-width:200px;word-break:break-all">' + _esc(f.host_url || f.ip || '') + '</td>' +
        '</tr>';
    }
    tbody.innerHTML = rows || '<tr><td colspan="5" style="text-align:center;opacity:0.5;padding:20px">No findings match filters</td></tr>';

    var chks = tbody.querySelectorAll('.bw-finding-chk');
    for (var j = 0; j < chks.length; j++) {
      chks[j].addEventListener('change', function () {
        if (this.checked) _bwState.selectedKeys[this.dataset.key] = true;
        else delete _bwState.selectedKeys[this.dataset.key];
        _updateFindingCount();
      });
    }
    _updateFindingCount();
  }

  function _updateFindingCount() {
    var n = Object.keys(_bwState.selectedKeys).length;
    var el = document.getElementById('bwFindingCount');
    if (el) el.textContent = n + ' / ' + _bwState.findings.length + ' selected';
    var btn = document.getElementById('bwCommit');
    if (btn) {
      btn.textContent = 'Import ' + n + ' Findings';
      btn.disabled = n === 0;
    }
  }

  // ── Commit ─────────────────────────────────────────────────────────

  function _commitImport() {
    var btn = document.getElementById('bwCommit');
    if (btn) { btn.disabled = true; btn.textContent = 'Importing...'; }

    var hosts = Object.keys(_bwState.selectedHosts);
    var keys = Object.keys(_bwState.selectedKeys);

    fetch('/api/import/burp/' + projectId + '/commit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        cache_key: _bwState.cacheKey,
        scope: _bwState.selectedScope,
        hosts: hosts,
        finding_keys: keys,
      }),
    })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
      .then(function (res) {
        if (!res.ok) {
          _showError(res.data.error || 'Import failed');
          if (btn) { btn.disabled = false; btn.textContent = 'Retry Import'; }
          return;
        }
        _renderDone(res.data.imported, res.data.total);
      })
      .catch(function (err) {
        _showError('Network error: ' + err.message);
        if (btn) { btn.disabled = false; btn.textContent = 'Retry Import'; }
      });
  }

  // ── Done ───────────────────────────────────────────────────────────

  function _renderDone(imported, total) {
    var body = document.getElementById('bwBody');
    var footer = document.getElementById('bwFooter');
    document.getElementById('bwTitle').textContent = 'Burp Import Complete';

    body.innerHTML =
      '<div style="text-align:center;padding:40px 0">' +
        '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--clr-info,#22c55e)" stroke-width="2">' +
          '<path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' +
        '<div style="margin-top:16px;font-size:1.1rem;font-weight:600">' +
          imported + ' findings imported</div>' +
        '<div style="margin-top:8px;font-size:0.85rem;opacity:0.6">from ' +
          _esc(_bwState.filename) + '</div>' +
        (imported < total
          ? '<div style="margin-top:8px;font-size:0.8rem;opacity:0.5">' +
            (total - imported) + ' findings were deduplicated or skipped</div>'
          : '') +
      '</div>';

    footer.innerHTML =
      '<div></div>' +
      '<button type="button" class="btn btn-primary btn-sm" id="bwDoneBtn">Done</button>';

    document.getElementById('bwDoneBtn').addEventListener('click', function () {
      window._burpWizardClose();
      var btn = document.querySelector('#tabNav .tab-btn[data-tab="findings"]');
      if (btn) btn.click();
    });
  }

  // ── Helpers ────────────────────────────────────────────────────────

  function _esc(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function _showError(msg) {
    var el = document.getElementById('bwError');
    if (el) { el.textContent = msg; el.style.display = ''; }
  }
  function _hideError() {
    var el = document.getElementById('bwError');
    if (el) { el.style.display = 'none'; el.textContent = ''; }
  }

  // ── Public entry point ─────────────────────────────────────────────

  window._openBurpWizard = function () {
    _ensureModal();
    _bwState.cacheKey = '';
    _bwState.hosts = [];
    _bwState.findings = [];
    _bwState.selectedHosts = {};
    _bwState.selectedKeys = {};
    _bwState.step = 0;
    _show();
    _renderStep1();
  };

})();
