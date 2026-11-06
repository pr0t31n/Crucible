(function(){
  'use strict';

  var _cfg = JSON.parse(document.getElementById('wizardConfig').textContent);
  var TOTAL_STEPS = 4;
  var EDIT_MODE   = _cfg.editMode;
  var PROJECT_ID  = _cfg.projectId;
  var PRESET_TOOLS = _cfg.presetTools || [];

  var TOOL_META = {
    ss3:{key:'SS',name:'Scattershot3',cls:'tool-ss'},
    osift:{key:'OS',name:'OSift',cls:'tool-os'},
    trawler:{key:'TR',name:'Trawler',cls:'tool-tr'},
    fracture:{key:'FR',name:'Fracture',cls:'tool-fr'},
    siphon:{key:'SI',name:'Siphon',cls:'tool-si'},
    auger:{key:'AU',name:'Auger',cls:'tool-au'},
    aether:{key:'AE',name:'Aether (Wi-Fi)',cls:'tool-ae'},
    aether_b:{key:'AB',name:'Aether (Bluetooth)',cls:'tool-ab'},
    aether_z:{key:'AZ',name:'Aether (Zigbee)',cls:'tool-az'},
    aether_u:{key:'AW',name:'Aether (UWB)',cls:'tool-aw'},
    bastion:{key:'BA',name:'Bastion',cls:'tool-ba'},
    forge:{key:'FG',name:'Forge',cls:'tool-fg'},
    quill:{key:'QU',name:'Quill',cls:'tool-qu'},
    isotope:{key:'IS',name:'Isotope',cls:'tool-is'},
    dredge:{key:'DG',name:'Dredge',cls:'tool-dg'}
  };

  /* Scope type → allowed tools */
  var SCOPE_TOOL_MAP = {
    multi:     ['ss3','osift','trawler','fracture','siphon','auger','aether','aether_b','aether_z','aether_u','bastion','forge','quill','isotope','dredge'],
    endpoint:  ['dredge'],
    external:  ['ss3'],
    internal:  ['ss3'],
    webapp:    ['fracture'],
    api:       ['siphon'],
    osint:     ['osift'],
    database:  ['auger'],
    pcap:      ['trawler'],
    wifi:      ['aether'],
    bluetooth: ['aether_b'],
    zigbee:    ['aether_z'],
    uwb:       ['aether_u'],
    firewall:  ['bastion'],
    cloud:     ['forge'],
    mobile:    ['quill'],
    file:      ['isotope']
  };

  var WIRELESS_TOOLS = ['aether','aether_b','aether_z','aether_u'];
  var TEST_CONN_TOOLS = ['fracture','siphon'];

  var form      = document.getElementById('wizardForm');
  var btnNext   = document.getElementById('btnNext');
  var btnBack   = document.getElementById('btnBack');
  var btnHome   = document.getElementById('btnHome');
  var btnSubmit = document.getElementById('btnSubmit');
  var stepDots  = document.querySelectorAll('.wizard-step');
  var currentStep = 1;

  /* ── Scope-driven tool filtering ─────────────────────── */
  var scopeTypeEl = document.getElementById('scopeType');

  function applyScopeFilter() {
    var scope = scopeTypeEl.value;
    var allowed = SCOPE_TOOL_MAP[scope] || [];
    document.querySelectorAll('.tool-select-card').forEach(function(card) {
      var tool = card.dataset.tool;
      var cb = card.querySelector('input[type="checkbox"]');
      if (allowed.indexOf(tool) !== -1) {
        card.classList.remove('disabled');
      } else {
        card.classList.add('disabled');
        if (cb.checked && !(EDIT_MODE && PRESET_TOOLS.indexOf(tool) !== -1)) {
          cb.checked = false;
          card.classList.remove('selected');
        }
      }
    });
    updateScopeSections();
  }

  scopeTypeEl.addEventListener('change', applyScopeFilter);

  /* ── API spec files ──────────────────────────────────── */
  var apiFiles = [];
  var apiSpecFile = document.getElementById('apiSpecFile');
  var apiSpecList = document.getElementById('apiSpecList');
  var apiSpecCount = document.getElementById('apiSpecCount');

  apiSpecFile.addEventListener('change', function() {
    for (var i = 0; i < this.files.length; i++) apiFiles.push(this.files[i]);
    this.value = '';
    renderApiFiles();
  });

  function renderApiFiles() {
    apiSpecList.innerHTML = '';
    apiSpecCount.textContent = apiFiles.length ? apiFiles.length + ' file(s)' : 'No files selected';
    apiFiles.forEach(function(f, idx) {
      var li = document.createElement('li');
      li.innerHTML = '<span>' + escHtml(f.name) + '</span><span class="form-hint">' + formatBytes(f.size) + '</span><button type="button" class="file-remove" data-idx="' + idx + '">&times;</button>';
      apiSpecList.appendChild(li);
    });
    apiSpecList.querySelectorAll('.file-remove').forEach(function(btn) {
      btn.addEventListener('click', function() {
        apiFiles.splice(parseInt(this.dataset.idx), 1);
        renderApiFiles();
      });
    });
  }

  /* ── Firewall config files ─────────────────────────── */
  var fwFiles = [];
  var fwConfigFile = document.getElementById('fwConfigFile');
  var fwConfigList = document.getElementById('fwConfigList');
  var fwConfigCount = document.getElementById('fwConfigCount');

  fwConfigFile.addEventListener('change', function() {
    for (var i = 0; i < this.files.length; i++) fwFiles.push(this.files[i]);
    this.value = '';
    renderFwFiles();
  });

  function renderFwFiles() {
    fwConfigList.innerHTML = '';
    fwConfigCount.textContent = fwFiles.length ? fwFiles.length + ' file(s)' : 'No files selected';
    fwFiles.forEach(function(f, idx) {
      var li = document.createElement('li');
      li.innerHTML = '<span>' + escHtml(f.name) + '</span><span class="form-hint">' + formatBytes(f.size) + '</span><button type="button" class="file-remove" data-idx="' + idx + '">&times;</button>';
      fwConfigList.appendChild(li);
    });
    fwConfigList.querySelectorAll('.file-remove').forEach(function(btn) {
      btn.addEventListener('click', function() {
        fwFiles.splice(parseInt(this.dataset.idx), 1);
        renderFwFiles();
      });
    });
  }

  /* ── Mobile app file list + browser ──────────────────── */
  var _maBrowseModal = document.getElementById('maBrowseModal');
  var _maBrowseList = document.getElementById('maBrowseList');
  var _maBrowseLoading = document.getElementById('maBrowseLoading');
  var _maBrowseCrumbs = document.getElementById('maBrowseCrumbs');
  var _MA_EXT = ['.ipa','.apk','.aab','.xapk'];
  var mobileAppPaths = [];

  function _maIsApp(name) {
    var n = name.toLowerCase();
    return _MA_EXT.some(function(e){ return n.endsWith(e); });
  }

  function _maRenderList() {
    var ul = document.getElementById('mobileAppList');
    if (!ul) return;
    ul.innerHTML = '';
    mobileAppPaths.forEach(function(p, i) {
      var li = document.createElement('li');
      var ext = p.split('.').pop().toLowerCase();
      var badge = (ext === 'ipa' ? 'iOS' : ext === 'apk' || ext === 'aab' || ext === 'xapk' ? 'Android' : '');
      li.innerHTML = '<span style="flex:1;word-break:break-all">' + escHtml(p) + '</span>' +
        (badge ? '<span style="font-size:.7rem;padding:1px 6px;border-radius:8px;background:var(--accent-muted);color:var(--accent-primary);white-space:nowrap">' + badge + '</span>' : '') +
        '<button type="button" class="file-remove" data-idx="' + i + '" title="Remove">&times;</button>';
      ul.appendChild(li);
    });
    ul.querySelectorAll('.file-remove').forEach(function(btn) {
      btn.addEventListener('click', function() {
        mobileAppPaths.splice(parseInt(this.dataset.idx), 1);
        _maRenderList();
      });
    });
  }

  function _maAddFile(path) {
    if (!path) return;
    path = path.trim();
    if (!path) return;
    if (mobileAppPaths.indexOf(path) !== -1) return;
    mobileAppPaths.push(path);
    _maRenderList();
  }

  var _maAddBtn = document.getElementById('btnMobileAddFile');
  if (_maAddBtn) _maAddBtn.addEventListener('click', function() {
    var inp = document.getElementById('mobileAppPathInput');
    _maAddFile(inp.value);
    inp.value = '';
  });
  var _maPathInput = document.getElementById('mobileAppPathInput');
  if (_maPathInput) _maPathInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); _maAddFile(this.value); this.value = ''; }
  });

  function _maOpenBrowse() {
    if (_maBrowseModal) _maBrowseModal.classList.add('open');
    var cur = valOf('mobileAppPathInput');
    var start = cur ? cur.replace(/\/[^/]*$/, '') || '/' : (navigator.platform.indexOf('Mac') > -1 ? '/Users' : '/');
    _maBrowseNavigate(start);
  }

  function _maCloseBrowse() {
    if (_maBrowseModal) _maBrowseModal.classList.remove('open');
  }

  function _maBrowseNavigate(folder) {
    if (_maBrowseLoading) _maBrowseLoading.hidden = false;
    if (_maBrowseList) _maBrowseList.innerHTML = '';
    fetch('/api/merger/browse', {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({folder:folder})})
    .then(function(r){return r.json();})
    .then(function(data) {
      if (_maBrowseLoading) _maBrowseLoading.hidden = true;
      if (_maBrowseCrumbs) _maBrowseCrumbs.textContent = data.current;
      if (!_maBrowseList) return;
      _maBrowseList.innerHTML = '';
      if (data.parent) {
        var pli = document.createElement('li');
        pli.className = 'dg-browse-parent';
        pli.innerHTML = '<svg class="dg-browse-icon" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg><span class="dg-browse-name">..</span>';
        pli.addEventListener('click', function(){ _maBrowseNavigate(data.parent); });
        _maBrowseList.appendChild(pli);
      }
      data.entries.forEach(function(entry) {
        if (!entry.is_dir && !_maIsApp(entry.name)) return;
        var li = document.createElement('li');
        var icon = entry.is_dir
          ? '<svg class="dg-browse-icon" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>'
          : '<svg class="dg-browse-icon" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
        li.innerHTML = icon + '<span class="dg-browse-name">' + escHtml(entry.name) + '</span>';
        if (entry.is_dir) {
          li.addEventListener('click', function(){ _maBrowseNavigate(entry.path); });
        } else {
          li.addEventListener('click', function(){
            _maAddFile(entry.path);
            _maCloseBrowse();
          });
        }
        _maBrowseList.appendChild(li);
      });
    })
    .catch(function(err) {
      if (_maBrowseLoading) { _maBrowseLoading.hidden = false; _maBrowseLoading.textContent = 'Error: ' + err.message; }
    });
  }

  var btnMobileBrowse = document.getElementById('btnMobileBrowse');
  if (btnMobileBrowse) btnMobileBrowse.addEventListener('click', _maOpenBrowse);
  if (document.getElementById('maBrowseClose')) document.getElementById('maBrowseClose').addEventListener('click', _maCloseBrowse);
  if (document.getElementById('maBrowseCancel')) document.getElementById('maBrowseCancel').addEventListener('click', _maCloseBrowse);
  if (_maBrowseModal) _maBrowseModal.addEventListener('click', function(e) { if (e.target === _maBrowseModal) _maCloseBrowse(); });

  /* ── Isotope files ────────────────────────────────────── */
  var isoFiles = [];
  var isoFileInput = document.getElementById('isoFileInput');
  var isoFileList  = document.getElementById('isoFileList');
  var isoFileCount = document.getElementById('isoFileCount');
  if (isoFileInput) {
    isoFileInput.addEventListener('change', function() {
      for (var i = 0; i < this.files.length; i++) isoFiles.push(this.files[i]);
      this.value = '';
      renderIsoFiles();
    });
  }
  function renderIsoFiles() {
    if (!isoFileList) return;
    isoFileList.innerHTML = '';
    isoFileCount.textContent = isoFiles.length ? isoFiles.length + ' file(s)' : 'No files selected';
    isoFiles.forEach(function(f, idx) {
      var li = document.createElement('li');
      li.innerHTML = '<span>' + escHtml(f.name) + '</span><span class="form-hint">' + formatBytes(f.size) + '</span><button type="button" class="file-remove" data-idx="' + idx + '">&times;</button>';
      isoFileList.appendChild(li);
    });
    isoFileList.querySelectorAll('.file-remove').forEach(function(btn) {
      btn.addEventListener('click', function() {
        isoFiles.splice(parseInt(this.dataset.idx), 1);
        renderIsoFiles();
      });
    });
  }

  function getIsoModules() {
    var mods = [];
    document.querySelectorAll('.iso-module:checked').forEach(function(cb) { mods.push(cb.value); });
    return mods;
  }

  /* ── Auger mode toggle + DB file upload ───────────────── */
  var augerModeEl = document.getElementById('augerMode');
  if (augerModeEl) {
    augerModeEl.addEventListener('change', function() {
      var isFile = this.value === 'file';
      document.getElementById('augerRemoteFields').hidden = isFile;
      document.getElementById('augerFileFields').hidden   = !isFile;
    });
  }
  var dbFiles = [];
  var dbFileInput = document.getElementById('dbFileInput');
  var dbFileList  = document.getElementById('dbFileList');
  var dbFileCount = document.getElementById('dbFileCount');
  if (dbFileInput) {
    dbFileInput.addEventListener('change', function() {
      for (var i = 0; i < this.files.length; i++) dbFiles.push(this.files[i]);
      this.value = '';
      renderDbFiles();
    });
  }
  function renderDbFiles() {
    if (!dbFileList) return;
    dbFileList.innerHTML = '';
    dbFileCount.textContent = dbFiles.length ? dbFiles.length + ' file(s)' : 'No files selected';
    dbFiles.forEach(function(f, idx) {
      var li = document.createElement('li');
      li.innerHTML = '<span>' + escHtml(f.name) + '</span><span class="form-hint">' + formatBytes(f.size) + '</span><button type="button" class="file-remove" data-idx="' + idx + '">&times;</button>';
      dbFileList.appendChild(li);
    });
    dbFileList.querySelectorAll('.file-remove').forEach(function(btn) {
      btn.addEventListener('click', function() {
        dbFiles.splice(parseInt(this.dataset.idx), 1);
        renderDbFiles();
      });
    });
  }

  /* ── Mobile app paths (pre-populate in edit mode) ─────── */
  if (_cfg.mobileAppPaths && Array.isArray(_cfg.mobileAppPaths) && _cfg.mobileAppPaths.length) {
    _cfg.mobileAppPaths.forEach(function(p) { if (p) mobileAppPaths.push(p); });
    _maRenderList();
  } else if (_cfg.mobileAppPath) {
    mobileAppPaths.push(_cfg.mobileAppPath);
    _maRenderList();
  }
  var _mobilePlatformEl = document.getElementById('mobilePlatform');
  if (_mobilePlatformEl && _cfg.mobilePlatform) _mobilePlatformEl.value = _cfg.mobilePlatform;

  /* ── Dredge collection path (file browser) ──────────────── */
  var dgCollectionPath = _cfg.dredgeCollectionPath || '';
  var dgCollectionType = '';
  var dgCollectionCount = document.getElementById('dgCollectionCount');
  var dgCollectionDisplay = document.getElementById('dgCollectionDisplay');
  var dgCollectionPathEl = document.getElementById('dgCollectionPath');
  var dgCollectionTypeBadge = document.getElementById('dgCollectionTypeBadge');

  function _dgSetSelection(path, type, label) {
    dgCollectionPath = path || '';
    dgCollectionType = type || '';
    if (dgCollectionCount) dgCollectionCount.textContent = path ? path.split('/').pop() : 'No path selected';
    if (dgCollectionDisplay) dgCollectionDisplay.hidden = !path;
    if (dgCollectionPathEl) dgCollectionPathEl.textContent = path || '';
    if (dgCollectionTypeBadge) dgCollectionTypeBadge.textContent = label || type || '';
  }

  var btnDgClearPath = document.getElementById('btnDgClearPath');
  if (btnDgClearPath) btnDgClearPath.addEventListener('click', function() { _dgSetSelection('','',''); });

  if (dgCollectionPath) {
    fetch('/api/dredge/detect', {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:dgCollectionPath})})
    .then(function(r){return r.json();})
    .then(function(d){ if(d.valid) _dgSetSelection(d.path,d.type,d.label); else _dgSetSelection(dgCollectionPath,'unknown','Unknown'); })
    .catch(function(){ _dgSetSelection(dgCollectionPath,'unknown','Unknown'); });
  }

  /* ── Dredge file browser modal ─────────────────────────── */
  var _dgBrowseModal = document.getElementById('dgBrowseModal');
  var _dgBrowseList = document.getElementById('dgBrowseList');
  var _dgBrowseLoading = document.getElementById('dgBrowseLoading');
  var _dgBrowseCrumbs = document.getElementById('dgBrowseCrumbs');
  var _dgBrowseSelectFolder = document.getElementById('dgBrowseSelectFolder');
  var _dgBrowseDetectBar = document.getElementById('dgBrowseDetectBar');
  var _dgBrowseDetectLabel = document.getElementById('dgBrowseDetectLabel');
  var _dgBrowseCurrent = '';

  var _DG_FOLDER_SVG = '<svg class="dg-browse-icon" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>';
  var _DG_FILE_SVG = '<svg class="dg-browse-icon" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
  var _DG_UP_SVG = '<svg class="dg-browse-icon" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>';

  var _dgDefaultStart = navigator.platform.indexOf('Mac') > -1 ? '/Users/Shared/clients' : '/clients';

  function _dgOpenBrowse() {
    if (_dgBrowseModal) _dgBrowseModal.classList.add('open');
    _dgBrowseNavigate(dgCollectionPath ? dgCollectionPath.replace(/\/[^/]*$/, '') || '/' : _dgDefaultStart);
  }

  function _dgCloseBrowse() {
    if (_dgBrowseModal) _dgBrowseModal.classList.remove('open');
  }

  function _dgBrowseNavigate(folder) {
    if (_dgBrowseLoading) _dgBrowseLoading.hidden = false;
    if (_dgBrowseList) _dgBrowseList.innerHTML = '';
    if (_dgBrowseDetectBar) _dgBrowseDetectBar.hidden = true;
    if (_dgBrowseSelectFolder) _dgBrowseSelectFolder.disabled = true;

    fetch('/api/merger/browse', {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({folder:folder})})
    .then(function(r){return r.json();})
    .then(function(data) {
      if (_dgBrowseLoading) _dgBrowseLoading.hidden = true;
      _dgBrowseCurrent = data.current;
      if (_dgBrowseCrumbs) _dgBrowseCrumbs.textContent = data.current;

      _dgCheckFolder(data.current);

      if (!_dgBrowseList) return;
      _dgBrowseList.innerHTML = '';

      if (data.parent) {
        var pli = document.createElement('li');
        pli.className = 'dg-browse-parent';
        pli.innerHTML = _DG_UP_SVG + '<span class="dg-browse-name">..</span>';
        pli.addEventListener('click', function(){ _dgBrowseNavigate(data.parent); });
        _dgBrowseList.appendChild(pli);
      }

      data.entries.forEach(function(entry) {
        if (!entry.is_dir && entry.name.toLowerCase().indexOf('.json') === -1) return;
        var li = document.createElement('li');
        li.innerHTML = (entry.is_dir ? _DG_FOLDER_SVG : _DG_FILE_SVG) + '<span class="dg-browse-name">' + escHtml(entry.name) + '</span>';
        if (entry.is_dir) {
          li.addEventListener('click', function(){ _dgBrowseNavigate(entry.path); });
        } else {
          li.addEventListener('click', function(){ _dgSelectPath(entry.path); });
        }
        _dgBrowseList.appendChild(li);
      });
    })
    .catch(function(err) {
      if (_dgBrowseLoading) { _dgBrowseLoading.hidden = false; _dgBrowseLoading.textContent = 'Error: ' + err.message; }
    });
  }

  function _dgCheckFolder(folder) {
    fetch('/api/dredge/detect', {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:folder})})
    .then(function(r){return r.json();})
    .then(function(d) {
      if (d.valid && d.type === 'cmd_dir') {
        if (_dgBrowseDetectBar) { _dgBrowseDetectBar.hidden = false; }
        if (_dgBrowseDetectLabel) _dgBrowseDetectLabel.textContent = 'This folder is a ' + d.label;
        if (_dgBrowseSelectFolder) { _dgBrowseSelectFolder.disabled = false; _dgBrowseSelectFolder._detectedPath = d.path; _dgBrowseSelectFolder._detectedType = d.type; _dgBrowseSelectFolder._detectedLabel = d.label; }
      } else {
        if (_dgBrowseDetectBar) _dgBrowseDetectBar.hidden = true;
        if (_dgBrowseSelectFolder) { _dgBrowseSelectFolder.disabled = true; _dgBrowseSelectFolder._detectedPath = null; }
      }
    })
    .catch(function(){});
  }

  function _dgSelectPath(path) {
    fetch('/api/dredge/detect', {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path})})
    .then(function(r){return r.json();})
    .then(function(d) {
      if (d.valid) {
        _dgSetSelection(d.path, d.type, d.label);
        _dgCloseBrowse();
      } else {
        alert(d.error || 'Not a recognised Dredge collection');
      }
    })
    .catch(function(err){ alert('Detection failed: ' + err.message); });
  }

  var btnDgBrowse = document.getElementById('btnDgBrowse');
  if (btnDgBrowse) btnDgBrowse.addEventListener('click', _dgOpenBrowse);
  if (document.getElementById('dgBrowseClose')) document.getElementById('dgBrowseClose').addEventListener('click', _dgCloseBrowse);
  if (document.getElementById('dgBrowseCancel')) document.getElementById('dgBrowseCancel').addEventListener('click', _dgCloseBrowse);
  if (_dgBrowseSelectFolder) {
    _dgBrowseSelectFolder.addEventListener('click', function() {
      if (this._detectedPath) { _dgSetSelection(this._detectedPath, this._detectedType, this._detectedLabel); _dgCloseBrowse(); }
    });
  }
  if (_dgBrowseModal) {
    _dgBrowseModal.addEventListener('click', function(e) { if (e.target === _dgBrowseModal) _dgCloseBrowse(); });
  }

  /* ── Dredge external tool files ──────────────────────── */
  var dgExtToolFiles = [];
  var dgExtToolFileEl = document.getElementById('dgExtToolFile');
  var dgExtToolList = document.getElementById('dgExtToolList');
  var dgExtToolCount = document.getElementById('dgExtToolCount');
  if (dgExtToolFileEl) {
    dgExtToolFileEl.addEventListener('change', function() {
      for (var i = 0; i < this.files.length; i++) dgExtToolFiles.push(this.files[i]);
      this.value = '';
      renderDgExtToolFiles();
    });
  }
  function renderDgExtToolFiles() {
    if (!dgExtToolList) return;
    dgExtToolList.innerHTML = '';
    dgExtToolCount.textContent = dgExtToolFiles.length ? dgExtToolFiles.length + ' file(s)' : 'No files selected';
    dgExtToolFiles.forEach(function(f, idx) {
      var li = document.createElement('li');
      li.innerHTML = '<span>' + escHtml(f.name) + '</span><span class="form-hint">' + formatBytes(f.size) + '</span><button type="button" class="file-remove" data-idx="' + idx + '">&times;</button>';
      dgExtToolList.appendChild(li);
    });
    dgExtToolList.querySelectorAll('.file-remove').forEach(function(btn) {
      btn.addEventListener('click', function() {
        dgExtToolFiles.splice(parseInt(this.dataset.idx), 1);
        renderDgExtToolFiles();
      });
    });
  }

  /* ── Dredge mode toggle (Import vs WinRM) ────────────── */
  var dredgeModeEl = document.getElementById('dredgeMode');
  function updateDredgeMode() {
    if (!dredgeModeEl) return;
    var isWinrm = dredgeModeEl.value === 'winrm';
    var importFields = document.getElementById('dredgeImportFields');
    var winrmFields = document.getElementById('dredgeWinrmFields');
    if (importFields) importFields.hidden = isWinrm;
    if (winrmFields) winrmFields.hidden = !isWinrm;
  }
  if (dredgeModeEl) {
    dredgeModeEl.addEventListener('change', updateDredgeMode);
    updateDredgeMode();
  }

  function getDgExtParsers() {
    var parsers = [];
    document.querySelectorAll('.dg-ext-parser:checked').forEach(function(cb) { parsers.push(cb.value); });
    return parsers;
  }

  /* ── Auto-exclude testing device IPs ─────────────────── */
  var btnAutoExclude = document.getElementById('btnAutoExclude');
  if (btnAutoExclude) {
    btnAutoExclude.addEventListener('click', function() {
      var btn = this; btn.disabled = true; btn.textContent = 'Detecting...';
      var statusEl = document.getElementById('autoExcludeStatus');
      fetch('/api/device-ips', {method:'GET',credentials:'same-origin'})
      .then(function(r){return r.json();})
      .then(function(d) {
        var ips = d.ips || [];
        if (!ips.length) { statusEl.textContent = 'No IPs detected'; return; }
        var area = document.getElementById('exclusions');
        var existing = area.value.trim();
        var lines = existing ? existing.split('\n').map(function(l){return l.trim();}).filter(Boolean) : [];
        var added = 0;
        ips.forEach(function(ip) {
          if (lines.indexOf(ip) === -1) { lines.push(ip); added++; }
        });
        area.value = lines.join('\n');
        statusEl.textContent = added ? 'Added ' + added + ' IP(s): ' + ips.join(', ') : 'All IPs already listed';
      })
      .catch(function(e) { statusEl.textContent = 'Error: ' + e.message; })
      .finally(function() { btn.disabled = false; btn.textContent = '+ Add Testing Device IPs'; });
    });
  }

  /* ── Cloud provider field toggling ───────────────────── */
  var cloudProviderEl = document.getElementById('cloudProvider');
  function updateCloudFields() {
    var prov = cloudProviderEl.value;
    var showAws   = prov === 'all' || prov === 'aws';
    var showAzure = prov === 'all' || prov === 'azure';
    var showGcp   = prov === 'all' || prov === 'gcp';
    document.getElementById('cloudAwsAuthBlock').hidden = !showAws;
    document.getElementById('cloudAzureGroup').hidden   = !showAzure;
    document.getElementById('cloudGcpGroup').hidden     = !showGcp;
  }

  /* AWS auth method radio toggle */
  function updateAwsAuthMethod() {
    var sel = document.querySelector('input[name="awsAuthMethod"]:checked');
    var method = sel ? sel.value : 'profile';
    document.getElementById('awsAuthProfile').hidden = method !== 'profile';
    document.getElementById('awsAuthKeys').hidden    = method !== 'keys';
    document.getElementById('awsAuthConsole').hidden  = method !== 'console';
  }
  document.querySelectorAll('input[name="awsAuthMethod"]').forEach(function(r) {
    r.addEventListener('change', updateAwsAuthMethod);
  });
  cloudProviderEl.addEventListener('change', updateCloudFields);

  /* ── Mobile analysis mode toggle ─────────────────────── */
  var mobileModeEl = document.getElementById('mobileMode');
  var fridaEnabledEl = document.getElementById('fridaEnabled');
  var mitmEnabledEl = document.getElementById('mitmEnabled');
  function updateMobileMode() {
    if (!mobileModeEl) return;
    var mode = mobileModeEl.value;
    var showStatic = mode === 'static' || mode === 'full';
    var showDynamic = mode === 'dynamic' || mode === 'full';
    document.getElementById('mobileStaticGroup').hidden = !showStatic;
    document.getElementById('mobileDynamicGroup').hidden = !showDynamic;
    var phasesGroup = document.getElementById('quillPhasesGroup');
    if (phasesGroup) phasesGroup.hidden = !showDynamic;
  }
  if (mobileModeEl) { mobileModeEl.addEventListener('change', updateMobileMode); updateMobileMode(); }
  function _fridaStatusMsg(el, type, msg) {
    el.hidden = false;
    el.style.background = type === 'error' ? 'var(--bg-error, #3a1c1c)' : type === 'warn' ? 'var(--bg-warn, #3a2e1c)' : 'var(--bg-info, #1c2a3a)';
    el.style.color = type === 'error' ? 'var(--text-error, #ff6b6b)' : type === 'warn' ? 'var(--text-warn, #ffb347)' : 'var(--text-info, #6bc5ff)';
    el.innerHTML = msg;
  }
  function fetchFridaDevices(selectEl, statusEl, savedDeviceId) {
    if (!selectEl) return;
    selectEl.innerHTML = '<option value="">Scanning...</option>';
    selectEl.disabled = true;
    if (statusEl) statusEl.hidden = true;
    fetch('/api/frida-devices', {credentials: 'same-origin'})
      .then(function(r) { return r.json(); })
      .then(function(data) {
        selectEl.disabled = false;
        selectEl.innerHTML = '';
        if (!data.ok) {
          if (data.error === 'frida_not_installed') {
            selectEl.innerHTML = '<option value="">(Frida not installed)</option>';
            if (statusEl) _fridaStatusMsg(statusEl, 'error',
              '<strong>Frida is not installed.</strong><br>' +
              'Install: <code>pip3 install frida-tools frida</code><br>' +
              'Then download <code>frida-server</code> for your device from ' +
              '<a href="https://github.com/frida/frida/releases" target="_blank" style="color:inherit;text-decoration:underline">GitHub releases</a> ' +
              '(match the version to your desktop frida-tools).<br>' +
              'Push to device: <code>adb push frida-server /data/local/tmp/ &amp;&amp; adb shell chmod 755 /data/local/tmp/frida-server &amp;&amp; adb shell su -c \'/data/local/tmp/frida-server -D &amp;\'</code>');
          } else if (data.error === 'no_devices') {
            selectEl.innerHTML = '<option value="">(No devices found)</option>';
            if (statusEl) _fridaStatusMsg(statusEl, 'warn',
              '<strong>No mobile devices detected.</strong><br>' +
              'Connect your Android or iOS device via USB and ensure USB debugging is enabled. ' +
              'Frida-server must be running on the device.');
          } else {
            selectEl.innerHTML = '<option value="">(Error: ' + (data.message || 'unknown') + ')</option>';
            if (statusEl) _fridaStatusMsg(statusEl, 'error', data.message || 'Unknown error');
          }
          return;
        }
        selectEl.innerHTML = '<option value="">-- Select device --</option>';
        (data.devices || []).forEach(function(d) {
          var opt = document.createElement('option');
          opt.value = d.id;
          opt.textContent = d.name + ' (' + d.id + ')';
          selectEl.appendChild(opt);
        });
        if (savedDeviceId) selectEl.value = savedDeviceId;
        if (data.devices && data.devices.length === 1) selectEl.value = data.devices[0].id;
        if (statusEl) statusEl.hidden = true;
      })
      .catch(function() {
        selectEl.disabled = false;
        selectEl.innerHTML = '<option value="">(Scan failed)</option>';
        if (statusEl) _fridaStatusMsg(statusEl, 'error', 'Failed to reach server. Check network connection.');
      });
  }
  var _fridaRefreshBtn = document.getElementById('fridaRefreshBtn');
  var _fridaStatusEl = document.getElementById('fridaDeviceStatus');
  var _fridaSelectEl = document.getElementById('fridaDevice');
  if (_fridaRefreshBtn) {
    _fridaRefreshBtn.addEventListener('click', function() {
      fetchFridaDevices(_fridaSelectEl, _fridaStatusEl);
    });
  }
  function updateFridaFields() {
    if (!fridaEnabledEl) return;
    document.getElementById('fridaGroup').hidden = !fridaEnabledEl.checked;
    if (fridaEnabledEl.checked && _fridaSelectEl && _fridaSelectEl.options.length <= 1 && !_fridaSelectEl.options[0].value) {
      fetchFridaDevices(_fridaSelectEl, _fridaStatusEl, _cfg.fridaDevice || '');
    }
  }
  if (fridaEnabledEl) { fridaEnabledEl.addEventListener('change', updateFridaFields); updateFridaFields(); }
  function updateMitmFields() {
    if (!mitmEnabledEl) return;
    document.getElementById('mobileMitmGroup').hidden = !mitmEnabledEl.checked;
    updateUpstreamCaField();
  }
  function updateUpstreamCaField() {
    var g = document.getElementById('mitmUpstreamCaGroup');
    if (g) g.hidden = !valOf('mitmUpstreamProxy');
  }
  var _proxyCaPem = '';
  var _proxyCaName = '';
  var _proxyCaFileEl = document.getElementById('mitmBurpCaFile');
  if (_proxyCaFileEl) {
    _proxyCaFileEl.addEventListener('change', function() {
      var f = this.files && this.files[0];
      if (!f) return;
      var reader = new FileReader();
      reader.onload = function(e) {
        _proxyCaPem = e.target.result;
        _proxyCaName = f.name;
        var nameEl = document.getElementById('mitmBurpCaName');
        if (nameEl) nameEl.textContent = f.name;
        var clrEl = document.getElementById('mitmBurpCaClear');
        if (clrEl) clrEl.hidden = false;
      };
      reader.readAsText(f);
    });
  }
  window.clearProxyCa = function() {
    _proxyCaPem = '';
    _proxyCaName = '';
    var nameEl = document.getElementById('mitmBurpCaName');
    if (nameEl) nameEl.textContent = '(none selected)';
    var clrEl = document.getElementById('mitmBurpCaClear');
    if (clrEl) clrEl.hidden = true;
    if (_proxyCaFileEl) _proxyCaFileEl.value = '';
  };
  var _upEl = document.getElementById('mitmUpstreamProxy');
  if (_upEl) _upEl.addEventListener('input', updateUpstreamCaField);
  if (mitmEnabledEl) mitmEnabledEl.addEventListener('change', updateMitmFields);

  /* ── Restore saved mobile settings in edit mode ─────────── */
  if (mobileModeEl && _cfg.analysisMode) {
    mobileModeEl.value = _cfg.analysisMode;
    updateMobileMode();
  }
  if (fridaEnabledEl && _cfg.fridaAnalysis) {
    fridaEnabledEl.checked = true;
    updateFridaFields();
  }
  if (_cfg.fridaDevice) { fetchFridaDevices(_fridaSelectEl, _fridaStatusEl, _cfg.fridaDevice); }
  if (_cfg.targetProcess) { var _tpEl = document.getElementById('targetProcess'); if (_tpEl) _tpEl.value = _cfg.targetProcess; }
  if (mitmEnabledEl && _cfg.mitmAnalysis) {
    mitmEnabledEl.checked = true;
    updateMitmFields();
  }
  if (_cfg.mitmPort) { var _mpEl = document.getElementById('mitmPort'); if (_mpEl) _mpEl.value = _cfg.mitmPort; }
  if (_cfg.mitmUpstreamProxy) { var _muEl = document.getElementById('mitmUpstreamProxy'); if (_muEl) _muEl.value = _cfg.mitmUpstreamProxy; }
  if (_cfg.mitmBurpCa) {
    _proxyCaPem = _cfg.mitmBurpCa;
    _proxyCaName = _cfg.mitmBurpCaName || 'proxy-ca.pem';
    var _cnEl = document.getElementById('mitmBurpCaName');
    if (_cnEl) _cnEl.textContent = _proxyCaName;
    var _ccEl = document.getElementById('mitmBurpCaClear');
    if (_ccEl) _ccEl.hidden = false;
  }
  updateUpstreamCaField();

  /* ── Quill phases helper + restore ─────────────────────── */
  function getQuillPhases() {
    var phases = [];
    document.querySelectorAll('.quillPhase:checked').forEach(function(cb) {
      phases.push(cb.value);
    });
    return phases;
  }
  if (_cfg.quillPhases && Array.isArray(_cfg.quillPhases)) {
    document.querySelectorAll('.quillPhase').forEach(function(cb) {
      cb.checked = _cfg.quillPhases.indexOf(cb.value) !== -1;
    });
  }

  /* ── Engagement hours toggle ───────────────────────────── */
  var wizEngToggle = document.getElementById('wizEngagementEnabled');
  var wizEngConfig = document.getElementById('wizEngagementConfig');
  if (wizEngToggle && wizEngConfig) {
    wizEngToggle.addEventListener('change', function() {
      wizEngConfig.style.display = this.checked ? 'flex' : 'none';
    });
  }

  /* ── Tool card selection (div, not label — avoids double-toggle) ── */
  var toolCards = document.querySelectorAll('.tool-select-card');
  toolCards.forEach(function(card) {
    var cb = card.querySelector('input[type="checkbox"]');
    if (PRESET_TOOLS.indexOf(cb.value) !== -1) {
      cb.checked = true;
      card.classList.add('selected');
    }
    card.addEventListener('click', function(e) {
      if (card.classList.contains('disabled')) return;
      cb.checked = !cb.checked;
      card.classList.toggle('selected', cb.checked);
      updateScopeSections();
    });
  });

  function getSelectedTools() {
    var tools = [];
    form.querySelectorAll('input[name="tools"]:checked').forEach(function(cb) { tools.push(cb.value); });
    return tools;
  }

  /* ── Scope sections visibility based on selected tools ── */
  var TOOL_SECTION_MAP = {
    ss3:'scopeSs3Section', fracture:'scopeFractureSection', siphon:'scopeSiphonSection',
    osift:'scopeOsiftSection', auger:'scopeAugerSection', trawler:'scopeTrawlerSection',
    aether:'scopeWirelessSection', aether_b:'scopeWirelessSection', aether_z:'scopeWirelessSection', aether_u:'scopeWirelessSection',
    bastion:'scopeBastionSection', forge:'scopeForgeSection', quill:'scopeQuillSection',
    isotope:'scopeIsotopeSection', dredge:'scopeEndpointSection'
  };
  var EXCLUSION_TOOLS = ['ss3','osift','trawler','fracture','siphon','auger','dredge'];
  function updateScopeSections() {
    var tools = getSelectedTools();
    var shown = {};
    tools.forEach(function(t){ var s = TOOL_SECTION_MAP[t]; if(s) shown[s] = true; });
    Object.keys(TOOL_SECTION_MAP).forEach(function(k){
      var sec = TOOL_SECTION_MAP[k];
      var el = document.getElementById(sec);
      if (el) el.hidden = !shown[sec];
    });
    var exEl = document.getElementById('scopeExclusionsSection');
    if (exEl) exEl.hidden = !tools.some(function(t){ return EXCLUSION_TOOLS.indexOf(t) !== -1; });
    updateCloudFields();
    updateAwsAuthMethod();
    updateMobileMode();
    updateDredgeMode();
  }

  /* ── Client short auto-derive ────────────────────────── */
  var clientNameEl  = document.getElementById('clientName');
  var clientShortEl = document.getElementById('clientShort');
  var shortManual   = EDIT_MODE && clientShortEl.value.trim().length > 0;

  clientShortEl.addEventListener('input', function() { shortManual = this.value.trim().length > 0; });
  clientNameEl.addEventListener('input', function() {
    if (shortManual) return;
    var words = this.value.trim().split(/\s+/).filter(Boolean);
    if (!words.length) { clientShortEl.value = ''; return; }
    clientShortEl.value = words.length === 1
      ? words[0].substring(0,12).toLowerCase().replace(/[^a-z0-9_]/g,'')
      : words.map(function(w){return w[0];}).join('').toLowerCase().replace(/[^a-z0-9_]/g,'');
  });

  /* ── Step navigation ─────────────────────────────────── */
  function showStep(n) {
    currentStep = n;
    document.querySelectorAll('.wizard-panel').forEach(function(p) { p.hidden = parseInt(p.dataset.step) !== n; });
    stepDots.forEach(function(dot) {
      var s = parseInt(dot.dataset.step);
      dot.classList.remove('active','done');
      if (s === n) dot.classList.add('active');
      else if (s < n || EDIT_MODE) dot.classList.add('done');
    });
    btnBack.hidden   = (n <= 1);
    btnHome.style.display = (n > 1) ? 'none' : '';
    btnNext.hidden   = (n === TOTAL_STEPS);
    btnSubmit.hidden = (n !== TOTAL_STEPS);
    if (n === 2) applyScopeFilter();
    if (n === 3) updateScopeSections();
    if (n === TOTAL_STEPS) buildReview();
    window.scrollTo({top:0,behavior:'smooth'});
  }

  stepDots.forEach(function(dot) {
    dot.addEventListener('click', function() {
      var target = parseInt(this.dataset.step);
      if (target < currentStep) showStep(target);
      else if (EDIT_MODE) {
        var ok = true;
        for (var s = currentStep; s < target; s++) { if (!validateStep(s)) { ok = false; break; } }
        if (ok) showStep(target);
      }
      else if (target === currentStep + 1 && validateStep(currentStep)) showStep(target);
    });
  });

  btnNext.addEventListener('click', function() { if (validateStep(currentStep)) showStep(currentStep + 1); });
  btnBack.addEventListener('click', function() { if (currentStep > 1) showStep(currentStep - 1); });

  /* ── Validation ──────────────────────────────────────── */
  function validateStep(n) {
    clearErrors();
    if (n === 1) {
      var ok = true;
      if (!valOf('engName')) { markError(document.getElementById('engName'), 'Engagement name is required'); ok = false; }
      if (!valOf('clientName')) { markError(document.getElementById('clientName'), 'Client name is required'); ok = false; }
      if (!scopeTypeEl.value) { markError(scopeTypeEl, 'Scope type is required'); ok = false; }
      return ok;
    }
    if (n === 2) {
      var checked = form.querySelectorAll('.tool-select-card input[type="checkbox"]:checked');
      if (!checked.length) {
        var grid = document.querySelector('.tool-select-grid');
        var err = document.createElement('span'); err.className = 'form-error'; err.textContent = 'Select at least one tool';
        grid.parentNode.insertBefore(err, grid);
        return false;
      }
    }
    if (n === 3) {
      var ok = true;
      var quillSec = document.getElementById('scopeQuillSection');
      if (quillSec && !quillSec.hidden) {
        var _qm = (document.getElementById('mobileMode') || {}).value || 'static';
        var _qHasApp = mobileAppPaths.length > 0;
        var _qFrida = !!(document.getElementById('fridaEnabled') || {}).checked;
        var _qMitm = !!(document.getElementById('mitmEnabled') || {}).checked;
        var _qPlatform = (document.getElementById('mobilePlatform') || {}).value || 'auto';
        if ((_qm === 'static' || _qm === 'full') && !_qHasApp) {
          markError(document.getElementById('mobileAppPathInput'), 'At least one application binary is required for static analysis');
          ok = false;
        }
        if ((_qm === 'dynamic' || _qm === 'full') && !_qFrida && !_qMitm) {
          var _dynLabel = document.getElementById('mobileDynamicGroup');
          if (_dynLabel) { var _de = document.createElement('span'); _de.className = 'form-error'; _de.textContent = 'Select at least one dynamic method: Frida and/or MITM'; _dynLabel.insertBefore(_de, _dynLabel.firstChild); }
          ok = false;
        }
        if (_qFrida && !_qHasApp && !valOf('targetProcess')) {
          markError(document.getElementById('targetProcess'), 'Target process is required when no app binary is provided (e.g. com.example.app)');
          ok = false;
        }
        if (!_qHasApp && _qPlatform === 'auto') {
          markError(document.getElementById('mobilePlatform'), 'Select a platform — auto-detect requires an app binary');
          ok = false;
        }
      }
      return ok;
    }
    return true;
  }

  function markError(el, msg) {
    el.classList.add('is-error');
    var err = document.createElement('span'); err.className = 'form-error'; err.textContent = msg;
    el.parentNode.appendChild(err);
    if (!document.querySelector('.form-control.is-error:focus')) el.focus();
  }

  function clearErrors() {
    form.querySelectorAll('.is-error').forEach(function(el){ el.classList.remove('is-error'); });
    form.querySelectorAll('.form-error').forEach(function(el){ el.remove(); });
  }

  /* ── Build review panel ──────────────────────────────── */
  function buildReview() {
    var g = document.getElementById('reviewEngagement'); g.innerHTML = '';
    addR(g,'Name',valOf('engName')); addR(g,'Client',valOf('clientName'));
    addR(g,'Client Short',valOf('clientShort'));
    addR(g,'Scope',selText('scopeType')); addR(g,'Start Date',valOf('startDate')); addR(g,'End Date',valOf('endDate'));
    var _wizEh = document.getElementById('wizEngagementEnabled');
    if (_wizEh && _wizEh.checked) {
      addR(g,'Engagement Hours',document.getElementById('wizEngagementStart').value+' – '+document.getElementById('wizEngagementEnd').value+' ('+document.getElementById('wizEngagementTz').value+')');
    }
    var _wizSched = document.getElementById('wizSchedAt');
    if (_wizSched && _wizSched.value) {
      addR(g,'Scheduled Start',new Date(_wizSched.value).toLocaleString());
    }

    var td = document.getElementById('reviewTools'); td.innerHTML = '';
    var tools = getSelectedTools();
    if (!tools.length) { td.innerHTML = '<span class="review-tools-empty">No tools selected</span>'; }
    else tools.forEach(function(t) {
      var m = TOOL_META[t] || {key:t.toUpperCase(),name:t,cls:''};
      var c = document.createElement('span'); c.className = 'review-tool-chip';
      c.innerHTML = '<span class="tool-badge '+m.cls+'">'+escHtml(m.key)+'</span> '+escHtml(m.name); td.appendChild(c);
    });

    var sg = document.getElementById('reviewScope'); sg.innerHTML = '';
    function _sec(id){ var e=document.getElementById(id); return e && !e.hidden; }
    if (_sec('scopeSs3Section')) {
      addR(sg,'Network CIDRs',valOf('cidrs'));
      var _ss3mr = valOf('ss3DiscMinRate'); if (_ss3mr) addR(sg,'Discovery Min Rate',_ss3mr+' pps');
      var _ss3mp = valOf('ss3DiscMinParallelism'); if (_ss3mp) addR(sg,'Discovery Min Parallelism',_ss3mp);
      var _ss3tt = document.getElementById('ss3TimingTemplate').value; if (_ss3tt) addR(sg,'Timing Template','T'+_ss3tt+' — '+document.getElementById('ss3TimingTemplate').selectedOptions[0].text.split(' — ')[1]);
      var _ss3ps = valOf('ss3PassiveSeedDuration'); if (_ss3ps) addR(sg,'Passive Seed',_ss3ps+'s tcpdump → Trawler');
    }
    if (_sec('scopeFractureSection')) {
      addR(sg,'Web URLs',valOf('targetUrls'));
      var frR = getRoles('fr');
      addR(sg,'Fracture Roles', frR.length ? frR.map(function(r){return r.role+' ('+r.username+')';}).join(', ') : '—');
      var _ptaKeys = Object.keys(_perTargetAuth);
      if (_ptaKeys.length) {
        var _ptaTested = _ptaKeys.filter(function(u){ return _perTargetAuth[u]._tested; }).length;
        addR(sg,'Per-Target Auth', _ptaTested + '/' + _ptaKeys.length + ' URLs configured');
      } else if (_savedAuth.fracture) {
        addR(sg,'Fracture Auth','Saved ('+(_savedAuth.fracture.method||'none')+')');
      }
    }
    if (_sec('scopeSiphonSection')) {
      addR(sg,'API URLs',valOf('apiUrls'));
      addR(sg,'API Specs',apiFiles.length ? apiFiles.map(function(f){return f.name;}).join(', ') : '');
      var siR = getRoles('si');
      addR(sg,'Siphon Roles', siR.length ? siR.map(function(r){return r.role+' ('+r.username+')';}).join(', ') : '—');
      if (_savedAuth.siphon) addR(sg,'Siphon Auth','Saved ('+(_savedAuth.siphon.method||'none')+')');
    }
    if (_sec('scopeOsiftSection')) addR(sg,'Domains',valOf('domains'));
    if (_sec('scopeAugerSection')) {
      var auMode = document.getElementById('augerMode').value;
      if (auMode === 'file') {
        addR(sg,'Auger Mode','Database File Import');
        addR(sg,'File Type',selText('augerFileType'));
        addR(sg,'DB Files',dbFiles.length ? dbFiles.map(function(f){return f.name;}).join(', ') : '');
      } else {
        addR(sg,'DB Targets',valOf('dbTargets'));
        if (valOf('augerDbType')) addR(sg,'DB Type',selText('augerDbType'));
        if (valOf('augerUsername')) addR(sg,'DB Credentials',valOf('augerUsername') + ' / ********');
        if (valOf('augerJdbc')) addR(sg,'JDBC',valOf('augerJdbc'));
        if (document.getElementById('augerSsl').checked) addR(sg,'SSL','Enabled');
      }
    }
    if (_sec('scopeTrawlerSection')) {
      addR(sg,'PCAP Files',pcapFiles.length ? pcapFiles.map(function(f){return f.name;}).join(', ') : '');
      addR(sg,'Trawler Targets',valOf('trawlerTargets'));
    }
    if (_sec('scopeEndpointSection')) {
      addR(sg,'Endpoint Targets',valOf('endpointTargets'));
      var dgMode = document.getElementById('dredgeMode');
      if (dgMode) {
        addR(sg,'Dredge Mode',dgMode.value === 'winrm' ? 'WinRM Remote' : 'Import Collection');
        if (dgMode.value === 'import') {
          addR(sg,'Collection Path',dgCollectionPath || '');
          if (dgCollectionType) addR(sg,'Collection Type',dgCollectionType === 'cmd_dir' ? 'CMD Batch Directory' : 'PowerShell JSON');
        } else {
          addR(sg,'WinRM Host',valOf('dgWinrmHost'));
          if (valOf('dgWinrmUser')) addR(sg,'WinRM User',valOf('dgWinrmUser'));
          addR(sg,'WinRM Port',valOf('dgWinrmPort'));
          if (document.getElementById('dgWinrmSsl').checked) addR(sg,'WinRM SSL','Enabled');
        }
      }
      if (valOf('dgVtKey')) addR(sg,'VirusTotal API','Configured');
      if (valOf('dgAbuseKey')) addR(sg,'AbuseIPDB','Configured');
      if (valOf('dgSkipSections')) addR(sg,'Skip Sections',valOf('dgSkipSections'));
      var dgParsers = getDgExtParsers();
      if (dgParsers.length) addR(sg,'External Parsers',dgParsers.join(', '));
      if (dgExtToolFiles.length) addR(sg,'External Files',dgExtToolFiles.map(function(f){return f.name;}).join(', '));
    }
    if (_sec('scopeWirelessSection')) {
        var _wiSel = document.getElementById('wirelessInterface');
        var _wiAp = document.getElementById('wirelessApInterface');
        if (_wiSel && _wiSel.value) addR(sg,'Primary Interface',_wiSel.value);
        if (_wiAp && _wiAp.value) addR(sg,'AP Interface',_wiAp.value);
        addR(sg,'Default Scope Mode',document.getElementById('wirelessDefaultMode').value);
        addR(sg,'Active SSIDs',valOf('activeSSIDs'));
        addR(sg,'Passive SSIDs',valOf('passiveSSIDs'));
    }
    if (_sec('scopeBastionSection')) {
      addR(sg,'FW Vendor',selText('fwVendor'));
      addR(sg,'FW Configs',fwFiles.length ? fwFiles.map(function(f){return f.name;}).join(', ') : '');
    }
    if (_sec('scopeForgeSection')) {
      addR(sg,'Cloud Provider',selText('cloudProvider'));
      if (!document.getElementById('cloudAwsAuthBlock').hidden) {
        var _akid = valOf('awsAccessKeyId');
        var _curl = valOf('awsConsoleUrl');
        var _prof = valOf('awsProfile');
        if (_akid) addR(sg,'AWS Auth','Access Keys (' + _akid.substring(0,8) + '...)');
        else if (_curl) addR(sg,'AWS Auth','Console Login (' + _curl + ')');
        else addR(sg,'AWS Auth','CLI Profile (' + (_prof || 'default') + ')');
        if (valOf('awsRegion')) addR(sg,'AWS Region',valOf('awsRegion'));
      }
      if (!document.getElementById('cloudAzureGroup').hidden) addR(sg,'Azure Subscription',valOf('azureSubscription'));
      if (!document.getElementById('cloudGcpGroup').hidden) addR(sg,'GCP Project',valOf('gcpProject'));
    }
    if (_sec('scopeQuillSection')) {
      addR(sg,'Platform',selText('mobilePlatform'));
      addR(sg,'Analysis Mode',selText('mobileMode'));
      var _mm = document.getElementById('mobileMode').value;
      if (_mm === 'static' || _mm === 'full') {
        addR(sg,'App Files', mobileAppPaths.length ? mobileAppPaths.map(function(p){return p.split('/').pop();}).join(', ') : '(none)');
      }
      if (_mm === 'dynamic' || _mm === 'full') {
        var _dynParts = [];
        if ((document.getElementById('fridaEnabled') || {}).checked) {
          var _tp = valOf('targetProcess'); var _fd = valOf('fridaDevice');
          _dynParts.push('Frida' + (_tp ? ' (' + _tp + ')' : '') + (_fd ? ' on ' + _fd : ''));
        }
        if ((document.getElementById('mitmEnabled') || {}).checked) {
          var _mitmDesc = 'MITM (port ' + valOf('mitmPort') + ')';
          var _upProxy = valOf('mitmUpstreamProxy');
          if (_upProxy) {
            _mitmDesc += ' → ' + _upProxy;
            if (_proxyCaName) _mitmDesc += ' (CA: ' + _proxyCaName + ')';
          }
          _dynParts.push(_mitmDesc);
        }
        addR(sg,'Dynamic Testing', _dynParts.length ? _dynParts.join(' + ') : '(none selected)');
      }
      if (_mm === 'dynamic' || _mm === 'full') {
        var _qPhases = getQuillPhases();
        if (_qPhases.length === 7) {
          addR(sg, 'Analysis Phases', 'All (7 phases)');
        } else if (_qPhases.length) {
          addR(sg, 'Analysis Phases', _qPhases.join(', '));
        } else {
          addR(sg, 'Analysis Phases', '(none — legacy mode)');
        }
      }
    }
    if (_sec('scopeIsotopeSection')) {
      addR(sg,'Analysis Files',isoFiles.length ? isoFiles.map(function(f){return f.name;}).join(', ') : '');
      addR(sg,'Modules',getIsoModules().join(', '));
      addR(sg,'Archive Depth',valOf('isoArchiveDepth'));
    }
    addR(sg,'Exclusions',valOf('exclusions'));

    var pg = document.getElementById('reviewPeople'); pg.innerHTML = '';
    var hc = valOf('consultName')||valOf('consultTitle')||valOf('consultEmail');
    var hp = valOf('pocName')||valOf('pocPhone')||valOf('pocEmail');
    if (hc||hp) {
      document.getElementById('reviewConsultantSection').hidden = false;
      if (hc) addR(pg,'Consultant',[valOf('consultName'),valOf('consultTitle'),valOf('consultEmail')].filter(Boolean).join(' / '));
      if (hp) addR(pg,'Client POC',[valOf('pocName'),valOf('pocPhone'),valOf('pocEmail')].filter(Boolean).join(' / '));
    } else document.getElementById('reviewConsultantSection').hidden = true;
  }

  function addR(g,l,v) {
    var le = document.createElement('span'); le.className = 'review-label'; le.textContent = l; g.appendChild(le);
    var ve = document.createElement('span'); ve.className = v ? 'review-value' : 'review-empty'; ve.textContent = v || '—'; g.appendChild(ve);
  }

  function textToArray(id) {
    var raw = valOf(id); if (!raw) return [];
    return raw.split('\n').map(function(l){return l.trim();}).filter(Boolean);
  }

  /* ── Wireless interface selection + SSID scanning ─────── */
  var _wifiInterfaces = [];

  function refreshWifiInterfaces(preselect, preselectAp) {
    var sel = document.getElementById('wirelessInterface');
    var selAp = document.getElementById('wirelessApInterface');
    var scanBtn = document.getElementById('btnScanSSIDs');
    var info = document.getElementById('wirelessIfaceInfo');
    if (!sel) return;
    sel.innerHTML = '<option value="">Loading...</option>';
    if (selAp) selAp.innerHTML = '<option value="">Loading...</option>';
    fetch('/api/wifi-interfaces', {credentials: 'same-origin'})
      .then(function(r) { return r.json(); })
      .then(function(d) {
        _wifiInterfaces = d.interfaces || [];
        sel.innerHTML = '<option value="">— Select interface —</option>';
        if (selAp) selAp.innerHTML = '<option value="">— None (use primary) —</option>';
        if (!_wifiInterfaces.length) {
          sel.innerHTML = '<option value="">No wireless interfaces detected</option>';
          if (info) info.textContent = 'No wireless interfaces found on this system.';
          if (scanBtn) scanBtn.disabled = true;
          return;
        }
        _wifiInterfaces.forEach(function(iface) {
          var label = iface.interface;
          var details = [];
          if (iface.bus && iface.bus !== 'Unknown') details.push(iface.bus);
          if (iface.manufacturer) details.push(iface.manufacturer);
          if (details.length) label += ' (' + details.join(' — ') + ')';
          if (iface.mode && iface.mode !== 'unknown') label += ' [' + iface.mode + ']';
          if (iface.channel) label += ' ch' + iface.channel;
          var opt = document.createElement('option');
          opt.value = iface.interface;
          opt.textContent = label;
          sel.appendChild(opt);
          if (selAp) {
            var opt2 = opt.cloneNode(true);
            selAp.appendChild(opt2);
          }
        });
        if (preselect) sel.value = preselect;
        if (preselectAp && selAp) selAp.value = preselectAp;
        _updateIfaceInfo();
        if (scanBtn) scanBtn.disabled = !sel.value;
      })
      .catch(function() {
        sel.innerHTML = '<option value="">— Failed to load —</option>';
        if (info) info.textContent = 'Could not reach the server to list interfaces.';
      });
  }

  function _updateIfaceInfo() {
    var sel = document.getElementById('wirelessInterface');
    var info = document.getElementById('wirelessIfaceInfo');
    var scanBtn = document.getElementById('btnScanSSIDs');
    if (!sel || !info) return;
    var v = sel.value;
    if (scanBtn) scanBtn.disabled = !v;
    if (!v) { info.textContent = ''; return; }
    var iface = _wifiInterfaces.find(function(i) { return i.interface === v; });
    if (iface) {
      var parts = [];
      if (iface.manufacturer) parts.push(iface.manufacturer);
      if (iface.bus && iface.bus !== 'Unknown') parts.push(iface.bus);
      if (iface.mode && iface.mode !== 'unknown') parts.push('Mode: ' + iface.mode);
      if (iface.channel) parts.push('Channel: ' + iface.channel);
      if (iface.type && iface.type !== 'unknown') parts.push('Type: ' + iface.type);
      info.textContent = parts.join(' · ') || '';
    } else {
      info.textContent = '';
    }
  }

  var _ifSel = document.getElementById('wirelessInterface');
  if (_ifSel) _ifSel.addEventListener('change', _updateIfaceInfo);

  var _refreshBtn = document.getElementById('btnRefreshWifiIfaces');
  if (_refreshBtn) {
    _refreshBtn.addEventListener('click', function() {
      refreshWifiInterfaces();
    });
  }

  /* SSID Scanning */
  var _btnScan = document.getElementById('btnScanSSIDs');
  if (_btnScan) {
    _btnScan.addEventListener('click', function() {
      var iface = (document.getElementById('wirelessInterface') || {}).value;
      if (!iface) return;
      var status = document.getElementById('ssidScanStatus');
      var resultsDiv = document.getElementById('ssidScanResults');
      var body = document.getElementById('ssidScanBody');
      _btnScan.disabled = true;
      if (status) status.textContent = 'Scanning...';
      fetch('/api/wifi-scan?interface=' + encodeURIComponent(iface), {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
          var nets = d.networks || [];
          if (!nets.length) {
            if (status) status.textContent = 'No networks found. Try a different interface or check monitor mode.';
            _btnScan.disabled = false;
            return;
          }
          if (status) status.textContent = nets.length + ' network(s) found';
          body.innerHTML = '';
          var activeSet = {};
          textToArray('activeSSIDs').forEach(function(s) { activeSet[s] = true; });
          var passiveSet = {};
          textToArray('passiveSSIDs').forEach(function(s) { passiveSet[s] = true; });
          nets.sort(function(a, b) { return (b.signal || 0) - (a.signal || 0); });
          nets.forEach(function(n, i) {
            var ssid = n.ssid || '(hidden)';
            var bssid = n.bssid || '';
            var sig = n.signal != null ? n.signal + ' dBm' : '';
            var ch = n.channel || '';
            var sec = n.security || (n.encrypted ? 'Encrypted' : 'Open');
            var alreadyActive = activeSet[ssid];
            var alreadyPassive = passiveSet[ssid];
            var preAssign = alreadyActive ? 'active' : alreadyPassive ? 'passive' : 'active';
            var row = document.createElement('tr');
            row.innerHTML =
              '<td style="text-align:center"><input type="checkbox" class="ssid-scan-check" data-idx="' + i + '"' +
                (alreadyActive || alreadyPassive ? ' checked' : '') + '></td>' +
              '<td>' + _esc(ssid) + (alreadyActive ? ' <span style="color:var(--risk-info);font-size:0.75rem">(in active)</span>' :
                alreadyPassive ? ' <span style="color:var(--text-muted);font-size:0.75rem">(in passive)</span>' : '') + '</td>' +
              '<td style="font-family:monospace;font-size:0.78rem">' + _esc(bssid) + '</td>' +
              '<td style="text-align:center">' + _esc(sig) + '</td>' +
              '<td style="text-align:center">' + _esc(String(ch)) + '</td>' +
              '<td>' + _esc(sec) + '</td>' +
              '<td style="text-align:center"><select class="ssid-assign form-control" style="font-size:0.78rem;padding:2px 4px" data-idx="' + i + '">' +
                '<option value="active"' + (preAssign === 'active' ? ' selected' : '') + '>Active</option>' +
                '<option value="passive"' + (preAssign === 'passive' ? ' selected' : '') + '>Passive</option>' +
              '</select></td>';
            row.dataset.ssid = ssid;
            body.appendChild(row);
          });
          if (resultsDiv) resultsDiv.hidden = false;
          _btnScan.disabled = false;
        })
        .catch(function(err) {
          if (status) status.textContent = 'Scan failed: ' + (err.message || 'network error');
          _btnScan.disabled = false;
        });
    });
  }

  function _esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  var _selectAll = document.getElementById('ssidSelectAll');
  if (_selectAll) {
    _selectAll.addEventListener('change', function() {
      var checks = document.querySelectorAll('.ssid-scan-check');
      var v = this.checked;
      checks.forEach(function(c) { c.checked = v; });
    });
  }

  var _applyBtn = document.getElementById('btnApplySSIDs');
  if (_applyBtn) {
    _applyBtn.addEventListener('click', function() {
      var rows = document.querySelectorAll('#ssidScanBody tr');
      var activeTA = document.getElementById('activeSSIDs');
      var passiveTA = document.getElementById('passiveSSIDs');
      var activeList = textToArray('activeSSIDs');
      var passiveList = textToArray('passiveSSIDs');
      var activeSet = {}; activeList.forEach(function(s) { activeSet[s] = true; });
      var passiveSet = {}; passiveList.forEach(function(s) { passiveSet[s] = true; });
      rows.forEach(function(row) {
        var check = row.querySelector('.ssid-scan-check');
        var assign = row.querySelector('.ssid-assign');
        if (!check || !check.checked || !assign) return;
        var ssid = row.dataset.ssid;
        if (!ssid || ssid === '(hidden)') return;
        var target = assign.value;
        if (target === 'active' && !activeSet[ssid]) {
          activeList.push(ssid);
          activeSet[ssid] = true;
          if (passiveSet[ssid]) {
            passiveList = passiveList.filter(function(s) { return s !== ssid; });
            delete passiveSet[ssid];
          }
        } else if (target === 'passive' && !passiveSet[ssid]) {
          passiveList.push(ssid);
          passiveSet[ssid] = true;
          if (activeSet[ssid]) {
            activeList = activeList.filter(function(s) { return s !== ssid; });
            delete activeSet[ssid];
          }
        }
      });
      if (activeTA) activeTA.value = activeList.join('\n');
      if (passiveTA) passiveTA.value = passiveList.join('\n');
      validateSSIDExclusivity();
      checkWirelessAutoQueueGating();
    });
  }

  var _clearScanBtn = document.getElementById('btnClearScanResults');
  if (_clearScanBtn) {
    _clearScanBtn.addEventListener('click', function() {
      var resultsDiv = document.getElementById('ssidScanResults');
      if (resultsDiv) resultsDiv.hidden = true;
      var body = document.getElementById('ssidScanBody');
      if (body) body.innerHTML = '';
      var status = document.getElementById('ssidScanStatus');
      if (status) status.textContent = '';
    });
  }

  /* Auto-load interfaces when wireless section becomes visible */
  var _wifiIfacesLoaded = false;
  var _scopeObs = new MutationObserver(function(mutations) {
    mutations.forEach(function(m) {
      if (m.attributeName === 'hidden') {
        var el = m.target;
        if (el.id === 'scopeWirelessSection' && !el.hidden && !_wifiIfacesLoaded) {
          _wifiIfacesLoaded = true;
          var preIface = '';
          var preApIface = '';
          if (EDIT_MODE && _cfg) {
            preIface = _cfg.wirelessInterface || '';
            preApIface = _cfg.wirelessApInterface || '';
          }
          refreshWifiInterfaces(preIface, preApIface);
        }
      }
    });
  });
  var _scopeEl = document.getElementById('scopeWirelessSection');
  if (_scopeEl) _scopeObs.observe(_scopeEl, {attributes: true, attributeFilter: ['hidden']});

  /* ── SSID mutual exclusivity validation ────────────────── */
  function validateSSIDExclusivity() {
    var active = textToArray('activeSSIDs');
    var passive = textToArray('passiveSSIDs');
    var activeSet = {};
    active.forEach(function(s) { activeSet[s] = true; });
    var overlap = passive.filter(function(s) { return activeSet[s]; });
    var warn = document.getElementById('ssidOverlapWarning');
    if (overlap.length) {
      if (warn) {
        warn.textContent = 'The following SSID(s) appear in both Active and Passive scope: ' + overlap.join(', ');
        warn.hidden = false;
      }
      return false;
    }
    if (warn) warn.hidden = true;
    return true;
  }

  /* ── Auto-queue gating for wireless-only passive scope ── */
  function checkWirelessAutoQueueGating() {
    var aqCheckbox = document.getElementById('autoQueue');
    if (!aqCheckbox) return;
    var active = textToArray('activeSSIDs');
    var passive = textToArray('passiveSSIDs');
    var defMode = (document.getElementById('wirelessDefaultMode') || {}).value || 'active';
    var hasAnyWireless = active.length > 0 || passive.length > 0;
    if (hasAnyWireless && active.length === 0 && passive.length > 0 && defMode === 'passive') {
      aqCheckbox.checked = false;
      aqCheckbox.disabled = true;
      var label = aqCheckbox.closest('label') || aqCheckbox.parentElement;
      if (label) label.setAttribute('data-tooltip', 'Auto-queue disabled: all SSIDs are passive (monitoring only)');
    } else {
      aqCheckbox.disabled = false;
      var label2 = aqCheckbox.closest('label') || aqCheckbox.parentElement;
      if (label2) label2.removeAttribute('data-tooltip');
    }
  }

  /* Wire live validation to textareas and default mode select */
  ['activeSSIDs', 'passiveSSIDs'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', function() { validateSSIDExclusivity(); checkWirelessAutoQueueGating(); });
      el.addEventListener('blur', function() { validateSSIDExclusivity(); checkWirelessAutoQueueGating(); });
    }
  });
  var wdm = document.getElementById('wirelessDefaultMode');
  if (wdm) wdm.addEventListener('change', function() { checkWirelessAutoQueueGating(); });

  /* ── Submit ──────────────────────────────────────────── */
  btnSubmit.addEventListener('click', function() {
    if (!validateStep(1) || !validateStep(2) || !validateStep(3)) {
      return;
    }
    if (!validateSSIDExclusivity()) {
      return;
    }
    btnSubmit.disabled = true;
    btnSubmit.textContent = EDIT_MODE ? 'Saving…' : 'Creating…';

    var payload = {
      name: valOf('engName'),
      client_name: valOf('clientName'),
      client_short: valOf('clientShort') || valOf('clientName').toLowerCase().replace(/\s+/g,'_').replace(/[^a-z0-9_]/g,''),
      scope: document.getElementById('scopeType').value,
      start_date: valOf('startDate'),
      end_date: valOf('endDate'),
      tools: getSelectedTools(),
      auto_queue: document.getElementById('autoQueue').checked,
      beacon_url: valOf('wizBeaconUrl'),
      beacon_enabled: document.getElementById('wizBeaconEnabled') ? document.getElementById('wizBeaconEnabled').checked : false,
      oos_handling: (document.querySelector('input[name="oosHandling"]:checked') || {}).value || 'explicit',
      consultant: {name:valOf('consultName'),title:valOf('consultTitle'),email:valOf('consultEmail')},
      client_poc: {name:valOf('pocName'),phone:valOf('pocPhone'),email:valOf('pocEmail')},
      scope_definition: {
        network_cidrs: textToArray('cidrs'),
        ss3_discovery_min_rate: parseInt(valOf('ss3DiscMinRate')) || 0,
        ss3_discovery_min_parallelism: parseInt(valOf('ss3DiscMinParallelism')) || 0,
        ss3_timing_template: document.getElementById('ss3TimingTemplate').value,
        ss3_passive_seed_duration: parseInt(valOf('ss3PassiveSeedDuration')) || 0,
        target_urls: textToArray('targetUrls'),
        fracture_roles: getRoles('fr'),
        fracture_auth: _savedAuth.fracture || null,
        fracture_per_target_auth: (function() {
          var c = {}; for (var u in _perTargetAuth) { if (_perTargetAuth.hasOwnProperty(u)) {
            var a = {}; for (var k in _perTargetAuth[u]) { if (k !== '_tested') a[k] = _perTargetAuth[u][k]; }
            c[u] = a;
          }} return Object.keys(c).length ? c : null;
        })(),
        api_urls: textToArray('apiUrls'),
        api_specs: apiFiles.map(function(f){return f.name;}),
        siphon_roles: getRoles('si'),
        siphon_auth: _savedAuth.siphon || null,
        domains: textToArray('domains'),
        db_targets: textToArray('dbTargets'),
        auger_mode: document.getElementById('augerMode') ? document.getElementById('augerMode').value : 'remote',
        auger_db_type: valOf('augerDbType'),
        auger_database: valOf('augerDatabase'),
        auger_username: valOf('augerUsername'),
        auger_password: valOf('augerPassword'),
        auger_jdbc: valOf('augerJdbc'),
        auger_ssl: document.getElementById('augerSsl') ? document.getElementById('augerSsl').checked : false,
        auger_file_type: document.getElementById('augerFileType') ? document.getElementById('augerFileType').value : '',
        auger_db_files: dbFiles.map(function(f){return f.name;}),
        trawler_pcaps: pcapFiles.map(function(f){return f.name;}),
        trawler_targets: textToArray('trawlerTargets'),
        endpoint_targets: textToArray('endpointTargets'),
        dredge_mode: document.getElementById('dredgeMode') ? document.getElementById('dredgeMode').value : 'import',
        dredge_collection_path: dgCollectionPath,
        dredge_winrm_host: valOf('dgWinrmHost'),
        dredge_winrm_user: valOf('dgWinrmUser'),
        dredge_winrm_pass: valOf('dgWinrmPass'),
        dredge_winrm_port: parseInt(valOf('dgWinrmPort')) || 5985,
        dredge_winrm_ssl: document.getElementById('dgWinrmSsl') ? document.getElementById('dgWinrmSsl').checked : false,
        dredge_vt_key: valOf('dgVtKey'),
        dredge_abuseipdb_key: valOf('dgAbuseKey'),
        dredge_skip_sections: valOf('dgSkipSections'),
        dredge_ext_parsers: getDgExtParsers(),
        dredge_ext_files: dgExtToolFiles.map(function(f){return f.name;}),
        wireless_interface: (document.getElementById('wirelessInterface') || {}).value || '',
        wireless_ap_interface: (document.getElementById('wirelessApInterface') || {}).value || '',
        wireless_active_ssids: textToArray('activeSSIDs'),
        wireless_passive_ssids: textToArray('passiveSSIDs'),
        wireless_default_scope_mode: document.getElementById('wirelessDefaultMode').value,
        wireless_ssids: textToArray('activeSSIDs').concat(textToArray('passiveSSIDs')),
        exclusions: textToArray('exclusions'),
        firewall_vendor: document.getElementById('fwVendor').value,
        firewall_configs: fwFiles.map(function(f){return f.name;}),
        cloud_provider: document.getElementById('cloudProvider').value,
        aws_auth_method: (document.querySelector('input[name="awsAuthMethod"]:checked') || {}).value || 'profile',
        aws_profile: valOf('awsProfile'),
        aws_region: valOf('awsRegion'),
        aws_access_key_id: valOf('awsAccessKeyId'),
        aws_secret_key: valOf('awsSecretKey'),
        aws_console_url: valOf('awsConsoleUrl'),
        aws_console_user: valOf('awsConsoleUser'),
        aws_console_pass: valOf('awsConsolePass'),
        azure_subscription: valOf('azureSubscription'),
        gcp_project: valOf('gcpProject'),
        mobile_platform: (document.getElementById('mobilePlatform') || {}).value || 'auto',
        analysis_mode: (document.getElementById('mobileMode') || {}).value || 'static',
        mobile_app_paths: mobileAppPaths.slice(),
        frida_analysis: !!(document.getElementById('fridaEnabled') || {}).checked,
        frida_device: valOf('fridaDevice'),
        target_process: valOf('targetProcess'),
        mitm_analysis: !!(document.getElementById('mitmEnabled') || {}).checked,
        mitm_port: parseInt(valOf('mitmPort')) || 8080,
        mitm_upstream_proxy: valOf('mitmUpstreamProxy'),
        mitm_proxy_ca_pem: _proxyCaPem,
        mitm_proxy_ca_name: _proxyCaName,
        quill_phases: getQuillPhases(),
        isotope_files: isoFiles.map(function(f){return f.name;}),
        isotope_modules: getIsoModules(),
        isotope_archive_depth: parseInt(valOf('isoArchiveDepth')) || 5
      }
    };

    /* Engagement hours */
    var wizEhEnabled = document.getElementById('wizEngagementEnabled');
    if (wizEhEnabled && wizEhEnabled.checked) {
      var ehDays = [];
      document.querySelectorAll('.wizEngDay:checked').forEach(function(cb) {
        ehDays.push(parseInt(cb.value));
      });
      payload.engagement_hours = {
        enabled: true,
        start_time: document.getElementById('wizEngagementStart').value,
        end_time: document.getElementById('wizEngagementEnd').value,
        timezone: document.getElementById('wizEngagementTz').value,
        days: ehDays
      };
    }

    /* Scheduled engagement start */
    var wizSchedAt = document.getElementById('wizSchedAt');
    if (wizSchedAt && wizSchedAt.value) {
      payload.scheduled_start = new Date(wizSchedAt.value).toISOString();
    }

    var url = EDIT_MODE ? '/api/update_project/' + PROJECT_ID : '/api/create_project';
    fetch(url, {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
    .then(function(r) { if (!r.ok) return r.json().then(function(d){throw new Error(d.error||'Server error');}); return r.json(); })
    .then(function(data) { window.location.href = '/project/' + (data.project_id || data.id || PROJECT_ID); })
    .catch(function(err) {
      btnSubmit.disabled = false;
      btnSubmit.textContent = EDIT_MODE ? 'Save Changes' : 'Create Engagement';
      alert('Error: ' + err.message);
    });
  });

  /* ── Helpers ─────────────────────────────────────────── */
  function valOf(id) { var el = document.getElementById(id); return el ? el.value.trim() : ''; }
  function selText(id) { var el = document.getElementById(id); return el ? el.options[el.selectedIndex].text : ''; }
  function escHtml(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function formatBytes(b) { if(b<1024)return b+' B'; if(b<1048576)return(b/1024).toFixed(1)+' KB'; return(b/1048576).toFixed(1)+' MB'; }

  /* ── PCAP files (Trawler) ──────────────────────────────── */
  var pcapFiles = [];
  var pcapFileEl = document.getElementById('pcapFile');
  var pcapListEl = document.getElementById('pcapList');
  var pcapCountEl = document.getElementById('pcapCount');
  if (pcapFileEl) {
    pcapFileEl.addEventListener('change', function() {
      for (var i = 0; i < this.files.length; i++) pcapFiles.push(this.files[i]);
      this.value = '';
      renderPcapFiles();
    });
  }
  function renderPcapFiles() {
    if (!pcapListEl) return;
    pcapListEl.innerHTML = '';
    pcapCountEl.textContent = pcapFiles.length ? pcapFiles.length + ' file(s)' : 'No files selected';
    pcapFiles.forEach(function(f, idx) {
      var li = document.createElement('li');
      li.innerHTML = '<span>' + escHtml(f.name) + '</span><span class="form-hint">' + formatBytes(f.size) + '</span><button type="button" class="file-remove" data-idx="' + idx + '">&times;</button>';
      pcapListEl.appendChild(li);
    });
    pcapListEl.querySelectorAll('.file-remove').forEach(function(btn) {
      btn.addEventListener('click', function() {
        pcapFiles.splice(parseInt(this.dataset.idx), 1);
        renderPcapFiles();
      });
    });
  }

  /* ── Role matrix (per-tool: fr = Fracture, si = Siphon) ── */
  function _escAttr(s) { return (s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }

  function addRoleRow(prefix, role, username, password) {
    var wrap = document.getElementById(prefix + 'RoleRows');
    if (!wrap) return;
    var row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:.5rem;align-items:center;flex-wrap:wrap';
    row.innerHTML =
      '<input type="text" class="form-control role-name" placeholder="Role name (e.g. admin)" value="'+_escAttr(role||'')+'" style="flex:1;min-width:120px">' +
      '<input type="text" class="form-control role-user" placeholder="Username" value="'+_escAttr(username||'')+'" style="flex:1;min-width:140px">' +
      '<input type="password" class="form-control role-pass" placeholder="Password" value="'+_escAttr(password||'')+'" style="flex:1;min-width:140px" autocomplete="new-password">' +
      '<button type="button" class="btn btn-sm btn-ghost" style="color:#f85149;flex-shrink:0" onclick="removeRoleRow(this,\''+prefix+'\')" title="Remove row">&#x2715;</button>';
    wrap.appendChild(row);
  }

  window.removeRoleRow = function(btn, prefix) {
    btn.parentElement.remove();
  };

  function getRoles(prefix) {
    var wrap = document.getElementById(prefix + 'RoleRows');
    if (!wrap) return [];
    var roles = [];
    wrap.querySelectorAll('div').forEach(function(row) {
      var name = row.querySelector('.role-name');
      var user = row.querySelector('.role-user');
      var pass = row.querySelector('.role-pass');
      if (name && user) {
        var r = name.value.trim(), u = user.value.trim(), p = pass ? pass.value : '';
        if (r || u) roles.push({role:r,username:u,password:p});
      }
    });
    return roles;
  }

  /* ── Per-tool test connection ─────────────────────────── */
  var TC_AUTH_FIELDS = {
    none:[],
    auto:[{key:'username',label:'Username',type:'text'},{key:'password',label:'Password',type:'password'}],
    bearer:[{key:'token',label:'Token',type:'text',placeholder:'eyJhbGciOiJ...'}],
    basic:[{key:'username',label:'Username',type:'text'},{key:'password',label:'Password',type:'password'}],
    form_login:[{key:'username',label:'Username',type:'text'},{key:'password',label:'Password',type:'password'},{key:'login_url',label:'Login URL',type:'text',placeholder:'https://app/login'},{key:'login_mode',label:'Login Mode',type:'text',placeholder:'standard'}],
    api_key:[{key:'api_key',label:'API Key',type:'text'},{key:'api_key_header',label:'Header Name',type:'text',placeholder:'X-API-Key'}],
    session_cookie:[{key:'session_cookie',label:'Cookie Value',type:'text',placeholder:'session=abc123'}],
    oauth2_client:[{key:'oauth_token_url',label:'Token URL',type:'text'},{key:'oauth_client_id',label:'Client ID',type:'text'},{key:'oauth_client_secret',label:'Client Secret',type:'password'},{key:'oauth_scope',label:'Scope',type:'text'}],
    oauth1:[{key:'oauth1_consumer_key',label:'Consumer Key',type:'text'},{key:'oauth1_consumer_secret',label:'Consumer Secret',type:'password'},{key:'oauth1_token',label:'Access Token',type:'text'},{key:'oauth1_token_secret',label:'Token Secret',type:'password'}],
    ntlm:[{key:'username',label:'Username',type:'text'},{key:'password',label:'Password',type:'password'},{key:'domain',label:'Domain',type:'text'}],
    digest:[{key:'username',label:'Username',type:'text'},{key:'password',label:'Password',type:'password'}],
    mtls:[{key:'mtls_cert',label:'Client Cert Path',type:'text'},{key:'mtls_key',label:'Client Key Path',type:'text'},{key:'mtls_ca_bundle',label:'CA Bundle Path',type:'text'}],
    saml:[{key:'saml_assertion',label:'SAML Assertion',type:'text'},{key:'saml_acs_url',label:'ACS URL',type:'text'}],
    oidc:[{key:'oidc_id_token',label:'ID Token',type:'text'},{key:'oidc_userinfo_url',label:'UserInfo URL',type:'text'}],
    totp:[{key:'username',label:'Username',type:'text'},{key:'password',label:'Password',type:'password'},{key:'totp_secret',label:'TOTP Secret',type:'text'}],
    proxy_header:[{key:'proxy_header_name',label:'Header Name',type:'text'},{key:'proxy_header_value',label:'Header Value',type:'text'}],
    kerberos:[{key:'username',label:'Username',type:'text'},{key:'password',label:'Password',type:'password'},{key:'kerberos_realm',label:'Realm',type:'text'}],
    custom_header:[{key:'token',label:'Header Value',type:'text',placeholder:'Bearer xyz...'},{key:'token_type',label:'Header Name',type:'text',placeholder:'Authorization'}]
  };

  var _savedAuth = {};
  var _perTargetAuth = {};

  function updateFrTargetTable() {
    var urls = textToArray('targetUrls');
    var section = document.getElementById('frPerTargetAuthSection');
    var tbody = document.getElementById('frPerTargetAuthBody');
    var targetSelect = document.getElementById('frTcTarget');
    if (!section || !tbody || !targetSelect) return;
    section.hidden = urls.length === 0;
    tbody.innerHTML = '';
    var prevVal = targetSelect.value;
    targetSelect.innerHTML = '<option value="">— Select a target URL —</option>';
    urls.forEach(function(url) {
      var auth = _perTargetAuth[url] || {};
      var tested = auth._tested;
      var method = auth.method || 'auto';
      var preview = method === 'auto' ? 'Auto-Detect' : method;
      if (auth.username) preview += ' (' + auth.username.substring(0, 20) + (auth.username.length > 20 ? '…' : '') + ')';
      var tr = document.createElement('tr');
      tr.style.borderBottom = '1px solid var(--border-subtle, var(--border))';
      tr.innerHTML =
        '<td style="padding:6px 8px;word-break:break-all;max-width:300px">' + escHtml(url) + '</td>' +
        '<td style="padding:6px 8px;text-align:center;color:' + (tested ? 'var(--status-success, #22c55e)' : 'var(--text-muted, #888)') + ';font-weight:600">' + (tested ? '✓' : '—') + '</td>' +
        '<td style="padding:6px 8px;color:var(--text-muted, #888)">' + escHtml(preview) + '</td>';
      tbody.appendChild(tr);
      var opt = document.createElement('option');
      opt.value = url; opt.textContent = url;
      if (url === prevVal) opt.selected = true;
      targetSelect.appendChild(opt);
    });
  }

  var _frUrlsEl = document.getElementById('targetUrls');
  if (_frUrlsEl) {
    _frUrlsEl.addEventListener('input', updateFrTargetTable);
    _frUrlsEl.addEventListener('blur', updateFrTargetTable);
  }

  function renderTcAuthFields(prefix) {
    var methodEl = document.getElementById(prefix + 'TcAuthMethod');
    var fieldsEl = document.getElementById(prefix + 'TcAuthFields');
    if (!methodEl || !fieldsEl) return;
    var fields = TC_AUTH_FIELDS[methodEl.value] || [];
    fieldsEl.innerHTML = '';
    fields.forEach(function(f) {
      var fid = prefix + '_tc_' + f.key;
      var div = document.createElement('div'); div.style.marginBottom = '8px';
      div.innerHTML = '<label class="form-label" for="'+fid+'">'+escHtml(f.label)+'</label>'
        +'<input type="'+(f.type||'text')+'" id="'+fid+'" class="form-control tc-auth-input" data-key="'+f.key+'"'
        +(f.placeholder?' placeholder="'+escHtml(f.placeholder)+'"':'')+'>';
      fieldsEl.appendChild(div);
    });
  }

  function collectTcAuth(prefix) {
    var methodEl = document.getElementById(prefix + 'TcAuthMethod');
    var fieldsEl = document.getElementById(prefix + 'TcAuthFields');
    if (!methodEl) return {};
    var method = methodEl.value;
    if (method === 'none') return {};
    var auth = {method:method};
    var roles = getRoles(prefix);
    if (roles.length) {
      auth.username = roles[0].username;
      auth.password = roles[0].password;
    }
    fieldsEl.querySelectorAll('.tc-auth-input').forEach(function(el) {
      if (!el.value.trim()) return;
      auth[el.dataset.key] = el.value;
    });
    return auth;
  }

  function setupTestConn(prefix, toolId) {
    var methodEl = document.getElementById(prefix + 'TcAuthMethod');
    var btnEl    = document.getElementById('btn' + prefix.charAt(0).toUpperCase() + prefix.slice(1) + 'TestConn');
    var saveBtn  = document.getElementById('btn' + prefix.charAt(0).toUpperCase() + prefix.slice(1) + 'SaveAuth');
    if (methodEl) methodEl.addEventListener('change', function(){ renderTcAuthFields(prefix); });
    renderTcAuthFields(prefix);

    if (btnEl) {
      btnEl.addEventListener('click', function() {
        var target = valOf(prefix + 'TcTarget');
        if (!target) { alert(prefix === 'fr' ? 'Select a target URL from the dropdown.' : 'Enter a target URL.'); return; }
        var btn = this; btn.disabled = true; btn.textContent = 'Testing...';
        var authPayload = collectTcAuth(prefix);
        fetch('/api/test-connection/' + toolId, {
          method:'POST',credentials:'same-origin',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({target:target,auth:authPayload})
        })
        .then(function(r){return r.json();})
        .then(function(d) {
          var area = document.getElementById(prefix + 'TcResultArea'); area.hidden = false;
          document.getElementById(prefix + 'TcResultTitle').textContent = d.ok ? 'Connection Successful' : 'Connection Failed';
          document.getElementById(prefix + 'TcResultBadge').innerHTML = d.ok
            ? '<span class="status-badge" style="background:var(--status-running);color:#fff">OK</span>'
            : '<span class="status-badge" style="background:var(--status-error);color:#fff">FAIL</span>';
          document.getElementById(prefix + 'TcResultBody').textContent = d.result
            ? JSON.stringify(d.result,null,2)
            : (d.stdout||'')+(d.stderr?'\n--- stderr ---\n'+d.stderr:'')+(d.error?'\nError: '+d.error:'');
          var saveArea = document.getElementById(prefix + 'TcSaveArea');
          if (saveArea) saveArea.hidden = !d.ok;
          if (d.ok && d.result && d.result.discovered_method && prefix === 'fr') {
            var methodEl = document.getElementById(prefix + 'TcAuthMethod');
            if (methodEl) { methodEl.value = d.result.discovered_method; renderTcAuthFields(prefix); }
          }
          // Enable fingerprint button on test-connection failure (FR only)
          if (!d.ok && prefix === 'fr') {
            var fpBtn = document.getElementById('btnFrFingerprint');
            if (fpBtn) { fpBtn.disabled = false; fpBtn.title = 'Record auth flow via a real browser'; }
          }
        })
        .catch(function(e) {
          var area = document.getElementById(prefix + 'TcResultArea'); area.hidden = false;
          document.getElementById(prefix + 'TcResultTitle').textContent = 'Error';
          document.getElementById(prefix + 'TcResultBadge').innerHTML = '<span class="status-badge" style="background:var(--status-error);color:#fff">ERR</span>';
          document.getElementById(prefix + 'TcResultBody').textContent = e.message || 'Request failed';
          // Enable fingerprint button on error too (FR only)
          if (prefix === 'fr') {
            var fpBtn = document.getElementById('btnFrFingerprint');
            if (fpBtn) { fpBtn.disabled = false; fpBtn.title = 'Record auth flow via a real browser'; }
          }
        })
        .finally(function(){ btn.disabled = false; btn.textContent = 'Test Connection'; });
      });
    }

    if (saveBtn) {
      saveBtn.addEventListener('click', function() {
        var auth = collectTcAuth(prefix);
        var selectedUrl = document.getElementById(prefix + 'TcTarget').value;
        auth.target = selectedUrl;
        if (selectedUrl && prefix === 'fr') {
          auth._tested = true;
          _perTargetAuth[selectedUrl] = auth;
          updateFrTargetTable();
        }
        _savedAuth[toolId] = auth;
        var statusEl = document.getElementById(prefix + 'TcSaveStatus');
        if (statusEl) statusEl.textContent = selectedUrl
          ? 'Auth saved for ' + selectedUrl
          : 'Saved for ' + toolId.charAt(0).toUpperCase() + toolId.slice(1);
      });
    }
  }

  setupTestConn('fr', 'fracture');
  setupTestConn('si', 'siphon');

  /* ── Fingerprint Auth (FR only) ───────────────────────── */
  (function() {
    var fpBtn = document.getElementById('btnFrFingerprint');
    if (!fpBtn) return;
    fpBtn.addEventListener('click', function() {
      var target = valOf('frTcTarget');
      if (!target) { alert('Enter a target URL first.'); return; }
      fpBtn.disabled = true; fpBtn.textContent = 'Launching...';
      var statusEl = document.getElementById('frFpStatus');
      if (statusEl) statusEl.textContent = 'Starting fingerprint browser...';
      fetch('/api/fingerprint-auth', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target})
      })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var area = document.getElementById('frFpResultArea'); area.hidden = false;
        if (d.ok) {
          document.getElementById('frFpResultTitle').textContent = 'Fingerprint Captured';
          document.getElementById('frFpResultBadge').innerHTML =
            '<span class="status-badge" style="background:var(--status-running);color:#fff">OK</span>';
          document.getElementById('frFpResultBody').textContent = JSON.stringify(d.fingerprint, null, 2);
          var reminder = document.getElementById('frFpReminderArea');
          if (reminder) reminder.hidden = false;
          if (statusEl) statusEl.textContent = '';
          // Auto-populate auth fields from fingerprint
          if (d.fingerprint && d.fingerprint.fracture_auth_config) {
            var fc = d.fingerprint.fracture_auth_config;
            var methodEl = document.getElementById('frTcAuthMethod');
            if (methodEl && fc.method) {
              methodEl.value = fc.method;
              renderTcAuthFields('fr');
              setTimeout(function() {
                if (fc.login_url) {
                  var lu = document.querySelector('#frTcAuthFields [data-key="login_url"]');
                  if (lu) lu.value = fc.login_url;
                }
                if (fc.username_field) {
                  var uf = document.querySelector('#frTcAuthFields [data-key="login_username_field"]');
                  if (uf) uf.value = fc.username_field;
                }
                if (fc.password_field) {
                  var pf = document.querySelector('#frTcAuthFields [data-key="login_password_field"]');
                  if (pf) pf.value = fc.password_field;
                }
                if (fc.login_mode) {
                  var lm = document.querySelector('#frTcAuthFields [data-key="login_mode"]');
                  if (lm) lm.value = fc.login_mode;
                }
              }, 100);
            }
          }
        } else {
          document.getElementById('frFpResultTitle').textContent = 'Fingerprint Failed';
          document.getElementById('frFpResultBadge').innerHTML =
            '<span class="status-badge" style="background:var(--status-error);color:#fff">FAIL</span>';
          document.getElementById('frFpResultBody').textContent = d.error || d.stderr || 'Unknown error';
          if (statusEl) statusEl.textContent = '';
        }
      })
      .catch(function(e) {
        var area = document.getElementById('frFpResultArea'); area.hidden = false;
        document.getElementById('frFpResultTitle').textContent = 'Error';
        document.getElementById('frFpResultBadge').innerHTML =
          '<span class="status-badge" style="background:var(--status-error);color:#fff">ERR</span>';
        document.getElementById('frFpResultBody').textContent = e.message || 'Request failed';
        if (statusEl) statusEl.textContent = '';
      })
      .finally(function() { fpBtn.disabled = false; fpBtn.textContent = 'Fingerprint Auth'; });
    });
  })();

  /* ── OOS Handling — confirmation modal ────────────────── */
  var _oosRadios = document.querySelectorAll('input[name="oosHandling"]');
  var _oosModal = document.getElementById('oosConfirmModal');
  var _oosPendingValue = null;

  function _showOosModal(val) {
    _oosPendingValue = val;
    document.getElementById('oosModalSeparated').hidden = (val !== 'separated');
    document.getElementById('oosModalCombined').hidden = (val !== 'combined');
    _oosModal.classList.add('open');
  }

  _oosRadios.forEach(function(r) {
    r.addEventListener('change', function() {
      if (this.value !== 'explicit') {
        _showOosModal(this.value);
      }
    });
  });

  document.getElementById('oosModalConfirm').addEventListener('click', function() {
    _oosModal.classList.remove('open');
    _oosPendingValue = null;
  });

  function _cancelOos() {
    _oosModal.classList.remove('open');
    document.querySelector('input[name="oosHandling"][value="explicit"]').checked = true;
    _oosPendingValue = null;
  }
  document.getElementById('oosModalCancel').addEventListener('click', _cancelOos);
  document.getElementById('oosModalDeny').addEventListener('click', _cancelOos);

  /* ── Edit mode: restore saved roles ────────────────────── */
  if (EDIT_MODE) {
    (_cfg.fractureRoles || []).forEach(function(r) { addRoleRow('fr', r.role, r.username, r.password); });
    (_cfg.siphonRoles || []).forEach(function(r) { addRoleRow('si', r.role, r.username, r.password); });

    if (_cfg.cloudProvider && _cfg.cloudProvider !== 'all') {
      cloudProviderEl.value = _cfg.cloudProvider;
    }
    var _authMethod = _cfg.awsAuthMethod || '';
    if (!_authMethod) {
      if (document.getElementById('awsConsoleUrl').value) _authMethod = 'console';
      else if (document.getElementById('awsAccessKeyId').value) _authMethod = 'keys';
      else if (document.getElementById('awsProfile').value) _authMethod = 'profile';
    }
    if (_authMethod) {
      var _radio = document.querySelector('input[name="awsAuthMethod"][value="' + _authMethod + '"]');
      if (_radio) _radio.checked = true;
    }
    updateCloudFields();
    updateAwsAuthMethod();
    var _fpta = _cfg.fracturePerTargetAuth || {};
    if (Object.keys(_fpta).length) {
      _perTargetAuth = _fpta;
      for (var _u in _perTargetAuth) { if (_perTargetAuth.hasOwnProperty(_u)) _perTargetAuth[_u]._tested = true; }
    }
    setTimeout(updateFrTargetTable, 100);
  }

  if (!EDIT_MODE) { setTimeout(updateFrTargetTable, 100); }

  /* ── Edit mode: load existing engagement hours + scheduled starts ── */
  if (EDIT_MODE && PROJECT_ID) {
    fetch('/api/engagement_hours/' + PROJECT_ID)
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d || !d.enabled) return;
        var toggle = document.getElementById('wizEngagementEnabled');
        if (toggle) { toggle.checked = true; toggle.dispatchEvent(new Event('change')); }
        var s = document.getElementById('wizEngagementStart');
        var e = document.getElementById('wizEngagementEnd');
        var tz = document.getElementById('wizEngagementTz');
        if (s && d.start_time) s.value = d.start_time;
        if (e && d.end_time) e.value = d.end_time;
        if (tz && d.timezone) tz.value = d.timezone;
        if (d.days) {
          document.querySelectorAll('.wizEngDay').forEach(function(cb) {
            cb.checked = d.days.indexOf(parseInt(cb.value)) !== -1;
          });
        }
      }).catch(function() {});
    fetch('/api/scheduled_starts/' + PROJECT_ID)
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var schedules = d.schedules || [];
        var pending = schedules.filter(function(s) { return s.status === 'pending'; });
        if (pending.length) {
          var dt = new Date(pending[0].scheduled_at);
          var input = document.getElementById('wizSchedAt');
          if (input) {
            var local = new Date(dt.getTime() - dt.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
            input.value = local;
          }
        }
      }).catch(function() {});
  }

  /* ── Init ────────────────────────────────────────────── */
  applyScopeFilter();
  showStep(1);

  /* ── Expose addRoleRow globally (called from onclick in template) ── */
  window.addRoleRow = addRoleRow;

  /* ── Beacon test connection ── */
  window.testBeaconConnection = function() {
    var url = (document.getElementById('wizBeaconUrl').value || '').trim();
    var result = document.getElementById('beaconTestResult');
    if (!url) { result.textContent = 'Enter a Beacon URL first'; result.style.color = 'var(--status-error)'; return; }
    result.textContent = 'Testing…'; result.style.color = 'var(--text-muted)';
    fetch('/api/beacon_test', {method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url})})
      .then(function(r){return r.json();})
      .then(function(d){
        if (d.ok) { result.textContent = '✓ Connected'; result.style.color = 'var(--status-running)'; }
        else { result.textContent = d.error || 'Connection failed'; result.style.color = 'var(--status-error)'; }
      })
      .catch(function(){ result.textContent = 'Request failed'; result.style.color = 'var(--status-error)'; });
  };
})();
