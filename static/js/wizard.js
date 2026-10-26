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

  /* ── Mobile app files ────────────────────────────────── */
  var mobileFiles = [];
  var mobileAppFile = document.getElementById('mobileAppFile');
  var mobileAppList = document.getElementById('mobileAppList');
  var mobileAppCount = document.getElementById('mobileAppCount');

  mobileAppFile.addEventListener('change', function() {
    for (var i = 0; i < this.files.length; i++) mobileFiles.push(this.files[i]);
    this.value = '';
    renderMobileFiles();
  });

  function renderMobileFiles() {
    mobileAppList.innerHTML = '';
    mobileAppCount.textContent = mobileFiles.length ? mobileFiles.length + ' file(s)' : 'No files selected';
    mobileFiles.forEach(function(f, idx) {
      var li = document.createElement('li');
      li.innerHTML = '<span>' + escHtml(f.name) + '</span><span class="form-hint">' + formatBytes(f.size) + '</span><button type="button" class="file-remove" data-idx="' + idx + '">&times;</button>';
      mobileAppList.appendChild(li);
    });
    mobileAppList.querySelectorAll('.file-remove').forEach(function(btn) {
      btn.addEventListener('click', function() {
        mobileFiles.splice(parseInt(this.dataset.idx), 1);
        renderMobileFiles();
      });
    });
  }

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
    document.getElementById('cloudAwsGroup').hidden       = !showAws;
    document.getElementById('cloudAwsRegionGroup').hidden  = !showAws;
    document.getElementById('cloudAzureGroup').hidden      = !showAzure;
    document.getElementById('cloudGcpGroup').hidden        = !showGcp;
  }
  cloudProviderEl.addEventListener('change', updateCloudFields);

  /* ── Mobile dynamic analysis toggle ──────────────────── */
  var mobileDynamicEl = document.getElementById('mobileDynamic');
  function updateMobileDynamic() {
    var isDynamic = mobileDynamicEl.value === 'both';
    document.getElementById('mobileFridaGroup').hidden = !isDynamic;
  }
  mobileDynamicEl.addEventListener('change', updateMobileDynamic);

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
  function updateScopeSections() {
    var tools = getSelectedTools();
    var shown = {};
    tools.forEach(function(t){ var s = TOOL_SECTION_MAP[t]; if(s) shown[s] = true; });
    Object.keys(TOOL_SECTION_MAP).forEach(function(k){
      var sec = TOOL_SECTION_MAP[k];
      var el = document.getElementById(sec);
      if (el) el.hidden = !shown[sec];
    });
    updateCloudFields();
    updateMobileDynamic();
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
      if (_savedAuth.fracture) addR(sg,'Fracture Auth','Saved ('+(_savedAuth.fracture.method||'none')+')');
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
    if (_sec('scopeWirelessSection')) addR(sg,'SSIDs',valOf('ssids'));
    if (_sec('scopeBastionSection')) {
      addR(sg,'FW Vendor',selText('fwVendor'));
      addR(sg,'FW Configs',fwFiles.length ? fwFiles.map(function(f){return f.name;}).join(', ') : '');
    }
    if (_sec('scopeForgeSection')) {
      addR(sg,'Cloud Provider',selText('cloudProvider'));
      if (!document.getElementById('cloudAwsGroup').hidden) addR(sg,'AWS Profile',valOf('awsProfile') || 'default');
      if (!document.getElementById('cloudAzureGroup').hidden) addR(sg,'Azure Subscription',valOf('azureSubscription'));
      if (!document.getElementById('cloudGcpGroup').hidden) addR(sg,'GCP Project',valOf('gcpProject'));
    }
    if (_sec('scopeQuillSection')) {
      addR(sg,'Platform',selText('mobilePlatform'));
      addR(sg,'Analysis',selText('mobileDynamic'));
      addR(sg,'App Files',mobileFiles.length ? mobileFiles.map(function(f){return f.name;}).join(', ') : '');
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

  /* ── Submit ──────────────────────────────────────────── */
  btnSubmit.addEventListener('click', function() {
    if (!validateStep(1) || !validateStep(2)) {
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
        wireless_ssids: textToArray('ssids'),
        exclusions: textToArray('exclusions'),
        firewall_vendor: document.getElementById('fwVendor').value,
        firewall_configs: fwFiles.map(function(f){return f.name;}),
        cloud_provider: document.getElementById('cloudProvider').value,
        aws_profile: valOf('awsProfile'),
        aws_region: valOf('awsRegion'),
        azure_subscription: valOf('azureSubscription'),
        gcp_project: valOf('gcpProject'),
        mobile_platform: document.getElementById('mobilePlatform').value,
        mobile_dynamic: document.getElementById('mobileDynamic').value === 'both',
        mobile_apps: mobileFiles.map(function(f){return f.name;}),
        frida_device: valOf('fridaDevice'),
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
        if (!target) { alert('Enter a target URL.'); return; }
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
        auth.target = valOf(prefix + 'TcTarget');
        _savedAuth[toolId] = auth;
        var statusEl = document.getElementById(prefix + 'TcSaveStatus');
        if (statusEl) statusEl.textContent = 'Saved for ' + toolId.charAt(0).toUpperCase() + toolId.slice(1);
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
  }

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
