/**
 * Attack Chain Visualization — Crucible v2.0
 * Interactive directed-graph view of attack chains detected from engagement findings.
 */
(function () {
  'use strict';

  /* ── Inject component CSS ────────────────────────────────── */
  document.head.insertAdjacentHTML('beforeend', '<style>' + [
    /* Layout */
    '.ach-layout{display:flex;gap:0;height:calc(100vh - 180px);min-height:480px}',
    '.ach-list{width:28%;min-width:220px;max-width:340px;border-right:1px solid var(--border-mid);overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;background:var(--bg-surface)}',
    '.ach-graph{flex:1;position:relative;background:var(--bg-primary);overflow:hidden}',
    '.ach-graph-container{width:100%;height:100%}',
    '.ach-detail{width:22%;min-width:200px;max-width:320px;border-left:1px solid var(--border-mid);overflow-y:auto;padding:12px;background:var(--bg-surface)}',

    /* Chain list items */
    '.ach-item{padding:10px 12px;border-radius:var(--radius-sm);cursor:pointer;border:1px solid transparent;transition:background var(--transition-fast),border-color var(--transition-fast)}',
    '.ach-item:hover{background:var(--bg-hover)}',
    '.ach-item.selected{background:var(--bg-card);border-color:var(--accent-primary)}',
    '.ach-item-name{font-weight:600;font-size:.88rem;color:var(--text-primary);margin-bottom:4px;display:flex;align-items:center;gap:6px}',
    '.ach-item-meta{display:flex;align-items:center;gap:6px;font-size:.76rem;color:var(--text-muted)}',
    '.ach-badge-auto{background:var(--accent-muted);color:var(--accent-primary);padding:1px 6px;border-radius:3px;font-size:.68rem;font-weight:600}',
    '.ach-badge-manual{background:rgba(146,208,80,.15);color:#92D050;padding:1px 6px;border-radius:3px;font-size:.68rem;font-weight:600}',

    /* Node type badges */
    '.ach-nt{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}',
    '.ach-nt-discovery{background:rgba(74,144,217,.18);color:#4a90d9}',
    '.ach-nt-finding{background:rgba(231,113,111,.18);color:#E7716F}',
    '.ach-nt-credential{background:rgba(255,192,0,.18);color:#d4a000}',
    '.ach-nt-access{background:rgba(39,174,96,.18);color:#27ae60}',
    '.ach-nt-impact{background:rgba(255,0,255,.18);color:#FF00FF}',

    /* Graph controls */
    '.ach-controls{position:absolute;top:10px;right:10px;display:flex;flex-direction:column;gap:4px;z-index:5}',
    '.ach-ctrl-btn{width:32px;height:32px;border:1px solid var(--border-mid);border-radius:var(--radius-sm);background:var(--bg-card);color:var(--text-primary);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:.9rem;transition:background var(--transition-fast)}',
    '.ach-ctrl-btn:hover{background:var(--bg-hover)}',

    /* Graph empty state */
    '.ach-graph-empty{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--text-muted);font-size:.9rem;pointer-events:none}',

    /* Detail panel */
    '.ach-detail-section{margin-bottom:16px}',
    '.ach-detail-label{font-size:.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}',
    '.ach-detail-value{font-size:.86rem;color:var(--text-primary);word-break:break-word}',
    '.ach-detail-empty{color:var(--text-muted);font-size:.84rem;text-align:center;padding:40px 10px}',

    /* Actions row */
    '.ach-actions{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}',
    '.ach-item-actions{display:flex;gap:4px;margin-top:6px}',
    '.ach-item-actions .btn{padding:2px 8px;font-size:.72rem}',

    /* Modal overlay — reusable */
    '.ach-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:1000;display:none;align-items:center;justify-content:center}',
    '.ach-modal-overlay.active{display:flex}',
    '.ach-modal{background:var(--bg-card);border:1px solid var(--border-mid);border-radius:var(--radius-lg);max-width:640px;width:92%;max-height:85vh;overflow-y:auto;padding:0;box-shadow:var(--shadow-lg)}',
    '.ach-modal-header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border-mid)}',
    '.ach-modal-title{font-size:1rem;font-weight:700;color:var(--text-primary)}',
    '.ach-modal-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1.2rem;line-height:1}',
    '.ach-modal-body{padding:16px 20px}',
    '.ach-modal-footer{padding:12px 20px;border-top:1px solid var(--border-mid);display:flex;justify-content:flex-end;gap:8px}',

    /* Builder node list */
    '.ach-node-row{display:flex;gap:6px;align-items:center;margin-bottom:6px;padding:6px 8px;background:var(--bg-surface);border-radius:var(--radius-sm);font-size:.82rem}',
    '.ach-node-row .ach-nt{font-size:.66rem}',
    '.ach-edge-row{display:flex;gap:6px;align-items:center;margin-bottom:6px;padding:6px 8px;background:var(--bg-surface);border-radius:var(--radius-sm);font-size:.82rem}',

    /* Template grid */
    '.ach-tpl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;max-height:50vh;overflow-y:auto}',
    '.ach-tpl-card{padding:12px;border:1px solid var(--border-mid);border-radius:var(--radius-sm);cursor:pointer;transition:border-color var(--transition-fast)}',
    '.ach-tpl-card:hover,.ach-tpl-card.selected{border-color:var(--accent-primary);background:var(--bg-hover)}',
    '.ach-tpl-card-name{font-weight:600;font-size:.86rem;color:var(--text-primary);margin-bottom:4px}',
    '.ach-tpl-card-desc{font-size:.78rem;color:var(--text-secondary)}',
    '.ach-tpl-card-meta{font-size:.72rem;color:var(--text-muted);margin-top:4px}',

    /* Legend */
    '.ach-legend{position:absolute;bottom:10px;left:10px;background:var(--bg-card);border:1px solid var(--border-mid);border-radius:var(--radius-sm);padding:8px 12px;font-size:.72rem;z-index:5;display:flex;gap:10px;flex-wrap:wrap}',
    '.ach-legend-item{display:flex;align-items:center;gap:4px}',
    '.ach-legend-dot{width:10px;height:10px;border-radius:2px}',
  ].join('\n') + '</style>');


  /* ── Constants ────────────────────────────────────────────── */
  var NODE_TYPES = ['DISCOVERY', 'FINDING', 'CREDENTIAL', 'ACCESS', 'IMPACT'];
  var EDGE_RELATIONS = [
    'leads_to', 'exposes', 'grants', 'enables', 'escalates',
    'pivots_to', 'chains_with', 'requires', 'mitigated_by', 'impacts'
  ];
  var NODE_COLORS = {
    DISCOVERY: '#4a90d9', FINDING: '#E7716F', CREDENTIAL: '#FFC000',
    ACCESS: '#27ae60', IMPACT: '#FF00FF'
  };
  var NODE_SHAPES = {
    DISCOVERY: 'diamond', FINDING: 'round-rectangle', CREDENTIAL: 'hexagon',
    ACCESS: 'star', IMPACT: 'octagon'
  };
  var RISK_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  var RISK_COLORS = {
    CRITICAL: '#FF00FF', HIGH: '#E7716F', MEDIUM: '#FFC000',
    LOW: '#92D050', INFO: '#BDD7EC'
  };

  /* ── State ────────────────────────────────────────────────── */
  var _achChains = [];
  var _achSelected = null;      // selected chain id
  var _achSelectedNode = null;  // selected node id
  var _achCy = null;            // cytoscape instance
  var _achLoaded = false;       // whether the tab has been initialized
  var _achCyReady = false;      // whether Cytoscape libs are loaded
  var _achTemplates = null;     // cached templates


  /* ── Utility ─────────────────────────────────────────────── */
  function _escHtml(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  function _riskColor(r) { return RISK_COLORS[(r || '').toUpperCase()] || '#888'; }
  function _riskOrder(r) { var o = RISK_ORDER[(r || '').toUpperCase()]; return o !== undefined ? o : 5; }

  function _toast(msg, type) {
    var c = document.getElementById('toastContainer');
    if (!c) return;
    var t = document.createElement('div');
    t.className = 'toast' + (type === 'error' ? ' toast-error' : type === 'success' ? ' toast-success' : '');
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(function () { t.style.opacity = '0'; setTimeout(function () { t.remove(); }, 300); }, 3500);
  }

  function _api(method, path, body) {
    var opts = { method: method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (r) {
      if (!r.ok) return r.json().catch(function () { return { error: r.statusText }; }).then(function (d) { return Promise.reject(d); });
      return r.json();
    });
  }

  function _truncate(s, n) {
    s = s || '';
    return s.length > n ? s.substring(0, n) + '...' : s;
  }

  function _riskBadge(risk) {
    var r = (risk || 'INFO').toUpperCase();
    return '<span class="risk-badge risk-' + r.toLowerCase() + '" style="font-size:.68rem;padding:2px 8px">' + _escHtml(r) + '</span>';
  }

  function _ntBadge(nt) {
    var t = (nt || '').toUpperCase();
    return '<span class="ach-nt ach-nt-' + t.toLowerCase() + '">' + _escHtml(t) + '</span>';
  }


  /* ── CDN Loader ──────────────────────────────────────────── */
  function _loadScript(url, cb) {
    var s = document.createElement('script');
    s.src = url;
    s.onload = cb;
    s.onerror = function () { _toast('Failed to load: ' + url, 'error'); };
    document.head.appendChild(s);
  }

  function _ensureCytoscape(cb) {
    if (_achCyReady) return cb();
    // Libraries may already be loaded via deferred script tags in the HTML.
    if (window.cytoscape && window.dagre) {
      if (window.cytoscapeDagre && !window.cytoscape._dagreReg) {
        window.cytoscape.use(window.cytoscapeDagre);
        window.cytoscape._dagreReg = true;
      }
      _achCyReady = true;
      return cb();
    }
    // Fallback: load from CDN if not already present
    _loadScript('https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js', function () {
      _loadScript('https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js', function () {
        _loadScript('https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js', function () {
          if (window.cytoscape && window.cytoscapeDagre && !window.cytoscape._dagreReg) {
            window.cytoscape.use(window.cytoscapeDagre);
            window.cytoscape._dagreReg = true;
          }
          _achCyReady = true;
          cb();
        });
      });
    });
  }


  /* ── Tab Activation ──────────────────────────────────────── */
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.tab-btn[data-tab="attack-chains"]');
    if (!btn) return;
    if (!_achLoaded) {
      _achLoaded = true;
      _ensureCytoscape(function () {
        _achFetchChains();
      });
    }
  });


  /* ── Data Fetching ───────────────────────────────────────── */
  function _achFetchChains() {
    _api('GET', '/api/chains/' + PID).then(function (data) {
      _achChains = data.chains || [];
      _achRenderList();
      _achUpdatePill();
      if (_achSelected) {
        var found = _achChains.find(function (c) { return c.id === _achSelected; });
        if (found) _achRenderGraph(found);
        else { _achSelected = null; _achClearGraph(); }
      }
    }).catch(function (err) {
      _toast('Failed to load chains: ' + (err.error || 'unknown'), 'error');
    });
  }

  function _achUpdatePill() {
    var pill = document.getElementById('chainsPill');
    if (pill) pill.textContent = _achChains.length || '';
  }


  /* ── List Rendering ──────────────────────────────────────── */
  function _achRenderList() {
    var container = document.getElementById('chainListPanel');
    if (!container) return;

    // Keep the actions row at top
    var actionsRow = container.querySelector('.ach-actions');
    container.innerHTML = '';
    if (actionsRow) container.appendChild(actionsRow);
    else {
      var ar = document.createElement('div');
      ar.className = 'ach-actions';
      ar.innerHTML =
        '<button type="button" class="btn btn-xs btn-primary" id="achDetectBtn">Detect Chains</button>' +
        '<button type="button" class="btn btn-xs btn-secondary" id="achNewBtn">New Chain</button>' +
        '<button type="button" class="btn btn-xs btn-ghost" id="achTemplateBtn">From Template</button>';
      container.appendChild(ar);

      ar.querySelector('#achDetectBtn').addEventListener('click', _achDetect);
      ar.querySelector('#achNewBtn').addEventListener('click', _achOpenBuilder);
      ar.querySelector('#achTemplateBtn').addEventListener('click', _achOpenTemplatePicker);
    }

    if (_achChains.length === 0) {
      var empty = document.createElement('div');
      empty.className = 'ach-detail-empty';
      empty.textContent = 'No attack chains. Click "Detect Chains" to auto-detect from findings.';
      container.appendChild(empty);
      return;
    }

    // Sort by risk then name
    var sorted = _achChains.slice().sort(function (a, b) {
      var rd = _riskOrder(a.risk) - _riskOrder(b.risk);
      return rd !== 0 ? rd : (a.name || '').localeCompare(b.name || '');
    });

    sorted.forEach(function (chain) {
      var div = document.createElement('div');
      div.className = 'ach-item' + (chain.id === _achSelected ? ' selected' : '');
      div.dataset.chainId = chain.id;

      var nodeCount = (chain.nodes || []).length;
      var edgeCount = (chain.edges || []).length;
      var autoBadge = chain.auto_detected
        ? '<span class="ach-badge-auto">AUTO</span>'
        : '<span class="ach-badge-manual">MANUAL</span>';

      div.innerHTML =
        '<div class="ach-item-name">' + _riskBadge(chain.risk) + ' ' + _escHtml(_truncate(chain.name, 30)) + '</div>' +
        '<div class="ach-item-meta">' + autoBadge + ' <span>' + nodeCount + ' nodes</span> <span>' + edgeCount + ' edges</span></div>' +
        '<div class="ach-item-actions">' +
        '  <button type="button" class="btn btn-xs btn-ghost ach-export-btn" data-chain-id="' + chain.id + '">Export</button>' +
        '  <button type="button" class="btn btn-xs btn-danger ach-delete-btn" data-chain-id="' + chain.id + '">Delete</button>' +
        '</div>';

      div.addEventListener('click', function (e) {
        if (e.target.closest('.ach-export-btn') || e.target.closest('.ach-delete-btn')) return;
        _achSelectChain(chain.id);
      });

      var exportBtn = div.querySelector('.ach-export-btn');
      if (exportBtn) exportBtn.addEventListener('click', function () { _achExportChain(chain.id); });

      var deleteBtn = div.querySelector('.ach-delete-btn');
      if (deleteBtn) deleteBtn.addEventListener('click', function () { _achDeleteChain(chain.id); });

      container.appendChild(div);
    });
  }


  /* ── Chain Selection ─────────────────────────────────────── */
  function _achSelectChain(chainId) {
    _achSelected = chainId;
    _achSelectedNode = null;
    _achRenderList();

    var chain = _achChains.find(function (c) { return c.id === chainId; });
    if (chain) {
      _achRenderGraph(chain);
      _achRenderChainDetail(chain);
    }
  }


  /* ── Graph Rendering ─────────────────────────────────────── */
  function _achClearGraph() {
    if (_achCy) { _achCy.destroy(); _achCy = null; }
    var gp = document.getElementById('chainGraphPanel');
    if (!gp) return;
    var gc = gp.querySelector('.ach-graph-container');
    if (gc) gc.innerHTML = '';
    var empty = gp.querySelector('.ach-graph-empty');
    if (empty) empty.style.display = '';
  }

  function _achRenderGraph(chain) {
    var gp = document.getElementById('chainGraphPanel');
    if (!gp || !window.cytoscape) return;

    var empty = gp.querySelector('.ach-graph-empty');
    if (empty) empty.style.display = 'none';

    var gc = gp.querySelector('.ach-graph-container');
    if (!gc) return;

    var elements = [];

    // Nodes
    (chain.nodes || []).forEach(function (n) {
      elements.push({
        group: 'nodes',
        data: {
          id: n.id,
          label: _truncate(n.label, 25),
          fullLabel: n.label || '',
          nodeType: n.node_type || 'FINDING',
          risk: (n.risk || 'INFO').toUpperCase(),
          ip: n.ip || '',
          port: n.port || 0,
          tool: n.tool || '',
          findingId: n.finding_id || '',
          metadata: n.metadata || {}
        }
      });
    });

    // Edges
    (chain.edges || []).forEach(function (e, i) {
      elements.push({
        group: 'edges',
        data: {
          id: 'e' + i,
          source: e.source_id,
          target: e.target_id,
          relation: e.relation || 'leads_to',
          confidence: e.confidence || 'Firm',
          description: e.description || ''
        }
      });
    });

    if (_achCy) { _achCy.destroy(); _achCy = null; }

    _achCy = window.cytoscape({
      container: gc,
      elements: elements,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '10px',
            'font-family': 'Inter, sans-serif',
            'color': '#ccc',
            'text-outline-color': '#111',
            'text-outline-width': 1,
            'text-margin-y': 6,
            'width': 36,
            'height': 36,
            'border-width': 2,
            'border-color': '#333'
          }
        },
        // Per node-type styles
        { selector: 'node[nodeType="DISCOVERY"]', style: { 'background-color': NODE_COLORS.DISCOVERY, 'shape': NODE_SHAPES.DISCOVERY, 'border-color': '#3670a8' } },
        { selector: 'node[nodeType="FINDING"]', style: { 'background-color': NODE_COLORS.FINDING, 'shape': NODE_SHAPES.FINDING, 'border-color': '#c0504d' } },
        { selector: 'node[nodeType="CREDENTIAL"]', style: { 'background-color': NODE_COLORS.CREDENTIAL, 'shape': NODE_SHAPES.CREDENTIAL, 'border-color': '#b08600' } },
        { selector: 'node[nodeType="ACCESS"]', style: { 'background-color': NODE_COLORS.ACCESS, 'shape': NODE_SHAPES.ACCESS, 'border-color': '#1e8a4c' } },
        { selector: 'node[nodeType="IMPACT"]', style: { 'background-color': NODE_COLORS.IMPACT, 'shape': NODE_SHAPES.IMPACT, 'border-color': '#c000c0' } },
        // Selected node
        { selector: 'node:selected', style: { 'border-width': 4, 'border-color': '#fff', 'overlay-opacity': 0.08 } },
        // Edges
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#555',
            'target-arrow-color': '#555',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 1.1,
            'label': 'data(relation)',
            'font-size': '8px',
            'font-family': 'Inter, sans-serif',
            'color': '#888',
            'text-rotation': 'autorotate',
            'text-outline-color': '#111',
            'text-outline-width': 1,
            'text-margin-y': -8
          }
        },
        { selector: 'edge[relation="exposes"]', style: { 'line-style': 'dashed' } },
        { selector: 'edge[relation="grants"]', style: { 'line-style': 'dotted', 'line-color': '#FFC000', 'target-arrow-color': '#FFC000' } },
        { selector: 'edge[relation="escalates"]', style: { 'width': 3.5, 'line-color': '#E7716F', 'target-arrow-color': '#E7716F' } },
        { selector: 'edge[relation="pivots_to"]', style: { 'line-style': 'dashed', 'line-dash-pattern': [8, 3, 2, 3], 'line-color': '#4a90d9', 'target-arrow-color': '#4a90d9' } },
        { selector: 'edge[relation="impacts"]', style: { 'line-color': '#FF00FF', 'target-arrow-color': '#FF00FF', 'width': 3 } },
        { selector: 'edge[relation="mitigated_by"]', style: { 'line-style': 'dotted', 'line-color': '#92D050', 'target-arrow-color': '#92D050' } },
        { selector: 'edge:selected', style: { 'width': 4, 'line-color': '#fff', 'target-arrow-color': '#fff' } }
      ],
      layout: _achLayoutOpts(),
      minZoom: 0.2,
      maxZoom: 4,
      wheelSensitivity: 0.3
    });

    // Node click
    _achCy.on('tap', 'node', function (evt) {
      var nodeData = evt.target.data();
      _achSelectedNode = nodeData.id;
      _achRenderNodeDetail(nodeData, chain);
    });

    // Click background -> deselect node, show chain summary
    _achCy.on('tap', function (evt) {
      if (evt.target === _achCy) {
        _achSelectedNode = null;
        _achRenderChainDetail(chain);
      }
    });
  }

  function _achLayoutOpts() {
    if (_achCyReady && window.cytoscape) {
      return { name: 'dagre', rankDir: 'TB', nodeSep: 50, rankSep: 60, animate: true, animationDuration: 300 };
    }
    return { name: 'grid' };
  }


  /* ── Detail Panel ────────────────────────────────────────── */
  function _achRenderChainDetail(chain) {
    var dp = document.getElementById('chainDetailPanel');
    if (!dp) return;
    dp.innerHTML =
      '<div class="ach-detail-section">' +
      '  <div class="ach-detail-label">Chain</div>' +
      '  <div class="ach-detail-value" style="font-weight:600;font-size:.94rem">' + _escHtml(chain.name) + '</div>' +
      '</div>' +
      '<div class="ach-detail-section">' +
      '  <div class="ach-detail-label">Risk</div>' +
      '  <div class="ach-detail-value">' + _riskBadge(chain.risk) + '</div>' +
      '</div>' +
      '<div class="ach-detail-section">' +
      '  <div class="ach-detail-label">Description</div>' +
      '  <div class="ach-detail-value">' + _escHtml(chain.description || 'No description') + '</div>' +
      '</div>' +
      '<div class="ach-detail-section">' +
      '  <div class="ach-detail-label">Statistics</div>' +
      '  <div class="ach-detail-value" style="font-size:.82rem">' +
      '    Nodes: ' + (chain.nodes || []).length + '<br>' +
      '    Edges: ' + (chain.edges || []).length + '<br>' +
      '    Type: ' + (chain.auto_detected ? 'Auto-detected' : 'Manual') +
      (chain.template_id ? '<br>Template: ' + _escHtml(chain.template_id) : '') +
      '  </div>' +
      '</div>' +
      '<div class="ach-detail-section">' +
      '  <div class="ach-detail-label">Created</div>' +
      '  <div class="ach-detail-value" style="font-size:.82rem">' + _escHtml(chain.created || '--') + '</div>' +
      '</div>' +
      '<div style="font-size:.76rem;color:var(--text-muted);margin-top:12px">Click a node to see details.</div>';
  }

  function _achRenderNodeDetail(nodeData, chain) {
    var dp = document.getElementById('chainDetailPanel');
    if (!dp) return;

    var ipPort = nodeData.ip || '';
    if (nodeData.port && nodeData.port !== 0 && String(nodeData.port) !== '0') {
      ipPort += ':' + nodeData.port;
    }

    var html =
      '<div class="ach-detail-section">' +
      '  <div class="ach-detail-label">Node Type</div>' +
      '  <div class="ach-detail-value">' + _ntBadge(nodeData.nodeType) + '</div>' +
      '</div>' +
      '<div class="ach-detail-section">' +
      '  <div class="ach-detail-label">Label</div>' +
      '  <div class="ach-detail-value" style="font-weight:600">' + _escHtml(nodeData.fullLabel) + '</div>' +
      '</div>';

    if (ipPort) {
      html += '<div class="ach-detail-section"><div class="ach-detail-label">Target</div><div class="ach-detail-value font-mono" style="font-size:.84rem">' + _escHtml(ipPort) + '</div></div>';
    }

    html += '<div class="ach-detail-section"><div class="ach-detail-label">Risk</div><div class="ach-detail-value">' + _riskBadge(nodeData.risk) + '</div></div>';

    if (nodeData.tool) {
      html += '<div class="ach-detail-section"><div class="ach-detail-label">Tool</div><div class="ach-detail-value">' + _escHtml(nodeData.tool) + '</div></div>';
    }

    // Show metadata fields
    var meta = nodeData.metadata || {};
    if (meta.description) {
      html += '<div class="ach-detail-section"><div class="ach-detail-label">Description</div><div class="ach-detail-value" style="font-size:.82rem">' + _escHtml(meta.description) + '</div></div>';
    }
    if (meta.remediation) {
      html += '<div class="ach-detail-section"><div class="ach-detail-label">Remediation</div><div class="ach-detail-value" style="font-size:.82rem">' + _escHtml(meta.remediation) + '</div></div>';
    }

    // "View Finding" button
    if (nodeData.findingId) {
      html += '<div style="margin-top:12px"><button type="button" class="btn btn-xs btn-primary" id="achViewFinding">View Finding</button></div>';
    }

    // Show connected edges
    var connEdges = (chain.edges || []).filter(function (e) {
      return e.source_id === nodeData.id || e.target_id === nodeData.id;
    });
    if (connEdges.length) {
      html += '<div class="ach-detail-section" style="margin-top:12px"><div class="ach-detail-label">Connections (' + connEdges.length + ')</div>';
      connEdges.forEach(function (e) {
        var dir = e.source_id === nodeData.id ? 'outgoing' : 'incoming';
        var otherNodeId = dir === 'outgoing' ? e.target_id : e.source_id;
        var otherNode = (chain.nodes || []).find(function (n) { return n.id === otherNodeId; });
        var otherLabel = otherNode ? otherNode.label : otherNodeId;
        html += '<div style="font-size:.78rem;color:var(--text-secondary);margin:3px 0">' +
          '<span style="color:var(--text-muted)">' + dir + '</span> ' +
          '<span style="font-weight:600">' + _escHtml(e.relation) + '</span> ' +
          _escHtml(_truncate(otherLabel, 20)) +
          '</div>';
      });
      html += '</div>';
    }

    dp.innerHTML = html;

    // Wire view-finding button
    var vfBtn = dp.querySelector('#achViewFinding');
    if (vfBtn) {
      vfBtn.addEventListener('click', function () {
        // Switch to findings tab and try to highlight
        var tabBtn = document.querySelector('.tab-btn[data-tab="findings"]');
        if (tabBtn) tabBtn.click();
        // Attempt to scroll to finding after a small delay
        setTimeout(function () {
          var findingRow = document.querySelector('[data-finding-id="' + nodeData.findingId + '"]');
          if (findingRow) {
            findingRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
            findingRow.style.outline = '2px solid var(--accent-primary)';
            setTimeout(function () { findingRow.style.outline = ''; }, 3000);
          }
        }, 400);
      });
    }
  }


  /* ── Auto Detection ──────────────────────────────────────── */
  function _achDetect() {
    var btn = document.getElementById('achDetectBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Detecting...'; }

    _api('POST', '/api/chains/' + PID + '/detect').then(function (data) {
      // Merge newly detected chains into local list
      var newChains = data.chains || [];
      newChains.forEach(function (nc) {
        var exists = _achChains.find(function (c) { return c.id === nc.id; });
        if (!exists) _achChains.push(nc);
      });
      _achRenderList();
      _achUpdatePill();
      var newCount = newChains.length;
      var metaCount = (data.meta_findings || []).length;
      _toast(data.message || ('Detection complete: ' + newCount + ' chain(s) found, ' + metaCount + ' meta-finding(s) emitted'), 'success');
      if (btn) { btn.disabled = false; btn.textContent = 'Detect Chains'; }
    }).catch(function (err) {
      _toast('Detection failed: ' + (err.error || 'unknown'), 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Detect Chains'; }
    });
  }


  /* ── Delete Chain ────────────────────────────────────────── */
  function _achDeleteChain(chainId) {
    if (!confirm('Delete this attack chain?')) return;
    _api('DELETE', '/api/chains/' + PID + '/' + chainId).then(function () {
      _achChains = _achChains.filter(function (c) { return c.id !== chainId; });
      if (_achSelected === chainId) { _achSelected = null; _achClearGraph(); }
      _achRenderList();
      _achUpdatePill();
      _toast('Chain deleted', 'success');
    }).catch(function (err) {
      _toast('Delete failed: ' + (err.error || 'unknown'), 'error');
    });
  }


  /* ── Export Chain ────────────────────────────────────────── */
  function _achExportChain(chainId) {
    _api('POST', '/api/chains/' + PID + '/' + chainId + '/export').then(function (data) {
      // Download as JSON
      var blob = new Blob([JSON.stringify(data.chain || data, null, 2)], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'attack_chain_' + chainId.substring(0, 8) + '.json';
      a.click();
      URL.revokeObjectURL(url);
      _toast('Chain exported', 'success');
    }).catch(function (err) {
      _toast('Export failed: ' + (err.error || 'unknown'), 'error');
    });
  }


  /* ── Graph Controls ──────────────────────────────────────── */
  window._achZoomIn = function () { if (_achCy) _achCy.zoom(_achCy.zoom() * 1.3); };
  window._achZoomOut = function () { if (_achCy) _achCy.zoom(_achCy.zoom() / 1.3); };
  window._achFit = function () { if (_achCy) _achCy.fit(undefined, 30); };
  window._achRelayout = function () {
    if (_achCy) _achCy.layout(_achLayoutOpts()).run();
  };


  /* ── Chain Builder Modal ─────────────────────────────────── */
  var _builderNodes = [];
  var _builderEdges = [];

  function _achOpenBuilder() {
    _builderNodes = [];
    _builderEdges = [];
    _achEnsureBuilderModal();
    _achRefreshBuilderUI();
    document.getElementById('achBuilderModal').classList.add('active');
  }

  function _achEnsureBuilderModal() {
    if (document.getElementById('achBuilderModal')) return;
    var overlay = document.createElement('div');
    overlay.id = 'achBuilderModal';
    overlay.className = 'ach-modal-overlay';
    overlay.innerHTML =
      '<div class="ach-modal" style="max-width:720px">' +
      '  <div class="ach-modal-header">' +
      '    <span class="ach-modal-title">New Attack Chain</span>' +
      '    <button type="button" class="ach-modal-close" onclick="document.getElementById(\'achBuilderModal\').classList.remove(\'active\')">&times;</button>' +
      '  </div>' +
      '  <div class="ach-modal-body">' +
      '    <div class="form-group mb-12">' +
      '      <label class="form-label">Chain Name</label>' +
      '      <input type="text" class="form-control" id="achBuilderName" placeholder="e.g. External Recon to Shell">' +
      '    </div>' +
      '    <div class="form-group mb-12">' +
      '      <label class="form-label">Description</label>' +
      '      <textarea class="form-control" id="achBuilderDesc" rows="2" placeholder="Describe the attack chain..."></textarea>' +
      '    </div>' +

      '    <div class="mb-12">' +
      '      <div class="form-label" style="margin-bottom:6px">Nodes</div>' +
      '      <div id="achBuilderNodes"></div>' +
      '      <div style="display:flex;gap:6px;margin-top:6px">' +
      '        <select class="form-select form-select-sm" id="achAddNodeType" style="width:140px">' +
             NODE_TYPES.map(function (t) { return '<option value="' + t + '">' + t + '</option>'; }).join('') +
      '        </select>' +
      '        <input type="text" class="form-control form-control-sm" id="achAddNodeLabel" placeholder="Label" style="flex:1">' +
      '        <input type="text" class="form-control form-control-sm" id="achAddNodeIp" placeholder="IP" style="width:120px">' +
      '        <input type="number" class="form-control form-control-sm" id="achAddNodePort" placeholder="Port" style="width:80px">' +
      '        <button type="button" class="btn btn-xs btn-primary" id="achAddNodeBtn">+</button>' +
      '      </div>' +
      '    </div>' +

      '    <div class="mb-12">' +
      '      <div class="form-label" style="margin-bottom:6px">Edges</div>' +
      '      <div id="achBuilderEdges"></div>' +
      '      <div style="display:flex;gap:6px;margin-top:6px">' +
      '        <select class="form-select form-select-sm" id="achEdgeSource" style="flex:1"></select>' +
      '        <select class="form-select form-select-sm" id="achEdgeRelation" style="width:120px">' +
             EDGE_RELATIONS.map(function (r) { return '<option value="' + r + '">' + r + '</option>'; }).join('') +
      '        </select>' +
      '        <select class="form-select form-select-sm" id="achEdgeTarget" style="flex:1"></select>' +
      '        <button type="button" class="btn btn-xs btn-primary" id="achAddEdgeBtn">+</button>' +
      '      </div>' +
      '    </div>' +
      '  </div>' +
      '  <div class="ach-modal-footer">' +
      '    <button type="button" class="btn btn-ghost btn-sm" onclick="document.getElementById(\'achBuilderModal\').classList.remove(\'active\')">Cancel</button>' +
      '    <button type="button" class="btn btn-primary btn-sm" id="achBuilderSave">Create Chain</button>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(overlay);

    overlay.querySelector('#achAddNodeBtn').addEventListener('click', function () {
      var type = document.getElementById('achAddNodeType').value;
      var label = document.getElementById('achAddNodeLabel').value.trim();
      var ip = document.getElementById('achAddNodeIp').value.trim();
      var port = parseInt(document.getElementById('achAddNodePort').value) || 0;
      if (!label) { _toast('Node label is required', 'error'); return; }
      var nodeId = 'n' + Date.now() + '_' + _builderNodes.length;
      _builderNodes.push({ id: nodeId, node_type: type, label: label, ip: ip, port: port, risk: 'INFO', tool: '', finding_id: null, metadata: {} });
      document.getElementById('achAddNodeLabel').value = '';
      document.getElementById('achAddNodeIp').value = '';
      document.getElementById('achAddNodePort').value = '';
      _achRefreshBuilderUI();
    });

    overlay.querySelector('#achAddEdgeBtn').addEventListener('click', function () {
      var src = document.getElementById('achEdgeSource').value;
      var tgt = document.getElementById('achEdgeTarget').value;
      var rel = document.getElementById('achEdgeRelation').value;
      if (!src || !tgt) { _toast('Select source and target nodes', 'error'); return; }
      if (src === tgt) { _toast('Source and target must differ', 'error'); return; }
      _builderEdges.push({ source_id: src, target_id: tgt, relation: rel, confidence: 'Firm', description: '' });
      _achRefreshBuilderUI();
    });

    overlay.querySelector('#achBuilderSave').addEventListener('click', _achSaveBuilder);

    // Close on overlay background click
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) overlay.classList.remove('active');
    });
  }

  function _achRefreshBuilderUI() {
    var nodesContainer = document.getElementById('achBuilderNodes');
    if (nodesContainer) {
      nodesContainer.innerHTML = '';
      _builderNodes.forEach(function (n, i) {
        var row = document.createElement('div');
        row.className = 'ach-node-row';
        row.innerHTML = _ntBadge(n.node_type) + ' <span style="flex:1">' + _escHtml(n.label) + '</span>' +
          (n.ip ? '<span class="font-mono" style="font-size:.78rem;color:var(--text-muted)">' + _escHtml(n.ip + (n.port ? ':' + n.port : '')) + '</span>' : '') +
          ' <button type="button" class="btn btn-xs btn-ghost" style="color:var(--risk-high)" data-idx="' + i + '">x</button>';
        row.querySelector('button').addEventListener('click', function () {
          var removedId = _builderNodes[i].id;
          _builderNodes.splice(i, 1);
          _builderEdges = _builderEdges.filter(function (e) { return e.source_id !== removedId && e.target_id !== removedId; });
          _achRefreshBuilderUI();
        });
        nodesContainer.appendChild(row);
      });
    }

    // Refresh edge source/target dropdowns
    var srcSelect = document.getElementById('achEdgeSource');
    var tgtSelect = document.getElementById('achEdgeTarget');
    if (srcSelect && tgtSelect) {
      var opts = _builderNodes.map(function (n) {
        return '<option value="' + n.id + '">' + _escHtml(_truncate(n.label, 20)) + ' (' + n.node_type + ')</option>';
      }).join('');
      srcSelect.innerHTML = '<option value="">-- Source --</option>' + opts;
      tgtSelect.innerHTML = '<option value="">-- Target --</option>' + opts;
    }

    var edgesContainer = document.getElementById('achBuilderEdges');
    if (edgesContainer) {
      edgesContainer.innerHTML = '';
      _builderEdges.forEach(function (e, i) {
        var srcNode = _builderNodes.find(function (n) { return n.id === e.source_id; });
        var tgtNode = _builderNodes.find(function (n) { return n.id === e.target_id; });
        var row = document.createElement('div');
        row.className = 'ach-edge-row';
        row.innerHTML =
          '<span style="flex:1">' + _escHtml((srcNode ? srcNode.label : '?')) + '</span>' +
          '<span style="font-weight:600;color:var(--accent-primary)">' + _escHtml(e.relation) + '</span>' +
          '<span style="flex:1;text-align:right">' + _escHtml((tgtNode ? tgtNode.label : '?')) + '</span>' +
          ' <button type="button" class="btn btn-xs btn-ghost" style="color:var(--risk-high)" data-idx="' + i + '">x</button>';
        row.querySelector('button').addEventListener('click', function () {
          _builderEdges.splice(i, 1);
          _achRefreshBuilderUI();
        });
        edgesContainer.appendChild(row);
      });
    }
  }

  function _achSaveBuilder() {
    var name = (document.getElementById('achBuilderName').value || '').trim();
    var desc = (document.getElementById('achBuilderDesc').value || '').trim();
    if (!name) { _toast('Chain name is required', 'error'); return; }
    if (_builderNodes.length < 2) { _toast('Add at least 2 nodes', 'error'); return; }

    // Determine highest risk
    var highestRisk = 'INFO';
    _builderNodes.forEach(function (n) {
      if (_riskOrder(n.risk) < _riskOrder(highestRisk)) highestRisk = (n.risk || 'INFO').toUpperCase();
    });

    var chain = {
      name: name,
      description: desc,
      risk: highestRisk,
      nodes: _builderNodes,
      edges: _builderEdges,
      auto_detected: false,
      template_id: null
    };

    _api('POST', '/api/chains/' + PID, chain).then(function (data) {
      document.getElementById('achBuilderModal').classList.remove('active');
      // Response may be the chain directly (has .id) or wrapped in {chain: ...}
      var newChain = data.chain || (data.id ? data : null);
      if (newChain) {
        var exists = _achChains.find(function (c) { return c.id === newChain.id; });
        if (!exists) _achChains.push(newChain);
      }
      _achRenderList();
      _achUpdatePill();
      _toast('Chain created', 'success');
    }).catch(function (err) {
      _toast('Create failed: ' + (err.error || 'unknown'), 'error');
    });
  }


  /* ── Template Picker Modal ───────────────────────────────── */
  var _selectedTplId = null;

  function _achOpenTemplatePicker() {
    _selectedTplId = null;
    _achEnsureTemplateModal();
    document.getElementById('achTemplateModal').classList.add('active');

    if (_achTemplates) {
      _achRenderTemplates(_achTemplates);
    } else {
      _api('GET', '/api/chains/' + PID + '/templates').then(function (data) {
        _achTemplates = data.templates || [];
        _achRenderTemplates(_achTemplates);
      }).catch(function (err) {
        _toast('Failed to load templates: ' + (err.error || 'unknown'), 'error');
      });
    }
  }

  function _achEnsureTemplateModal() {
    if (document.getElementById('achTemplateModal')) return;
    var overlay = document.createElement('div');
    overlay.id = 'achTemplateModal';
    overlay.className = 'ach-modal-overlay';
    overlay.innerHTML =
      '<div class="ach-modal">' +
      '  <div class="ach-modal-header">' +
      '    <span class="ach-modal-title">Chain Templates</span>' +
      '    <button type="button" class="ach-modal-close" onclick="document.getElementById(\'achTemplateModal\').classList.remove(\'active\')">&times;</button>' +
      '  </div>' +
      '  <div class="ach-modal-body">' +
      '    <div class="form-group mb-12">' +
      '      <label class="form-label">Chain Name (optional override)</label>' +
      '      <input type="text" class="form-control" id="achTplName" placeholder="Leave empty to use template name">' +
      '    </div>' +
      '    <div id="achTplGrid" class="ach-tpl-grid"></div>' +
      '  </div>' +
      '  <div class="ach-modal-footer">' +
      '    <button type="button" class="btn btn-ghost btn-sm" onclick="document.getElementById(\'achTemplateModal\').classList.remove(\'active\')">Cancel</button>' +
      '    <button type="button" class="btn btn-primary btn-sm" id="achTplCreate">Create from Template</button>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(overlay);

    overlay.querySelector('#achTplCreate').addEventListener('click', _achCreateFromTemplate);
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) overlay.classList.remove('active');
    });
  }

  function _achRenderTemplates(templates) {
    var grid = document.getElementById('achTplGrid');
    if (!grid) return;
    grid.innerHTML = '';
    templates.forEach(function (tpl) {
      var card = document.createElement('div');
      card.className = 'ach-tpl-card';
      card.dataset.tplId = tpl.id;
      card.innerHTML =
        '<div class="ach-tpl-card-name">' + _riskBadge(tpl.risk || 'MEDIUM') + ' ' + _escHtml(tpl.name) + '</div>' +
        '<div class="ach-tpl-card-desc">' + _escHtml(tpl.description || '') + '</div>' +
        '<div class="ach-tpl-card-meta">' + (tpl.nodes || []).length + ' nodes, ' + (tpl.edges || []).length + ' edges' +
        (tpl.category ? ' | ' + _escHtml(tpl.category) : '') + '</div>';
      card.addEventListener('click', function () {
        grid.querySelectorAll('.ach-tpl-card').forEach(function (c) { c.classList.remove('selected'); });
        card.classList.add('selected');
        _selectedTplId = tpl.id;
      });
      grid.appendChild(card);
    });
  }

  function _achCreateFromTemplate() {
    if (!_selectedTplId) { _toast('Select a template first', 'error'); return; }
    var name = (document.getElementById('achTplName').value || '').trim();

    _api('POST', '/api/chains/' + PID + '/from-template', { template_id: _selectedTplId, name: name || undefined }).then(function (data) {
      document.getElementById('achTemplateModal').classList.remove('active');
      var newChain = data.chain || (data.id ? data : null);
      if (newChain) {
        var exists = _achChains.find(function (c) { return c.id === newChain.id; });
        if (!exists) _achChains.push(newChain);
      }
      _achRenderList();
      _achUpdatePill();
      _toast('Chain created from template', 'success');
    }).catch(function (err) {
      _toast('Create failed: ' + (err.error || 'unknown'), 'error');
    });
  }


  /* ── Public refresh hook ─────────────────────────────────── */
  window._refreshAttackChains = function () {
    if (_achLoaded) _achFetchChains();
  };

})();
