/* ══════════════════════════════════════════════════════════════════
   CRUCIBLE — project.html controller
   ══════════════════════════════════════════════════════════════════ */
(function(){
'use strict';

/* ── Bootstrap data ────────────────────────────────────────────── */
var _cfg = JSON.parse(document.getElementById('projectConfig').textContent);
var PID = _cfg.pid;
var PROJECT = _cfg.project;
var TOOLS_CFG = _cfg.toolsCfg;
var PROJECT_TOOLS = PROJECT.tools || [];

/* ── Session heartbeat — detect timeout and redirect to login ──── */
(function _sessionHeartbeat() {
    var _heartbeatInterval = 60000;
    setInterval(function() {
        fetch('/api/session-check', {credentials: 'same-origin'})
            .then(function(r) {
                if (r.status === 401) {
                    window.location.href = '/login';
                }
            })
            .catch(function() {});
    }, _heartbeatInterval);
})();

/* ── Error-level classification (CLAUDE.md section 14g) ────────── */
var _ERR_LEVELS = new Set(['ERROR','EXCEPTION','TOOL_ERROR','FATAL','CRITICAL']);
function _isErrEntry(e) {
    var lv = (e && (e.level || e.severity || e.risk) || '').toString().toUpperCase();
    return _ERR_LEVELS.has(lv);
}

/* ── Tool ID resolution (subtool → parent tool_id) ─────────────── */
var _TOOL_ALIAS = {
    'scattershot3': 'ss3', 'scattershot': 'ss3', 'ss': 'ss3',
    'nmap': 'ss3', 'nmap-nse': 'ss3', 'masscan': 'ss3',
    'testssl.sh': 'testssl', 'shcheck': 'ss3',
    'gobuster': 'ss3', 'nikto': 'ss3', 'wpscan': 'ss3',
    'whatweb': 'ss3', 'ssh-audit': 'ss3',
    'http': 'ss3', 'http-fetch': 'ss3',
    'curl': 'ss3', 'nc-probe': 'ss3', 'snmpwalk': 'ss3',
    'smbmap': 'ss3', 'smbclient': 'ss3', 'enum4linux': 'ss3',
    'rpcclient': 'ss3', 'hydra': 'ss3', 'banner-grab': 'ss3',
    'http-probe': 'ss3',
    'osift-dns': 'osift', 'osift-crawl': 'osift',
    'virustotal': 'osift', 'trufflehog': 'osift',
    'censys': 'osift', 'shodan': 'osift', 'netlas': 'osift',
    'securitytrails': 'osift', 'tlsx': 'osift',
    'subfinder': 'osift', 'amass': 'osift', 'dnsx': 'osift',
    'chaos': 'osift', 'dnsdumpster': 'osift', 'rapiddns': 'osift',
    'theharvester': 'osift', 'recon-ng': 'osift', 'whois': 'osift',
    'metagoofil': 'osift', 'spiderfoot': 'osift',
};
function _resolveToolId(raw) {
    if (!raw) return '';
    var lower = raw.toLowerCase().trim();
    if (TOOLS_CFG[lower]) return lower;
    if (_TOOL_ALIAS[lower]) return _TOOL_ALIAS[lower];
    for (var tid in TOOLS_CFG) {
        if (TOOLS_CFG[tid].name && TOOLS_CFG[tid].name.toLowerCase() === lower) return tid;
    }
    return raw;
}

/* ── State ─────────────────────────────────────────────────────── */
var toolStatuses = {};      /* tool_id -> {status, phase, ...} */
var toolPhases = {};        /* tool_id -> { phase_key: {status, step, label, tools, active_tools} } */
var toolCheckpoints = {};   /* tool_id -> bool — true when a resume checkpoint exists on disk */
var consoleBuffers = {};    /* tool_id -> [lines] */
var selectedTool = null;    /* current console tool_id */
var _isMobile = /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);
var _MOBILE_CONSOLE_TAIL = 200;
var allFindings = [];       /* full array */
var filteredFindings = [];  /* after filter */
var showFP = false;
var fpFindings = [];        /* false positives */
var allActionItems = [];
var _actionSubTab = 'manual';
var allLogs = [];
var allErrors = [];
var logsPage = 1;
var errorsPage = 1;
var findingsPage = 1;
var FINDINGS_PER_PAGE = 50;
var LOGS_PER_PAGE = 100;
var ERRORS_PER_PAGE = 50;
var promptContext = null;    /* {project_id, tool_id, type} */
var sudoContext = null;      /* {project_id, tool_id} */
var riskOverrideCtx = null;  /* {finding} */
var notesCtx = null;         /* {finding} */
var settingsActiveTool = null;
var _activeIntelPanel = null;   /* currently displayed intel subtab id */
var _activeIntelTool = null;    /* tool_id for current intel subtab */
var _multiTargetState = {};     /* tool_id → {targets:[], activeTarget:'', perTarget:{url→{phases}}} */
var _mtActiveTarget = {};       /* tool_id → currently selected target URL for display */
var _findingsRefreshTimer = null;
var _activeToolCount = 0;
var _findingsDebouncePending = false;
var _findingsDebounceTimer = null;
var _findingsMissedWhileInactive = false;
var _v2Source = null;
var _serverSummary = null;
var _serverTotal = 0;
var _serverPages = 1;
var _v2Mode = false;
var _v2Params = {};
var _v2FiltersLoaded = false;
var _allFindingsLoaded = false;
var _sessState = { _loaded: false, sessions: [], refreshTimer: null };


/* ══════════════════════════════════════════════════════════════════
   1. TAB SWITCHING
   ══════════════════════════════════════════════════════════════════ */
var tabNav = document.getElementById('tabNav');
tabNav.addEventListener('click', function(e) {
    var btn = e.target.closest('.tab-btn');
    if (!btn) return;
    var tab = btn.getAttribute('data-tab');
    if (!tab) return;

    /* toggle active on buttons */
    tabNav.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');

    /* toggle panes */
    document.querySelectorAll('.tab-content[data-tab]').forEach(function(p) {
        p.classList.toggle('active', p.getAttribute('data-tab') === tab);
    });

    /* lazy-load on first visit, or catch up if findings arrived while away */
    if (tab === 'findings') {
        if (!allFindings._loaded) {
            loadFindings();
        } else if (_findingsMissedWhileInactive) {
            _findingsMissedWhileInactive = false;
            if (_v2Mode) _fetchFindingsV2(_v2Params || _buildV2Params());
            else loadFindings(true);
        }
    }
    if (tab === 'action-items' && !allActionItems._loaded) loadActionItems();
    if (tab === 'logs' && !allLogs._loaded) loadLogs();
    if (tab === 'errors' && !allErrors._loaded) loadErrors();
    if (tab === 'settings') initSettingsTabs();
    if (tab === 'import' && !_impState._loaded) initImportTab();
    if (tab === 'attack-surface' && typeof window._initAttackSurface === 'function') window._initAttackSurface();
    if (tab === 'ai-surface' && typeof window._initAiSurface === 'function') window._initAiSurface();
    if (tab === 'sessions' && !_sessState._loaded) loadSessions();
});


/* ══════════════════════════════════════════════════════════════════
   2. SOCKET.IO CONNECTION
   ══════════════════════════════════════════════════════════════════ */
var socket = io({transports: ['websocket', 'polling']});

socket.on('connect', function() {
    socket.emit('join_project', {project_id: PID});
    socket.emit('get_status', {project_id: PID});
});

socket.on('reconnect', function() {
    socket.emit('join_project', {project_id: PID});
    socket.emit('get_status', {project_id: PID});
    var _b = document.getElementById('socketBanner');
    if (_b) _b.hidden = true;
});

socket.on('disconnect', function() {
    var _b = document.getElementById('socketBanner');
    if (!_b) {
        _b = document.createElement('div');
        _b.id = 'socketBanner';
        _b.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;background:#d32f2f;color:#fff;text-align:center;padding:4px 12px;font-size:13px;cursor:pointer';
        _b.textContent = 'Live connection lost — controls will use HTTP fallback. Click to reconnect.';
        _b.onclick = function() { socket.connect(); };
        document.body.prepend(_b);
    }
    _b.hidden = false;
});

socket.on('connect_error', function() {
    fetch('/api/session-check', {credentials: 'same-origin'})
        .then(function(r) {
            if (r.status === 401) window.location.href = '/login';
        })
        .catch(function() {});
});

/* ── all_status: bulk tool status on connect ───────────────────── */
socket.on('all_status', function(data) {
    if (data.project_id !== PID) return;
    var tools = data.tools || {};
    for (var tid in tools) {
        toolStatuses[tid] = tools[tid];
        if (tools[tid].mitm_active !== undefined) {
            toolStatuses[tid]._mitm_active = !!tools[tid].mitm_active;
        }
        if (tools[tid].mitm_paused !== undefined) {
            toolStatuses[tid]._mitm_paused = !!tools[tid].mitm_paused;
        }
        _derivePhaseStatuses(tid, tools[tid]);
    }
    var phases = data.phases || {};
    for (var tid2 in phases) {
        if (!toolPhases[tid2]) toolPhases[tid2] = {};
        var cached = phases[tid2];
        for (var pk in cached) {
            var _cat = cached[pk].active_tools || null;
            if (!_cat && cached[pk].active_tool) _cat = [cached[pk].active_tool];
            toolPhases[tid2][pk] = {
                status: cached[pk].status || 'idle',
                step: cached[pk].step || '',
                label: cached[pk].label || pk,
                tools: cached[pk].tools || null,
                active_tools: _cat,
                ts: cached[pk].ts || '',
                target: cached[pk].target || ''
            };
        }
    }
    renderToolFeeds();
});

var _checkpointFetched = {};

function _derivePhaseStatuses(tid, stObj) {
    var st = (typeof stObj === 'string' ? stObj : (stObj.status || '')).toLowerCase();
    if (st !== 'complete' && st !== 'killed' && st !== 'failed' && st !== 'cancelled' && st !== 'error' && st !== 'halted') return;
    if (toolPhases[tid] && Object.keys(toolPhases[tid]).length > 0) return;
    if (_checkpointFetched[tid]) return;
    _checkpointFetched[tid] = true;
    _fetchCheckpointPhases(tid, st);
}

function _fetchCheckpointPhases(tid, terminalStatus) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/checkpoint/' + PID + '/' + tid);
    xhr.onload = function() {
        if (xhr.status === 200) {
            try {
                var data = JSON.parse(xhr.responseText);
                var ck = data.checkpoint;
                if (ck && ck.phase_status && Object.keys(ck.phase_status).length > 0) {
                    _applyCheckpointPhases(tid, ck, terminalStatus);
                    return;
                }
            } catch(e) {}
        }
        _fallbackFillPhases(tid, terminalStatus);
    };
    xhr.onerror = function() {
        _fallbackFillPhases(tid, terminalStatus);
    };
    xhr.send();
}

function _applyCheckpointPhases(tid, checkpoint, terminalStatus) {
    var phaseStatus = checkpoint.phase_status || {};
    var completedSet = {};
    (checkpoint.completed_phases || []).forEach(function(k) { completedSet[k] = true; });
    var specs = CRUCIBLE_PHASE_SPECS[tid];

    if (!toolPhases[tid]) toolPhases[tid] = {};

    function _mapStatus(ckSt) {
        if (ckSt === 'complete') return 'complete';
        if (ckSt === 'skipped') return 'skipped';
        if (ckSt === 'running') return 'cancelled';
        if (ckSt === 'error' || ckSt === 'failed') return 'error';
        return ckSt || 'idle';
    }

    function _fillFromSpec(specList) {
        for (var i = 0; i < specList.length; i++) {
            var s = specList[i];
            var ckEntry = phaseStatus[s.key];
            if (ckEntry) {
                toolPhases[tid][s.key] = {
                    status: _mapStatus(ckEntry.status),
                    step: ckEntry.detail || '',
                    label: ckEntry.label || s.label,
                    ts: ckEntry.updated_at || ''
                };
            } else if (completedSet[s.key]) {
                toolPhases[tid][s.key] = {status: 'complete', step: '', label: s.label, ts: ''};
            } else {
                toolPhases[tid][s.key] = {status: 'idle', step: '', label: s.label, ts: ''};
            }
            if (s.subPhases) _fillFromSpec(s.subPhases);
        }
    }

    if (specs) {
        _fillFromSpec(specs);
    } else {
        for (var key in phaseStatus) {
            if (!phaseStatus.hasOwnProperty(key)) continue;
            var entry = phaseStatus[key];
            toolPhases[tid][key] = {
                status: _mapStatus(entry.status),
                step: entry.detail || '',
                label: entry.label || key,
                ts: entry.updated_at || ''
            };
        }
    }

    var _bci = tid.indexOf(':');
    var _bTool = _bci !== -1 ? tid.substring(0, _bci) : tid;
    if (_activeIntelPanel === 'status'
            && (_activeIntelTool === tid || _activeIntelTool === _bTool)) {
        var body = document.getElementById('intelBody');
        var empty = document.getElementById('intelEmpty');
        if (body) renderStatusPanel(_activeIntelTool, body, empty);
    }
    renderToolFeeds();
}

function _fallbackFillPhases(tid, terminalStatus) {
    var phaseSt = (terminalStatus === 'complete') ? 'complete' :
                  (terminalStatus === 'killed' || terminalStatus === 'cancelled' || terminalStatus === 'halted') ? 'cancelled' : 'error';
    var specs = CRUCIBLE_PHASE_SPECS[tid];
    if (!specs) return;
    if (!toolPhases[tid]) toolPhases[tid] = {};
    function _fillSpec(spec) {
        var cur = toolPhases[tid][spec.key];
        if (!cur || cur.status === 'running' || cur.status === 'idle') {
            toolPhases[tid][spec.key] = {status: phaseSt, step: (cur && cur.step) || '', label: spec.label, ts: ''};
        }
        if (spec.subPhases) spec.subPhases.forEach(_fillSpec);
    }
    specs.forEach(_fillSpec);

    var _bci2 = tid.indexOf(':');
    var _bTool2 = _bci2 !== -1 ? tid.substring(0, _bci2) : tid;
    if (_activeIntelPanel === 'status'
            && (_activeIntelTool === tid || _activeIntelTool === _bTool2)) {
        var body = document.getElementById('intelBody');
        var empty = document.getElementById('intelEmpty');
        if (body) renderStatusPanel(_activeIntelTool, body, empty);
    }
    renderToolFeeds();
}

/* ── tool_status: single tool status update ────────────────────── */
socket.on('tool_status', function(data) {
    if (data.project_id !== PID) return;
    var _sci = data.tool_id.indexOf(':');
    var _baseTool = _sci !== -1 ? data.tool_id.substring(0, _sci) : data.tool_id;
    if (data.phase) {
        var _at = data.active_tools || null;
        if (!_at && data.active_tool) _at = [data.active_tool];
        var _phaseEntry = {
            status: data.status || 'idle',
            step: data.step || '',
            label: data.label || data.phase,
            tools: data.tools || null,
            active_tools: _at,
            ts: data.ts || '',
            target: data.target || ''
        };
        if (!toolPhases[data.tool_id]) toolPhases[data.tool_id] = {};
        toolPhases[data.tool_id][data.phase] = _phaseEntry;
        if (_sci !== -1) {
            var _otherScopes = Object.keys(toolPhases).filter(function(k) {
                return k !== data.tool_id && k.indexOf(_baseTool + ':') === 0;
            });
            if (_otherScopes.length === 0) {
                if (!toolPhases[_baseTool]) toolPhases[_baseTool] = {};
                toolPhases[_baseTool][data.phase] = _phaseEntry;
            }
        }
        if (data.target && data.target_total > 1) {
            var _mt = _multiTargetState[_baseTool];
            if (!_mt) {
                _mt = {targets: [], activeTarget: '', perTarget: {}, targetTotal: 0};
                _multiTargetState[_baseTool] = _mt;
            }
            _mt.targetTotal = data.target_total || 0;
            if (_mt.targets.indexOf(data.target) === -1) _mt.targets.push(data.target);
            _mt.activeTarget = data.target;
            if (!_mt.perTarget[data.target]) _mt.perTarget[data.target] = {};
            _mt.perTarget[data.target][data.phase] = _phaseEntry;
            if (!_mtActiveTarget[_baseTool]) _mtActiveTarget[_baseTool] = data.target;
        }
        var _phSt = (data.status || '').toLowerCase();
        if (_phSt === 'running' || _phSt === 'pausing') {
            var _cur = toolStatuses[data.tool_id];
            if (!_cur || !_cur.status || _cur.status === 'idle') {
                toolStatuses[data.tool_id] = {status: _phSt, tool_id: data.tool_id, project_id: data.project_id};
            }
        }
        if (data.mitm_active !== undefined) {
            if (!toolStatuses[data.tool_id]) toolStatuses[data.tool_id] = {};
            toolStatuses[data.tool_id]._mitm_active = !!data.mitm_active;
        }
        if (data.mitm_paused !== undefined) {
            if (!toolStatuses[data.tool_id]) toolStatuses[data.tool_id] = {};
            toolStatuses[data.tool_id]._mitm_paused = !!data.mitm_paused;
        }
        if (data.phase === 'mitm_capture' && (_phSt === 'complete' || _phSt === 'error' || _phSt === 'skipped')) {
            if (toolStatuses[data.tool_id]) {
                toolStatuses[data.tool_id]._mitm_active = false;
                toolStatuses[data.tool_id]._mitm_paused = false;
            }
        }
    } else {
        toolStatuses[data.tool_id] = data;
        if (_sci !== -1) {
            var _existing = toolStatuses[_baseTool];
            if (!_existing || _existing.resolved_key) {
                data.resolved_key = data.tool_id;
                toolStatuses[_baseTool] = data;
            }
        }
    }
    if (!data.phase) _fetchQueueData();
    renderToolFeeds();
    updateConsoleHeader();
    _updatePauseAllButtons();
    var _statusMatch = _activeIntelPanel === 'status'
        && (_activeIntelTool === data.tool_id || _activeIntelTool === _baseTool);
    if (_statusMatch) {
        var body = document.getElementById('intelBody');
        var empty = document.getElementById('intelEmpty');
        if (body) renderStatusPanel(_activeIntelTool, body, empty);
    }
    if (!data.phase && data.status === 'complete') {
        if (allFindings._loaded) loadFindings(true);
        if (_activeIntelPanel && _activeIntelPanel !== 'status' && _activeIntelPanel !== 'overview') {
            var toolScopes = TOOL_SUBTABS[data.tool_id] || TOOL_SUBTABS[_baseTool];
            if (toolScopes) {
                for (var si = 0; si < toolScopes.length; si++) {
                    if (toolScopes[si][0] === _activeIntelPanel) {
                        loadIntelPanel(_activeIntelPanel, _activeIntelTool);
                        break;
                    }
                }
            }
        }
    }
});

/* ── tool_registered: tool dynamically added to project ────────── */
socket.on('tool_registered', function(data) {
    if (data.project_id !== PID) return;
    var tid = data.tool_id;
    if (PROJECT_TOOLS.indexOf(tid) === -1) PROJECT_TOOLS.push(tid);
    if (data.tools) PROJECT.tools = data.tools;
    if (data.scope_tools) PROJECT.scope_tools = data.scope_tools;
    try { renderToolFeeds(); } catch(e) { console.error('tool_registered: renderToolFeeds failed', e); }
    try {
        if (data.scope && typeof _addToolToIntelScope === 'function') {
            _addToolToIntelScope(tid, data.scope, data.origin_scope);
        }
    } catch(e) { console.error('tool_registered: _addToolToIntelScope failed', e); }
    try {
        if (typeof _syncIntelScopes === 'function') _syncIntelScopes();
    } catch(e) { console.error('tool_registered: _syncIntelScopes failed', e); }
});

/* ── console_line: live console output ─────────────────────────── */
socket.on('console_line', function(data) {
    if (data.project_id !== PID) return;
    var tid = data.tool_id;
    if (!consoleBuffers[tid]) consoleBuffers[tid] = [];
    consoleBuffers[tid].push(data);
    var maxBuf = _isMobile ? _MOBILE_CONSOLE_TAIL : 5000;
    if (consoleBuffers[tid].length > maxBuf) consoleBuffers[tid].shift();
    if (tid === selectedTool) appendConsoleLine(data);
    var _clSt = toolStatuses[tid];
    if (!_clSt || !_clSt.status || _clSt.status === 'idle') {
        toolStatuses[tid] = {status: 'running', tool_id: tid, project_id: PID};
        renderToolFeeds();
        updateConsoleHeader();
    }
});

/* ── console_buffer: batch history ─────────────────────────────── */
socket.on('console_buffer', function(data) {
    if (data.project_id !== PID) return;
    var tid = data.tool_id;
    consoleBuffers[tid] = data.lines || [];
    if (tid === selectedTool) renderConsole();
});

/* ── tool_finding: new finding discovered ──────────────────────── */
socket.on('tool_finding', function(data) {
    if (data.project_id !== PID) return;
    var pill = document.getElementById('findingsPill');
    if (_v2Mode) {
        _serverTotal = (_serverTotal || 0) + 1;
        if (pill) pill.textContent = _serverTotal || '';
    } else {
        if (!allFindings._loaded) {
            allFindings = [];
            allFindings._loaded = true;
        }
        allFindings.push(data);
        if (pill) pill.textContent = allFindings.length || '';
    }
    _findingsDebouncePending = true;
    if (!_findingsDebounceTimer) {
        _findingsDebounceTimer = setTimeout(function() {
            _findingsDebounceTimer = null;
            if (!_findingsDebouncePending) return;
            _findingsDebouncePending = false;
            if (document.querySelector('.tab-content[data-tab="findings"].active')) {
                if (_v2Mode) {
                    _fetchFindingsV2(_v2Params);
                } else {
                    applyFindingsFilter();
                }
            } else {
                _findingsMissedWhileInactive = true;
            }
            updateRiskOverview();
        }, 2000);
    }
});

/* ── action item pill: count only non-complete/non-dismissed ────── */
function _activeActionCount(items) {
    var count = 0;
    for (var i = 0; i < items.length; i++) {
        var s = (items[i].status || 'pending').toLowerCase();
        if (s !== 'complete' && s !== 'dismissed' && s !== 'confirmed_missing' && s !== 'confirmed_exists') count++;
    }
    return count;
}

/* ── tool_action_item: new action item ─────────────────────────── */
socket.on('tool_action_item', function(data) {
    if (data.project_id !== PID) return;
    if (!allActionItems._loaded) {
        allActionItems = [];
        allActionItems._loaded = true;
    }
    if (data.id) {
        for (var i = 0; i < allActionItems.length; i++) {
            if (allActionItems[i].id === data.id) return;
        }
    }
    allActionItems.push(data);
    var inScope = allActionItems.filter(_isInScope);
    document.getElementById('actionPill').textContent = _activeActionCount(inScope) || '';
    if (document.querySelector('.tab-content[data-tab="action-items"].active')) {
        renderActionItems();
    }
});

/* ── findings_updated: server-side cache refreshed ─────────────── */
socket.on('findings_updated', function(data) {
    if (data.project_id !== PID) return;
    loadFindings(true);
});

/* ── action_items_updated: bulk generation (post-completion) ───── */
socket.on('action_items_updated', function(data) {
    if (data.project_id !== PID) return;
    fetch('/api/action-items/' + PID).then(function(r) { return r.json(); })
        .then(function(resp) {
            allActionItems = resp.items || [];
            allActionItems._loaded = true;
            var inScope = allActionItems.filter(_isInScope);
            document.getElementById('actionPill').textContent = _activeActionCount(inScope) || '';
            if (document.querySelector('.tab-content[data-tab="action-items"].active')) {
                renderActionItems();
            }
        });
});

/* ── tool_target / tool_port: new target data ──────────────────── */
var _targetRefreshTimer = null;
function _scheduleTargetRefresh() {
    if (_activeIntelPanel !== 'targets') return;
    if (_targetRefreshTimer) clearTimeout(_targetRefreshTimer);
    _targetRefreshTimer = setTimeout(function() {
        _targetRefreshTimer = null;
        var body = document.getElementById('intelBody');
        var empty = document.getElementById('intelEmpty');
        if (body) _loadIntelTargets(body, empty);
    }, 2000);
}

socket.on('tool_target', function(data) {
    if (data.project_id !== PID) return;
    _scheduleTargetRefresh();
});

socket.on('tool_port', function(data) {
    if (data.project_id !== PID) return;
    _scheduleTargetRefresh();
});

/* ── tool_log / tool_error: log entries ────────────────────────── */
socket.on('tool_log', function(data) {
    if (data.project_id !== PID) return;
    allLogs.push(data);
    if (_isErrEntry(data)) updateLogsPill();
    if (document.querySelector('.tab-content[data-tab="logs"].active')) renderLogs();
});

socket.on('tool_error', function(data) {
    if (data.project_id !== PID) return;
    allErrors.push(data);
    updateErrorsPill();
    if (document.querySelector('.tab-content[data-tab="errors"].active')) renderErrors();
});

/* ── tool_prompt: interactive prompt from tool ─────────────────── */
socket.on('tool_prompt', function(data) {
    if (data.project_id !== PID) return;
    var p = data.payload || data;
    if (p.type === 'sudo') {
        sudoContext = {project_id: PID, tool_id: data.tool_id};
        var toolName = TOOLS_CFG[data.tool_id] ? TOOLS_CFG[data.tool_id].name : data.tool_id;
        document.getElementById('sudoToolLabel').textContent = toolName + ' requires elevated privileges.';
        document.getElementById('sudoPasswordInput').value = '';
        document.getElementById('sudoModal').classList.add('open');
    } else {
        promptContext = {project_id: PID, tool_id: data.tool_id, type: p.type || 'input'};
        document.getElementById('promptTitle').textContent = p.title || 'Tool Prompt';
        document.getElementById('promptMessage').textContent = p.question || p.message || '';
        document.getElementById('promptInput').value = '';
        document.getElementById('promptInput').placeholder = p.placeholder || '';
        if (p.type === 'confirm' && p.options && p.options.length) {
            document.getElementById('promptInput').placeholder = p.options.join(' / ');
        }
        document.getElementById('promptModal').classList.add('open');
        document.getElementById('promptInput').focus();
    }
});

socket.on('prompt_resolved', function(data) {
    if (data.project_id !== PID) return;
    document.getElementById('promptModal').classList.remove('open');
    promptContext = null;
});

socket.on('sudo_accepted', function(data) {
    if (data.project_id !== PID) return;
    document.getElementById('sudoModal').classList.remove('open');
    sudoContext = null;
    toast('success', 'Authentication accepted.');
});

/* ── tool_done / tool_started / tool_killed ────────────────────── */
socket.on('tool_done', function(data) {
    if (data.project_id !== PID) return;
    var name = TOOLS_CFG[data.tool_id] ? TOOLS_CFG[data.tool_id].name : data.tool_id;
    if (data.status === 'failed') {
        toast('error', name + ' failed (exit code ' + (data.returncode || '?') + ').');
    } else {
        toast('info', name + ' completed.');
    }
    if (allFindings._loaded) loadFindings(true);
    if (_activeIntelPanel && _activeIntelPanel !== 'status' && _activeIntelPanel !== 'overview') {
        loadIntelPanel(_activeIntelPanel, _activeIntelTool);
    }
    _activeToolCount = Math.max(0, _activeToolCount - 1);
    if (_activeToolCount === 0 && _findingsRefreshTimer) {
        clearInterval(_findingsRefreshTimer);
        _findingsRefreshTimer = null;
    }
    if (allActionItems._loaded) loadActionItems();
    _populateEngagementTiming({engagement_start_time: null, engagement_end_time: new Date().toISOString()});
    _fetchQueueData();
    if (data.status === 'killed' || data.status === 'failed') {
        fetch('/api/checkpoint/' + PID + '/' + data.tool_id, {credentials: 'same-origin'})
            .then(function(r) { return r.json(); })
            .then(function(d) {
                toolCheckpoints[data.tool_id] = !!d.exists;
                _updatePauseAllButtons();
                if (data.tool_id === selectedTool) updateConsoleHeader();
            })
            .catch(function() { toolCheckpoints[data.tool_id] = false; });
    }
});

socket.on('tool_started', function(data) {
    if (data.project_id !== PID) return;
    toast('info', (TOOLS_CFG[data.tool_id] ? TOOLS_CFG[data.tool_id].name : data.tool_id) + ' started.');
    _activeToolCount++;
    _fetchQueueData();
    if (!_findingsRefreshTimer) {
        _findingsRefreshTimer = setInterval(function() {
            if (_v2Mode) {
                _fetchFindingsV2(_v2Params);
            } else if (allFindings._loaded) {
                loadFindings(true);
            }
        }, 30000);
    }
    var startEl = document.getElementById('engagementStartTime');
    if (startEl && startEl.textContent === '--') {
        _populateEngagementTiming({engagement_start_time: new Date().toISOString(), engagement_end_time: null});
    }
});

socket.on('tool_killed', function(data) {
    if (data.project_id !== PID) return;
    toast('warning', (TOOLS_CFG[data.tool_id] ? TOOLS_CFG[data.tool_id].name : data.tool_id) + ' killed.');
    _activeToolCount = Math.max(0, _activeToolCount - 1);
    if (_activeToolCount === 0 && _findingsRefreshTimer) {
        clearInterval(_findingsRefreshTimer);
        _findingsRefreshTimer = null;
    }
    _fetchQueueData();
    fetch('/api/checkpoint/' + PID + '/' + data.tool_id, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            toolCheckpoints[data.tool_id] = !!d.exists;
            _updatePauseAllButtons();
            if (data.tool_id === selectedTool) updateConsoleHeader();
        })
        .catch(function() { toolCheckpoints[data.tool_id] = false; });
});

socket.on('tool_queued', function(data) {
    if (data.project_id !== PID) return;
    var tid = data.tool_id;
    var name = TOOLS_CFG[tid] ? TOOLS_CFG[tid].name : tid;
    var msg = name + ' queued.';
    if (data.reason) msg += ' ' + data.reason;
    toast('info', msg);
    if (!toolStatuses[tid] || toolStatuses[tid].status !== 'running') {
        toolStatuses[tid] = toolStatuses[tid] || {};
        toolStatuses[tid].status = 'queued';
        if (data.reason) toolStatuses[tid].phase = data.reason;
    }
    _fetchQueueData();
});

/* ── Desktop notifications ────────────────────────────────────── */
var _notifRequested = false;
function _requestNotifPermission() {
    if (_notifRequested || !('Notification' in window)) return;
    _notifRequested = true;
    if (Notification.permission === 'default') {
        Notification.requestPermission();
    }
}
document.addEventListener('click', _requestNotifPermission, {once: true});

function _desktopNotify(title, body) {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    if (!document.hidden) return;
    try {
        var n = new Notification(title, {body: body, icon: '/static/img/logo.svg', tag: 'crucible-scan'});
        n.onclick = function() { window.focus(); n.close(); };
        setTimeout(function() { n.close(); }, 10000);
    } catch(e) {}
}

socket.on('tool_done', function(data) {
    if (data.project_id !== PID) return;
    var name = TOOLS_CFG[data.tool_id] ? TOOLS_CFG[data.tool_id].name : data.tool_id;
    _desktopNotify('Scan Complete', name + ' finished' + (data.status ? ' — ' + data.status : ''));
});
socket.on('tool_killed', function(data) {
    if (data.project_id !== PID) return;
    var name = TOOLS_CFG[data.tool_id] ? TOOLS_CFG[data.tool_id].name : data.tool_id;
    _desktopNotify('Scan Terminated', name + ' was killed');
});

/* ── console_cleared: tool session cleaned up after full reset ── */
socket.on('console_cleared', function(data) {
    if (data.project_id !== PID) return;
    var tid = data.tool_id;
    delete toolStatuses[tid];
    delete toolPhases[tid];
    // Also clear scope-qualified keys
    Object.keys(toolStatuses).forEach(function(k) {
        if (k === tid || k.indexOf(tid + ':') === 0) delete toolStatuses[k];
    });
    Object.keys(toolPhases).forEach(function(k) {
        if (k === tid || k.indexOf(tid + ':') === 0) delete toolPhases[k];
    });
    if (data.unregistered) {
        var idx = PROJECT_TOOLS.indexOf(tid);
        if (idx !== -1) PROJECT_TOOLS.splice(idx, 1);
        if (PROJECT.tools) {
            var ti = PROJECT.tools.indexOf(tid);
            if (ti !== -1) PROJECT.tools.splice(ti, 1);
        }
        if (PROJECT.scope_tools) {
            Object.keys(PROJECT.scope_tools).forEach(function(sk) {
                var arr = PROJECT.scope_tools[sk];
                var si = arr.indexOf(tid);
                if (si !== -1) arr.splice(si, 1);
            });
        }
        if (selectedTool === tid) {
            selectedTool = PROJECT_TOOLS.length ? PROJECT_TOOLS[0] : null;
        }
    }
    renderToolFeeds();
    updateConsoleHeader();
});

/* ── checkpoint_status ─────────────────────────────────────────── */
socket.on('checkpoint_status', function(data) {
    if (data.project_id !== PID) return;
    toolCheckpoints[data.tool_id] = !!data.exists;
    if (data.tool_id === selectedTool) {
        updateConsoleHeader();
    }
    _updatePauseAllButtons();
});

/* ── error: generic SocketIO error ─────────────────────────────── */
socket.on('error', function(data) {
    var msg = data.message || 'An error occurred.';
    if (msg === 'Not authenticated') {
        fetch('/api/session-check', {credentials: 'same-origin'})
            .then(function(r) {
                if (r.status === 401) {
                    window.location.href = '/login';
                } else {
                    socket.disconnect();
                    socket.connect();
                }
            })
            .catch(function() { window.location.href = '/login'; });
        return;
    }
    toast('error', msg);
});


/* ══════════════════════════════════════════════════════════════════
   3. SUMMARY TAB — System Info + Risk Overview
   ══════════════════════════════════════════════════════════════════ */
function loadSystemInfo() {
    fetch('/api/system_info', {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var grid = document.getElementById('systemInfoGrid');
            grid.innerHTML = '';
            var osInfo = (typeof d.os === 'object' && d.os) ? (d.os.os_name || d.os.system || '') : (d.os || '');
            var kernelInfo = d.kernel || ((typeof d.os === 'object' && d.os) ? d.os.release : '') || '';
            var ipInfo = d.ip || ((typeof d.interface === 'object' && d.interface) ? d.interface.ip : '') || '';
            var pyInfo = d.python || '';
            var uptimeInfo = d.uptime || '';
            var fields = [
                ['Hostname', d.hostname],
                ['OS', osInfo],
                ['Kernel', kernelInfo],
                ['IP Address', ipInfo],
                ['Python', pyInfo],
                ['Uptime', uptimeInfo]
            ];
            fields.forEach(function(f) {
                grid.innerHTML += '<div class="form-group"><span class="form-label">' + esc(f[0]) + '</span><span class="text-primary text-sm font-mono">' + esc(f[1] || '--') + '</span></div>';
            });
        })
        .catch(function() {
            document.getElementById('systemInfoGrid').innerHTML = '<div class="form-group"><span class="text-muted">Failed to load system info.</span></div>';
        });
}
loadSystemInfo();

/* ── Eager pill counts — load on page init without full tab data ── */
(function _loadPillCounts() {
    fetch('/api/action-items/' + PID, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var items = data.items || data || [];
            var inScope = items.filter(_isInScope);
            document.getElementById('actionPill').textContent = _activeActionCount(inScope) || '';
        }).catch(function(){});
    fetch('/api/errors/' + PID, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var entries = data.entries || data || [];
            document.getElementById('errorsPill').textContent = entries.length || '';
        }).catch(function(){});
})();

function updateRiskOverview() {
    var counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};
    if (_serverSummary) {
        counts.CRITICAL = _serverSummary.CRITICAL || 0;
        counts.HIGH = _serverSummary.HIGH || 0;
        counts.MEDIUM = _serverSummary.MEDIUM || 0;
        counts.LOW = _serverSummary.LOW || 0;
        counts.INFO = _serverSummary.INFO || 0;
    } else {
        allFindings.forEach(function(f) { var r = (f.risk||'').toUpperCase(); if (counts[r] !== undefined) counts[r]++; });
    }
    document.getElementById('riskCritical').textContent = counts.CRITICAL;
    document.getElementById('riskHigh').textContent = counts.HIGH;
    document.getElementById('riskMedium').textContent = counts.MEDIUM;
    document.getElementById('riskLow').textContent = counts.LOW;
    document.getElementById('riskInfo').textContent = counts.INFO;
    var total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW + counts.INFO;
    document.getElementById('riskTotal').textContent = total + ' finding' + (total !== 1 ? 's' : '');
    document.getElementById('findingsPill').textContent = _serverTotal || total || '';

    /* risk bar */
    var bar = document.getElementById('riskBarInner');
    bar.innerHTML = '';
    if (total) {
        var segs = [
            {c: counts.CRITICAL, color: 'var(--risk-critical)'},
            {c: counts.HIGH, color: 'var(--risk-high)'},
            {c: counts.MEDIUM, color: 'var(--risk-medium)'},
            {c: counts.LOW, color: 'var(--risk-low)'},
            {c: counts.INFO, color: 'var(--risk-info)'}
        ];
        segs.forEach(function(s) {
            if (!s.c) return;
            var d = document.createElement('div');
            d.style.width = ((s.c / total) * 100) + '%';
            d.style.background = s.color;
            d.style.height = '100%';
            bar.appendChild(d);
        });
    }
}


/* ══════════════════════════════════════════════════════════════════
   4. TOOL FEEDS — Summary + Console sidebar
   ══════════════════════════════════════════════════════════════════ */
var SCOPE_DISPLAY_NAMES = {
    external:'External', internal:'Internal',
    webapp:'Web Application', api:'API', osint:'OSINT', database:'Database',
    pcap:'PCAP Analysis', wifi:'Wi-Fi (802.11)', bluetooth:'Bluetooth (802.15.1)',
    zigbee:'Zigbee (802.15.4)', uwb:'Ultra-Wideband (UWB) (802.15.4z)',
    firewall:'Firewall Config Analysis', cloud:'Cloud Infrastructure',
    mobile:'Mobile Application', file:'File Analysis',
    endpoint:'Endpoint Security'
};

var _SCOPE_TARGET_KEY = {
    external:'network_cidrs', internal:'network_cidrs',
    webapp:'target_urls', api:'api_urls', osint:'domains',
    database:'db_targets', pcap:'trawler_targets',
    wifi:'wireless_ssids', bluetooth:'wireless_ssids',
    zigbee:'wireless_ssids', uwb:'wireless_ssids',
    endpoint:'endpoint_targets'
};

function renderToolFeeds() {
    _renderSummaryFeed();
    renderFeed('consoleToolFeed', true);
}

function _renderSummaryFeed() {
    var container = document.getElementById('summaryToolFeed');
    if (!container) return;
    container.innerHTML = '';

    var scopeTools = PROJECT.scope_tools || {};
    var scopeDef = PROJECT.scope_definition || {};
    var rendered = {};
    var scopeKeys = Object.keys(scopeTools).filter(function(k) { return k !== 'multi'; });

    scopeKeys.forEach(function(sk) {
        var tids = scopeTools[sk] || [];
        if (!tids.length) return;
        var dn = SCOPE_DISPLAY_NAMES[sk] || sk;
        var targetKey = _SCOPE_TARGET_KEY[sk] || '';
        var targets = targetKey ? (scopeDef[targetKey] || []) : [];
        if (typeof targets === 'string') targets = targets.split('\n').filter(function(t) { return t.trim(); });

        var header = document.createElement('div');
        header.style.cssText = 'padding:10px 0 4px;margin-top:8px;border-bottom:1px solid var(--border);display:flex;align-items:baseline;gap:8px';
        header.innerHTML = '<span style="font-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-primary)">' + esc(dn) + '</span>' +
            '<span style="font-size:11px;color:var(--text-muted)">' + tids.length + ' tool' + (tids.length !== 1 ? 's' : '') + '</span>';
        container.appendChild(header);

        if (targets.length) {
            var tgt = document.createElement('div');
            tgt.style.cssText = 'padding:4px 0 6px 4px;font-size:11px;color:var(--text-secondary);line-height:1.5';
            var label = targets.length === 1 ? 'Target' : 'Targets';
            tgt.innerHTML = '<span style="font-weight:600;color:var(--text-muted)">' + label + ':</span> ' +
                esc(targets.slice(0, 8).join(', ')) + (targets.length > 8 ? ' <span style="color:var(--text-muted)">+' + (targets.length - 8) + ' more</span>' : '');
            container.appendChild(tgt);
        }

        tids.forEach(function(tid) {
            rendered[tid] = true;
            container.appendChild(_buildFeedItem(tid, false));
        });
    });

    PROJECT_TOOLS.forEach(function(tid) {
        if (rendered[tid]) return;
        container.appendChild(_buildFeedItem(tid, false));
    });
}

function _buildFeedItem(tid, clickable) {
    var baseTid = tid;
    var scopeSuffix = '';
    var sci = tid.indexOf(':');
    if (sci !== -1) {
        baseTid = tid.substring(0, sci);
        scopeSuffix = tid.substring(sci + 1);
    }
    var cfg = TOOLS_CFG[baseTid] || {};
    var st = toolStatuses[tid] || {};
    var status = (st.status || 'idle').toLowerCase();
    var phase = st.phase || st.last_phase || '';
    var key = cfg.key || baseTid.toUpperCase().substring(0,2);
    var cssClass = 'tool-' + key.toLowerCase();

    var displayName = cfg.name || baseTid;
    if (scopeSuffix) {
        var isOOS = /_oos$/i.test(scopeSuffix);
        var scopeDisplay = scopeSuffix.replace(/_?oos$/i, '').replace(/_/g, ' ').trim();
        if (isOOS) {
            displayName += scopeDisplay ? ' — OOS ' + scopeDisplay : ' — OOS';
        } else if (scopeDisplay) {
            displayName += ' — ' + scopeDisplay;
        }
    }

    var item = document.createElement('div');
    item.className = 'feed-item' + (clickable && tid === selectedTool ? ' active' : '');
    item.setAttribute('data-tool', tid);

    var ver = st.tool_version || '';
    item.innerHTML =
        '<div class="feed-item-icon tool-badge ' + cssClass + '">' + esc(key) + '</div>' +
        '<div class="feed-item-body">' +
            '<div class="feed-item-name">' + esc(displayName) +
                (ver ? ' <span style="font-size:0.8em;color:var(--text-muted);font-weight:400">v' + esc(ver) + '</span>' : '') +
            '</div>' +
            '<div class="feed-item-preview">' + esc(phase || status) + '</div>' +
        '</div>' +
        '<div class="feed-item-actions">' +
            '<button class="btn-icon btn-instance-info" title="Instance details" data-tid="' + esc(tid) + '">' +
                '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>' +
            '</button>' +
        '</div>' +
        '<div class="feed-item-status">' +
            '<span class="status-badge status-' + esc(status) + '">' + esc(status) + '</span>' +
        '</div>';

    var infoBtn = item.querySelector('.btn-instance-info');
    if (infoBtn) {
        infoBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            openInstanceDetail(tid);
        });
    }

    if (clickable) {
        item.style.cursor = 'pointer';
        item.addEventListener('click', function() { selectTool(tid); });
    }
    return item;
}

var _NO_CONSOLE = {'nessus':1};
var _queueData = [];
var _ACTIVE_STATUSES = {'running':1,'pausing':1,'paused':1,'idle':1,'queued':1};
var _COMPLETE_STATUSES = {'complete':1,'failed':1,'killed':1};

function _fetchQueueData() {
    fetch('/api/queue/' + PID, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            _queueData = d.queue || [];
            renderToolFeeds();
        })
        .catch(function() {});
}

function _buildSectionHeader(label) {
    var hdr = document.createElement('div');
    hdr.style.cssText = 'padding:6px 8px 4px;margin-top:4px;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);border-bottom:1px solid var(--border)';
    hdr.textContent = label;
    return hdr;
}

function _buildQueueFeedItem(entry, position) {
    var tid = entry.tool_id;
    var cfg = TOOLS_CFG[tid] || {};
    var key = cfg.key || tid.toUpperCase().substring(0,2);
    var cssClass = 'tool-' + key.toLowerCase();
    var displayName = cfg.name || tid;
    var scope = entry.scope || '';
    if (scope) {
        var isOOS = /_oos$/i.test(scope);
        var sd = scope.replace(/_?oos$/i, '').replace(/_/g, ' ').trim();
        if (isOOS) displayName += sd ? ' — OOS ' + sd : ' — OOS';
        else if (sd) displayName += ' — ' + sd;
    }

    var item = document.createElement('div');
    item.className = 'feed-item';
    item.setAttribute('data-tool', tid);
    item.style.cursor = 'pointer';

    item.innerHTML =
        '<div class="feed-item-icon tool-badge ' + cssClass + '">' + esc(key) + '</div>' +
        '<div class="feed-item-body">' +
            '<div class="feed-item-name">' + esc(displayName) + '</div>' +
            '<div class="feed-item-preview" style="font-size:0.72rem;color:var(--text-muted)">Queued ' + esc(entry.queued_at || '') + '</div>' +
        '</div>' +
        '<div style="display:flex;align-items:center;gap:6px;margin-left:auto">' +
            '<span style="background:var(--accent);color:#fff;border-radius:999px;padding:1px 7px;font-size:11px;font-weight:700;min-width:20px;text-align:center">' + position + '</span>' +
            '<button class="btn-icon btn-dequeue" title="Remove from queue" data-tid="' + esc(tid) + '" style="color:var(--risk-high);opacity:0.7">' +
                '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>' +
            '</button>' +
        '</div>';

    item.querySelector('.btn-dequeue').addEventListener('click', function(e) {
        e.stopPropagation();
        _dequeueTool(tid);
    });
    item.addEventListener('click', function() { selectTool(tid); });
    return item;
}

function _dequeueTool(tid) {
    fetch('/api/dequeue', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, tool_id: tid})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok && d.removed) {
            toast('info', (TOOLS_CFG[tid] ? TOOLS_CFG[tid].name : tid) + ' removed from queue.');
            if (toolStatuses[tid] && toolStatuses[tid].status === 'queued') {
                toolStatuses[tid].status = 'idle';
            }
            _fetchQueueData();
        } else if (d.ok) {
            toast('info', 'Tool was not in the queue.');
        } else {
            toast('error', d.error || 'Dequeue failed.');
        }
    })
    .catch(function() { toast('error', 'Dequeue failed.'); });
}

function renderFeed(containerId, clickable) {
    var container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';

    var rendered = {};
    var _SCOPE_DYNAMIC = {'fracture':1,'siphon':1,'ss3':1,'osift':1};

    /* Collect all known tool ids (base + scoped dynamic) */
    var allTids = [];
    PROJECT_TOOLS.forEach(function(tid) {
        var st = toolStatuses[tid] || {};
        if (st.resolved_key) return;
        if (clickable && _NO_CONSOLE[tid]) return;
        allTids.push(tid);
    });
    Object.keys(toolStatuses).sort().forEach(function(tid) {
        if (tid.indexOf(':') === -1) return;
        if (allTids.indexOf(tid) !== -1) return;
        var st = (toolStatuses[tid] || {}).status || 'idle';
        if (st === 'idle') return;
        allTids.push(tid);
    });

    /* Classify each tool into sections */
    var depsTids = [];
    var activeTids = [];
    var completeTids = [];
    var queuedTidSet = {};
    _queueData.forEach(function(e) { queuedTidSet[e.tool_id] = true; });

    allTids.forEach(function(tid) {
        var baseTid = tid.indexOf(':') !== -1 ? tid.substring(0, tid.indexOf(':')) : tid;
        if (baseTid === 'deps') {
            depsTids.push(tid);
            return;
        }
        var st = (toolStatuses[tid] || {}).status || 'idle';
        if (_COMPLETE_STATUSES[st]) {
            completeTids.push(tid);
        } else {
            activeTids.push(tid);
        }
    });

    /* 1. Dependencies section — always visible */
    container.appendChild(_buildSectionHeader('Dependencies'));
    if (depsTids.length) {
        depsTids.forEach(function(tid) {
            rendered[tid] = true;
            container.appendChild(_buildFeedItem(tid, clickable));
        });
    } else {
        var depsPlaceholder = document.createElement('div');
        depsPlaceholder.className = 'feed-item';
        depsPlaceholder.setAttribute('data-tool', 'deps');
        depsPlaceholder.style.cursor = 'pointer';
        depsPlaceholder.innerHTML =
            '<div class="feed-item-icon tool-badge tool-dp">DP</div>' +
            '<div class="feed-item-body">' +
                '<div class="feed-item-name">Dependencies</div>' +
                '<div class="feed-item-preview">o365spray, nuclei, testssl...</div>' +
            '</div>' +
            '<div class="feed-item-status">' +
                '<span class="status-badge status-idle">idle</span>' +
            '</div>';
        if (clickable) {
            depsPlaceholder.addEventListener('click', function() { selectTool('deps'); });
        }
        container.appendChild(depsPlaceholder);
        rendered['deps'] = true;
    }

    /* 2. Active section */
    container.appendChild(_buildSectionHeader('Active'));
    if (activeTids.length) {
        activeTids.forEach(function(tid) {
            rendered[tid] = true;
            container.appendChild(_buildFeedItem(tid, clickable));
        });
    } else {
        var emptyActive = document.createElement('div');
        emptyActive.style.cssText = 'padding:8px 12px;font-size:0.78rem;color:var(--text-muted);font-style:italic';
        emptyActive.textContent = 'No active tools';
        container.appendChild(emptyActive);
    }

    /* 3. Queued section */
    container.appendChild(_buildSectionHeader('Queued'));
    if (_queueData.length) {
        _queueData.forEach(function(entry, idx) {
            rendered[entry.tool_id] = true;
            container.appendChild(_buildQueueFeedItem(entry, idx + 1));
        });
    } else {
        var emptyQueue = document.createElement('div');
        emptyQueue.style.cssText = 'padding:8px 12px;font-size:0.78rem;color:var(--text-muted);font-style:italic';
        emptyQueue.textContent = 'No queued tools';
        container.appendChild(emptyQueue);
    }

    /* 4. Completed section */
    container.appendChild(_buildSectionHeader('Completed'));
    if (completeTids.length) {
        completeTids.forEach(function(tid) {
            rendered[tid] = true;
            container.appendChild(_buildFeedItem(tid, clickable));
        });
    } else {
        var emptyComplete = document.createElement('div');
        emptyComplete.style.cssText = 'padding:8px 12px;font-size:0.78rem;color:var(--text-muted);font-style:italic';
        emptyComplete.textContent = 'No completed tools';
        container.appendChild(emptyComplete);
    }
}

renderToolFeeds();
_fetchQueueData();

/* ── Eager findings count for pill ────────────────────────────── */
fetch('/api/findings-count/' + PID, {credentials: 'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(d) {
        var pill = document.getElementById('findingsPill');
        if (pill && d.count) pill.textContent = d.count;
    })
    .catch(function() {});


/* ══════════════════════════════════════════════════════════════════
   5. CONSOLE TAB
   ══════════════════════════════════════════════════════════════════ */
function selectTool(tid) {
    selectedTool = tid;
    renderToolFeeds();
    updateConsoleHeader();
    document.getElementById('consoleInputBar').hidden = false;

    /* request console buffer if not cached */
    if (!consoleBuffers[tid]) {
        var req = {project_id: PID, tool_id: tid};
        if (_isMobile) req.tail = _MOBILE_CONSOLE_TAIL;
        socket.emit('get_console', req);
    }
    renderConsole();

    /* check checkpoint for resume */
    fetch('/api/checkpoint/' + PID + '/' + tid, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            toolCheckpoints[tid] = !!d.exists;
            document.getElementById('btnToolResume').disabled = !d.exists;
        })
        .catch(function() {
            toolCheckpoints[tid] = false;
            document.getElementById('btnToolResume').disabled = true;
        });
}

function updateConsoleHeader() {
    var _baseSel = selectedTool || '';
    var _selSci = _baseSel.indexOf(':');
    if (_selSci !== -1) _baseSel = _baseSel.substring(0, _selSci);
    var cfg = TOOLS_CFG[_baseSel] || {};
    var st = toolStatuses[selectedTool] || {};
    var status = (st.status || 'idle').toLowerCase();
    var key = cfg.key || _baseSel.toUpperCase().substring(0,2);

    document.getElementById('consoleTitleBadge').innerHTML = selectedTool
        ? '<span class="tool-badge tool-' + key.toLowerCase() + '">' + esc(key) + '</span>'
        : '';
    var _consTitle = cfg.name || _baseSel || 'Select a tool';
    if (selectedTool && _selSci !== -1) {
        var _ss = selectedTool.substring(_selSci + 1);
        var _sd = _ss.replace(/_?oos$/i, '').replace(/_/g, ' ').trim();
        _consTitle += _sd ? ' — OOS ' + _sd : ' — OOS';
    }
    document.getElementById('consoleTitle').textContent = _consTitle;
    document.getElementById('consoleStatusBadge').innerHTML = selectedTool
        ? '<span class="status-badge status-' + esc(status) + '">' + esc(status) + '</span>'
        : '';

    /* button states */
    var isRunning = status === 'running';
    var isPausing = status === 'pausing';
    var isPaused = status === 'paused';
    var isActive = isRunning || isPausing;
    var hasCheckpoint = toolCheckpoints[selectedTool] || false;
    var canResume = isPaused || (hasCheckpoint && !isActive);
    var isDeps = _baseSel === 'deps';
    document.getElementById('btnToolStart').disabled = !selectedTool || isActive || isPaused || isDeps;
    document.getElementById('btnToolKill').disabled = !selectedTool || !isActive;
    document.getElementById('btnToolPause').disabled = !selectedTool || !isRunning || isDeps;
    document.getElementById('btnToolResume').disabled = !selectedTool || !canResume || isDeps;
    document.getElementById('btnToolStart').style.display = isDeps ? 'none' : '';
    document.getElementById('btnToolPause').style.display = isDeps ? 'none' : '';
    document.getElementById('btnToolResume').style.display = isDeps ? 'none' : '';
    document.getElementById('btnConsoleClear').disabled = !selectedTool;
    document.getElementById('btnConsoleCopy').disabled = !selectedTool;
    document.getElementById('btnConsoleSave').disabled = !selectedTool;
    var _mitmActive = st._mitm_active && isRunning;
    var _mitmBtn = document.getElementById('btnMitmStop');
    _mitmBtn.style.display = _mitmActive ? '' : 'none';
    _mitmBtn.disabled = !_mitmActive;
    if (_mitmActive) _mitmBtn.textContent = 'Stop MITM';
    if (isPausing) {
        document.getElementById('btnToolPause').textContent = 'Pausing…';
        document.getElementById('btnToolPause').disabled = true;
    } else {
        document.getElementById('btnToolPause').textContent = 'Pause';
    }
}

function openInstanceDetail(tid) {
    var modal = document.getElementById('instanceDetailModal');
    var body = document.getElementById('instanceDetailBody');
    body.innerHTML = '<div class="flex-center p-20"><div class="spinner"></div></div>';
    modal.classList.add('open');

    var baseTid = tid;
    var sci = tid.indexOf(':');
    if (sci !== -1) baseTid = tid.substring(0, sci);
    var cfg = TOOLS_CFG[baseTid] || {};
    document.getElementById('instanceDetailTitle').textContent =
        (cfg.name || baseTid) + ' Instance';

    fetch('/api/console/instance/' + PID + '/' + encodeURIComponent(tid),
          {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var html = '<table class="detail-table">';
            html += '<tr><th>Tool</th><td>' + esc(d.tool_name || baseTid) + '</td></tr>';
            if (d.tool_version) {
                html += '<tr><th>Version</th><td><code>' + esc(d.tool_version) + '</code></td></tr>';
            }
            html += '<tr><th>Scope</th><td>' + esc(d.scope || 'default') + '</td></tr>';
            html += '<tr><th>Type</th><td>' +
                (d.is_oos
                    ? '<span class="status-badge status-oos">Out of Scope</span>'
                    : '<span class="status-badge status-running">In Scope</span>') +
                '</td></tr>';
            html += '<tr><th>Instance Key</th><td><code>' + esc(d.tool_key) + '</code></td></tr>';
            if (d.pids && d.pids.length) {
                var pidParts = d.pids.map(function(p) {
                    var ts = p.started_at ? ' <span class="text-secondary" style="font-size:0.85em">(' + esc(p.started_at) + ')</span>' : '';
                    return '<code>' + p.pid + '</code>' + ts;
                });
                html += '<tr><th>PID' + (d.pids.length > 1 ? 's' : '') + '</th><td>' + pidParts.join(', ') + '</td></tr>';
            }
            html += '</table>';

            if (d.targets && d.targets.length) {
                html += '<h4 style="margin:12px 0 6px">Targets (' + d.targets.length + ')</h4>';
                html += '<div class="instance-targets-list">';
                d.targets.forEach(function(t) {
                    html += '<div class="instance-target-item"><code>' + esc(t) + '</code></div>';
                });
                html += '</div>';
            } else {
                html += '<p class="text-secondary mt-12">No targets configured for this instance.</p>';
            }
            body.innerHTML = html;
        })
        .catch(function(err) {
            body.innerHTML = '<p class="text-secondary">Failed to load instance details.</p>';
        });
}

window.closeInstanceDetail = function() {
    document.getElementById('instanceDetailModal').classList.remove('open');
};

function renderConsole() {
    var body = document.getElementById('consoleBody');
    var lines = consoleBuffers[selectedTool] || [];
    body.innerHTML = '';
    if (!lines.length && selectedTool) {
        var st = toolStatuses[selectedTool] || {};
        var sts = (st.status || 'idle').toLowerCase();
        if (selectedTool === 'nessus' && sts === 'complete') {
            _loadNessusConsole(body);
            return;
        }
        var emptyMsg = 'No output yet. Start the tool to see console output.';
        if (sts === 'queued') emptyMsg = 'Tool is queued. Previous console output will appear when loaded.';
        else if (sts === 'complete') emptyMsg = 'Scan completed. No console output was captured for this run.';
        else if (sts === 'killed' || sts === 'cancelled') emptyMsg = 'Scan was cancelled. No console output was captured.';
        else if (sts === 'halted') emptyMsg = 'Scan was halted before completion. No console output was captured.';
        else if (sts === 'failed' || sts === 'error') emptyMsg = 'Scan failed. No console output was captured.';
        body.innerHTML = '<div class="empty-state"><div class="empty-state-text">' + emptyMsg + '</div></div>';
        return;
    }
    if (!selectedTool) {
        body.innerHTML = '<div class="empty-state"><div class="empty-state-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></div><div class="empty-state-title">No tool selected</div><div class="empty-state-text">Click a tool on the left to view its console output.</div></div>';
        return;
    }
    lines.forEach(function(l) { appendConsoleLine(l, true); });
    autoScroll();
}

function _loadNessusConsole(body) {
    body.innerHTML = '<div class="flex-center p-20"><div class="spinner"></div></div>';
    fetch('/api/nessus/console/' + PID, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var lines = data.lines || [];
            if (!lines.length) {
                body.innerHTML = '<div class="empty-state"><div class="empty-state-text">Nessus import complete. No findings data to display.</div></div>';
                return;
            }
            body.innerHTML = '';
            lines.forEach(function(l) { appendConsoleLine(l, true); });
        })
        .catch(function() {
            body.innerHTML = '<div class="empty-state"><div class="empty-state-text">Nessus import complete.</div></div>';
        });
}

function appendConsoleLine(entry, skipScroll) {
    var body = document.getElementById('consoleBody');
    /* clear empty-state if present */
    var es = body.querySelector('.empty-state');
    if (es) es.remove();

    var div = document.createElement('div');
    div.className = 'console-line';
    var text = entry.text || entry.line || entry.message || '';
    var cls = classifyLine(text, entry.level);
    if (cls) div.classList.add(cls);

    var ts = entry.ts || entry.timestamp || '';
    if (ts) {
        var span = document.createElement('span');
        span.className = 'console-ts';
        span.textContent = formatTs(ts);
        div.appendChild(span);
    }
    div.appendChild(document.createTextNode(text));
    body.appendChild(div);

    if (!skipScroll) autoScroll();
}

function classifyLine(text, level) {
    if (level) {
        var lv = level.toUpperCase();
        if (_ERR_LEVELS.has(lv)) return 'error';
        if (lv === 'WARN') return 'warn';
        if (lv === 'EVENT') return 'phase';
    }
    if (/\[!]|ERROR|FAIL|EXCEPTION/i.test(text)) return 'error';
    if (/WARN/i.test(text)) return 'warn';
    if (/\[\+]|SUCCESS|COMPLETE/i.test(text)) return 'ok';
    if (/PHASE|={3,}|---.*Phase/i.test(text)) return 'phase';
    if (/^\[SYS]|\[i\]/i.test(text)) return 'sys';
    return '';
}

function autoScroll() {
    if (!document.getElementById('autoScrollToggle').checked) return;
    var body = document.getElementById('consoleBody');
    body.scrollTop = body.scrollHeight;
}

/* ── Console toolbar buttons ───────────────────────────────────── */
document.getElementById('btnToolStart').addEventListener('click', function() {
    if (!selectedTool) return;
    socket.emit('tool_start', {project_id: PID, tool_id: selectedTool});
});

document.getElementById('btnToolKill').addEventListener('click', function() {
    if (!selectedTool) return;
    if (!confirm('Kill ' + (TOOLS_CFG[selectedTool] ? TOOLS_CFG[selectedTool].name : selectedTool) + '?')) return;
    fetch('/api/kill_subprocess', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, tool_id: selectedTool})
    }).then(function(r) {
        if (r.status === 401) { window.location.href = '/login'; return; }
        return r.json();
    }).then(function(d) {
        if (d && d.ok) refreshToolStatuses();
        else if (d && d.error) toast('error', d.error);
    }).catch(function(e) {
        toast('error', 'Kill request failed: ' + e.message);
    });
});

document.getElementById('btnToolPause').addEventListener('click', function() {
    if (!selectedTool) return;
    var name = TOOLS_CFG[selectedTool] ? TOOLS_CFG[selectedTool].name : selectedTool;
    if (!confirm('Pause ' + name + '? It will checkpoint and stop gracefully.')) return;
    fetch('/api/pause_tool', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, tool_id: selectedTool})
    }).then(function(r) {
        if (r.status === 401) window.location.href = '/login';
    });
});

document.getElementById('btnToolResume').addEventListener('click', function() {
    if (!selectedTool) return;
    socket.emit('tool_start', {project_id: PID, tool_id: selectedTool, resume: true});
});

document.getElementById('btnMitmStop').addEventListener('click', function() {
    if (!selectedTool) return;
    var btn = this;
    btn.disabled = true;
    btn.textContent = 'Stopping…';
    fetch('/api/mitm_stop', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, tool_id: selectedTool})
    }).then(function(r) { return r.json(); }).then(function(j) {
        if (j.ok) {
            btn.textContent = 'Sent';
            if (toolStatuses[selectedTool]) toolStatuses[selectedTool]._mitm_active = false;
            setTimeout(function() { updateConsoleHeader(); }, 1000);
        } else {
            btn.textContent = j.error || 'Failed';
            btn.disabled = false;
        }
    }).catch(function() { btn.textContent = 'Error'; btn.disabled = false; });
});

function _updatePauseAllButtons() {
    var hasRunning = false, hasResumable = false;
    for (var tid in toolStatuses) {
        var st = (toolStatuses[tid] || {}).status || '';
        if (st === 'running') hasRunning = true;
        if (st === 'paused') hasResumable = true;
        if (st === 'killed' && toolCheckpoints[tid]) hasResumable = true;
    }
    var pauseBtn = document.getElementById('btnPauseAll');
    var resumeBtn = document.getElementById('btnResumeAll');
    if (pauseBtn) pauseBtn.style.display = hasRunning ? '' : 'none';
    if (resumeBtn) resumeBtn.style.display = hasResumable ? '' : 'none';
}

function _pauseAll() {
    if (!confirm('Pause ALL running tools? They will checkpoint and stop gracefully.')) return;
    fetch('/api/pause_all', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID})
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) {
            toast('success', 'Pause requested for ' + (d.paused_tools || []).length + ' tool(s)');
            document.getElementById('btnPauseAll').style.display = 'none';
            document.getElementById('btnResumeAll').style.display = '';
        }
    });
}

function _resumeAll() {
    fetch('/api/resume_all', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID})
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) {
            toast('success', 'Resumed ' + (d.resumed_tools || []).length + ' tool(s)');
            document.getElementById('btnResumeAll').style.display = 'none';
            document.getElementById('btnPauseAll').style.display = '';
        }
    });
}

document.getElementById('btnConsoleCopy').addEventListener('click', function() {
    if (!selectedTool) return;
    var buf = consoleBuffers[selectedTool] || [];
    var text = buf.map(function(e) { return e.text || e; }).join('\n');
    navigator.clipboard.writeText(text).then(function() {
        toast('success', 'Console copied to clipboard.');
    }).catch(function() {
        toast('error', 'Failed to copy to clipboard.');
    });
});

document.getElementById('btnConsoleClear').addEventListener('click', function() {
    if (!selectedTool) return;
    consoleBuffers[selectedTool] = [];
    renderConsole();
    if (socket && socket.connected) {
        socket.emit('console_clear', {
            project_id: projectId,
            tool_id: selectedTool
        });
    }
});

/* ── console save helpers ─────────────────────────────────────── */
function _isoTs(ts) {
    if (!ts) return '';
    try {
        var d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        return d.toISOString();
    } catch(e) { return ts; }
}
function _toolDisplayName(tid) {
    var cfg = TOOLS_CFG[tid] || {};
    return cfg.name || tid;
}
function _formatConsoleBuffer(tid) {
    var lines = consoleBuffers[tid] || [];
    return lines.map(function(e) {
        var ts = _isoTs(e.ts || e.timestamp || '');
        var text = e.text || e.line || e.message || '';
        return ts ? '[' + ts + '] ' + text : text;
    }).join('\n');
}
function _triggerDownload(text, filename) {
    var blob = new Blob([text], {type: 'text/plain;charset=utf-8'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

document.getElementById('btnConsoleSave').addEventListener('click', function() {
    if (!selectedTool) return;
    var buf = consoleBuffers[selectedTool] || [];
    if (!buf.length) { toast('warning', 'No console output to save.'); return; }
    var name = _toolDisplayName(selectedTool).replace(/[^a-zA-Z0-9_-]/g, '_');
    var ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    _triggerDownload(_formatConsoleBuffer(selectedTool), name + '_console_' + ts + '.log');
    toast('success', 'Console output saved.');
});

document.getElementById('btnConsoleSaveAll').addEventListener('click', function() {
    var tids = Object.keys(consoleBuffers).filter(function(t) {
        return consoleBuffers[t] && consoleBuffers[t].length > 0;
    });
    if (!tids.length) { toast('warning', 'No console output to save.'); return; }
    var sections = tids.map(function(tid) {
        var header = '════════════════════════════════════════════════════════════\n' +
                     '  ' + _toolDisplayName(tid) + ' (' + tid + ')\n' +
                     '════════════════════════════════════════════════════════════';
        return header + '\n' + _formatConsoleBuffer(tid);
    });
    var ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    _triggerDownload(sections.join('\n\n\n'), 'crucible_console_all_' + ts + '.log');
    toast('success', 'All console output saved (' + tids.length + ' tools).');
});

/* ── stdin input ───────────────────────────────────────────────── */
function sendStdin() {
    var input = document.getElementById('stdinInput');
    var text = input.value;
    if (!text || !selectedTool) return;
    socket.emit('tool_input', {project_id: PID, tool_id: selectedTool, text: text});
    input.value = '';
}
document.getElementById('btnSendInput').addEventListener('click', sendStdin);
document.getElementById('stdinInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); sendStdin(); }
});


/* ══════════════════════════════════════════════════════════════════
   6. FINDINGS TAB
   ══════════════════════════════════════════════════════════════════ */
var _findingsRetries = 0;

function _buildV2Params() {
    var p = {};
    if (categoryViewActive) {
        p.page = 1;
        p.per_page = 100000;
    } else {
        p.page = findingsPage || 1;
        p.per_page = FINDINGS_PER_PAGE;
    }
    var scope = (document.getElementById('findingsFilterScope') || {}).value || '';
    if (scope) p.scope = scope;
    var tool = (document.getElementById('findingsFilterTool') || {}).value || '';
    if (tool) p.tool = tool;
    var search = (document.getElementById('findingsSearch') || {}).value || '';
    if (search) p.search = search;
    var oosFilter = (document.getElementById('findingsFilterOos') || {}).value || '';
    if (oosFilter === 'oos') p.include_oos = '1';
    else if (oosFilter === 'inscope') p.include_oos = '0';
    var activeRisks = [];
    for (var rk in _riskToggles) {
        if (_riskToggles[rk]) activeRisks.push(rk);
    }
    if (activeRisks.length < 5) p.risk = activeRisks.join(',');
    var sortMode = (document.getElementById('findingsSortOrder') || {}).value || 'risk';
    if (sortMode === 'alpha') { p.sort = 'title,risk_id'; }
    else { p.sort = 'risk_id,title'; }
    p.order = 'asc';
    return p;
}

function _fetchFindingsV2(params) {
    var qs = [];
    for (var k in params) {
        if (params[k] !== undefined && params[k] !== '') {
            qs.push(encodeURIComponent(k) + '=' + encodeURIComponent(params[k]));
        }
    }
    var url = '/api/findings/v2/' + PID + (qs.length ? '?' + qs.join('&') : '');
    fetch(url, {credentials: 'same-origin'})
        .then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function(data) {
            _findingsRetries = 0;
            if (data.error) throw new Error(data.error);
            filteredFindings = data.findings || [];
            _serverSummary = data.summary || null;
            _serverTotal = data.total || 0;
            _serverPages = data.pages || 1;
            _v2Source = data.source || 'cache';
            _v2Params = params;
            findingsPage = data.page || 1;
            var pill = document.getElementById('findingsPill');
            if (pill) pill.textContent = _serverTotal || '';
            if (categoryViewActive) {
                renderCategoryView();
            } else {
                renderFindingsTable();
            }
            updateFindingsStats();
            updateRiskOverview();
            _enrichEvidenceCounts(filteredFindings);
        })
        .catch(function(err) {
            console.warn('V2 findings fetch failed:', err.message);
            if (_findingsRetries < 3) {
                _findingsRetries++;
                setTimeout(function() { _fetchFindingsV2(params); },
                           _findingsRetries * 5000);
            }
        });
}

function _enrichEvidenceCounts(findings) {
    var ids = findings.map(function(f) { return f.id; }).filter(Boolean);
    if (!ids.length) return;
    var csv = ids.join(',');
    fetch('/api/finding/evidence-counts/' + PID + '?ids_csv=' + encodeURIComponent(csv), {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (!d.counts) return;
            var changed = false;
            findings.forEach(function(f) {
                var c = d.counts[f.id] || 0;
                if (c !== (f._ev_count || 0)) {
                    f._ev_count = c;
                    changed = true;
                }
            });
            if (changed) {
                if (categoryViewActive) renderCategoryView();
                else renderFindingsTable();
            }
        })
        .catch(function() {});
}

function _fetchV2Filters() {
    fetch('/api/findings/v2/' + PID + '/filters', {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            _v2FiltersLoaded = true;
            _populateFiltersFromServer(data);
        })
        .catch(function() { _v2FiltersLoaded = false; });
}

function _populateFiltersFromServer(data) {
    var scopeSel = document.getElementById('findingsFilterScope');
    if (scopeSel && data.scopes) {
        while (scopeSel.options.length > 1) scopeSel.remove(1);
        data.scopes.forEach(function(s) {
            var o = document.createElement('option');
            o.value = s; o.textContent = s;
            scopeSel.appendChild(o);
        });
    }
    var toolSel = document.getElementById('findingsFilterTool');
    if (toolSel && data.tools) {
        while (toolSel.options.length > 1) toolSel.remove(1);
        data.tools.forEach(function(t) {
            var tid = _resolveToolId(t.id || t.name);
            var cfg = TOOLS_CFG[tid];
            var label = cfg ? cfg.name : (t.name || t.id);
            var o = document.createElement('option');
            o.value = t.id || t.name;
            o.textContent = label;
            toolSel.appendChild(o);
        });
        var tOpts = Array.from(toolSel.options).slice(1);
        tOpts.sort(function(a,b){ return a.textContent.localeCompare(b.textContent); });
        tOpts.forEach(function(o){ toolSel.appendChild(o); });
    }
}

function _ensureAllFindings(cb) {
    if (_allFindingsLoaded && allFindings._loaded) {
        cb();
        return;
    }
    fetch('/api/findings/' + PID, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            allFindings = data.findings || data || [];
            allFindings._loaded = true;
            _allFindingsLoaded = true;
            populateFindingsScopeFilter();
            populateFindingsToolFilter();
            cb();
        })
        .catch(function(err) { console.warn('Full findings load failed:', err.message); });
}

function loadFindings(forceRefresh) {
    if (showFP) {
        if (!fpFindings._loaded) {
            fetch('/api/false-positives/' + PID, {credentials: 'same-origin'})
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    fpFindings = data.false_positives || data.findings || data || [];
                    fpFindings._loaded = true;
                    applyFindingsFilter();
                });
        } else {
            applyFindingsFilter();
        }
        return;
    }
    _v2Mode = true;
    if (forceRefresh) {
        fetch('/api/reload-findings/' + PID, {method: 'POST', credentials: 'same-origin'})
            .then(function(r) { return r.json(); })
            .then(function() {
                _allFindingsLoaded = false;
                _fetchV2Filters();
                _fetchFindingsV2(_buildV2Params());
            })
            .catch(function() { _fetchFindingsV2(_buildV2Params()); });
        return;
    }
    if (!_v2FiltersLoaded) _fetchV2Filters();
    _fetchFindingsV2(_buildV2Params());
}

var FINDING_TOOL_SCOPE = {
    trawler:'PCAP Analysis',
    osift:'OSINT', auger:'Database',
    bastion:'Firewall Config Analysis', forge:'Cloud Infrastructure',
    quill:'Mobile Application', isotope:'File Analysis',
    aether:'Wi-Fi (802.11)', aether_b:'Bluetooth (802.15.1)',
    aether_z:'Zigbee (802.15.4)', aether_u:'Ultra-Wideband (UWB) (802.15.4z)'
};

var _SCOPE_DYNAMIC_TOOLS = {fracture:1, siphon:1, ss3:1};

function _resolveToolScope(tool) {
    if (!_SCOPE_DYNAMIC_TOOLS[tool]) return null;
    var st = PROJECT.scope_tools || {};
    for (var sk in st) {
        if (sk === 'multi') continue;
        if (st[sk] && st[sk].indexOf(tool) !== -1) {
            return SCOPE_DISPLAY_NAMES[sk] || sk;
        }
    }
    return null;
}

function _findingScope(f) {
    if (f.scope === 'int') return 'Internal';
    if (f.scope === 'ext') return 'External';
    if (f.scope && SCOPE_DISPLAY_NAMES[f.scope]) return SCOPE_DISPLAY_NAMES[f.scope];
    var resolved = _resolveToolScope(f.tool);
    if (resolved) return resolved;
    return FINDING_TOOL_SCOPE[f.tool] || f.scope || '';
}

function _findingTarget(f) {
    if (f.ssid) return f.ssid;
    if (f.bssid) return f.bssid;
    if (f.api_endpoint_path) return (f.api_method ? f.api_method + ' ' : '') + f.api_endpoint_path;
    if (f.hostname && f.hostname !== f.ip) return f.hostname;
    var urls = f.target_urls || f.target_url || '';
    if (urls) return Array.isArray(urls) ? urls[0] : urls;
    if (f.ip) return f.ip + (f.port && f.port !== 0 && f.port !== '0' ? ':' + f.port : '');
    if (f.affected) return f.affected;
    return f.domain || '';
}

function _findingCategory(f) {
    if (f.category) return f.category;
    var title = f.title || '';
    var idx = title.indexOf(':');
    if (idx > 0) return title.substring(0, idx).trim();
    return 'UNASSIGNED';
}

function populateFindingsScopeFilter() {
    if (_v2Mode) return;
    var sel = document.getElementById('findingsFilterScope');
    var existing = new Set();
    sel.querySelectorAll('option').forEach(function(o) { if (o.value) existing.add(o.value); });
    allFindings.forEach(function(f) {
        var s = _findingScope(f);
        if (s && !existing.has(s)) {
            existing.add(s);
            var o = document.createElement('option');
            o.value = s;
            o.textContent = s;
            sel.appendChild(o);
        }
    });
    var opts = Array.from(sel.options).slice(1);
    opts.sort(function(a,b){ return a.textContent.localeCompare(b.textContent); });
    opts.forEach(function(o){ sel.appendChild(o); });
}

function populateFindingsToolFilter() {
    if (_v2Mode) return;
    var sel = document.getElementById('findingsFilterTool');
    while (sel.options.length > 1) sel.remove(1);
    var tools = {};
    allFindings.forEach(function(f) {
        var t = f.tool || '';
        if (t && !tools[t]) {
            tools[t] = true;
            var tid = _resolveToolId(t);
            var cfg = TOOLS_CFG[tid];
            var label = cfg ? cfg.name : t;
            var o = document.createElement('option');
            o.value = t;
            o.textContent = label;
            sel.appendChild(o);
        }
    });
    var tOpts = Array.from(sel.options).slice(1);
    tOpts.sort(function(a,b){ return a.textContent.localeCompare(b.textContent); });
    tOpts.forEach(function(o){ sel.appendChild(o); });
}

var _riskToggles = {CRITICAL:true, HIGH:true, MEDIUM:true, LOW:true, INFO:true};
var _kevFilterActive = false;
var categoryViewActive = false;

function applyFindingsFilter() {
    if (_v2Mode && !showFP) {
        findingsPage = 1;
        _fetchFindingsV2(_buildV2Params());
        return;
    }

    var scope = document.getElementById('findingsFilterScope').value;
    var tool = document.getElementById('findingsFilterTool').value;
    var search = document.getElementById('findingsSearch').value.toLowerCase();

    var oosFilter = (document.getElementById('findingsFilterOos') || {}).value || '';

    var src = showFP ? fpFindings : allFindings;
    filteredFindings = src.filter(function(f) {
        if (scope && _findingScope(f) !== scope) return false;
        var rk = (f.risk||'INFO').toUpperCase();
        if (!_riskToggles[rk]) return false;
        if (tool && (f.tool||'') !== tool) return false;
        if (oosFilter === 'oos' && !f.oos) return false;
        if (oosFilter === 'inscope' && f.oos) return false;
        if (_kevFilterActive && !f.kev) return false;
        if (search) {
            var hay = ((f.title||'') + ' ' + (f.ip||'') + ' ' + (f.hostname||'') +
                ' ' + (f.description||'') + ' ' + _findingTarget(f) +
                ' ' + (f.port||'') + ' ' + (f.affected||'') + ' ' + (f.tool||'')).toLowerCase();
            if (hay.indexOf(search) === -1) return false;
        }
        return true;
    });

    var _riskOrder = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};
    var sortMode = (document.getElementById('findingsSortOrder') || {}).value || 'risk';
    filteredFindings.sort(function(a, b) {
        if (sortMode === 'alpha') {
            var ta = (a.title||'').toLowerCase(), tb = (b.title||'').toLowerCase();
            if (ta !== tb) return ta < tb ? -1 : 1;
            var ra = _riskOrder[(a.risk||'INFO').toUpperCase()]; if (ra === undefined) ra = 5;
            var rb = _riskOrder[(b.risk||'INFO').toUpperCase()]; if (rb === undefined) rb = 5;
            return ra - rb;
        }
        var ra = _riskOrder[(a.risk||'INFO').toUpperCase()]; if (ra === undefined) ra = 5;
        var rb = _riskOrder[(b.risk||'INFO').toUpperCase()]; if (rb === undefined) rb = 5;
        if (ra !== rb) return ra - rb;
        var ka = a.kev ? 0 : 1, kb = b.kev ? 0 : 1;
        if (ka !== kb) return ka - kb;
        var ta = (a.title||'').toLowerCase(), tb = (b.title||'').toLowerCase();
        if (ta !== tb) return ta < tb ? -1 : 1;
        var sa = _findingScope(a), sb = _findingScope(b);
        if (sa !== sb) return sa < sb ? -1 : 1;
        var oa = (a.tool||'').toLowerCase(), ob = (b.tool||'').toLowerCase();
        if (oa !== ob) return oa < ob ? -1 : 1;
        return 0;
    });

    findingsPage = 1;
    if (categoryViewActive) {
        renderCategoryView();
    } else {
        renderFindingsTable();
    }
    updateFindingsStats();
}

function updateFindingsStats() {
    var kevCount = 0;
    if (_v2Mode && _serverSummary && !showFP) {
        document.getElementById('fStatCrit').textContent = _serverSummary.CRITICAL || 0;
        document.getElementById('fStatHigh').textContent = _serverSummary.HIGH || 0;
        document.getElementById('fStatMed').textContent = _serverSummary.MEDIUM || 0;
        document.getElementById('fStatLow').textContent = _serverSummary.LOW || 0;
        document.getElementById('fStatInfo').textContent = _serverSummary.INFO || 0;
        var _statsTotal = categoryViewActive ? filteredFindings.length : _serverTotal;
        document.getElementById('findingsCount').textContent = _statsTotal + ' finding' + (_statsTotal !== 1 ? 's' : '');
        kevCount = filteredFindings.filter(function(f) { return f.kev; }).length;
        var kevEl = document.getElementById('fStatKev');
        if (kevEl) kevEl.textContent = kevCount;
        return;
    }
    var src = showFP ? fpFindings : allFindings;
    var counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};
    src.forEach(function(f) {
        var r = (f.risk||'').toUpperCase();
        if (counts[r] !== undefined) counts[r]++;
        if (f.kev) kevCount++;
    });
    document.getElementById('fStatCrit').textContent = counts.CRITICAL;
    document.getElementById('fStatHigh').textContent = counts.HIGH;
    document.getElementById('fStatMed').textContent = counts.MEDIUM;
    document.getElementById('fStatLow').textContent = counts.LOW;
    document.getElementById('fStatInfo').textContent = counts.INFO;
    var kevEl = document.getElementById('fStatKev');
    if (kevEl) kevEl.textContent = kevCount;
    document.getElementById('findingsCount').textContent = filteredFindings.length + ' finding' + (filteredFindings.length !== 1 ? 's' : '');
}

function _renderSourcePills(sources) {
    if (!sources) return '';
    var parts = sources.replace(/\n/g, ',').split(',');
    var seen = {};
    var html = '';
    for (var i = 0; i < parts.length; i++) {
        var s = parts[i].trim();
        if (!s) continue;
        var sLower = s.toLowerCase();
        if (seen[sLower]) continue;
        seen[sLower] = true;
        var tid = _resolveToolId(s);
        var cfg = TOOLS_CFG[tid];
        var cls = cfg ? 'tool-' + cfg.key.toLowerCase() : 'tool-default';
        html += '<span class="source-pill ' + cls + '" title="' + esc(s) + '">' + esc(s) + '</span>';
    }
    return html;
}

var _ROLE_COLORS = {
    'unauthenticated': {bg:'#c62828',fg:'#fff'},
    'admin':           {bg:'#6a1b9a',fg:'#fff'},
    'administrator':   {bg:'#6a1b9a',fg:'#fff'},
    'superadmin':      {bg:'#4a148c',fg:'#fff'},
    'root':            {bg:'#4a148c',fg:'#fff'},
    'standard':        {bg:'#1565c0',fg:'#fff'},
    'user':            {bg:'#1565c0',fg:'#fff'},
    'viewer':          {bg:'#00838f',fg:'#fff'},
    'readonly':        {bg:'#00838f',fg:'#fff'},
    'read-only':       {bg:'#00838f',fg:'#fff'},
    'guest':           {bg:'#546e7a',fg:'#fff'},
    'api':             {bg:'#e65100',fg:'#fff'},
    'static':          {bg:'#1565c0',fg:'#fff'},
    'frida':           {bg:'#ad1457',fg:'#fff'},
    'mitm':            {bg:'#e65100',fg:'#fff'},
};
var _ROLE_FALLBACK = {bg:'#455a64',fg:'#fff'};
function _renderRolePills(roles) {
    if (!roles) return '';
    var parts = roles.split(',');
    var html = '';
    for (var i = 0; i < parts.length; i++) {
        var r = parts[i].trim();
        if (!r) continue;
        var c = _ROLE_COLORS[r.toLowerCase()] || _ROLE_FALLBACK;
        html += '<span class="role-pill" style="background:' + c.bg + ';color:' + c.fg + '" title="' + esc(r) + '">' + esc(r) + '</span>';
    }
    return html;
}

function renderFindingsTable() {
    var tbody = document.getElementById('findingsTableBody');
    var empty = document.getElementById('findingsEmpty');
    var pag = document.getElementById('findingsPagination');
    document.getElementById('findingsTable').parentElement.hidden = false;
    document.getElementById('findingsCategoryView').hidden = true;

    if (!filteredFindings.length) {
        tbody.innerHTML = '';
        empty.style.display = '';
        pag.hidden = true;
        return;
    }
    empty.style.display = 'none';

    var start, page;
    if (_v2Mode && !showFP) {
        start = 0;
        page = filteredFindings;
    } else {
        start = (findingsPage - 1) * FINDINGS_PER_PAGE;
        page = filteredFindings.slice(start, start + FINDINGS_PER_PAGE);
    }

    tbody.innerHTML = '';
    page.forEach(function(f, idx) {
        var riskCls = 'risk-' + (f.risk||'info').toLowerCase();
        var _tid = _resolveToolId(f.tool || f._tool || '');
        var toolKey = TOOLS_CFG[_tid] ? TOOLS_CFG[_tid].key : _tid.toUpperCase().substring(0,2) || '?';
        var toolCls = 'tool-' + toolKey.toLowerCase();
        var toolName = TOOLS_CFG[_tid] ? TOOLS_CFG[_tid].name : (f.tool || f._tool || _tid);
        var globalIdx = start + idx;

        var scope = _findingScope(f);
        var target = _findingTarget(f);
        var cvss = f.cvss_score != null ? parseFloat(f.cvss_score).toFixed(1) : '';
        var ip = f.ip || '';
        var url = f.target_url || f.target_urls || '';
        if (Array.isArray(url)) url = url[0] || '';
        var port = (f.port && f.port !== 0 && f.port !== '0') ? f.port : '';
        var affected = f.affected || '';
        var sources = f.sources || '';
        var evidence = f.output_file || f.output || '';
        var evCount = (f._ev_count || 0);
        var roles = f.roles || '';
        if (!roles && Array.isArray(f.accounts) && f.accounts.length) {
            roles = f.accounts.map(function(a) { return a.role || ''; }).filter(Boolean).join(', ');
        }
        var details = f.description || f.output || '';
        if (details.length > 80) details = details.substring(0, 80) + '…';

        var evCell = '<span style="color:var(--text-secondary)">—</span>';
        if (evidence || evCount > 0) {
            evCell = '<button class="btn btn-xs btn-evidence" data-action="evidence" data-idx="' + globalIdx + '" title="View evidence files">View';
            if (evCount > 0) evCell += ' <span class="ev-count-badge">' + evCount + '</span>';
            evCell += '</button>';
        }

        var tr = document.createElement('tr');
        tr.setAttribute('data-finding-idx', String(globalIdx));
        tr.style.cursor = 'pointer';
        tr.innerHTML =
            '<td class="col-risk"><span class="risk-badge ' + riskCls + '">' + esc((f.risk||'INFO').toUpperCase()) + '</span>' + (f.kev ? '<span class="kev-badge">KEV</span>' : '') + '</td>' +
            '<td class="text-sm">' + esc(cvss) + '</td>' +
            '<td class="text-sm">' + esc(scope) + '</td>' +
            '<td class="col-tool"><span class="tool-badge ' + toolCls + '" title="' + esc(toolName) + '">' + esc(toolKey) + '</span></td>' +
            '<td class="col-title"><a href="#" class="findings-title-link" data-idx="' + globalIdx + '">' + esc(f.title||'Untitled') + '</a>' + (f.oos ? ' <span class="oos-badge" title="Out-of-Scope">OOS</span>' : '') + '</td>' +
            '<td class="font-mono text-sm text-truncate" style="max-width:160px" title="' + esc(target) + '">' + esc(target) + '</td>' +
            '<td class="font-mono text-sm">' + esc(ip) + '</td>' +
            '<td class="text-sm text-truncate" style="max-width:140px" title="' + esc(url) + '">' + esc(url) + '</td>' +
            '<td class="font-mono text-sm">' + esc(String(port)) + '</td>' +
            '<td class="text-sm text-truncate" style="max-width:120px" title="' + esc(affected) + '">' + esc(affected) + '</td>' +
            '<td class="text-sm" style="max-width:140px">' + _renderSourcePills(sources) + '</td>' +
            '<td class="text-sm" style="max-width:100px">' + evCell + '</td>' +
            '<td class="text-sm">' + _renderRolePills(roles) + '</td>' +
            '<td class="text-sm text-truncate" style="max-width:160px" title="' + esc(f.description||'') + '">' + esc(details) + '</td>' +
            '<td class="col-actions">' +
                '<div class="flex gap-4">' +
                    (showFP
                        ? '<button class="btn btn-xs btn-ghost" data-action="recover" data-idx="' + globalIdx + '" title="Recover from False Positive" style="color:var(--success)">Recover</button>'
                        : '<button class="btn btn-xs btn-ghost" data-action="fp" data-idx="' + globalIdx + '" title="Mark as False Positive">FP</button>' +
                          '<button class="btn btn-xs btn-ghost" data-action="risk" data-idx="' + globalIdx + '" title="Override Risk">R</button>' +
                          '<button class="btn btn-xs btn-ghost" data-action="notes" data-idx="' + globalIdx + '" title="Notes">N</button>'
                    ) +
                '</div>' +
            '</td>';
        tbody.appendChild(tr);
    });

    /* pagination */
    var totalPages = (_v2Mode && !showFP) ? _serverPages : Math.ceil(filteredFindings.length / FINDINGS_PER_PAGE);
    if (totalPages > 1) {
        pag.hidden = false;
        pag.innerHTML = '';

        var _maxBtns = 10;
        var startP = Math.max(1, findingsPage - Math.floor(_maxBtns / 2));
        var endP = Math.min(totalPages, startP + _maxBtns - 1);
        if (endP - startP + 1 < _maxBtns) startP = Math.max(1, endP - _maxBtns + 1);

        if (startP > 1) {
            var first = document.createElement('button');
            first.className = 'pagination-btn';
            first.textContent = '1';
            first.setAttribute('data-page', 1);
            pag.appendChild(first);
            if (startP > 2) {
                var dots = document.createElement('span');
                dots.className = 'pagination-dots';
                dots.textContent = '…';
                pag.appendChild(dots);
            }
        }
        for (var p = startP; p <= endP; p++) {
            var btn = document.createElement('button');
            btn.className = 'pagination-btn' + (p === findingsPage ? ' active' : '');
            btn.textContent = p;
            btn.setAttribute('data-page', p);
            pag.appendChild(btn);
        }
        if (endP < totalPages) {
            if (endP < totalPages - 1) {
                var dots2 = document.createElement('span');
                dots2.className = 'pagination-dots';
                dots2.textContent = '…';
                pag.appendChild(dots2);
            }
            var last = document.createElement('button');
            last.className = 'pagination-btn';
            last.textContent = totalPages;
            last.setAttribute('data-page', totalPages);
            pag.appendChild(last);
        }
    } else {
        pag.hidden = true;
    }
}

function _getExpandedCategories() {
    var expanded = {};
    document.querySelectorAll('#findingsCategoryView .cat-header.open').forEach(function(el) {
        expanded[el.getAttribute('data-cat')] = true;
    });
    return expanded;
}

function _restoreExpandedCategories(expanded) {
    if (!expanded) return;
    document.querySelectorAll('#findingsCategoryView .cat-header').forEach(function(el) {
        if (expanded[el.getAttribute('data-cat')]) el.classList.add('open');
    });
}

function renderCategoryView() {
    var expanded = _getExpandedCategories();
    var wrap = document.getElementById('findingsCategoryView');
    var tableWrap = document.getElementById('findingsTable').parentElement;
    var empty = document.getElementById('findingsEmpty');
    var pag = document.getElementById('findingsPagination');
    pag.hidden = true;
    tableWrap.hidden = true;

    if (!filteredFindings.length) {
        wrap.innerHTML = '';
        wrap.hidden = true;
        empty.style.display = '';
        return;
    }
    empty.style.display = 'none';
    wrap.hidden = false;

    var _riskOrder = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};

    var catMap = {};
    var catOrder = [];
    filteredFindings.forEach(function(f, idx) {
        var cat = _findingCategory(f);
        if (!catMap[cat]) { catMap[cat] = {findings: [], indices: []}; catOrder.push(cat); }
        catMap[cat].findings.push(f);
        catMap[cat].indices.push(idx);
    });

    var _catSortMode = (document.getElementById('findingsSortOrder') || {}).value || 'risk';
    var _riskWeight = {CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFO:1};
    catOrder.sort(function(a, b) {
        if (_catSortMode === 'alpha') return a.localeCompare(b);
        var aFindings = catMap[a].findings, bFindings = catMap[b].findings;
        var aBestRisk = 5, bBestRisk = 5;
        aFindings.forEach(function(f) { var r = _riskOrder[(f.risk||'INFO').toUpperCase()]; if (r !== undefined && r < aBestRisk) aBestRisk = r; });
        bFindings.forEach(function(f) { var r = _riskOrder[(f.risk||'INFO').toUpperCase()]; if (r !== undefined && r < bBestRisk) bBestRisk = r; });
        if (aBestRisk !== bBestRisk) return aBestRisk - bBestRisk;
        var aWeight = 0, bWeight = 0;
        aFindings.forEach(function(f) { aWeight += _riskWeight[(f.risk||'INFO').toUpperCase()] || 1; });
        bFindings.forEach(function(f) { bWeight += _riskWeight[(f.risk||'INFO').toUpperCase()] || 1; });
        if (aWeight !== bWeight) return bWeight - aWeight;
        return a.localeCompare(b);
    });

    var html = '';
    var riskNames = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

    catOrder.forEach(function(cat) {
        var bucket = catMap[cat];
        var findings = bucket.findings;
        var indices = bucket.indices;

        var bestRisk = 'INFO';
        var bestRiskVal = 4;
        findings.forEach(function(f) {
            var r = _riskOrder[(f.risk||'INFO').toUpperCase()];
            if (r !== undefined && r < bestRiskVal) { bestRiskVal = r; bestRisk = riskNames[r]; }
        });
        var riskCls = 'risk-' + bestRisk.toLowerCase();

        var targetSet = {};
        findings.forEach(function(f) {
            var aff = (f.affected || '').trim();
            if (aff) {
                aff.split('\n').forEach(function(line) {
                    var s = line.trim();
                    if (!s) return;
                    var key = s.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
                    if (key) targetSet[key] = true;
                });
            } else {
                var tgt = (f.ip || f.hostname || '') + (f.port ? ':' + f.port : '');
                if (tgt) targetSet[tgt] = true;
            }
        });
        var targetCount = Object.keys(targetSet).length;

        var riskCounts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};
        findings.forEach(function(f) { var r = (f.risk||'INFO').toUpperCase(); if (riskCounts[r] !== undefined) riskCounts[r]++; });
        var riskBreakdown = '';
        riskNames.forEach(function(rn) {
            if (riskCounts[rn] > 0) {
                riskBreakdown += '<span class="risk-badge risk-' + rn.toLowerCase() + '" style="font-size:0.65rem;padding:0 5px;margin-left:2px">' + riskCounts[rn] + '</span>';
            }
        });

        var catId = 'cat-' + cat.replace(/[^a-zA-Z0-9]/g, '_');

        html += '<div class="cat-group">';
        html += '<div class="cat-header" data-cat="' + catId + '">';
        html += '<svg class="cat-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>';
        html += '<span class="cat-name">' + esc(cat) + '</span>';
        html += '<span class="cat-meta">';
        html += '<span class="risk-badge ' + riskCls + '">' + bestRisk + '</span>';
        html += riskBreakdown;
        html += '<span class="cat-count" title="Findings">' + findings.length + ' finding' + (findings.length !== 1 ? 's' : '') + '</span>';
        html += '<span class="cat-count" title="Affected targets">' + targetCount + ' target' + (targetCount !== 1 ? 's' : '') + '</span>';
        html += '</span>';
        html += '</div>';

        html += '<div class="cat-body" id="' + catId + '">';
        html += '<div class="overflow-x-auto"><table class="findings-table"><thead><tr>';
        html += '<th class="col-risk">Risk</th><th>CVSS</th><th>Scope</th><th class="col-tool">Tool</th><th class="col-title">Title</th><th>Target</th><th>IP</th><th>Port</th><th>Affected</th><th>Sources</th><th>Evidence</th></tr></thead><tbody>';

        var sortedPairs = indices.map(function(gi, li) { return {f: findings[li], gi: gi}; });
        sortedPairs.sort(function(a, b) {
            var ra = _riskOrder[(a.f.risk||'INFO').toUpperCase()]; if (ra === undefined) ra = 5;
            var rb = _riskOrder[(b.f.risk||'INFO').toUpperCase()]; if (rb === undefined) rb = 5;
            if (ra !== rb) return ra - rb;
            return (a.f.title||'').localeCompare(b.f.title||'');
        });

        sortedPairs.forEach(function(pair) {
            var f = pair.f;
            var globalIdx = pair.gi;
            var fRiskCls = 'risk-' + (f.risk||'info').toLowerCase();
            var _tid = _resolveToolId(f.tool || f._tool || '');
            var toolKey = TOOLS_CFG[_tid] ? TOOLS_CFG[_tid].key : _tid.toUpperCase().substring(0,2) || '?';
            var toolCls = 'tool-' + toolKey.toLowerCase();
            var toolName = TOOLS_CFG[_tid] ? TOOLS_CFG[_tid].name : (f.tool || f._tool || _tid);
            var scope = _findingScope(f);
            var target = _findingTarget(f);
            var cvss = f.cvss_score != null ? parseFloat(f.cvss_score).toFixed(1) : '';
            var ip = f.ip || '';
            var port = (f.port && f.port !== 0 && f.port !== '0') ? f.port : '';
            var affected = f.affected || '';
            var sources = f.sources || '';

            html += '<tr style="cursor:pointer" data-finding-cat-idx="' + globalIdx + '">';
            html += '<td class="col-risk"><span class="risk-badge ' + fRiskCls + '">' + esc((f.risk||'INFO').toUpperCase()) + '</span></td>';
            html += '<td class="text-sm">' + esc(cvss) + '</td>';
            html += '<td class="text-sm">' + esc(scope) + '</td>';
            html += '<td class="col-tool"><span class="tool-badge ' + toolCls + '" title="' + esc(toolName) + '">' + esc(toolKey) + '</span></td>';
            html += '<td class="col-title">' + esc(f.title||'Untitled') + (f.oos ? ' <span class="oos-badge" title="Out-of-Scope">OOS</span>' : '') + '</td>';
            html += '<td class="font-mono text-sm text-truncate" style="max-width:160px" title="' + esc(target) + '">' + esc(target) + '</td>';
            html += '<td class="font-mono text-sm">' + esc(ip) + '</td>';
            html += '<td class="font-mono text-sm">' + esc(String(port)) + '</td>';
            html += '<td class="text-sm text-truncate" style="max-width:120px" title="' + esc(affected) + '">' + esc(affected) + '</td>';
            var evidence = f.output_file || f.output || '';
            var evCnt = (f._ev_count || 0);
            var catEvCell = '<span style="color:var(--text-secondary)">—</span>';
            if (evidence || evCnt > 0) {
                catEvCell = '<button class="btn btn-xs btn-evidence" data-action="cat-evidence" data-cat-idx="' + globalIdx + '" title="View evidence files">View';
                if (evCnt > 0) catEvCell += ' <span class="ev-count-badge">' + evCnt + '</span>';
                catEvCell += '</button>';
            }
            html += '<td class="text-sm" style="max-width:140px">' + _renderSourcePills(sources) + '</td>';
            html += '<td class="text-sm" style="max-width:100px">' + catEvCell + '</td>';
            html += '</tr>';
        });

        html += '</tbody></table></div>';
        html += '</div>';
        html += '</div>';
    });

    wrap.innerHTML = html;
    _restoreExpandedCategories(expanded);
}

/* ── Findings event listeners ──────────────────────────────────── */
document.getElementById('findingsFilterScope').addEventListener('change', applyFindingsFilter);
document.getElementById('findingsFilterTool').addEventListener('change', applyFindingsFilter);
if (document.getElementById('findingsFilterOos'))
    document.getElementById('findingsFilterOos').addEventListener('change', applyFindingsFilter);
if (document.getElementById('findingsSortOrder'))
    document.getElementById('findingsSortOrder').addEventListener('change', applyFindingsFilter);
document.getElementById('findingsSearch').addEventListener('input', debounce(applyFindingsFilter, 250));

document.getElementById('findingsStatsBar').addEventListener('click', function(e) {
    var btn = e.target.closest('.risk-toggle');
    if (!btn) return;
    if (btn.id === 'kevFilterToggle') {
        _kevFilterActive = !_kevFilterActive;
        btn.classList.toggle('active', _kevFilterActive);
        applyFindingsFilter();
        return;
    }
    var rk = btn.getAttribute('data-risk');
    _riskToggles[rk] = !_riskToggles[rk];
    btn.classList.toggle('active', _riskToggles[rk]);
    applyFindingsFilter();
});

document.getElementById('btnClearFindingsFilters').addEventListener('click', function() {
    document.getElementById('findingsFilterScope').value = '';
    document.getElementById('findingsFilterTool').value = '';
    document.getElementById('findingsSearch').value = '';
    if (document.getElementById('findingsFilterOos'))
        document.getElementById('findingsFilterOos').value = '';
    if (document.getElementById('findingsSortOrder'))
        document.getElementById('findingsSortOrder').value = 'risk';
    _riskToggles = {CRITICAL:true, HIGH:true, MEDIUM:true, LOW:true, INFO:true};
    _kevFilterActive = false;
    document.querySelectorAll('.risk-toggle[data-risk]').forEach(function(b) { b.classList.add('active'); });
    var kevBtn = document.getElementById('kevFilterToggle');
    if (kevBtn) kevBtn.classList.remove('active');
    applyFindingsFilter();
});

document.getElementById('btnReloadFindings').addEventListener('click', function() { loadFindings(true); });

function _exportDefaultFilename(format) {
    var eng = (PROJECT.name || PROJECT.client_short || 'findings').replace(/ /g, '_');
    var base = 'Crucible_' + eng;
    if (format === 'csv_merged') return base + '_findings';
    if (format === 'csv_unmerged') return base + '_findings_unmerged';
    if (format === 'json') return base + '_findings';
    return base + '_findings';
}

document.getElementById('btnExportFindings').addEventListener('click', function() {
    var modal = document.getElementById('exportFindingsModal');
    var radios = modal.querySelectorAll('input[name="exportFormat"]');
    radios[0].checked = true;
    var def = _exportDefaultFilename('csv_merged');
    document.getElementById('exportFilename').value = def;
    document.getElementById('exportFilename').placeholder = def;
    document.getElementById('exportFileExt').textContent = '.csv';
    document.querySelectorAll('.export-format-option').forEach(function(el) { el.style.borderColor = ''; });
    radios[0].closest('.export-format-option').style.borderColor = 'var(--accent)';
    modal.classList.add('open');
});

(function() {
    var radios = document.querySelectorAll('input[name="exportFormat"]');
    var extSpan = document.getElementById('exportFileExt');
    var fnInput = document.getElementById('exportFilename');
    radios.forEach(function(r) {
        r.addEventListener('change', function() {
            extSpan.textContent = r.value === 'xlsx' ? '.xlsx' : r.value === 'json' ? '.json' : '.csv';
            var def = _exportDefaultFilename(r.value);
            fnInput.value = def;
            fnInput.placeholder = def;
            document.querySelectorAll('.export-format-option').forEach(function(el) {
                el.style.borderColor = '';
            });
            r.closest('.export-format-option').style.borderColor = 'var(--accent)';
        });
    });
})();

document.getElementById('btnExportFindingsGo').addEventListener('click', function() {
    var format = document.querySelector('input[name="exportFormat"]:checked').value;
    var fname = (document.getElementById('exportFilename').value || '').trim();
    var qp = fname ? '?filename=' + encodeURIComponent(fname) : '';
    var url;
    if (format === 'csv_merged') {
        url = '/api/export-findings/' + PID + qp;
    } else if (format === 'csv_unmerged') {
        url = '/api/export-findings-unmerged/' + PID + qp;
    } else if (format === 'json') {
        url = '/api/export-findings-json/' + PID + qp;
    } else {
        url = '/api/export-findings-xlsx/' + PID + qp;
    }
    window.location.href = url;
    document.getElementById('exportFindingsModal').classList.remove('open');
});

document.getElementById('btnShowFP').addEventListener('click', function() {
    showFP = !showFP;
    this.textContent = showFP ? 'Show Findings' : 'Show FP';
    if (showFP) {
        _v2Mode = false;
        if (!fpFindings._loaded) {
            fetch('/api/false-positives/' + PID, {credentials: 'same-origin'})
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    fpFindings = data.false_positives || data.findings || data || [];
                    fpFindings._loaded = true;
                    applyFindingsFilter();
                });
        } else {
            applyFindingsFilter();
        }
    } else {
        _v2Mode = true;
        findingsPage = 1;
        loadFindings(false);
    }
});

document.getElementById('btnToggleCategoryView').addEventListener('click', function() {
    categoryViewActive = !categoryViewActive;
    this.classList.toggle('active', categoryViewActive);
    this.textContent = categoryViewActive ? 'Individual View' : 'Category View';
    this.closest('.tab-content').classList.toggle('cat-mode', categoryViewActive);
    var tableWrap = document.getElementById('findingsTable').parentElement;
    var catWrap = document.getElementById('findingsCategoryView');
    var pag = document.getElementById('findingsPagination');
    if (categoryViewActive) {
        tableWrap.hidden = true;
        pag.hidden = true;
        findingsPage = 1;
        _fetchFindingsV2(_buildV2Params());
    } else {
        catWrap.hidden = true;
        catWrap.innerHTML = '';
        tableWrap.hidden = false;
        findingsPage = 1;
        _fetchFindingsV2(_buildV2Params());
    }
});

document.getElementById('findingsCategoryView').addEventListener('click', function(e) {
    var header = e.target.closest('.cat-header');
    if (header) {
        header.classList.toggle('open');
        return;
    }
    var evBtn = e.target.closest('[data-action="cat-evidence"]');
    if (evBtn) {
        e.stopPropagation();
        var eidx = parseInt(evBtn.getAttribute('data-cat-idx'), 10);
        if (filteredFindings[eidx]) openEvidenceViewer(filteredFindings[eidx]);
        return;
    }
    var row = e.target.closest('tr[data-finding-cat-idx]');
    if (row) {
        var idx = parseInt(row.getAttribute('data-finding-cat-idx'), 10);
        if (filteredFindings[idx]) openFindingDetail(filteredFindings[idx]);
    }
});

document.getElementById('findingsPagination').addEventListener('click', function(e) {
    if (categoryViewActive) return;
    var btn = e.target.closest('.pagination-btn');
    if (!btn) return;
    findingsPage = parseInt(btn.getAttribute('data-page'), 10);
    if (_v2Mode && !showFP) {
        var p = _buildV2Params();
        p.page = findingsPage;
        _fetchFindingsV2(p);
    } else {
        renderFindingsTable();
    }
});

/* ── Findings table click delegation ───────────────────────────── */
document.getElementById('findingsTableBody').addEventListener('click', function(e) {
    var link = e.target.closest('.findings-title-link');
    if (link) {
        e.preventDefault();
        var idx = parseInt(link.getAttribute('data-idx'), 10);
        openFindingDetail(filteredFindings[idx]);
        return;
    }

    var btn = e.target.closest('[data-action]');
    if (btn) {
        var action = btn.getAttribute('data-action');
        var idx2 = parseInt(btn.getAttribute('data-idx'), 10);
        var finding = filteredFindings[idx2];
        if (!finding) return;
        if (action === 'fp') markFP(finding);
        else if (action === 'recover') recoverFP(finding);
        else if (action === 'risk') openRiskOverride(finding);
        else if (action === 'notes') openNotesModal(finding);
        else if (action === 'evidence') openEvidenceViewer(finding);
        return;
    }

    var row = e.target.closest('tr[data-finding-idx]');
    if (row) {
        var rowIdx = parseInt(row.getAttribute('data-finding-idx'), 10);
        openFindingDetail(filteredFindings[rowIdx]);
    }
});

/* ── Finding detail modal ──────────────────────────────────────── */
function _detailField(label, val) {
    if (!val || val === '--') return '';
    return '<div class="form-group"><span class="form-label">' + esc(label) + '</span><span class="text-primary text-sm">' + esc(String(val)) + '</span></div>';
}
function _detailList(label, arr) {
    if (!arr || !arr.length) return '';
    var items = arr.map(function(v) { return typeof v === 'object' ? JSON.stringify(v) : String(v); });
    return '<div class="mb-8"><span class="form-label">' + esc(label) + '</span><div style="margin-top:4px">' +
        items.map(function(v) { return '<span class="tag">' + esc(v) + '</span> '; }).join('') + '</div></div>';
}
function _detailPre(label, val) {
    if (!val) return '';
    return '<div class="mb-8"><span class="form-label">' + esc(label) + '</span><pre style="margin-top:4px;max-height:200px">' + esc(val) + '</pre></div>';
}
function openFindingDetail(f) {
    if (!f) return;
    document.getElementById('findingDetailTitle').textContent = f.title || 'Finding';
    var body = document.getElementById('findingDetailBody');

    var html = '<div class="mb-8"><span class="risk-badge risk-' + (f.risk||'info').toLowerCase() + '">' + esc((f.risk||'INFO').toUpperCase()) + '</span>';
    if (f.kev) html += ' <span class="kev-badge">KEV</span>';
    if (f.confidence) html += ' <span class="tag">' + esc(f.confidence) + '</span>';
    html += '</div>';

    if (f.kev && f.kev_details && f.kev_details.length) {
        html += '<div class="kev-detail-section">';
        html += '<div class="form-label" style="margin-bottom:8px">CISA Known Exploited Vulnerability</div>';
        f.kev_details.forEach(function(k) {
            html += '<div class="form-grid mb-8" style="gap:4px 12px">';
            if (k.cve) html += _detailField('CVE', k.cve);
            if (k.vendor) html += _detailField('Vendor', k.vendor);
            if (k.product) html += _detailField('Product', k.product);
            if (k.name) html += _detailField('Vulnerability', k.name);
            if (k.date_added) html += _detailField('Date Added', k.date_added);
            if (k.due_date) html += _detailField('Remediation Due', k.due_date);
            html += _detailField('Ransomware Campaign', k.ransomware ? 'Known' : 'Unknown');
            html += '</div>';
        });
        html += '</div>';
    }

    html += '<div class="form-grid mb-16">';
    if (f.ip) html += _detailField('IP', f.ip);
    if (f.port && f.port !== 0 && f.port !== '0') html += _detailField('Port', f.port);
    if (f.service) html += _detailField('Service', f.service);
    html += '<div class="form-group"><span class="form-label">Tool</span><span class="text-primary">' + esc(f.tool||'--') + '</span></div>';
    html += '<div class="form-group"><span class="form-label">Date</span><span class="text-primary text-sm">' + esc(f.datetime||'--') + '</span></div>';
    if (f.cves) html += _detailField('CVEs', f.cves);
    if (f.hostname) html += _detailField('Hostname', f.hostname);
    if (f.scope) html += _detailField('Scope', f.scope);
    if (f.phase) html += _detailField('Phase', f.phase);
    if (f.catalogue_id) html += _detailField('Catalogue', f.catalogue_id);
    html += '</div>';

    if (f.output_file) html += _detailField('Evidence File', f.output_file);
    if (f.exploitdb) html += _detailField('ExploitDB', 'Yes');
    if (f.metasploit) html += _detailField('Metasploit', 'Yes');
    if (f.accepted != null) html += _detailField('Accepted', f.accepted ? 'Yes' : 'No');

    var _aff = (f.affected || '').trim();
    if (_aff) {
        var _affItems = _aff.split('\n').filter(function(a) { return a.trim(); });
        if (_affItems.length > 1) {
            html += _detailList('Affected Locations', _affItems);
        } else {
            html += '<div class="mb-8"><span class="form-label">Affected Locations</span><span class="text-primary text-sm" style="margin-left:8px">' + esc(_aff) + '</span></div>';
        }
    }

    var _src = (f.sources || '').trim();
    if (_src) {
        var _srcItems = _src.replace(/\n/g, ',').split(',').filter(function(s) { return s.trim(); }).map(function(s) { return s.trim(); });
        if (_srcItems.length > 0) html += _detailList('Sources', _srcItems);
    }

    html += _detailPre('Description', f.description || 'No description.');
    if (f.impact) html += _detailPre('Impact', f.impact);
    html += _detailPre('Remediation', f.remediation || 'No remediation provided.');

    var hasEnrichment = f.cvss_score || (f.cwe && f.cwe.length) || (f.mitre_attack && f.mitre_attack.length) ||
        (f.nist_800_53 && f.nist_800_53.length) || (f.pci_dss_4 && f.pci_dss_4.length) ||
        (f.metasploit_modules && f.metasploit_modules.length) || (f.searchsploit_terms && f.searchsploit_terms.length) ||
        f.nessus_plugin_id || (f.nessus_plugin_ids && f.nessus_plugin_ids.length) ||
        f.qualys_qid || (f.qualys_qids && f.qualys_qids.length) ||
        f.owasp || f.owasp_api || f.nist ||
        f.remediation_effort || f.remediation_component || f.remediation_category ||
        f.ssid || f.bssid || f.api_endpoint_path || f.subdevice ||
        (f.cve_examples && f.cve_examples.length);

    if (hasEnrichment) {
        html += '<details class="mb-8" open><summary style="cursor:pointer;font-weight:600;margin-bottom:8px">Enrichment</summary>';
        html += '<div class="form-grid" style="gap:8px">';
        if (f.cvss_score != null) html += _detailField('CVSS Score', f.cvss_score);
        if (f.cvss_vector) html += _detailField('CVSS Vector', f.cvss_vector);
        if (f.owasp) html += _detailField('OWASP Web', f.owasp);
        if (f.owasp_api) html += _detailField('OWASP API', f.owasp_api);
        if (f.nist) html += _detailField('NIST', f.nist);
        var _npids = f.nessus_plugin_ids && f.nessus_plugin_ids.length ? f.nessus_plugin_ids.join(', ') : (f.nessus_plugin_id || '');
        if (_npids) html += _detailField('Nessus Plugin', _npids);
        if (f.nessus_plugin_name) html += _detailField('Plugin Name', f.nessus_plugin_name);
        var _qqids = f.qualys_qids && f.qualys_qids.length ? f.qualys_qids.join(', ') : (f.qualys_qid || '');
        if (_qqids) html += _detailField('Qualys QID', _qqids);
        if (f.remediation_effort) html += _detailField('Effort', f.remediation_effort);
        if (f.remediation_component) html += _detailField('Component', f.remediation_component);
        if (f.remediation_category) html += _detailField('Category', f.remediation_category);
        if (f.ssid) html += _detailField('SSID', f.ssid);
        if (f.bssid) html += _detailField('BSSID', f.bssid);
        if (f.api_endpoint_path) html += _detailField('API Endpoint', (f.api_method ? f.api_method + ' ' : '') + f.api_endpoint_path);
        if (f.api_from_spec) html += _detailField('From Spec', 'Yes');
        if (f.is_rogue_endpoint) html += _detailField('Rogue Endpoint', 'Yes');
        if (f.subdevice) html += _detailField('Sub-device', f.subdevice);
        if (f.interface) html += _detailField('Interface', f.interface);
        if (f.instance) html += _detailField('Instance', f.instance);
        if (f.classification) html += _detailField('Classification', f.classification);
        html += '</div>';
        html += _detailList('CWE', f.cwe);
        html += _detailList('MITRE ATT&CK', (f.mitre_attack||[]).map(function(m) { return (m.technique||'')+ ' ' +(m.name||''); }));
        html += _detailList('Metasploit Modules', f.metasploit_modules);
        html += _detailList('Searchsploit Terms', f.searchsploit_terms);
        html += _detailList('NIST 800-53', f.nist_800_53);
        html += _detailList('NIST 800-171', f.nist_800_171);
        html += _detailList('NIST CSF 2.0', f.nist_csf2);
        html += _detailList('PCI DSS 4', f.pci_dss_4);
        html += _detailList('ISO 27001', f.iso_27001);
        html += _detailList('ISO 27002', f.iso_27002);
        html += _detailList('SOC2', f.soc2);
        html += _detailList('HITRUST', f.hitrust);
        html += _detailList('GDPR', f.gdpr);
        html += _detailList('CVE Examples', f.cve_examples);
        html += _detailList('Source Tools', f.source_tools);
        html += _detailList('Aliases', f.aliases);
        if (f.plugin_output) html += _detailPre('Plugin Output', f.plugin_output);
        html += '</details>';
    }

    if (f.output) html += _detailPre('Output', f.output);
    if (f.command) html += '<div class="mb-8"><span class="form-label">Command</span><pre style="margin-top:4px">' + esc(f.command) + '</pre></div>';

    if (f.exploit_details && f.exploit_details.length) {
        html += '<details class="mb-8"><summary style="cursor:pointer;font-weight:600;margin-bottom:8px">Exploit Details (' + f.exploit_details.length + ')</summary>';
        f.exploit_details.forEach(function(ed) {
            html += '<div style="margin-bottom:6px;padding:6px;background:var(--bg-card);border-radius:6px">' +
                '<div class="text-sm font-mono">' + esc(ed.url || ed.reference || JSON.stringify(ed)) + '</div></div>';
        });
        html += '</details>';
    }

    if (f.notes && f.notes.length) {
        html += '<div class="mb-8"><span class="form-label">Notes (' + f.notes.length + ')</span>';
        f.notes.forEach(function(n) {
            html += '<div style="margin-top:4px;padding:6px;background:var(--bg-card);border-radius:4px" class="text-sm note-md">' + _renderNoteMd(typeof n === 'string' ? n : n.text || '') + '</div>';
        });
        html += '</div>';
    }

    html += '<div class="mb-8" style="border-top:1px solid var(--border);padding-top:12px;margin-top:16px">';
    html += '<span class="form-label">Evidence Attachments</span>';
    html += '<div id="evidenceListContainer" style="margin-top:8px"><span class="text-sm text-secondary">Loading...</span></div>';
    html += '<div id="evidenceDropzone" class="ev-dropzone" data-fid="' + esc(f.id || '') + '">';
    html += '<input type="file" id="evidenceFileInput" multiple class="ev-dropzone-input">';
    html += '<div class="ev-dropzone-label">';
    html += '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>';
    html += ' Drop files here or <span style="color:var(--accent);cursor:pointer">browse</span>';
    html += '</div></div>';
    html += '</div>';

    body.innerHTML = html;
    document.getElementById('findingDetailModal').classList.add('open');

    _loadEvidenceList(f.id || '');
    _setupDropzone(f.id || '');
}

function _loadEvidenceList(findingId) {
    var container = document.getElementById('evidenceListContainer');
    if (!container) return;
    fetch('/api/finding/evidence/' + PID + '/' + findingId, {credentials: 'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (!d.evidence || !d.evidence.length) {
            container.innerHTML = '<span class="text-sm text-secondary">No attachments yet.</span>';
            return;
        }
        var html = '<div class="ev-list">';
        d.evidence.forEach(function(ev) {
            var sizeStr = ev.size_bytes < 1024 ? ev.size_bytes + ' B'
                : ev.size_bytes < 1048576 ? (ev.size_bytes / 1024).toFixed(1) + ' KB'
                : (ev.size_bytes / 1048576).toFixed(1) + ' MB';
            html += '<div class="ev-list-item">';
            if (ev.is_image) {
                html += '<div class="ev-thumb"><img src="/api/finding/evidence-download/' + PID + '/' + esc(ev.id) + '" alt="' + esc(ev.filename) + '"></div>';
            } else {
                html += '<div class="ev-thumb ev-thumb-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div>';
            }
            html += '<div class="ev-info">';
            html += '<a href="/api/finding/evidence-download/' + PID + '/' + esc(ev.id) + '" class="ev-filename" title="' + esc(ev.filename) + '">' + esc(ev.filename) + '</a>';
            html += '<span class="text-xs text-secondary">' + sizeStr + '</span>';
            html += '</div>';
            html += '<button class="btn btn-xs btn-ghost ev-delete" data-evid="' + esc(ev.id) + '" data-fid="' + esc(findingId) + '" title="Delete attachment" style="color:var(--risk-high)">&times;</button>';
            html += '</div>';
        });
        html += '</div>';
        container.innerHTML = html;
        container.querySelectorAll('.ev-delete').forEach(function(btn) {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                var evid = btn.getAttribute('data-evid');
                var fid = btn.getAttribute('data-fid');
                if (!confirm('Delete this attachment?')) return;
                fetch('/api/finding/evidence-delete/' + PID + '/' + evid, {
                    method: 'DELETE', credentials: 'same-origin'
                }).then(function(r) { return r.json(); }).then(function(rd) {
                    if (rd.ok) {
                        toast('success', 'Attachment deleted');
                        _loadEvidenceList(fid);
                        if (allFindings._loaded) loadFindings(true);
                    } else {
                        toast('error', rd.error || 'Delete failed');
                    }
                }).catch(function() { toast('error', 'Delete failed'); });
            });
        });
    })
    .catch(function() {
        container.innerHTML = '<span class="text-sm text-secondary">Could not load attachments.</span>';
    });
}

function _setupDropzone(findingId) {
    var dz = document.getElementById('evidenceDropzone');
    if (!dz) return;
    var input = document.getElementById('evidenceFileInput');

    dz.addEventListener('click', function() { input.click(); });
    dz.addEventListener('dragover', function(e) { e.preventDefault(); dz.classList.add('ev-dropzone-active'); });
    dz.addEventListener('dragleave', function() { dz.classList.remove('ev-dropzone-active'); });
    dz.addEventListener('drop', function(e) {
        e.preventDefault();
        dz.classList.remove('ev-dropzone-active');
        if (e.dataTransfer.files.length) _doEvidenceUpload(findingId, e.dataTransfer.files);
    });
    input.addEventListener('change', function() {
        if (input.files.length) _doEvidenceUpload(findingId, input.files);
    });
}

function _doEvidenceUpload(findingId, files) {
    var uploaded = 0;
    var total = files.length;
    for (var i = 0; i < total; i++) {
        var fd = new FormData();
        fd.append('finding_id', findingId);
        fd.append('file', files[i]);
        fetch('/api/finding/attach-evidence/' + PID, {
            method: 'POST',
            credentials: 'same-origin',
            body: fd
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            uploaded++;
            if (d.ok) {
                toast('success', 'Attached: ' + (d.evidence ? d.evidence.filename : ''));
            } else {
                toast('error', d.error || 'Upload failed');
            }
            if (uploaded === total) {
                _loadEvidenceList(findingId);
                if (allFindings._loaded) loadFindings(true);
            }
        })
        .catch(function() {
            uploaded++;
            toast('error', 'Upload failed');
            if (uploaded === total) _loadEvidenceList(findingId);
        });
    }
}

window.closeFindingDetail = function() {
    document.getElementById('findingDetailModal').classList.remove('open');
};

/* ── Evidence viewer ─────────────────────────────────────────── */
var _evFiles = [];
var _evPairs = [];
var _evDual = false;
var _evHlTerms = [];
var _evHlIndex = -1;
var _evHlCount = 0;
var _evCurrentFinding = null;

var _INJECTION_TITLE_RE = /injection|xss|sqli|sql.?injection|ssrf|rce|command.?injection|xxe|ssti|ldap.?injection|xpath|header.?injection|crlf|open.?redirect|lfi|rfi|traversal|deserialization|smuggling/i;

function _buildHighlightTerms(f) {
    if (!f) return [];
    if (Array.isArray(f.highlights) && f.highlights.length > 0) {
        return f.highlights.filter(function(t) { return typeof t === 'string' && t.length >= 2; }).slice(0, 20);
    }
    var terms = {};
    var termList = [];
    function addTerm(t) { if (t && !terms[t]) { terms[t] = true; termList.push(t); } }

    if (f.cves) {
        f.cves.split(',').forEach(function(c) { c = c.trim(); if (c) addTerm(c); });
    }
    var rawTitle = f.title || '';
    var isHeaderLike = /^(Header Data Leakage|Technology Identified|Software Version Disclosed|HTTP Header Fingerprints|Unknown Header Identified|Endpoint-Specific Security Header Found|Missing Security Header):/i.test(rawTitle);
    if (isHeaderLike && f.output) {
        f.output.split('\n').forEach(function(line) {
            line = line.trim();
            if (/^(HTTP Status:|Matched at:|Plugin:|Missing:)\s/i.test(line)) return;
            if (line.length >= 5 && line.length < 120) addTerm(line);
        });
    }
    if (termList.length === 0) {
        var title = rawTitle.replace(/^(Missing Security Header|Header Data Leakage|Technology Identified|HTTP Method Tampering|HTTP Method Accepted But Not Functional|Software Version Disclosed|Load Balancer Detected|WAF \/ Edge Security Platform Active|SSL\/TLS Vulnerability|SSL\/TLS Vulnerability \(Potential\)|SSL\/TLS Certificate|SSL\/TLS Ciphers|SSL\/TLS Forward Secrecy|Deprecated Protocol Enabled|Single Page Application|Missing Secure Cookie Attribute|Misconfigured Secure Cookie Attribute|Insecure Protocol Detected|Weak Cipher Identified|Weak Cipher Accepted):\s*/i, '');
        if (title.length > 3 && title.length < 80) addTerm(title);
    }
    if (Array.isArray(f.cwe)) {
        f.cwe.forEach(function(c) { if (c) addTerm(String(c)); });
    }
    var kwPatterns = [/(?:CVE-\d{4}-\d+)/gi, /(?:CWE-\d+)/gi, /(?:T\d{4}(?:\.\d+)?)/g];
    var desc = (f.description || '') + ' ' + (f.output || '');
    kwPatterns.forEach(function(rx) {
        var m;
        while ((m = rx.exec(desc)) !== null) addTerm(m[0]);
    });
    if (/ViewState/i.test(rawTitle)) {
        ['__VIEWSTATE', 'MAC', 'encryption', 'ViewState', 'EnableViewStateMac'].forEach(addTerm);
    }
    if (/Telerik/i.test(rawTitle)) {
        ['Telerik.Web.UI', 'DialogHandler', 'WebResource.axd', 'ScriptResource.axd', 'RadAsyncUpload'].forEach(addTerm);
    }
    if (/Cookie Attribute/i.test(rawTitle) && f.output) {
        addTerm('Set-Cookie');
        var cookieM = (f.output || '').match(/Set-Cookie:\s*([^=]+)=/i);
        if (cookieM) addTerm(cookieM[1].trim());
    }
    if (/Insecure Protocol Detected/i.test(rawTitle)) {
        var protoM = rawTitle.match(/Insecure Protocol Detected:\s*(.+)/i);
        if (protoM) addTerm(protoM[1].trim());
    }
    if (/cipher|ssl|tls|sslscan|testssl/i.test(rawTitle)) {
        var cipherOut = (f.output || '') + '\n' + (f.description || '');
        var cipherRx = /\b([A-Z][A-Z0-9]+-(?:[A-Z0-9]+-)*[A-Z0-9]+(?:-(?:SHA|SHA256|SHA384|GCM|CCM|CCM8|POLY1305|CBC)(?:\d*)?))\b/g;
        var cm;
        while ((cm = cipherRx.exec(cipherOut)) !== null) {
            if (cm[1].length >= 6) addTerm(cm[1]);
        }
    }
    return termList.filter(function(t) { return t.length >= 3; }).slice(0, 15);
}

function _applyHighlights(text, terms) {
    if (!terms.length || !text) return { html: esc(text), count: 0 };
    var escaped = esc(text);
    var count = 0;
    var sorted = terms.slice().sort(function(a, b) { return b.length - a.length; });
    sorted.forEach(function(term) {
        var escapedTerm = esc(term).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        var rx = new RegExp('(' + escapedTerm + ')', 'gi');
        escaped = escaped.replace(rx, function(match) {
            count++;
            return '<mark class="ev-hl" data-hl-idx="' + count + '">' + match + '</mark>';
        });
    });
    return { html: escaped, count: count };
}

function _updateHighlightBar(count, terms) {
    _evHlCount = count;
    _evHlIndex = -1;
    var bar = document.getElementById('evidenceHighlightBar');
    var cntEl = document.getElementById('evHlCount');
    var termsEl = document.getElementById('evHlTerms');
    if (!bar) return;
    if (count > 0) {
        bar.hidden = false;
        bar.style.display = 'flex';
        cntEl.textContent = count + ' highlight' + (count !== 1 ? 's' : '');
        if (termsEl) termsEl.textContent = 'Terms: ' + terms.slice(0, 5).join(', ') + (terms.length > 5 ? ' …' : '');
        _evHlNav(1);
    } else {
        bar.hidden = true;
        bar.style.display = 'none';
        if (termsEl) termsEl.textContent = '';
        if (cntEl) cntEl.textContent = '';
    }
}

function _evHlNav(dir) {
    if (_evHlCount === 0) return;
    var prev = document.querySelector('.ev-hl-current');
    if (prev) prev.classList.remove('ev-hl-current');
    _evHlIndex = (_evHlIndex + dir + _evHlCount) % _evHlCount;
    var marks = document.querySelectorAll('.ev-hl');
    if (_evHlIndex < marks.length) {
        var mark = marks[_evHlIndex];
        mark.classList.add('ev-hl-current');
        var scrollable = mark.parentElement;
        while (scrollable && scrollable !== document.body) {
            var st = getComputedStyle(scrollable);
            if ((st.overflowY === 'auto' || st.overflowY === 'scroll') &&
                scrollable.scrollHeight > scrollable.clientHeight) break;
            scrollable = scrollable.parentElement;
        }
        if (scrollable && scrollable !== document.body) {
            var paneRect = scrollable.getBoundingClientRect();
            var markRect = mark.getBoundingClientRect();
            var scrollY = scrollable.scrollTop + (markRect.top - paneRect.top)
                          - (paneRect.height / 2) + (markRect.height / 2);
            scrollable.scrollTo({ top: Math.max(0, scrollY), behavior: 'smooth' });
        }
        var hScroll = mark.parentElement;
        while (hScroll && hScroll !== document.body) {
            var hSt = getComputedStyle(hScroll);
            if ((hSt.overflowX === 'auto' || hSt.overflowX === 'scroll') &&
                hScroll.scrollWidth > hScroll.clientWidth) break;
            hScroll = hScroll.parentElement;
        }
        if (hScroll && hScroll !== document.body) {
            var hRect = hScroll.getBoundingClientRect();
            var mRect = mark.getBoundingClientRect();
            var scrollX = hScroll.scrollLeft + (mRect.left - hRect.left)
                          - (hRect.width / 2) + (mRect.width / 2);
            hScroll.scrollTo({ left: Math.max(0, scrollX), behavior: 'smooth' });
        }
    }
    var cntEl = document.getElementById('evHlCount');
    if (cntEl) cntEl.textContent = (_evHlIndex + 1) + ' / ' + _evHlCount;
}

function _parseJsonArrays(raw) {
    var trimmed = (raw || '').trim();
    if (!trimmed || trimmed.charAt(0) !== '[') return null;
    try { var a = JSON.parse(trimmed); if (Array.isArray(a)) return a; } catch(e) {}
    var merged = [];
    trimmed.split('\n').forEach(function(line) {
        var l = line.trim();
        if (!l || l.charAt(0) !== '[') return;
        try {
            var a = JSON.parse(l);
            if (Array.isArray(a)) a.forEach(function(e) { merged.push(e); });
        } catch(e2) {}
    });
    return merged.length ? merged : null;
}

function _parseOutputFilePaths(raw) {
    var arr = _parseJsonArrays(raw);
    if (arr) {
        var paths = [];
        arr.forEach(function(entry) {
            if (typeof entry === 'string') { paths.push(entry); return; }
            if (entry.file) paths.push(entry.file);
            if (entry.req) paths.push(entry.req);
            if (entry.resp) paths.push(entry.resp);
        });
        var filtered = paths.filter(function(p) { return !!p; });
        if (filtered.length) return filtered;
    }
    return raw.replace(/\n/g, ',').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return !!p; });
}

function _extractEvidencePairs(raw) {
    var arr = _parseJsonArrays(raw);
    if (!arr) return [];
    var pairs = [];
    arr.forEach(function(entry) {
        if (typeof entry !== 'object' || !entry) return;
        if (entry.req || entry.resp) {
            var label = entry.url || entry.label || '';
            if (label) {
                try {
                    var u = new URL(label);
                    label = u.hostname + (u.port ? ':' + u.port : '') + u.pathname;
                } catch(e2) {}
            }
            pairs.push({
                request: entry.req || '',
                response: entry.resp || '',
                label: label
            });
        }
    });
    return pairs;
}

function openEvidenceViewer(f) {
    if (!f) return;
    var raw = f.output_file || '';
    var paths = raw ? _parseOutputFilePaths(raw) : [];
    var jsonPairs = _extractEvidencePairs(raw);

    if (!paths.length && !jsonPairs.length && !(f.output || '').trim()) {
        toast('warning', 'No evidence files for this finding.');
        return;
    }

    _evCurrentFinding = f;
    _evHlTerms = _buildHighlightTerms(f);
    _evHlCount = 0;
    _evHlIndex = -1;

    var _hlBar = document.getElementById('evidenceHighlightBar');
    if (_hlBar) { _hlBar.hidden = true; _hlBar.style.display = 'none'; }
    var _hlTerms = document.getElementById('evHlTerms');
    if (_hlTerms) _hlTerms.textContent = '';

    document.getElementById('evidenceViewerTitle').textContent = 'Evidence: ' + (f.title || 'Finding');

    if (!paths.length && !jsonPairs.length && (f.output || '').trim()) {
        _setupOutputPane(f);
        document.getElementById('evidenceViewerModal').classList.add('open');
        return;
    }

    if (jsonPairs.length) {
        _evDual = true;
        _setupDualPaneFromPairs(jsonPairs, f);
    } else {
        var hasReq = false, hasResp = false;
        paths.forEach(function(p) {
            if (p.indexOf('_request.') !== -1 || /_request$/.test(p)) hasReq = true;
            if (p.indexOf('_response.') !== -1 || /_response$/.test(p)) hasResp = true;
        });
        _evDual = hasReq && hasResp;

        if (_evDual) {
            _setupDualPane(paths, f);
        } else {
            _setupSinglePane(paths);
        }
    }

    document.getElementById('evidenceViewerModal').classList.add('open');
}

function _setupOutputPane(f) {
    _evFiles = [];
    var sp = document.getElementById('evidenceSinglePane');
    var dp = document.getElementById('evidenceDualPane');
    sp.hidden = false; sp.style.display = 'flex';
    dp.hidden = true;  dp.style.display = 'none';
    document.getElementById('evidenceDualControls').hidden = true;

    var nav = document.getElementById('evidenceFileNav');
    nav.innerHTML = '';
    nav.hidden = true; nav.style.display = 'none';

    var pre = document.getElementById('evidenceContentPre');
    var container = document.getElementById('evidenceContent');
    var existing = container.querySelector('.ev-image');
    if (existing) existing.remove();

    var display = f.output || '';
    if (f.command) display = '$ ' + f.command + '\n\n' + display;
    if (_evHlTerms.length) {
        var hl = _applyHighlights(display, _evHlTerms);
        pre.innerHTML = hl.html;
        _updateHighlightBar(hl.count, _evHlTerms);
    } else {
        pre.textContent = display;
        _updateHighlightBar(0, []);
    }
}

function _extractIpFromPath(path) {
    var parts = path.split('/');
    for (var i = 0; i < parts.length; i++) {
        if (/^\d+_\d+_\d+_\d+$/.test(parts[i])) {
            return parts[i].replace(/_/g, '.');
        }
    }
    var m = path.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    return m ? m[1] : null;
}

function _setupSinglePane(paths) {
    _evFiles = paths;
    var sp = document.getElementById('evidenceSinglePane');
    var dp = document.getElementById('evidenceDualPane');
    sp.hidden = false; sp.style.display = 'flex';
    dp.hidden = true;  dp.style.display = 'none';
    document.getElementById('evidenceDualControls').hidden = true;

    var nav = document.getElementById('evidenceFileNav');
    nav.innerHTML = '';

    if (paths.length === 1) {
        nav.hidden = true; nav.style.display = 'none';
        _loadEvidenceFile(paths[0]);
        return;
    }

    nav.hidden = false; nav.style.display = '';

    var ipGroups = {};
    var ipOrder = [];
    var hasMultipleIps = false;

    paths.forEach(function(p) {
        var ip = _extractIpFromPath(p) || '__general__';
        if (!ipGroups[ip]) {
            ipGroups[ip] = [];
            ipOrder.push(ip);
        }
        ipGroups[ip].push(p);
    });

    hasMultipleIps = ipOrder.length > 1 || (ipOrder.length === 1 && ipOrder[0] !== '__general__');

    var fileListContainer = document.createElement('div');
    fileListContainer.id = 'evFileListContainer';

    if (hasMultipleIps && ipOrder.length > 1) {
        var sel = document.createElement('select');
        sel.className = 'ev-ip-select';
        var allOpt = document.createElement('option');
        allOpt.value = '__all__';
        allOpt.textContent = 'All Locations (' + paths.length + ' files)';
        sel.appendChild(allOpt);
        ipOrder.forEach(function(ip) {
            var opt = document.createElement('option');
            opt.value = ip;
            opt.textContent = (ip === '__general__' ? 'General' : ip) + ' (' + ipGroups[ip].length + ')';
            sel.appendChild(opt);
        });
        sel.addEventListener('change', function() {
            _renderEvFileButtons(fileListContainer, ipGroups, ipOrder, sel.value);
        });
        nav.appendChild(sel);
    }

    nav.appendChild(fileListContainer);
    _renderEvFileButtons(fileListContainer, ipGroups, ipOrder, '__all__');
}

function _renderEvFileButtons(container, ipGroups, ipOrder, filterIp) {
    container.innerHTML = '';
    var firstBtn = null;
    var showAll = (filterIp === '__all__');

    ipOrder.forEach(function(ip) {
        if (!showAll && ip !== filterIp) return;
        var groupPaths = ipGroups[ip];
        if (ipOrder.length > 1 && showAll) {
            var label = document.createElement('div');
            label.style.cssText = 'font-size:0.7rem;font-weight:700;color:var(--text-secondary);padding:6px 4px 2px;border-top:1px solid var(--border-color);margin-top:4px';
            if (container.children.length === 0) label.style.borderTop = 'none';
            label.textContent = ip === '__general__' ? 'General' : ip;
            container.appendChild(label);
        }
        groupPaths.forEach(function(p) {
            var btn = document.createElement('button');
            btn.className = 'ev-nav-btn';
            btn.textContent = p.split('/').pop() || p;
            btn.title = p;
            btn.addEventListener('click', function() {
                container.querySelectorAll('.ev-nav-btn').forEach(function(b) { b.classList.remove('active'); });
                btn.classList.add('active');
                _loadEvidenceFile(p);
            });
            container.appendChild(btn);
            if (!firstBtn) firstBtn = btn;
        });
    });

    if (firstBtn) {
        firstBtn.classList.add('active');
        _loadEvidenceFile(firstBtn.title);
    }
}

function _setupDualPane(paths, f) {
    var sp = document.getElementById('evidenceSinglePane');
    var dp = document.getElementById('evidenceDualPane');
    sp.hidden = true;  sp.style.display = 'none';
    dp.hidden = false;  dp.style.display = 'flex';
    document.getElementById('evidenceDualControls').hidden = false;

    var pairMap = {};
    paths.forEach(function(p) {
        var base;
        if (p.indexOf('_request.') !== -1) {
            base = p.replace(/_request\.[^.]+$/, '');
            if (!pairMap[base]) pairMap[base] = {};
            pairMap[base].request = p;
        } else if (p.indexOf('_response.') !== -1) {
            base = p.replace(/_response\.[^.]+$/, '');
            if (!pairMap[base]) pairMap[base] = {};
            pairMap[base].response = p;
        }
    });

    _evPairs = [];
    for (var base in pairMap) {
        if (!pairMap.hasOwnProperty(base)) continue;
        var label = base;
        var dirParts = base.split('/');
        for (var d = 0; d < dirParts.length; d++) {
            if (dirParts[d].indexOf('__') !== -1) {
                label = dirParts[d].replace(/__/g, '/');
                break;
            }
        }
        _evPairs.push({
            request: pairMap[base].request || '',
            response: pairMap[base].response || '',
            label: label
        });
    }

    if (!_evPairs.length && f.affected) {
        _evPairs.push({ request: paths[0] || '', response: paths[1] || '', label: f.affected });
    }

    var sel = document.getElementById('evidenceLocationSelect');
    sel.innerHTML = '';
    _evPairs.forEach(function(pair, i) {
        var o = document.createElement('option');
        o.value = String(i);
        o.textContent = pair.label || ('Location ' + (i + 1));
        sel.appendChild(o);
    });
    sel.onchange = function() { _loadDualPaneEvidence(parseInt(sel.value, 10)); };

    if (_evPairs.length) _loadDualPaneEvidence(0);
}

function _setupDualPaneFromPairs(pairs, f) {
    var sp = document.getElementById('evidenceSinglePane');
    var dp = document.getElementById('evidenceDualPane');
    sp.hidden = true;  sp.style.display = 'none';
    dp.hidden = false;  dp.style.display = 'flex';
    document.getElementById('evidenceDualControls').hidden = false;

    _evPairs = pairs;

    var sel = document.getElementById('evidenceLocationSelect');
    sel.innerHTML = '';
    _evPairs.forEach(function(pair, i) {
        var o = document.createElement('option');
        o.value = String(i);
        o.textContent = pair.label || (f.affected || ('Location ' + (i + 1)));
        sel.appendChild(o);
    });
    sel.onchange = function() { _loadDualPaneEvidence(parseInt(sel.value, 10)); };

    if (_evPairs.length === 1) {
        document.getElementById('evidenceDualControls').hidden = true;
    }
    if (_evPairs.length) _loadDualPaneEvidence(0);
}

var _EV_IMAGE_EXT = ['.png','.jpg','.jpeg','.gif','.bmp','.svg','.webp','.ico','.tiff','.tif'];

function _isImageFile(path) {
    var lo = path.toLowerCase();
    for (var i = 0; i < _EV_IMAGE_EXT.length; i++) {
        if (lo.lastIndexOf(_EV_IMAGE_EXT[i]) === lo.length - _EV_IMAGE_EXT[i].length) return true;
    }
    return false;
}

function _evEndsWith(str, suffix) {
    return str.length >= suffix.length && str.lastIndexOf(suffix) === str.length - suffix.length;
}

function _evPad(n) {
    var s = '';
    for (var i = 0; i < n; i++) s += '  ';
    return s;
}

function _evBeautifyJSON(text) {
    try {
        var obj = JSON.parse(text);
        return JSON.stringify(obj, null, 2);
    } catch(e) {
        return text;
    }
}

function _evBeautifyJSONL(text) {
    var lines = text.split('\n');
    var out = [];
    for (var i = 0; i < lines.length; i++) {
        var ln = lines[i].trim();
        if (!ln) continue;
        try {
            out.push(JSON.stringify(JSON.parse(ln), null, 2));
        } catch(e) {
            out.push(ln);
        }
    }
    return out.join('\n\n');
}

function _evBeautifyXML(text) {
    var s = text.replace(/>\s+</g, '><').replace(/(>)(<)(\/*)/g, '$1\n$2$3');
    var lines = s.split('\n');
    var result = '';
    var indent = 0;
    for (var i = 0; i < lines.length; i++) {
        var ln = lines[i].trim();
        if (!ln) continue;
        if (ln.match(/^<\/[^>]+>$/)) indent = Math.max(0, indent - 1);
        result += _evPad(indent) + ln + '\n';
        if (ln.match(/^<[^\/!?][^>]*[^\/]>$/) && !ln.match(/^<(br|hr|img|input|meta|link|col|area|base|embed|param|source|track|wbr)\b/i)) {
            indent++;
        }
    }
    return result.trim();
}

function _evBeautifyBraces(text) {
    var nlCount = 0;
    for (var k = 0; k < text.length && k < 2000; k++) {
        if (text[k] === '\n') nlCount++;
    }
    if (nlCount > 5) return text;

    var result = '';
    var indent = 0;
    var inStr = false;
    var strCh = '';
    var paren = 0;
    var prev = '';

    for (var i = 0; i < text.length; i++) {
        var c = text[i];
        if (inStr) {
            result += c;
            if (c === strCh && prev !== '\\') inStr = false;
            prev = (c === '\\' && prev === '\\') ? '' : c;
            continue;
        }
        if (c === '"' || c === "'") { inStr = true; strCh = c; result += c; prev = c; continue; }
        if (c === '(') { paren++; result += c; }
        else if (c === ')') { paren = Math.max(0, paren - 1); result += c; }
        else if (c === '{') { indent++; result += ' {\n' + _evPad(indent); }
        else if (c === '}') { indent = Math.max(0, indent - 1); result += '\n' + _evPad(indent) + '}'; }
        else if (c === ';' && paren === 0) { result += ';\n' + _evPad(indent); }
        else if (c === '\n' || c === '\r') { /* collapse */ }
        else { result += c; }
        prev = c;
    }
    return result.trim();
}

function _evSniffType(content) {
    var t = content.trimLeft();
    var head = t.substring(0, 512);
    if (t.charAt(0) === '{' || t.charAt(0) === '[') {
        try { JSON.parse(content); return 'json'; } catch(e) {}
    }
    if (head.indexOf('<?xml') !== -1 || (head.charAt(0) === '<' && head.indexOf('<!DOCTYPE') !== -1)) return 'xml';
    if (head.charAt(0) === '<' && head.match(/^<[a-zA-Z!]/)) return 'xml';
    if (head.match(/^\s*\{[\s\S]*[;{}]/) || head.match(/^\s*(function|var|const|let|import|export|module)\s/)) return 'js';
    if (head.match(/^\s*<\?php/)) return 'js';
    if (head.match(/^\s*(@import|@charset|@media|[.#a-zA-Z][a-zA-Z0-9_-]*\s*\{)/)) return 'css';
    return null;
}

function _evBeautify(content, path) {
    if (!content || content.length > 1048576) return content;
    var lo = path.toLowerCase();

    if (_evEndsWith(lo, '.jsonl') || _evEndsWith(lo, '.ndjson')) return _evBeautifyJSONL(content);
    if (_evEndsWith(lo, '.json')) return _evBeautifyJSON(content);
    if (_evEndsWith(lo, '.xml') || _evEndsWith(lo, '.xhtml') || _evEndsWith(lo, '.nmap') || _evEndsWith(lo, '.gnmap')) return _evBeautifyXML(content);
    if (_evEndsWith(lo, '.html') || _evEndsWith(lo, '.htm')) return _evBeautifyXML(content);
    if (_evEndsWith(lo, '.js') || _evEndsWith(lo, '.css') || _evEndsWith(lo, '.php') ||
        _evEndsWith(lo, '.ts') || _evEndsWith(lo, '.jsx') || _evEndsWith(lo, '.tsx') ||
        _evEndsWith(lo, '.scss') || _evEndsWith(lo, '.less')) return _evBeautifyBraces(content);

    var sniffed = _evSniffType(content);
    if (sniffed === 'json') return _evBeautifyJSON(content);
    if (sniffed === 'xml')  return _evBeautifyXML(content);
    if (sniffed === 'js' || sniffed === 'css') return _evBeautifyBraces(content);

    return content;
}

function _loadEvidenceFile(path) {
    var container = document.getElementById('evidenceContent');
    var pre = document.getElementById('evidenceContentPre');

    if (_isImageFile(path)) {
        pre.textContent = '';
        var existing = container.querySelector('.ev-image');
        if (existing) existing.remove();
        var img = document.createElement('img');
        img.className = 'ev-image';
        img.style.cssText = 'max-width:100%;max-height:100%;object-fit:contain;display:block;margin:0 auto';
        img.alt = path.split('/').pop() || path;
        img.src = '/api/file_serve/' + PID + '?path=' + encodeURIComponent(path);
        img.onerror = function() { pre.textContent = 'Failed to load image: ' + path; img.remove(); };
        container.appendChild(img);
        return;
    }

    var existing2 = container.querySelector('.ev-image');
    if (existing2) existing2.remove();
    pre.textContent = 'Loading…';
    fetch('/api/file_content/' + PID + '?path=' + encodeURIComponent(path), {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.error) {
                pre.textContent = 'Error: ' + data.error;
                _updateHighlightBar(0, []);
            } else {
                var display = _evBeautify(data.content || '', path) || '(empty file)';
                if (_evHlTerms.length) {
                    var hl = _applyHighlights(display, _evHlTerms);
                    pre.innerHTML = hl.html;
                    _updateHighlightBar(hl.count, _evHlTerms);
                } else {
                    pre.textContent = display;
                    _updateHighlightBar(0, []);
                }
            }
        })
        .catch(function(err) {
            pre.textContent = 'Failed to load file: ' + err.message;
            _updateHighlightBar(0, []);
        });
}

function _loadDualPaneEvidence(idx) {
    var pair = _evPairs[idx];
    if (!pair) return;

    var reqPre = document.getElementById('evidenceRequestPre');
    var resPre = document.getElementById('evidenceResponsePre');
    reqPre.textContent = 'Loading…';
    resPre.textContent = 'Loading…';

    _evHlCount = 0;
    _evHlIndex = -1;
    var isInjection = _evCurrentFinding && _INJECTION_TITLE_RE.test(_evCurrentFinding.title || '');
    var hlReq = _evHlTerms.length > 0 && isInjection;
    var hlResp = _evHlTerms.length > 0;
    var totalHl = 0;

    function _updateDualBar() {
        var bar = document.getElementById('evidenceHighlightBar');
        var cntEl = document.getElementById('evHlCount');
        var termsEl = document.getElementById('evHlTerms');
        _evHlCount = totalHl;
        _evHlIndex = -1;
        if (totalHl > 0 && bar) {
            bar.hidden = false;
            bar.style.display = 'flex';
            cntEl.textContent = totalHl + ' highlight' + (totalHl !== 1 ? 's' : '');
            if (termsEl) termsEl.textContent = 'Terms: ' + _evHlTerms.slice(0, 5).join(', ') + (_evHlTerms.length > 5 ? ' …' : '');
            _evHlNav(1);
        } else if (bar) {
            bar.hidden = true;
            bar.style.display = 'none';
            if (termsEl) termsEl.textContent = '';
            if (cntEl) cntEl.textContent = '';
        }
    }

    var loaded = 0;
    function _checkDone() { loaded++; if (loaded >= 2) _updateDualBar(); }

    function _loadPaneContent(path, pre, doHl) {
        if (!path) { pre.textContent = '(no file)'; _checkDone(); return; }
        if (_isImageFile(path)) {
            pre.textContent = '';
            var img = document.createElement('img');
            img.style.cssText = 'max-width:100%;max-height:100%;object-fit:contain;display:block;margin:0 auto';
            img.alt = path.split('/').pop() || path;
            img.src = '/api/file_serve/' + PID + '?path=' + encodeURIComponent(path);
            img.onerror = function() { pre.textContent = 'Failed to load image: ' + path; img.remove(); };
            pre.parentNode.insertBefore(img, pre.nextSibling);
            _checkDone();
            return;
        }
        fetch('/api/file_content/' + PID + '?path=' + encodeURIComponent(path), {credentials: 'same-origin'})
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.error) { pre.textContent = 'Error: ' + data.error; }
                else {
                    var display = _evBeautify(data.content || '', path) || '(empty)';
                    if (doHl && _evHlTerms.length) {
                        var hl = _applyHighlights(display, _evHlTerms);
                        pre.innerHTML = hl.html;
                        totalHl += hl.count;
                    } else {
                        pre.textContent = display;
                    }
                }
                _checkDone();
            })
            .catch(function(err) { pre.textContent = 'Failed: ' + err.message; _checkDone(); });
    }

    var reqPane = reqPre.parentNode;
    var resPane = resPre.parentNode;
    if (reqPane) { var _ri = reqPane.querySelector('img'); if (_ri) _ri.remove(); }
    if (resPane) { var _si = resPane.querySelector('img'); if (_si) _si.remove(); }

    _loadPaneContent(pair.request, reqPre, hlReq);
    _loadPaneContent(pair.response, resPre, hlResp);
}

window.closeEvidenceViewer = function() {
    document.getElementById('evidenceViewerModal').classList.remove('open');
};

/* ── Finding actions ───────────────────────────────────────────── */
var _fpCtx = null;

function markFP(f) {
    _fpCtx = f;
    document.getElementById('fpModalTitle').textContent = f.title || 'Finding';
    var affRaw = (f.affected || '').trim();
    var locations = affRaw ? affRaw.split('\n').filter(function(a) { return a.trim(); }) : [];

    var singleEl = document.getElementById('fpModalSingle');
    var multiEl = document.getElementById('fpModalMulti');
    var listEl = document.getElementById('fpLocationList');
    var checkAll = document.getElementById('fpCheckAll');

    if (locations.length <= 1) {
        singleEl.style.display = '';
        multiEl.style.display = 'none';
    } else {
        singleEl.style.display = 'none';
        multiEl.style.display = '';
        checkAll.checked = false;
        listEl.innerHTML = '';
        locations.forEach(function(loc, i) {
            var row = document.createElement('label');
            row.className = 'fp-check-row';
            row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:6px 12px;cursor:pointer;font-size:.85rem';
            if (i < locations.length - 1) row.style.borderBottom = '1px solid var(--border)';
            var cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.className = 'fp-loc-cb';
            cb.value = loc.trim();
            row.appendChild(cb);
            var span = document.createElement('span');
            span.className = 'font-mono';
            span.style.wordBreak = 'break-all';
            span.textContent = loc.trim();
            row.appendChild(span);
            listEl.appendChild(row);
        });
    }
    document.getElementById('fpModal').classList.add('open');
}

window.closeFPModal = function() {
    document.getElementById('fpModal').classList.remove('open');
    _fpCtx = null;
};

document.getElementById('fpCheckAll').addEventListener('change', function() {
    var cbs = document.querySelectorAll('#fpLocationList .fp-loc-cb');
    var checked = this.checked;
    cbs.forEach(function(cb) { cb.checked = checked; cb.disabled = checked; });
});

document.getElementById('btnFPConfirm').addEventListener('click', function() {
    if (!_fpCtx) return;
    var f = _fpCtx;
    var affRaw = (f.affected || '').trim();
    var locations = affRaw ? affRaw.split('\n').filter(function(a) { return a.trim(); }) : [];
    var checkAll = document.getElementById('fpCheckAll');

    if (locations.length <= 1 || checkAll.checked) {
        fetch('/api/suppress-finding', {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({project_id: PID, finding_id: f.id, tool: f.tool})
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) { toast('success', 'Finding marked as FP.'); loadFindings(); _refreshActiveIntel(); closeFPModal(); }
            else toast('error', d.error || 'Failed.');
        });
        return;
    }

    var selected = [];
    document.querySelectorAll('#fpLocationList .fp-loc-cb:checked').forEach(function(cb) {
        selected.push(cb.value);
    });
    if (!selected.length) {
        toast('warning', 'Select at least one affected location (or mark the entire finding).');
        return;
    }

    fetch('/api/suppress-finding-partial', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, finding_id: f.id, affected_locations: selected})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) {
            var msg = selected.length === 1
                ? '1 affected location marked as FP.'
                : selected.length + ' affected locations marked as FP.';
            toast('success', msg);
            loadFindings();
            _refreshActiveIntel();
            closeFPModal();
        } else {
            toast('error', d.error || 'Failed.');
        }
    });
});

function recoverFP(f) {
    if (!confirm('Recover "' + (f.title || 'this finding') + '" from false positives?')) return;
    fetch('/api/unsuppress-finding', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, finding_id: f.id})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) {
            toast('success', 'Finding recovered.');
            fpFindings = fpFindings.filter(function(fp) { return fp.id !== f.id; });
            loadFindings();
            _refreshActiveIntel();
        } else {
            toast('error', d.error || 'Recovery failed.');
        }
    });
}

function openRiskOverride(f) {
    riskOverrideCtx = f;
    document.getElementById('riskOverrideLabel').textContent = f.title || '';
    document.getElementById('riskOverrideSelect').value = (f.risk||'INFO').toUpperCase();
    document.getElementById('riskOverrideReason').value = '';
    document.getElementById('riskOverrideModal').classList.add('open');
}

window.closeRiskOverride = function() {
    document.getElementById('riskOverrideModal').classList.remove('open');
    riskOverrideCtx = null;
};

document.getElementById('btnRiskOverrideSave').addEventListener('click', function() {
    if (!riskOverrideCtx) return;
    fetch('/api/risk-override', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            project_id: PID, finding_id: riskOverrideCtx.id, tool: riskOverrideCtx.tool,
            risk: document.getElementById('riskOverrideSelect').value,
            reason: document.getElementById('riskOverrideReason').value
        })
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) { toast('success', 'Risk overridden.'); loadFindings(); _refreshActiveIntel(); closeRiskOverride(); }
        else toast('error', d.error || 'Failed.');
    });
});

function openNotesModal(f) {
    notesCtx = f;
    document.getElementById('notesInput').value = f.notes || '';
    document.getElementById('notesModal').classList.add('open');
}

window.closeNotesModal = function() {
    document.getElementById('notesModal').classList.remove('open');
    notesCtx = null;
};

document.getElementById('btnNotesSave').addEventListener('click', function() {
    if (!notesCtx) return;
    fetch('/api/finding-notes', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            project_id: PID, finding_id: notesCtx.id, tool: notesCtx.tool,
            text: document.getElementById('notesInput').value
        })
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) { toast('success', 'Notes saved.'); closeNotesModal(); }
        else toast('error', d.error || 'Failed.');
    });
});


/* ══════════════════════════════════════════════════════════════════
   7. TARGETS (rendered inside Intelligence tab)
   ══════════════════════════════════════════════════════════════════ */
function _loadIntelTargets(body, empty) {
    body.innerHTML = '<div class="flex-center p-20"><div class="spinner"></div></div>';
    body.hidden = false;
    empty.style.display = 'none';

    var targetType = _TARGETS_SCOPES[_activeScope] || 'network';
    var scopeFilter = '';
    if (_activeScope === SCOPE_DISPLAY_NAMES['external']) scopeFilter = 'external';
    else if (_activeScope === SCOPE_DISPLAY_NAMES['internal']) scopeFilter = 'internal';

    fetch('/api/targets/' + PID, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var t = data.targets || {};
            if (targetType === 'osint') {
                _renderOsintIntel(body, empty, t.osint || []);
            } else {
                var hosts = t.network || [];
                if (scopeFilter) {
                    hosts = hosts.filter(function(h) { return h.scope === scopeFilter; });
                }
                _renderHostsIntel(body, empty, hosts);
            }
        })
        .catch(function() {
            body.innerHTML = '<div class="empty-state"><div class="empty-state-text">Failed to load targets.</div></div>';
        });
}

var _bogusOS = /^(bad gateway|not found|redirect|moved|error|ok|forbidden|unauthorized|n\/a|ssdp\/upnp|uses vnc|soap|java console|upnp|ssdp|protocol \d|none)$/i;
function _cleanOS(v) { return (v && !_bogusOS.test(v.trim())) ? v : ''; }
function _isConfirmedPort(p) {
    if (typeof p !== 'object') return true;
    var st = (p.state || 'open').toLowerCase();
    return st === 'open';
}

function _renderHostsIntel(body, empty, hosts) {
    if (!hosts.length) {
        body.hidden = true;
        empty.style.display = '';
        empty.querySelector('.empty-state-text').textContent = 'No network hosts discovered yet.';
        return;
    }
    var html =
        '<div class="panel"><div class="panel-header"><span class="panel-title">Network Hosts</span>' +
        '<span class="text-sm" style="color:var(--text-muted)">' + hosts.length + ' host(s)</span></div>' +
        '<div class="panel-body"><div class="overflow-x-auto">' +
        '<table class="findings-table"><thead><tr>' +
        '<th>IP</th><th>Hostname</th><th>Ports</th><th>Services</th><th>OS</th>' +
        '</tr></thead><tbody>';
    hosts.forEach(function(h) {
        var confirmed = (h.ports || []).filter(_isConfirmedPort);
        var ports = confirmed.map(function(p) { return typeof p === 'object' ? p.port : p; }).join(', ');
        var services = h.services ? (Array.isArray(h.services) ? h.services.join(', ') : String(h.services))
            : confirmed.map(function(p) { return typeof p === 'object' ? (p.service||'') : ''; }).filter(Boolean).join(', ');
        var os = _cleanOS(h.os);
        html +=
            '<tr><td class="font-mono">' + esc(h.ip||'') + '</td>' +
            '<td>' + esc(h.hostname||'--') + '</td>' +
            '<td class="font-mono text-sm">' + esc(ports||'--') + '</td>' +
            '<td class="text-sm">' + esc(services||'--') + '</td>' +
            '<td class="text-sm">' + esc(os||'--') + '</td></tr>';
    });
    html += '</tbody></table></div></div></div>';
    body.innerHTML = html;
}

function _renderOsintIntel(body, empty, assets) {
    if (!assets.length) {
        body.hidden = true;
        empty.style.display = '';
        empty.querySelector('.empty-state-text').textContent = 'No OSINT assets discovered yet.';
        return;
    }
    var subdomains = [];
    var ips = [];
    var emails = [];
    var domains = [];
    var other = [];
    assets.forEach(function(a) {
        var t = (a.type || '').toLowerCase();
        if (t === 'subdomain') subdomains.push(a);
        else if (t === 'ip') ips.push(a);
        else if (t === 'email') emails.push(a);
        else if (t === 'domain') domains.push(a);
        else other.push(a);
    });
    var html = '';
    if (domains.length) {
        html += '<div class="panel" style="margin-bottom:16px"><div class="panel-header"><span class="panel-title" style="color:var(--clr-accent)">Root Domains</span>' +
            '<span class="text-sm" style="color:var(--text-muted)">' + domains.length + '</span></div>' +
            '<div class="panel-body"><div class="overflow-x-auto"><table class="findings-table"><thead><tr><th>Domain</th><th>Company</th></tr></thead><tbody>';
        domains.forEach(function(d) {
            html += '<tr><td class="font-mono">' + esc(d.value||'') + '</td><td>' + esc(d.details||'--') + '</td></tr>';
        });
        html += '</tbody></table></div></div></div>';
    }
    if (subdomains.length) {
        html += '<div class="panel" style="margin-bottom:16px"><div class="panel-header"><span class="panel-title" style="color:var(--clr-accent)">Subdomains</span>' +
            '<span class="text-sm" style="color:var(--text-muted)">' + subdomains.length + ' subdomain(s)</span></div>' +
            '<div class="panel-body"><div class="overflow-x-auto"><table class="findings-table"><thead><tr>' +
            '<th>Subdomain</th><th>IP</th><th>Source</th><th>HTTP Status</th><th>Redirects</th></tr></thead><tbody>';
        subdomains.forEach(function(s) {
            var parts = (s.details || '').split(' | ');
            var ip = '';
            var httpSt = '';
            var redir = '';
            parts.forEach(function(p) {
                p = p.trim();
                if (p.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) ip = p;
                else if (p.indexOf('HTTP ') === 0) httpSt = p.replace('HTTP ', '');
                else if (p.indexOf('→') === 0) redir = p.substring(2);
            });
            html += '<tr><td class="font-mono text-sm">' + esc(s.value||'') + '</td>' +
                '<td class="font-mono text-sm">' + esc(ip||'--') + '</td>' +
                '<td class="text-sm">' + esc(s.source||'--') + '</td>' +
                '<td class="text-sm">' + esc(httpSt||'--') + '</td>' +
                '<td class="text-sm">' + esc(redir||'--') + '</td></tr>';
        });
        html += '</tbody></table></div></div></div>';
    }
    /* emails are in the dedicated OSINT Emails subtab */
    if (other.length) {
        html += '<div class="panel"><div class="panel-header"><span class="panel-title">Other Assets</span>' +
            '<span class="text-sm" style="color:var(--text-muted)">' + other.length + '</span></div>' +
            '<div class="panel-body"><div class="overflow-x-auto"><table class="findings-table"><thead><tr>' +
            '<th>Type</th><th>Value</th><th>Source</th><th>Details</th></tr></thead><tbody>';
        other.forEach(function(a) {
            html += '<tr><td><span class="badge">' + esc(a.type||'') + '</span></td>' +
                '<td class="font-mono text-sm">' + esc(a.value||'') + '</td>' +
                '<td class="text-sm">' + esc(a.source||'--') + '</td>' +
                '<td class="text-sm">' + esc(a.details||'--') + '</td></tr>';
        });
        html += '</tbody></table></div></div></div>';
    }
    body.innerHTML = html;
}


/* ══════════════════════════════════════════════════════════════════
   8. ACTION ITEMS TAB
   ══════════════════════════════════════════════════════════════════ */
var _showOOS = false;

function _toggleOOS() {
    _showOOS = !_showOOS;
    var btn = document.getElementById('oosToggleBtn');
    if (_showOOS) {
        btn.style.background = 'rgba(231,76,60,.15)';
        btn.style.color = 'var(--risk-high)';
        btn.style.borderColor = 'var(--risk-high)';
    } else {
        btn.style.background = 'transparent';
        btn.style.color = 'var(--text-muted)';
        btn.style.borderColor = 'var(--border)';
    }
    renderActionItems();
}

var _showResets = false;
function _toggleResets() {
    _showResets = !_showResets;
    var btn = document.getElementById('resetToggleBtn');
    if (_showResets) {
        btn.style.background = 'rgba(249,115,22,.15)';
        btn.style.color = '#f97316';
        btn.style.borderColor = '#f97316';
        btn.textContent = 'Hide Resets';
    } else {
        btn.style.background = 'transparent';
        btn.style.color = 'var(--text-muted)';
        btn.style.borderColor = 'var(--border)';
        btn.textContent = 'Show Resets';
    }
    renderActionItems();
}

var _resetItemIdx = -1;

function _openResetModal(idx) {
    var item = allActionItems[idx];
    if (!item) return;
    _resetItemIdx = idx;
    var status = item.status || 'pending';
    var tool = (item.recommended_tool || '').toLowerCase();
    var toolName = (TOOLS_CFG[tool] || {}).name || tool || 'tool';
    var body = document.getElementById('actionResetBody');
    var confirmBtn = document.getElementById('actionResetConfirmBtn');

    if (status === 'running') {
        var pid = '';
        var ts = toolStatuses[tool];
        if (ts && ts.pid) pid = ts.pid;
        body.innerHTML =
            '<div style="padding:8px 0">' +
            '<p style="margin-bottom:12px;color:var(--risk-high);font-weight:600">' +
            'Cannot reset — ' + esc(toolName) + ' is currently executing.</p>' +
            '<p class="text-sm" style="margin-bottom:8px">The task must fail, be cancelled, or complete before a reset can occur.</p>' +
            (pid ? '<p class="text-sm"><strong>Process ID:</strong> <code>' + esc(String(pid)) + '</code></p>' : '') +
            '</div>';
        confirmBtn.hidden = true;
    } else {
        body.innerHTML =
            '<div style="padding:8px 0">' +
            '<p style="margin-bottom:12px">Reset this action item back to <strong>pending</strong>?</p>' +
            '<p class="text-sm text-muted" style="margin-bottom:8px"><strong>Title:</strong> ' + esc(item.title || '') + '</p>' +
            '<p class="text-sm text-muted"><strong>Status:</strong> ' + esc(status) + ' → pending</p>' +
            '<p class="text-sm text-muted" style="margin-top:12px">This will restore the original action buttons (Execute, Queue, Dismiss) for this item.</p>' +
            '</div>';
        confirmBtn.hidden = false;
    }
    document.getElementById('actionResetModal').classList.add('open');
}

function _confirmReset() {
    var item = allActionItems[_resetItemIdx];
    if (!item) return;
    document.getElementById('actionResetModal').classList.remove('open');
    fetch('/api/action-item/reset', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, item_id: item.id})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) {
            toast('info', 'Action item reset to pending.');
            loadActionItems();
            if (d.console_cleared) {
                var tid = d.tool_id || '';
                if (tid) {
                    delete toolStatuses[tid];
                    delete toolPhases[tid];
                    Object.keys(toolStatuses).forEach(function(k) {
                        if (k.indexOf(tid + ':') === 0) delete toolStatuses[k];
                    });
                    Object.keys(toolPhases).forEach(function(k) {
                        if (k.indexOf(tid + ':') === 0) delete toolPhases[k];
                    });
                    if (d.unregistered) {
                        var idx = PROJECT_TOOLS.indexOf(tid);
                        if (idx !== -1) PROJECT_TOOLS.splice(idx, 1);
                        if (PROJECT.tools) {
                            var ti = PROJECT.tools.indexOf(tid);
                            if (ti !== -1) PROJECT.tools.splice(ti, 1);
                        }
                        if (PROJECT.scope_tools) {
                            Object.keys(PROJECT.scope_tools).forEach(function(sk) {
                                var arr = PROJECT.scope_tools[sk];
                                var si = arr.indexOf(tid);
                                if (si !== -1) arr.splice(si, 1);
                            });
                        }
                        if (selectedTool === tid) {
                            selectedTool = PROJECT_TOOLS.length ? PROJECT_TOOLS[0] : null;
                        }
                    }
                    renderToolFeeds();
                    updateConsoleHeader();
                }
                toast('info', 'Console session cleaned up for ' + (d.tool_name || 'tool') + '.');
            }
        } else {
            toast('error', d.error || 'Reset failed.');
        }
    });
}

var _launchItemIdx = -1;
var _launchToolId = '';
var _launchSchema = null;
var _launchSettings = {};
var _launchItemId = '';
var _launchIsExternal = false;

function _openLaunchModal(idx) {
    var item = allActionItems[idx];
    if (!item) return;
    _launchItemIdx = idx;
    _launchItemId = item.id || '';
    _launchToolId = (item.recommended_tool || '').toLowerCase();

    if (_launchToolId === 'nessus') {
        _openNessusScanModal(item);
        return;
    }

    var title = (TOOLS_CFG[_launchToolId] || {}).name || _launchToolId;
    document.getElementById('actionLaunchTitle').textContent = 'Launch ' + title;
    document.getElementById('actionLaunchBody').innerHTML = '<p class="text-muted text-sm">Loading settings...</p>';
    document.getElementById('actionLaunchExecBtn').disabled = true;
    document.getElementById('actionLaunchModal').classList.add('open');
    fetch('/api/settings/' + PID + '/' + _launchToolId, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            _launchSettings = d.settings || {};
            _launchSchema = (d.schema && d.schema.fields) ? d.schema.fields : [];
            _launchIsExternal = !!d.is_external;
            _renderLaunchForm(item);
            document.getElementById('actionLaunchExecBtn').disabled = false;
            if (_launchIsExternal) { _fetchCommandPreview(item); }
        })
        .catch(function() {
            document.getElementById('actionLaunchBody').innerHTML =
                '<p class="text-muted">Could not load settings. Click Execute to launch with defaults.</p>';
            _launchSchema = [];
            _launchIsExternal = false;
            document.getElementById('actionLaunchExecBtn').disabled = false;
        });
}

function _mergeItemDefaults(item) {
    if (!item) return;
    var tid = _launchToolId;
    var t = item.target || '';
    var meta = item.metadata || {};
    var orig = meta.original_settings || null;
    if (orig && typeof orig === 'object') {
        var skip = {'auth': 1, '_auth_hint': 1};
        Object.keys(orig).forEach(function(k) {
            if (skip[k]) return;
            if (_launchSettings[k] === undefined || _launchSettings[k] === null
                || _launchSettings[k] === '') {
                _launchSettings[k] = orig[k];
            }
        });
        if (orig.auth && typeof orig.auth === 'object' && orig.auth.enabled) {
            _launchSettings.auth = orig.auth;
        }
    }
    if (tid === 'siphon') {
        if (!_launchSettings.api_base_url && t) _launchSettings.api_base_url = t;
        if (!_launchSettings.environment) _launchSettings.environment = 'non-production';
    } else if (tid === 'fracture') {
        if (!_launchSettings.target_url && t) _launchSettings.target_url = t;
    } else if (tid === 'auger') {
        if (!_launchSettings.host && t) {
            if (item.port && t.indexOf(':') === -1) {
                _launchSettings.host = t + ':' + item.port;
            } else {
                _launchSettings.host = t;
            }
        }
    } else if (tid === 'ss3' || tid === 'osift') {
        if (!_launchSettings.targets && t) _launchSettings.targets = t;
    }
    if (meta.auth_state === 'authenticated' && tid === 'siphon') {
        if (!_launchSettings.auth || !_launchSettings.auth.enabled) {
            _launchSettings._auth_hint = 'Source scan was authenticated — configure auth before launching.';
        }
    }
}

function _renderLaunchForm(item) {
    _mergeItemDefaults(item);
    var body = document.getElementById('actionLaunchBody');
    var html = '<div style="margin-bottom:16px">' +
        '<div class="text-sm" style="margin-bottom:4px"><strong>Target:</strong> <code>' + esc(item.target || '--') + '</code></div>' +
        '<div class="text-sm"><strong>Action:</strong> ' + esc(item.title || '') + '</div>' +
        '</div>';
    if (_launchSchema.length) {
        html += '<div style="display:flex;flex-direction:column;gap:12px">';
        _launchSchema.forEach(function(f) {
            var key = f.key;
            var val = _launchSettings[key];
            if (val === undefined || val === null) val = '';
            var label = f.label || key;
            var type = f.type || 'text';
            html += '<div>';
            html += '<label class="text-sm" style="display:block;margin-bottom:4px;font-weight:500">' + esc(label) + '</label>';
            if (type === 'tags') {
                var tagVal = Array.isArray(val) ? val.join(', ') : String(val);
                html += '<input type="text" class="form-input" data-skey="' + esc(key) + '" data-stype="tags" value="' + esc(tagVal) + '" placeholder="' + esc(f.placeholder || '') + '" style="width:100%">';
            } else if (type === 'select' && f.options) {
                html += '<select class="form-input" data-skey="' + esc(key) + '" style="width:100%">';
                f.options.forEach(function(o) {
                    var ov = typeof o === 'string' ? o : o.value;
                    var ol = typeof o === 'string' ? o : (o.label || o.value);
                    html += '<option value="' + esc(ov) + '"' + (String(val) === String(ov) ? ' selected' : '') + '>' + esc(ol) + '</option>';
                });
                html += '</select>';
            } else if (type === 'checkbox' || type === 'boolean') {
                html += '<input type="checkbox" data-skey="' + esc(key) + '" data-stype="bool"' + (val ? ' checked' : '') + '>';
            } else if (type === 'number') {
                html += '<input type="number" class="form-input" data-skey="' + esc(key) + '" value="' + esc(String(val)) + '" style="width:100%">';
            } else {
                html += '<input type="text" class="form-input" data-skey="' + esc(key) + '" value="' + esc(String(val)) + '" placeholder="' + esc(f.placeholder || '') + '" style="width:100%">';
            }
            html += '</div>';
        });
        html += '</div>';
        if (_launchSettings._auth_hint) {
            html += '<div style="margin-top:12px;padding:10px 14px;background:var(--warn-bg, #fef3cd);border:1px solid var(--warn-border, #ffc107);border-radius:6px;font-size:0.85rem">' +
                '<strong>⚠ Auth Required:</strong> ' + esc(_launchSettings._auth_hint) +
                '</div>';
        }
    } else if (!_launchIsExternal) {
        html += '<p class="text-muted text-sm">No configurable settings for this tool.</p>';
    }
    if (_launchIsExternal) {
        html += '<div style="margin-top:16px">' +
            '<label class="text-sm" style="display:block;margin-bottom:4px;font-weight:600">Command</label>' +
            '<textarea id="launchCmdPreview" class="form-input" ' +
            'style="width:100%;min-height:72px;font-family:monospace;font-size:0.8rem;resize:vertical" ' +
            'placeholder="Loading command..."></textarea>' +
            '<p class="text-muted" style="font-size:0.7rem;margin-top:4px">Review and edit the command before executing.</p>' +
            '</div>';
    }
    body.innerHTML = html;
}

function _fetchCommandPreview(item) {
    var payload = {project_id: PID, tool_id: _launchToolId, item_id: item.id || ''};
    fetch('/api/preview-command', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        var ta = document.getElementById('launchCmdPreview');
        if (ta) { ta.value = d.command || ''; }
    })
    .catch(function() {
        var ta = document.getElementById('launchCmdPreview');
        if (ta) { ta.placeholder = 'Could not load command preview'; }
    });
}

function _execWithSettings() {
    var item = _launchItemId
        ? allActionItems.find(function(a) { return a.id === _launchItemId; })
        : allActionItems[_launchItemIdx];
    if (!item) return;
    var overrides = {};
    var inputs = document.getElementById('actionLaunchBody').querySelectorAll('[data-skey]');
    inputs.forEach(function(el) {
        var key = el.getAttribute('data-skey');
        var stype = el.getAttribute('data-stype') || '';
        if (stype === 'bool') {
            overrides[key] = el.checked;
        } else if (stype === 'tags') {
            overrides[key] = el.value.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
        } else if (el.type === 'number') {
            overrides[key] = el.value ? Number(el.value) : '';
        } else {
            overrides[key] = el.value;
        }
    });
    document.getElementById('actionLaunchExecBtn').disabled = true;
    document.getElementById('actionLaunchExecBtn').textContent = 'Launching...';
    fetch('/api/action-item/execute', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify((function() {
            var p = {project_id: PID, item_id: item.id, settings: overrides};
            if (_launchIsExternal) {
                var ta = document.getElementById('launchCmdPreview');
                if (ta && ta.value.trim()) { p.custom_command = ta.value.trim(); }
            }
            return p;
        })())
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        document.getElementById('actionLaunchExecBtn').disabled = false;
        document.getElementById('actionLaunchExecBtn').textContent = 'Execute';
        if (d.ok) {
            toast('success', 'Tool launched.');
            document.getElementById('actionLaunchModal').classList.remove('open');
            loadActionItems();
        } else {
            toast('error', d.error || 'Launch failed.');
        }
    })
    .catch(function() {
        document.getElementById('actionLaunchExecBtn').disabled = false;
        document.getElementById('actionLaunchExecBtn').textContent = 'Execute';
        toast('error', 'Launch failed.');
    });
}

function _isInScope(a) { return a.in_scope !== false; }

var _actionRetries = 0;
window.loadActionItems = function() {
    fetch('/api/action-items/' + PID, {credentials: 'same-origin'})
        .then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function(data) {
            _actionRetries = 0;
            if (data.error) throw new Error(data.error);
            allActionItems = data.items || data || [];
            allActionItems._loaded = true;
            renderActionItems();
        })
        .catch(function(err) {
            console.warn('Action items load failed:', err.message);
            if (_actionRetries < 3) {
                _actionRetries++;
                setTimeout(function() { loadActionItems(); },
                           _actionRetries * 5000);
            }
        });
};

function renderActionItems() {
    var tbody = document.getElementById('actionTableBody');
    var empty = document.getElementById('actionEmpty');
    var manualContainer = document.getElementById('manualCheckContainer');
    var automatedContainer = document.getElementById('automatedContainer');

    var manualItems = allActionItems.filter(function(a) { return a.type === 'manual_check'; });
    var automatedItems = allActionItems.filter(function(a) { return a.type !== 'manual_check'; });

    var manualPending = manualItems.filter(function(a) {
        var s = (a.status||'').toLowerCase();
        return s !== 'confirmed_missing' && s !== 'confirmed_exists';
    }).length;
    var manualPill = document.getElementById('manualPill');
    var automatedPill = document.getElementById('automatedPill');
    if (manualPill) manualPill.textContent = manualPending || '';
    if (automatedPill) automatedPill.textContent = _activeActionCount(automatedItems.filter(_isInScope)) || '';

    if (_actionSubTab === 'manual') {
        if (manualContainer) manualContainer.hidden = false;
        if (automatedContainer) automatedContainer.hidden = true;
        _renderManualChecks(manualItems);
        document.getElementById('actionPill').textContent =
            (manualPending + _activeActionCount(automatedItems.filter(_isInScope))) || '';
        return;
    }
    if (manualContainer) manualContainer.hidden = true;
    if (automatedContainer) automatedContainer.hidden = false;

    var _priOrder = {critical:0, urgent:0, high:1, recommended:2, medium:2, low:3, optional:3};
    function _sortActionItems(arr) {
        return arr.slice().sort(function(a, b) {
            var pa = _priOrder[(a.priority||'').toLowerCase()] ?? 4;
            var pb = _priOrder[(b.priority||'').toLowerCase()] ?? 4;
            if (pa !== pb) return pa - pb;
            return (a.title||'').localeCompare(b.title||'');
        });
    }
    var inScopeItems = automatedItems.filter(_isInScope);
    var oosItems = automatedItems.filter(function(a) { return !_isInScope(a); });
    var visible = _sortActionItems(_showOOS ? oosItems : inScopeItems);

    /* summary counts — always reflect visible set */
    var counts = {urgent: 0, recommended: 0, optional: 0};
    visible.forEach(function(a) {
        var p = (a.priority || '').toLowerCase();
        if (p === 'urgent' || p === 'critical' || p === 'high') counts.urgent++;
        else if (p === 'recommended' || p === 'medium') counts.recommended++;
        else counts.optional++;
    });
    document.getElementById('actUrgent').textContent = counts.urgent;
    document.getElementById('actRecommended').textContent = counts.recommended;
    document.getElementById('actOptional').textContent = counts.optional;
    document.getElementById('actionPill').textContent =
        (manualPending + _activeActionCount(inScopeItems)) || '';
    document.getElementById('oosCount').textContent = oosItems.length;
    renderBulkActionBar();

    if (!visible.length) {
        tbody.innerHTML = '';
        empty.style.display = '';
        document.querySelector('#actionEmpty .empty-state-title').textContent =
            _showOOS ? 'No out-of-scope items' : 'No action items';
        return;
    }
    empty.style.display = 'none';

    tbody.innerHTML = '';
    visible.forEach(function(a) {
        var idx = allActionItems.indexOf(a);
        var pClass = '';
        var pText = a.priority || 'Optional';
        var pl = pText.toLowerCase();
        if (pl === 'urgent' || pl === 'critical' || pl === 'high') pClass = 'color:var(--risk-high)';
        else if (pl === 'recommended' || pl === 'medium') pClass = 'color:var(--risk-medium)';
        else pClass = 'color:var(--risk-info)';

        var status = a.status || 'pending';
        var tr = document.createElement('tr');
        var scopeKey = (a.scope || '').toLowerCase();
        var scopeLabel = SCOPE_DISPLAY_NAMES[scopeKey] || scopeKey || '--';
        var recTool = (a.recommended_tool || '').toLowerCase();
        var hasExecTool = recTool && recTool !== 'manual';
        var hasMeta = a.metadata && (a.metadata.recommendations || a.description);
        var actBtns = '';
        if (status === 'pending') {
            if (hasExecTool) actBtns += '<button class="btn btn-xs btn-primary" data-act="launch" data-idx="' + idx + '">Execute</button>';
            if (hasMeta || !hasExecTool) actBtns += '<button class="btn btn-xs btn-secondary" data-act="details" data-idx="' + idx + '">Details</button>';
            if (recTool === 'nessus') actBtns += '<button class="btn btn-xs btn-secondary" data-act="nessus-import" data-idx="' + idx + '">Import</button>';
            actBtns += '<button class="btn btn-xs btn-ghost" data-act="dismiss" data-idx="' + idx + '">Dismiss</button>';
            if (hasExecTool) actBtns += '<button class="btn btn-xs btn-secondary" data-act="queue" data-idx="' + idx + '">Queue</button>';
        } else if (status === 'failed') {
            actBtns += '<button class="btn btn-xs" data-act="reset" data-idx="' + idx + '" style="border-color:#f97316;color:#f97316">Reset</button>';
        } else if (_showResets && (status === 'queued' || status === 'running' || status === 'complete')) {
            actBtns += '<button class="btn btn-xs" data-act="reset" data-idx="' + idx + '" style="border-color:#f97316;color:#f97316">Reset</button>';
        }
        tr.innerHTML =
            '<td style="' + pClass + ';font-weight:600;font-size:0.78rem;text-transform:uppercase">' + esc(pText) + '</td>' +
            '<td>' + esc(a.title||'') + '</td>' +
            '<td class="font-mono text-sm">' + esc(a.target||'--') + '</td>' +
            '<td class="text-sm">' + esc(scopeLabel) + '</td>' +
            '<td class="text-sm">' + esc(a.recommended_tool||a.tool||'--') + '</td>' +
            '<td><span class="status-badge status-' + esc(status) + '">' + esc(status) + '</span></td>' +
            '<td><div class="flex gap-4">' + actBtns + '</div></td>';
        tbody.appendChild(tr);
    });
}

document.getElementById('actionTableBody').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-act]');
    if (!btn) return;
    var act = btn.getAttribute('data-act');
    var idx = parseInt(btn.getAttribute('data-idx'), 10);
    var item = allActionItems[idx];
    if (!item) return;

    if (act === 'launch') {
        _openLaunchModal(idx);
    } else if (act === 'reset') {
        _openResetModal(idx);
    } else if (act === 'dismiss') {
        fetch('/api/action-item/dismiss', {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({project_id: PID, item_id: item.id})
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) { toast('info', 'Action dismissed.'); loadActionItems(); }
            else toast('error', d.error || 'Failed.');
        });
    } else if (act === 'queue') {
        fetch('/api/action-item/queue', {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({project_id: PID, item_id: item.id})
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) { toast('info', 'Action queued.'); loadActionItems(); }
            else toast('error', d.error || 'Failed.');
        });
    } else if (act === 'details') {
        _showActionDetail(item);
    } else if (act === 'nessus-import') {
        _nessusShowImportModal();
    }
});

function _fmtDesc(text) {
    var safe = esc(text);
    var lines = safe.split('\n');
    var out = '', inOl = false;
    for (var i = 0; i < lines.length; i++) {
        var ln = lines[i];
        var m = ln.match(/^\s*(\d+)\.\s+(.+)/);
        if (m) {
            if (!inOl) { out += '<ol style="margin:6px 0 6px 20px;font-size:0.85rem">'; inOl = true; }
            out += '<li style="margin-bottom:4px">' + m[2] + '</li>';
        } else {
            if (inOl) { out += '</ol>'; inOl = false; }
            if (ln.trim()) out += '<p style="margin:0 0 6px">' + ln + '</p>';
        }
    }
    if (inOl) out += '</ol>';
    return out;
}

function _showActionDetail(item) {
    document.getElementById('actionDetailTitle').textContent = item.title || 'Action Item';
    var body = document.getElementById('actionDetailBody');
    var html = '';
    if (item.description) html += '<div style="margin-bottom:12px">' + _fmtDesc(item.description) + '</div>';
    if (item.target) html += '<div class="text-sm" style="margin-bottom:8px"><strong>Target:</strong> <code>' + esc(item.target) + '</code></div>';
    var meta = item.metadata || {};
    var recs = meta.recommendations;
    if (recs) {
        if (recs.manual_steps && recs.manual_steps.length) {
            html += '<div style="margin-top:12px"><strong>Recommended Steps:</strong><ol style="margin:6px 0 0 20px;font-size:0.85rem">';
            recs.manual_steps.forEach(function(s) { html += '<li style="margin-bottom:4px">' + esc(s) + '</li>'; });
            html += '</ol></div>';
        }
        if (recs.msf_modules && recs.msf_modules.length) {
            html += '<div style="margin-top:12px"><strong>Metasploit Modules:</strong><ul style="margin:6px 0 0 20px;font-size:0.85rem">';
            recs.msf_modules.forEach(function(m) { html += '<li><code>' + esc(m) + '</code></li>'; });
            html += '</ul></div>';
        }
        if (recs.github_pocs && recs.github_pocs.length) {
            html += '<div style="margin-top:12px"><strong>PoC References:</strong><ul style="margin:6px 0 0 20px;font-size:0.85rem">';
            recs.github_pocs.forEach(function(u) { html += '<li><code>' + esc(u) + '</code></li>'; });
            html += '</ul></div>';
        }
    }
    if (meta.risk) html += '<div class="text-sm" style="margin-top:8px"><strong>Risk:</strong> ' + esc(meta.risk) + '</div>';
    if (meta.cves) html += '<div class="text-sm" style="margin-top:4px"><strong>CVEs:</strong> ' + esc(meta.cves) + '</div>';
    if (!html) html = '<p class="text-muted">No additional details available.</p>';
    body.innerHTML = html;
    document.getElementById('actionDetailModal').classList.add('open');
}

/* ── Bulk action bar + modal ───────────────────────────────── */
var _bulkCurrentKey = '';
var _BULK_SKIP_TOOLS = {authprobe:1, manual:1, '':1};

function _bulkGroupKey(a) {
    var tool = (a.recommended_tool || '').toLowerCase();
    if (_BULK_SKIP_TOOLS[tool]) return null;
    if (tool === 'ss3') {
        var scope = (a.metadata && a.metadata.scope) || a.scope || 'ext';
        var scopeLabel = /^int/.test(scope) ? 'INT' : 'EXT';
        return tool + ':' + scopeLabel;
    }
    var isAuth = !!(a.metadata && a.metadata.credentialled_scan);
    return tool + (isAuth ? ':auth' : ':unauth');
}

function _bulkGroupLabel(key) {
    var isOos = key.indexOf('oos:') === 0;
    var cleanKey = isOos ? key.substring(4) : key;
    var parts = cleanKey.split(':');
    var tool = parts[0];
    var cfg = TOOLS_CFG[tool] || {};
    var name = cfg.name || tool;
    var prefix = isOos ? 'OOS: Start ' : 'Start ';
    if (tool === 'ss3') {
        var scopeLabel = parts[1] || 'EXT';
        return prefix + name + ' - ' + scopeLabel;
    }
    var authLabel = parts[1] === 'auth' ? 'AUTH' : 'UNAUTH';
    return prefix + name + ' - ' + authLabel;
}

/* ── Sub-tab click handler ──────────────────────────────────────── */
(function() {
    var nav = document.getElementById('actionSubNav');
    if (!nav) return;
    nav.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-action-tab]');
        if (!btn) return;
        _actionSubTab = btn.getAttribute('data-action-tab');
        nav.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        renderActionItems();
    });
})();

/* ── Manual check card renderer ────────────────────────────────── */
function _renderManualChecks(items) {
    var grid = document.getElementById('manualChecksGrid');
    var emptyEl = document.getElementById('manualEmpty');
    if (!grid) return;
    if (!items.length) {
        grid.innerHTML = '';
        if (emptyEl) emptyEl.hidden = false;
        return;
    }
    if (emptyEl) emptyEl.hidden = true;
    var _priOrder = {critical:0, high:1, medium:2, low:3, info:4};
    var sorted = items.slice().sort(function(a, b) {
        var pa = _priOrder[(a.priority||'').toLowerCase()] ?? 4;
        var pb = _priOrder[(b.priority||'').toLowerCase()] ?? 4;
        if (pa !== pb) return pa - pb;
        var sa = (a.status||'').toLowerCase(), sb = (b.status||'').toLowerCase();
        var ra = (sa === 'confirmed_missing' || sa === 'confirmed_exists') ? 1 : 0;
        var rb = (sb === 'confirmed_missing' || sb === 'confirmed_exists') ? 1 : 0;
        return ra - rb;
    });
    var html = '';
    for (var i = 0; i < sorted.length; i++) {
        var item = sorted[i];
        var meta = item.metadata || {};
        var status = (item.status || 'pending').toLowerCase();
        var resolved = (status === 'confirmed_missing' || status === 'confirmed_exists');
        var pri = (item.priority || 'HIGH').toUpperCase();
        var priColor = pri === 'CRITICAL' ? 'var(--risk-critical)' :
                       pri === 'HIGH' ? 'var(--risk-high)' :
                       pri === 'MEDIUM' ? 'var(--risk-medium)' : 'var(--risk-low)';
        var instructions = meta.instructions || [];
        var owasp = meta.owasp_mapping || '';
        html += '<div class="manual-check-card">';
        html += '<div class="mc-header">';
        html += '<span class="badge" style="background:' + priColor + ';color:#fff;font-size:.7rem">' + esc(pri) + '</span>';
        html += '<span class="mc-title">' + esc(item.title || '') + '</span>';
        html += '</div>';
        html += '<div class="mc-desc">' + esc(item.description || '') + '</div>';
        if (owasp) html += '<div class="mc-owasp-ref">OWASP: ' + esc(owasp) + '</div>';
        if (instructions.length) {
            html += '<button type="button" class="mc-toggle-instructions" onclick="this.nextElementSibling.classList.toggle(\'expanded\');this.textContent=this.nextElementSibling.classList.contains(\'expanded\')?\'Hide instructions\':\'Show instructions\'">Show instructions</button>';
            html += '<div class="mc-instructions"><ol>';
            for (var j = 0; j < instructions.length; j++) {
                html += '<li>' + esc(instructions[j]) + '</li>';
            }
            html += '</ol></div>';
        }
        if (resolved) {
            if (status === 'confirmed_missing') {
                html += '<div class="mc-resolved-badge missing">Issue Confirmed — Finding Created</div>';
            } else {
                html += '<div class="mc-resolved-badge exists">Verified — No Issue Found</div>';
            }
        } else {
            html += '<div class="manual-check-actions">';
            html += '<button type="button" class="mc-btn-missing" onclick="_resolveManualCheck(\'' + esc(item.id) + '\',\'missing\',this)">Missing — Issue Confirmed</button>';
            html += '<button type="button" class="mc-btn-exists" onclick="_resolveManualCheck(\'' + esc(item.id) + '\',\'exists\',this)">Exists — No Issue</button>';
            html += '</div>';
        }
        html += '</div>';
    }
    grid.innerHTML = html;
}

function _resolveManualCheck(itemId, resolution, btn) {
    var card = btn.closest('.manual-check-card');
    var btns = card.querySelectorAll('button.mc-btn-missing, button.mc-btn-exists');
    btns.forEach(function(b) { b.disabled = true; });
    fetch('/api/action-item/resolve-manual', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, item_id: itemId, resolution: resolution})
    }).then(function(r) { return r.json(); }).then(function(resp) {
        if (resp.ok) {
            for (var i = 0; i < allActionItems.length; i++) {
                if (allActionItems[i].id === itemId) {
                    allActionItems[i].status = resp.status;
                    break;
                }
            }
            renderActionItems();
            if (resolution === 'missing') {
                loadFindings(true);
            }
        } else {
            btns.forEach(function(b) { b.disabled = false; });
            alert(resp.error || 'Failed to resolve manual check');
        }
    }).catch(function() {
        btns.forEach(function(b) { b.disabled = false; });
    });
}

/* ── manual_check_resolved socket event ────────────────────────── */
socket.on('manual_check_resolved', function(data) {
    if (!data || !data.item_id) return;
    for (var i = 0; i < allActionItems.length; i++) {
        if (allActionItems[i].id === data.item_id) {
            allActionItems[i].status = data.status;
            break;
        }
    }
    if (document.querySelector('.tab-content[data-tab="action-items"].active')) {
        renderActionItems();
    }
    if (data.resolution === 'missing') loadFindings(true);
});

function renderBulkActionBar() {
    var bar = document.getElementById('bulkActionBar');
    if (!bar) return;
    var pending;
    if (_showOOS) {
        pending = allActionItems.filter(function(a) {
            return (a.status||'pending') === 'pending' && !_isInScope(a);
        });
    } else {
        pending = allActionItems.filter(function(a) {
            return (a.status||'pending') === 'pending' && _isInScope(a);
        });
    }
    if (!pending.length) { bar.hidden = true; bar.innerHTML = ''; return; }

    var groups = {};
    pending.forEach(function(a) {
        var key = _bulkGroupKey(a);
        if (!key) return;
        var gk = _showOOS ? 'oos:' + key : key;
        if (!groups[gk]) groups[gk] = {key: gk, count: 0};
        groups[gk].count++;
    });

    var keys = Object.keys(groups);
    if (!keys.length) { bar.hidden = true; bar.innerHTML = ''; return; }

    keys.sort();
    bar.innerHTML = '';
    keys.forEach(function(k) {
        var g = groups[k];
        var btn = document.createElement('button');
        btn.className = 'btn btn-sm';
        btn.style.borderColor = _showOOS ? 'var(--risk-high)' : '';
        btn.style.color = _showOOS ? 'var(--risk-high)' : '';
        btn.style.background = _showOOS ? 'rgba(231,76,60,.1)' : '';
        if (!_showOOS) btn.classList.add('btn-secondary');
        btn.textContent = _bulkGroupLabel(k) + ' (' + g.count + ')';
        btn.onclick = function() { openBulkActionModal(k); };
        bar.appendChild(btn);
    });
    bar.hidden = false;
}

function openBulkActionModal(groupKey) {
    _bulkCurrentKey = groupKey;
    document.getElementById('bulkActionTitle').textContent = _bulkGroupLabel(groupKey);
    var isOos = groupKey.indexOf('oos:') === 0;
    var rawKey = isOos ? groupKey.substring(4) : groupKey;

    var matching = allActionItems.filter(function(a) {
        if ((a.status||'pending') !== 'pending') return false;
        if (isOos ? _isInScope(a) : !_isInScope(a)) return false;
        return _bulkGroupKey(a) === rawKey;
    });

    var list = document.getElementById('bulkTargetList');
    list.innerHTML = '';
    if (!matching.length) {
        list.innerHTML = '<p class="text-muted text-sm">No pending targets.</p>';
    } else {
        var tbl = document.createElement('table');
        tbl.className = 'data-table';
        tbl.style.width = '100%';
        tbl.innerHTML = '<thead><tr><th style="width:32px"></th><th>Target</th><th>Title</th><th>Priority</th></tr></thead>';
        var tb = document.createElement('tbody');
        matching.forEach(function(a) {
            var tr = document.createElement('tr');
            tr.innerHTML =
                '<td><input type="checkbox" class="bulk-target-cb" data-item-id="' + esc(a.id) + '" data-target="' + esc(a.target||'') + '" checked></td>' +
                '<td class="font-mono text-sm">' + esc(a.target||'--') + '</td>' +
                '<td class="text-sm">' + esc(a.title||'') + '</td>' +
                '<td class="text-sm">' + esc(a.priority||'medium') + '</td>';
            tb.appendChild(tr);
        });
        tbl.appendChild(tb);
        list.appendChild(tbl);
    }
    _bulkUpdateCount();
    document.getElementById('bulkActionModal').classList.add('open');
}

function closeBulkActionModal() {
    document.getElementById('bulkActionModal').classList.remove('open');
}

function _bulkSelectAll(checked) {
    var cbs = document.querySelectorAll('#bulkTargetList .bulk-target-cb');
    cbs.forEach(function(cb) { cb.checked = checked; });
    _bulkUpdateCount();
}

function _bulkUpdateCount() {
    var cbs = document.querySelectorAll('#bulkTargetList .bulk-target-cb:checked');
    document.getElementById('bulkSelectedCount').textContent = cbs.length + ' selected';
    document.getElementById('bulkExecuteBtn').disabled = cbs.length === 0;
}

document.addEventListener('change', function(e) {
    if (e.target.classList.contains('bulk-target-cb')) _bulkUpdateCount();
});

function _bulkExecute() {
    var cbs = document.querySelectorAll('#bulkTargetList .bulk-target-cb:checked');
    if (!cbs.length) { toast('warning', 'No targets selected.'); return; }
    var itemIds = [];
    var targets = [];
    cbs.forEach(function(cb) {
        itemIds.push(cb.getAttribute('data-item-id'));
        var t = cb.getAttribute('data-target');
        if (t && targets.indexOf(t) === -1) targets.push(t);
    });

    var _rawKey = _bulkCurrentKey.indexOf('oos:') === 0
        ? _bulkCurrentKey.substring(4) : _bulkCurrentKey;
    var toolId = _rawKey.split(':')[0];
    var label = _bulkGroupLabel(_bulkCurrentKey);

    var itemScope = null;
    var firstItem = allActionItems.find(function(a) {
        return itemIds.indexOf(a.id) !== -1;
    });
    if (firstItem && firstItem.source_tool && PROJECT.scope_tools) {
        var st = PROJECT.scope_tools;
        for (var sk in st) {
            if (sk !== 'multi' && st[sk].indexOf(firstItem.source_tool) !== -1) {
                itemScope = sk;
                break;
            }
        }
    }

    document.getElementById('bulkExecuteBtn').disabled = true;
    document.getElementById('bulkExecuteBtn').textContent = 'Launching...';

    var postBody = {
        project_id: PID,
        tool_id: toolId,
        item_ids: itemIds,
        targets: targets,
        group_key: _rawKey
    };
    if (itemScope) postBody.scope = itemScope;
    if (_bulkCurrentKey.indexOf('oos:') === 0) postBody.oos = true;

    fetch('/api/bulk-launch-tool', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(postBody)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        document.getElementById('bulkExecuteBtn').disabled = false;
        document.getElementById('bulkExecuteBtn').textContent = 'Execute';
        if (d.ok) {
            toast('success', d.status === 'queued'
                ? label + ' queued (' + targets.length + ' targets)'
                : label + ' launched (' + targets.length + ' targets)');
            closeBulkActionModal();
            loadActionItems();
        } else {
            toast('error', d.error || 'Bulk launch failed.');
        }
    })
    .catch(function() {
        document.getElementById('bulkExecuteBtn').disabled = false;
        document.getElementById('bulkExecuteBtn').textContent = 'Execute';
        toast('error', 'Bulk launch failed.');
    });
}

/* ── Nessus scan launch modal ── */
var _nessusInlineUrl = '';
var _nessusInlineUser = '';
var _nessusInlinePass = '';
var _neScanPendingItem = null;

function _openNessusScanModal(item) {
    var modal = document.getElementById('actionLaunchModal');
    document.getElementById('actionLaunchTitle').textContent = 'Nessus Scan';
    var body = document.getElementById('actionLaunchBody');
    body.innerHTML = '<p class="text-muted text-sm">Connecting to Nessus server...</p>';
    document.getElementById('actionLaunchExecBtn').disabled = true;
    modal.classList.add('open');

    _nessusInlineUrl = '';
    _nessusInlineUser = '';
    _nessusInlinePass = '';
    _neScanPendingItem = item;

    fetch('/api/nessus/test/' + PID, {method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({})})
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (!d.ok) {
            _renderNessusAuthForm(body, item);
            return;
        }
        fetch('/api/nessus/policies/' + PID, {credentials: 'same-origin'})
        .then(function(r2) { return r2.json(); })
        .then(function(pd) {
            _renderNessusScanForm(body, item, pd.policies || []);
            document.getElementById('actionLaunchExecBtn').disabled = false;
        })
        .catch(function() {
            _renderNessusScanForm(body, item, []);
            document.getElementById('actionLaunchExecBtn').disabled = false;
        });
    })
    .catch(function() {
        _renderNessusAuthForm(body, item);
    });
}

function _renderNessusAuthForm(body, item) {
    _neScanPendingItem = item;
    body.innerHTML =
        '<p style="font-size:.85rem;color:var(--text-muted);margin:0 0 .8rem">Enter Nessus credentials to connect and launch a scan.</p>' +
        '<div style="display:flex;flex-direction:column;gap:.4rem">' +
            '<label style="font-size:.8rem;font-weight:600">Nessus URL</label>' +
            '<input type="text" id="neScanUrl" value="https://127.0.0.1:8834" style="padding:.4rem .6rem;border:1px solid var(--border-mid);border-radius:4px;background:var(--bg-secondary);color:var(--text-primary)">' +
            '<label style="font-size:.8rem;font-weight:600">Username</label>' +
            '<input type="text" id="neScanUser" placeholder="nessus" style="padding:.4rem .6rem;border:1px solid var(--border-mid);border-radius:4px;background:var(--bg-secondary);color:var(--text-primary)">' +
            '<label style="font-size:.8rem;font-weight:600">Password</label>' +
            '<input type="password" id="neScanPass" style="padding:.4rem .6rem;border:1px solid var(--border-mid);border-radius:4px;background:var(--bg-secondary);color:var(--text-primary)">' +
        '</div>' +
        '<p id="neScanAuthStatus" style="font-size:.78rem;color:var(--text-muted);margin:.5rem 0 0"></p>' +
        '<div style="margin-top:.6rem;display:flex;gap:.5rem;justify-content:flex-end">' +
            '<button class="btn btn-primary" id="neScanConnectBtn">Connect</button>' +
        '</div>';
    document.getElementById('actionLaunchExecBtn').disabled = true;
    document.getElementById('neScanConnectBtn').addEventListener('click', _neScanConnect);
}

function _neScanConnect() {
    var url = (document.getElementById('neScanUrl').value || '').trim();
    var user = (document.getElementById('neScanUser').value || '').trim();
    var pass = document.getElementById('neScanPass').value || '';
    var statusEl = document.getElementById('neScanAuthStatus');
    var connectBtn = document.getElementById('neScanConnectBtn');
    if (!user || !pass) {
        if (statusEl) { statusEl.textContent = 'Username and password are required.'; statusEl.style.color = 'var(--risk-high,#dc3545)'; }
        return;
    }
    if (connectBtn) connectBtn.disabled = true;
    if (statusEl) { statusEl.textContent = 'Connecting...'; statusEl.style.color = 'var(--text-muted)'; }

    fetch('/api/nessus/test/' + PID, {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({nessus_url: url, nessus_user: user, nessus_pass: pass})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (connectBtn) connectBtn.disabled = false;
        if (!d.ok) {
            if (statusEl) { statusEl.textContent = d.message || 'Connection failed'; statusEl.style.color = 'var(--risk-high,#dc3545)'; }
            return;
        }
        _nessusInlineUrl = url;
        _nessusInlineUser = user;
        _nessusInlinePass = pass;
        var body = document.getElementById('actionLaunchBody');
        _renderNessusScanForm(body, _neScanPendingItem, d.policies || []);
        document.getElementById('actionLaunchExecBtn').disabled = false;
    })
    .catch(function(err) {
        if (connectBtn) connectBtn.disabled = false;
        if (statusEl) { statusEl.textContent = 'Connection error: ' + err; statusEl.style.color = 'var(--risk-high,#dc3545)'; }
    });
}

function _renderNessusScanForm(body, item, policies) {
    var target = esc(item.target || '');
    var html = '<div style="margin-bottom:16px">' +
        '<div class="text-sm" style="margin-bottom:4px"><strong>Target:</strong> <code>' + target + '</code></div>' +
        '</div>';

    html += '<div style="margin-bottom:16px">' +
        '<label class="text-sm" style="display:block;margin-bottom:6px;font-weight:600">Scan Type</label>' +
        '<div style="display:flex;flex-direction:column;gap:8px">' +
        '<label class="radio-label" style="display:flex;align-items:center;gap:8px;cursor:pointer">' +
            '<input type="radio" name="nessusScanType" value="basic" checked>' +
            '<span class="text-sm"><strong>Basic Network Scan</strong> <span class="badge-sm" style="background:var(--blue-500);color:#fff;font-size:9px;vertical-align:middle;margin-left:4px">DEFAULT</span></span>' +
        '</label>' +
        '<label class="radio-label" style="display:flex;align-items:center;gap:8px;cursor:pointer">' +
            '<input type="radio" name="nessusScanType" value="advanced">' +
            '<span class="text-sm"><strong>Advanced Scan</strong></span>' +
        '</label>' +
        '<label class="radio-label" style="display:flex;align-items:center;gap:8px;cursor:pointer">' +
            '<input type="radio" name="nessusScanType" value="custom"' + (policies.length ? '' : ' disabled') + '>' +
            '<span class="text-sm"><strong>Custom Policy</strong>' + (policies.length ? '' : ' <span class="text-muted">(none available)</span>') + '</span>' +
        '</label>' +
        '</div></div>';

    // Advanced options panel (hidden by default)
    html += '<div id="nessusAdvOpts" style="display:none;border:1px solid var(--border-color);border-radius:6px;padding:12px;margin-bottom:16px">';

    // Ping host toggle
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">' +
        '<span class="text-sm" style="font-weight:500">Ping the Remote Host</span>' +
        '<label class="toggle-switch"><input type="checkbox" id="nessusPingToggle"><span class="toggle-slider"></span></label>' +
        '</div>';

    // Ping method checkboxes (hidden unless ping toggled on)
    html += '<div id="nessusPingMethods" style="display:none;margin-bottom:12px;padding-left:16px">' +
        '<div style="display:flex;gap:16px;flex-wrap:wrap">' +
        '<label class="text-sm" style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" data-ping="arp"> ARP</label>' +
        '<label class="text-sm" style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" data-ping="tcp"> TCP</label>' +
        '<label class="text-sm" style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" data-ping="icmp"> ICMP</label>' +
        '<label class="text-sm" style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" data-ping="udp"> UDP</label>' +
        '</div></div>';

    // Port Scan Range
    html += '<div style="margin-bottom:12px">' +
        '<label class="text-sm" style="display:block;margin-bottom:4px;font-weight:500">Port Scan Range</label>' +
        '<select id="nessusPortRange" class="form-input" style="width:100%">' +
        '<option value="default" selected>default</option>' +
        '<option value="21, 22, 80">21, 22, 80</option>' +
        '<option value="1-2000">1-2000</option>' +
        '<option value="all">all</option>' +
        '</select></div>';

    // Network Port Scanners
    html += '<div style="margin-bottom:12px">' +
        '<label class="text-sm" style="display:block;margin-bottom:4px;font-weight:500">Network Port Scanners</label>' +
        '<div style="display:flex;gap:16px;flex-wrap:wrap">' +
        '<label class="text-sm" style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" data-scanner="tcp"> TCP</label>' +
        '<label class="text-sm" style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" data-scanner="syn" checked> SYN</label>' +
        '<label class="text-sm" style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" data-scanner="udp"> UDP</label>' +
        '</div></div>';

    // Web Application Scanning toggle
    html += '<div style="display:flex;align-items:center;justify-content:space-between">' +
        '<span class="text-sm" style="font-weight:500">Web Application Scanning</span>' +
        '<label class="toggle-switch"><input type="checkbox" id="nessusWebApp"><span class="toggle-slider"></span></label>' +
        '</div>';

    html += '</div>';

    // Custom policy dropdown (hidden by default)
    html += '<div id="nessusCustomPolicyBox" style="display:none;margin-bottom:16px">' +
        '<label class="text-sm" style="display:block;margin-bottom:4px;font-weight:500">Custom Policy</label>' +
        '<select id="nessusCustomPolicy" class="form-input" style="width:100%">';
    if (policies.length) {
        policies.forEach(function(p) {
            html += '<option value="' + esc(String(p.id)) + '">' + esc(p.name) + '</option>';
        });
    } else {
        html += '<option value="">No custom policies found</option>';
    }
    html += '</select></div>';

    body.innerHTML = html;

    // Wire up scan type radio listeners
    var radios = body.querySelectorAll('input[name="nessusScanType"]');
    radios.forEach(function(r) {
        r.addEventListener('change', function() {
            document.getElementById('nessusAdvOpts').style.display =
                r.value === 'advanced' ? 'block' : 'none';
            document.getElementById('nessusCustomPolicyBox').style.display =
                r.value === 'custom' ? 'block' : 'none';
        });
    });

    // Wire ping toggle
    var pingToggle = document.getElementById('nessusPingToggle');
    if (pingToggle) {
        pingToggle.addEventListener('change', function() {
            document.getElementById('nessusPingMethods').style.display =
                this.checked ? 'block' : 'none';
        });
    }
}

// Override _execWithSettings for Nessus — collect scan config and POST to /api/nessus/scan
var _origExecWithSettings = _execWithSettings;
_execWithSettings = function() {
    if (_launchToolId !== 'nessus') {
        return _origExecWithSettings();
    }

    var item = _launchItemId
        ? allActionItems.find(function(a) { return a.id === _launchItemId; })
        : allActionItems[_launchItemIdx];
    if (!item) return;

    var scanType = (document.querySelector('input[name="nessusScanType"]:checked') || {}).value || 'basic';
    var payload = {
        targets: item.target || '',
        scan_type: scanType,
        name: 'Crucible-' + PID + '-' + (item.target || '').replace(/[^a-zA-Z0-9.-]/g, '_'),
    };

    if (_nessusInlineUser && _nessusInlinePass) {
        payload.nessus_url = _nessusInlineUrl;
        payload.nessus_user = _nessusInlineUser;
        payload.nessus_pass = _nessusInlinePass;
    }

    if (scanType === 'advanced') {
        var pingOn = document.getElementById('nessusPingToggle') && document.getElementById('nessusPingToggle').checked;
        payload.advanced = {
            ping_host: pingOn,
            ping_arp: pingOn && !!(document.querySelector('[data-ping="arp"]') || {}).checked,
            ping_tcp: pingOn && !!(document.querySelector('[data-ping="tcp"]') || {}).checked,
            ping_icmp: pingOn && !!(document.querySelector('[data-ping="icmp"]') || {}).checked,
            ping_udp: pingOn && !!(document.querySelector('[data-ping="udp"]') || {}).checked,
            port_range: (document.getElementById('nessusPortRange') || {}).value || 'default',
            scanner_tcp: !!(document.querySelector('[data-scanner="tcp"]') || {}).checked,
            scanner_syn: !!(document.querySelector('[data-scanner="syn"]') || {}).checked,
            scanner_udp: !!(document.querySelector('[data-scanner="udp"]') || {}).checked,
            webapp_scanning: document.getElementById('nessusWebApp') && document.getElementById('nessusWebApp').checked,
        };
    } else if (scanType === 'custom') {
        var sel = document.getElementById('nessusCustomPolicy');
        if (sel && sel.value) payload.policy_id = parseInt(sel.value, 10);
    }

    document.getElementById('actionLaunchExecBtn').disabled = true;
    document.getElementById('actionLaunchExecBtn').textContent = 'Launching...';
    fetch('/api/nessus/scan/' + PID, {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        document.getElementById('actionLaunchExecBtn').disabled = false;
        document.getElementById('actionLaunchExecBtn').textContent = 'Execute';
        if (d.scan_id) {
            toast('success', 'Nessus scan launched (ID: ' + d.scan_id + ')');
            document.getElementById('actionLaunchModal').classList.remove('open');
            if (item.id) {
                fetch('/api/action-item/update-status', {
                    method: 'POST', credentials: 'same-origin',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({project_id: PID, item_id: item.id, status: 'running'})
                }).catch(function() {});
            }
            loadActionItems();
        } else {
            toast('error', d.error || 'Nessus scan launch failed.');
        }
    })
    .catch(function() {
        document.getElementById('actionLaunchExecBtn').disabled = false;
        document.getElementById('actionLaunchExecBtn').textContent = 'Execute';
        toast('error', 'Nessus scan launch failed.');
    });
};


/* ── Nessus import (multi-step modal matching Vantage pattern) ── */
var _neImpSessionRef = '';
var _neImpPendingFile = null;
var _neImpPendingScanId = null;
var _neImpForceMode = false;

function _nessusShowImportModal() {
    _neImpSessionRef = '';
    _neImpPendingFile = null;
    _neImpPendingScanId = null;
    _neImpForceMode = false;
    var existing = document.getElementById('nessusImportModal');
    if (existing) existing.remove();
    var modal = document.createElement('div');
    modal.id = 'nessusImportModal';
    modal.className = 'modal-overlay';
    modal.innerHTML =
        '<div class="modal-box" style="max-width:480px">' +
            '<div class="modal-header">' +
                '<span class="modal-title">Import Nessus Results</span>' +
                '<span class="modal-close" data-nessus-close><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></span>' +
            '</div>' +
            '<div class="modal-body" style="padding:.8rem 1.1rem">' +
                /* Step 1: import method choice */
                '<div id="neImpStep1">' +
                    '<p style="font-size:.85rem;color:var(--text-muted);margin:0 0 .8rem">Choose how to import Nessus scan results into this project.</p>' +
                    '<div style="display:flex;flex-direction:column;gap:.5rem">' +
                        '<button class="btn btn-primary" style="text-align:left;padding:.6rem .9rem" data-ne-action="api"><strong>Import from Nessus API</strong><br><span style="font-size:.78rem;opacity:.8">Connect to a running Nessus instance and import a completed scan</span></button>' +
                        '<button class="btn btn-ghost" style="text-align:left;padding:.6rem .9rem;border:1px solid var(--border-mid)" data-ne-action="file"><strong>Upload .nessus File</strong><br><span style="font-size:.78rem;opacity:.8">Upload an exported .nessus XML file from disk</span></button>' +
                    '</div>' +
                '</div>' +
                /* Step 2a: API credentials */
                '<div id="neImpStepAPI" hidden>' +
                    '<p style="font-size:.85rem;color:var(--text-muted);margin:0 0 .5rem">Enter Nessus API credentials to connect and list available scans.</p>' +
                    '<div style="display:flex;flex-direction:column;gap:.4rem">' +
                        '<label style="font-size:.8rem;font-weight:600">Nessus URL</label>' +
                        '<input type="text" id="neImpUrl" value="https://127.0.0.1:8834" style="padding:.4rem .6rem;border:1px solid var(--border-mid);border-radius:4px;background:var(--bg-secondary);color:var(--text-primary)">' +
                        '<label style="font-size:.8rem;font-weight:600">Username</label>' +
                        '<input type="text" id="neImpUser" placeholder="nessus" style="padding:.4rem .6rem;border:1px solid var(--border-mid);border-radius:4px;background:var(--bg-secondary);color:var(--text-primary)">' +
                        '<label style="font-size:.8rem;font-weight:600">Password</label>' +
                        '<input type="password" id="neImpPass" placeholder="" style="padding:.4rem .6rem;border:1px solid var(--border-mid);border-radius:4px;background:var(--bg-secondary);color:var(--text-primary)">' +
                    '</div>' +
                    '<p id="neImpAPIStatus" style="font-size:.78rem;color:var(--text-muted);margin:.5rem 0 0"></p>' +
                    '<div style="margin-top:.6rem;display:flex;gap:.5rem;justify-content:flex-end">' +
                        '<button class="btn btn-ghost" data-ne-back="step1">Back</button>' +
                        '<button class="btn btn-primary" id="neImpConnectBtn" data-ne-action="connect">Connect</button>' +
                    '</div>' +
                '</div>' +
                /* Step 2b: scan list from API */
                '<div id="neImpStepScanList" hidden>' +
                    '<p style="font-size:.85rem;color:var(--text-muted);margin:0 0 .5rem">Select a <strong>completed</strong> scan to import.</p>' +
                    '<div id="neImpScanList" style="max-height:300px;overflow-y:auto;border:1px solid var(--border-mid);border-radius:6px;padding:.4rem"></div>' +
                    '<p id="neImpScanStatus" style="font-size:.78rem;color:var(--text-muted);margin:.5rem 0 0"></p>' +
                    '<div style="margin-top:.6rem;display:flex;gap:.5rem;justify-content:flex-end">' +
                        '<button class="btn btn-ghost" data-ne-back="api">Back</button>' +
                    '</div>' +
                '</div>' +
                /* Step 2c: file upload */
                '<div id="neImpStepFile" hidden>' +
                    '<p style="font-size:.85rem;color:var(--text-muted);margin:0 0 .5rem">Upload a <code>.nessus</code> file exported from Nessus.</p>' +
                    '<input type="file" id="neImpFileInput" accept=".nessus,.xml" style="margin-bottom:.5rem">' +
                    '<p id="neImpFileStatus" style="font-size:.78rem;color:var(--text-muted);margin:.3rem 0 0"></p>' +
                    '<div style="margin-top:.6rem;display:flex;gap:.5rem;justify-content:flex-end">' +
                        '<button class="btn btn-ghost" data-ne-back="step1">Back</button>' +
                        '<button class="btn btn-primary" id="neImpUploadBtn" disabled data-ne-action="upload">Upload &amp; Import</button>' +
                    '</div>' +
                '</div>' +
                /* Step 3: scope warning */
                '<div id="neImpStepScope" hidden>' +
                    '<div style="background:var(--bg-warning,#fff3cd);border:1px solid var(--border-warning,#ffc107);border-radius:6px;padding:.7rem .9rem;margin-bottom:.6rem">' +
                        '<strong style="color:var(--text-warning,#856404)">Out-of-Scope Targets Detected</strong>' +
                        '<p style="font-size:.82rem;margin:.3rem 0 0;color:var(--text-warning,#856404)">The Nessus results contain targets that are <strong>not in the project scope</strong>. Importing these results may introduce findings for systems outside the engagement.</p>' +
                    '</div>' +
                    '<div style="margin-bottom:.5rem"><strong style="font-size:.82rem">Out-of-scope IPs:</strong>' +
                        '<div id="neImpOOSList" style="max-height:150px;overflow-y:auto;border:1px solid var(--border-mid);border-radius:4px;padding:.3rem .5rem;margin-top:.3rem;font-family:monospace;font-size:.8rem"></div>' +
                    '</div>' +
                    '<div style="margin-bottom:.5rem"><span style="font-size:.82rem" id="neImpScopeStats"></span></div>' +
                    '<div style="display:flex;gap:.5rem;justify-content:flex-end">' +
                        '<button class="btn btn-ghost" data-ne-action="cancel-scope">Cancel Import</button>' +
                        '<button class="btn btn-primary" style="background:var(--risk-high,#dc3545);border-color:var(--risk-high,#dc3545)" data-ne-action="force-import">Import Anyway</button>' +
                    '</div>' +
                '</div>' +
                /* Step 4: import warning (pre-import confirmation) */
                '<div id="neImpStepWarn" hidden>' +
                    '<div style="background:var(--bg-warning,#fff3cd);border:1px solid var(--border-warning,#ffc107);border-radius:6px;padding:.7rem .9rem;margin-bottom:.6rem">' +
                        '<strong style="color:var(--text-warning,#856404)">Import Warning</strong>' +
                        '<p style="font-size:.82rem;margin:.3rem 0 0;color:var(--text-warning,#856404)">Importing an incorrect or unrelated Nessus scan will introduce invalid findings into this project. Ensure the selected scan corresponds to the correct engagement and target scope before proceeding.</p>' +
                    '</div>' +
                    '<p id="neImpWarnDetail" style="font-size:.82rem;color:var(--text-muted);margin:0 0 .5rem"></p>' +
                    '<div style="display:flex;gap:.5rem;justify-content:flex-end">' +
                        '<button class="btn btn-ghost" data-ne-action="cancel-warn">Cancel</button>' +
                        '<button class="btn btn-primary" data-ne-action="confirm-import">Confirm Import</button>' +
                    '</div>' +
                '</div>' +
            '</div>' +
            '<div class="modal-footer" id="neImpFooter">' +
                '<button class="btn btn-ghost" data-nessus-close>Cancel</button>' +
            '</div>' +
        '</div>';
    document.body.appendChild(modal);
    requestAnimationFrame(function() { modal.classList.add('open'); });

    modal.querySelectorAll('[data-nessus-close]').forEach(function(el) {
        el.onclick = function() { _neImpCloseModal(); };
    });
    modal.addEventListener('click', function(e) {
        if (e.target === modal) _neImpCloseModal();
    });

    modal.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-ne-action]');
        if (!btn) {
            var back = e.target.closest('[data-ne-back]');
            if (back) {
                var target = back.getAttribute('data-ne-back');
                if (target === 'step1') _neImpShowOnly('neImpStep1');
                else if (target === 'api') _neImpShowOnly('neImpStepAPI');
            }
            return;
        }
        var action = btn.getAttribute('data-ne-action');
        if (action === 'api') _neImpSelectAPI();
        else if (action === 'file') _neImpSelectFile();
        else if (action === 'connect') _neImpConnect();
        else if (action === 'upload') _neImpUploadFile();
        else if (action === 'cancel-scope') _neImpCloseModal();
        else if (action === 'force-import') _neImpForceImport();
        else if (action === 'cancel-warn') _neImpCloseModal();
        else if (action === 'confirm-import') _neImpConfirmImport();
    });
}

function _neImpCloseModal() {
    var modal = document.getElementById('nessusImportModal');
    if (!modal) return;
    modal.classList.remove('open');
    setTimeout(function() { modal.remove(); }, 200);
}

function _neImpShowOnly(stepId) {
    ['neImpStep1','neImpStepAPI','neImpStepScanList','neImpStepFile','neImpStepScope','neImpStepWarn'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.hidden = (id !== stepId);
    });
    var footer = document.getElementById('neImpFooter');
    if (footer) footer.hidden = (stepId !== 'neImpStep1');
}

function _neImpSelectAPI() {
    var urlEl = document.getElementById('neImpUrl');
    var userEl = document.getElementById('neImpUser');
    var passEl = document.getElementById('neImpPass');
    var statusEl = document.getElementById('neImpAPIStatus');
    if (urlEl) urlEl.value = 'https://127.0.0.1:8834';
    if (userEl) userEl.value = '';
    if (passEl) passEl.value = '';
    if (statusEl) statusEl.textContent = '';
    _neImpShowOnly('neImpStepAPI');
}

function _neImpSelectFile() {
    var fi = document.getElementById('neImpFileInput');
    var fs = document.getElementById('neImpFileStatus');
    var ub = document.getElementById('neImpUploadBtn');
    if (fi) fi.value = '';
    if (fs) fs.textContent = '';
    if (ub) ub.disabled = true;
    _neImpShowOnly('neImpStepFile');
    if (fi) fi.onchange = function() {
        var f = this.files[0];
        if (f && (f.name.toLowerCase().endsWith('.nessus') || f.name.toLowerCase().endsWith('.xml'))) {
            if (ub) ub.disabled = false;
            if (fs) { fs.textContent = 'Selected: ' + f.name + ' (' + (f.size/1024).toFixed(1) + ' KB)'; fs.style.color = 'var(--text-muted)'; }
        } else if (f) {
            if (ub) ub.disabled = true;
            if (fs) { fs.textContent = 'Only .nessus/.xml files are accepted.'; fs.style.color = 'var(--risk-high,#dc3545)'; }
        }
    };
}

function _neImpConnect() {
    var url  = (document.getElementById('neImpUrl').value || '').trim();
    var user = (document.getElementById('neImpUser').value || '').trim();
    var pass = document.getElementById('neImpPass').value || '';
    var statusEl = document.getElementById('neImpAPIStatus');
    var connectBtn = document.getElementById('neImpConnectBtn');
    if (!user || !pass) {
        if (statusEl) { statusEl.textContent = 'Username and password are required.'; statusEl.style.color = 'var(--risk-high,#dc3545)'; }
        return;
    }
    if (connectBtn) connectBtn.disabled = true;
    if (statusEl) { statusEl.textContent = 'Connecting...'; statusEl.style.color = 'var(--text-muted)'; }

    fetch('/api/nessus/api-connect', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: url, username: user, password: pass})
    })
    .then(function(r) {
        var ct = r.headers.get('content-type') || '';
        if (!ct.includes('application/json')) throw new Error('Server error (HTTP ' + r.status + ')');
        return r.json();
    })
    .then(function(d) {
        if (connectBtn) connectBtn.disabled = false;
        if (d.error) {
            if (statusEl) { statusEl.textContent = d.error; statusEl.style.color = 'var(--risk-high,#dc3545)'; }
            return;
        }
        _neImpSessionRef = d._session_ref || '';
        _neImpBuildScanList(d.scans || []);
        _neImpShowOnly('neImpStepScanList');
    })
    .catch(function(err) {
        if (connectBtn) connectBtn.disabled = false;
        if (statusEl) { statusEl.textContent = 'Connection error: ' + err; statusEl.style.color = 'var(--risk-high,#dc3545)'; }
    });
}

function _neImpBuildScanList(scans) {
    var list = document.getElementById('neImpScanList');
    if (!list) return;
    list.innerHTML = '';
    if (!scans.length) {
        list.innerHTML = '<p style="font-size:.82rem;color:var(--text-muted);text-align:center;padding:1rem">No scans found on this Nessus instance.</p>';
        return;
    }
    scans.forEach(function(s) {
        var row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:.35rem .5rem;border-bottom:1px solid var(--border-mid);gap:.5rem';
        var statusColor = s.can_import ? 'var(--success,#28a745)' : 'var(--text-muted)';
        var statusIcon = s.can_import ? '✅' : (s.status === 'Running' ? '🔄' : '⏸');
        var importBtn = s.can_import
            ? '<button class="btn btn-xs btn-primary" data-ne-scan-id="' + s.id + '" data-ne-scan-name="' + esc(s.name).replace(/"/g,'&quot;') + '" style="font-size:10px;padding:2px 10px;white-space:nowrap">Import</button>'
            : '<span style="font-size:.75rem;color:var(--text-muted);white-space:nowrap">Not available</span>';
        row.innerHTML =
            '<div style="flex:1;min-width:0">' +
                '<div style="font-size:.83rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(s.name) + '</div>' +
                '<div style="font-size:.75rem;color:' + statusColor + '">' + statusIcon + ' ' + esc(s.status) + '</div>' +
            '</div>' + importBtn;
        list.appendChild(row);
    });
    list.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-ne-scan-id]');
        if (!btn) return;
        var scanId = parseInt(btn.getAttribute('data-ne-scan-id'), 10);
        var scanName = btn.getAttribute('data-ne-scan-name') || '';
        _neImpPendingScanId = scanId;
        _neImpForceMode = false;
        var warnDetail = document.getElementById('neImpWarnDetail');
        if (warnDetail) warnDetail.textContent = 'Scan: "' + scanName + '" (ID: ' + scanId + ')';
        _neImpShowOnly('neImpStepWarn');
    });
}

function _neImpUploadFile() {
    var fi = document.getElementById('neImpFileInput');
    if (!fi || !fi.files[0]) return;
    var f = fi.files[0];
    _neImpPendingFile = f;
    _neImpForceMode = false;
    var ub = document.getElementById('neImpUploadBtn');
    var fs = document.getElementById('neImpFileStatus');
    if (ub) ub.disabled = true;
    if (fs) fs.textContent = 'Validating scope...';

    var fd = new FormData();
    fd.append('file', f);
    fd.append('validate_only', 'true');
    fetch('/api/nessus/upload/' + PID, {method: 'POST', credentials: 'same-origin', body: fd})
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (ub) ub.disabled = false;
        if (d.error) {
            if (fs) { fs.textContent = d.error; fs.style.color = 'var(--risk-high,#dc3545)'; }
        } else if (d.scope_warning) {
            _neImpShowScopeWarning(d);
        } else {
            var warnDetail = document.getElementById('neImpWarnDetail');
            if (warnDetail) warnDetail.textContent = 'File: ' + f.name + ' — all targets are in scope';
            _neImpShowOnly('neImpStepWarn');
        }
    })
    .catch(function(err) {
        if (ub) ub.disabled = false;
        if (fs) { fs.textContent = 'Error: ' + err; fs.style.color = 'var(--risk-high,#dc3545)'; }
    });
}

function _neImpShowScopeWarning(data) {
    var oosList = document.getElementById('neImpOOSList');
    if (oosList) oosList.innerHTML = (data.out_of_scope || []).map(function(ip) { return '<div>' + esc(ip) + '</div>'; }).join('');
    var stats = document.getElementById('neImpScopeStats');
    if (stats) stats.innerHTML = '<strong>' + (data.out_of_scope||[]).length + '</strong> of <strong>' + data.total_hosts + '</strong> target(s) are not in scope. <strong>' + (data.in_scope||[]).length + '</strong> target(s) are in scope.';
    _neImpForceMode = false;
    _neImpShowOnly('neImpStepScope');
}

function _neImpForceImport() {
    _neImpForceMode = true;
    var warnDetail = document.getElementById('neImpWarnDetail');
    if (_neImpPendingFile) {
        if (warnDetail) warnDetail.textContent = 'File: ' + _neImpPendingFile.name + ' (scope override — out-of-scope targets will be included)';
    } else if (_neImpPendingScanId) {
        if (warnDetail) warnDetail.textContent = 'API Scan ID: ' + _neImpPendingScanId + ' (scope override — out-of-scope targets will be included)';
    }
    _neImpShowOnly('neImpStepWarn');
}

function _neImpConfirmImport() {
    if (_neImpPendingFile) {
        _neImpDoFileUpload(_neImpPendingFile, _neImpForceMode);
    } else if (_neImpPendingScanId) {
        _neImpDoAPIImport(_neImpPendingScanId, _neImpForceMode);
    }
}

function _neImpDoFileUpload(file, force) {
    _neImpCloseModal();
    toast('info', 'Importing Nessus file...');
    var fd = new FormData();
    fd.append('file', file);
    if (force) fd.append('force', 'true');
    fetch('/api/nessus/upload/' + PID, {method: 'POST', credentials: 'same-origin', body: fd})
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.scope_warning) {
            _nessusShowImportModal();
            _neImpPendingFile = file;
            _neImpShowScopeWarning(d);
            return;
        }
        if (d.ok) {
            toast('success', 'Nessus import complete — ' + d.finding_count + ' findings');
            loadActionItems();
        } else {
            toast('error', d.error || 'Import failed');
        }
    })
    .catch(function(err) { toast('error', 'Import error: ' + err); });
}

function _neImpDoAPIImport(scanId, force) {
    _neImpCloseModal();
    toast('info', 'Importing scan from Nessus API (this may take a moment)...');
    fetch('/api/nessus/api-import/' + PID, {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({scan_id: scanId, session_ref: _neImpSessionRef, force: force})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.scope_warning) {
            _nessusShowImportModal();
            _neImpPendingScanId = scanId;
            _neImpShowScopeWarning(d);
            return;
        }
        if (d.ok) {
            toast('success', 'Nessus API import complete — ' + d.finding_count + ' findings');
            loadActionItems();
        } else {
            toast('error', d.error || 'API import failed');
        }
    })
    .catch(function(err) { toast('error', 'API import error: ' + err); });
}

socket.on('nessus_done', function(data) {
    toast('success', 'Nessus import complete: ' + (data.finding_count || 0) + ' findings.');
    loadActionItems();
});

socket.on('nessus_ai_status', function(data) {
    loadActionItems();
});

socket.on('nessus_purged', function() {
    toast('info', 'Nessus findings purged.');
    loadActionItems();
});


/* ══════════════════════════════════════════════════════════════════
   9. INTELLIGENCE TAB
   ══════════════════════════════════════════════════════════════════ */
var intelSubNav = document.getElementById('intelSubNav');
/* ── Intel scope tabs + sub-tab filtering ─────────────────────── */
var intelScopeNav = document.getElementById('intelScopeNav');
var _activeScope = null;
var _scopeToolsMap = {};

/* ── Per-tool subtab definitions: [id, display name] ─────────── */
var TOOL_SUBTABS = {
    ss3:      [['status','{scope} Status'],['net-hosts','Host Map'],['net-services','Service Matrix'],['net-software','Software Inventory'],['net-ports','Port Heatmap'],['net-roles','Server Roles'],['net-hostname-env','Environment Map'],['net-hostname-apps','Application Inventory'],['net-hostname-hw','Hardware Inventory'],['net-posture','Network Posture'],['screenshots','{scope} Screenshots']],
    fracture: [['status','WebApp Status'],['webapp-intel','Web Application Intelligence'],['structure','WebApp Structure Map'],['access','WebApp Access Matrix'],['auth','WebApp Auth Status'],['cookies','WebApp Cookies'],['screenshots','WebApp Screenshots']],
    siphon:   [['status','API Status'],['structure','API Structure Map'],['access','API Access Matrix'],['auth','API Auth Status'],['cookies','API Cookies'],['api','API Inventory']],
    osift:    [['status','OSINT Status'],['osint-domains','OSINT Domains'],['osint-dns','OSINT DNS'],['osint-certs','OSINT Certificates'],['osint-emails','OSINT Emails'],['osint-people','OSINT People'],['osint-breaches','OSINT Data Breaches'],['osint-wayback','OSINT Wayback URLs'],['osint-typosquat','OSINT Typosquatting']],
    trawler:  [['status','PCAP Status'],['traffic-overview','Traffic Overview'],['traffic-convos','Traffic Conversations']],
    auger:    [['status','Database Status'],['db-schema','DB Schema Map'],['db-privs','DB Privilege Matrix']],
    bastion:  [['status','Firewall Status'],['fw-rules','FW Rule Matrix'],['fw-zones','FW Zone Map'],['fw-compliance','FW Policy Compliance'],['fw-config','FW Config Summary']],
    forge:    [['status','Cloud Status'],['cloud-resources','Cloud Resource Inventory'],['cloud-iam','Cloud IAM Matrix'],['cloud-services','Cloud Service Dashboard']],
    quill:    [['status','Mobile Status'],['mobile-components','Mobile Component Map'],['mobile-perms','Mobile Permission Matrix'],['mobile-hardening','Mobile Binary Hardening'],['mobile-data','Mobile Data Flow'],['mobile-domains','Domains & URLs'],['mobile-emails','Emails'],['mitm-cert','MITM CA Cert']],
    isotope:  [['status','File Status'],['iso-properties','File Properties'],['iso-entropy','Entropy Analysis'],['iso-contents','Archive Contents'],['iso-strings','String Analysis'],['iso-code','Code Analysis'],['iso-metadata','Metadata'],['iso-binary','Binary Analysis'],['iso-secrets','Secrets Detection'],['iso-ioc','IOC Matches']],
    dredge:   [['status','Endpoint Status'],['endpoint-overview','System Overview'],['endpoint-hardening','Hardening Assessment'],['endpoint-cis','CIS Benchmark'],['endpoint-nist','NIST 800-123'],['endpoint-stig','DISA STIG'],['endpoint-software','Software Inventory'],['endpoint-ad','Active Directory'],['endpoint-network','Network Posture'],['endpoint-browser','Browser Security'],['endpoint-disk','Disk & Storage'],['endpoint-hardware','Hardware Inventory']],
    aether:   [['status','Wi-Fi Status']], aether_b: [['status','Bluetooth Status']], aether_z: [['status','Zigbee Status']], aether_u: [['status','UWB Status']]
};

/* ── Native scope for each tool (used as default when scope_tools is absent) */
var TOOL_NATIVE_SCOPES = {
    ss3:'external', osift:'osint', fracture:'webapp', siphon:'api',
    trawler:'pcap', auger:'database', bastion:'firewall', forge:'cloud',
    quill:'mobile', isotope:'file', dredge:'endpoint', aether:'wifi',
    aether_b:'bluetooth', aether_z:'zigbee', aether_u:'uwb'
};

var _SS3_SCOPE_SUB = [
    {key: 'p1_discovery',  label: 'Phase 1: Host Discovery',              toolList: true},
    {key: 'p1_5_hostname', label: 'Phase 1.5: Hostname Resolution',       toolList: true},
    {key: 'p2_portscan',   label: 'Phase 2: Port Scan & Service Analysis',toolList: true},
    {key: 'p2_nuclei',     label: 'Phase 2: Nuclei IP Scan',              toolList: true},
    {key: 'p3_nuclei',     label: 'Phase 3: Nuclei Web Scan',             toolList: true},
    {key: 'p4_exploit',    label: 'Phase 4: Searchsploit',                toolList: true},
    {key: 'p4b_sploitus',  label: 'Phase 4b: Sploitus',                   toolList: true},
    {key: 'p4c_metasploit',label: 'Phase 4c: Metasploit',                 toolList: true},
    {key: 'p5_db',         label: 'Phase 5: Database Attacks',            toolList: true},
    {key: 'p6_brute',      label: 'Phase 6: Hydra Brute Force',           toolList: true},
    {key: 'p12_ad',        label: 'Phase 12: AD Assessment',              toolList: true},
    {key: 'p13_webapp',    label: 'Phase 13: Web App Attack',             toolList: true}
];

var CRUCIBLE_PHASE_SPECS = {
    ss3: [
        {key: 'init_tools',   label: 'INIT: Tool Discovery',  toolList: true},
        {key: 'init_updates', label: 'INIT: Plugin Updates',  toolList: true},
        {key: 'scope_int',    label: 'Scan: Internal Scope',  expandable: true,
         subPhases: _SS3_SCOPE_SUB.map(function(s) { return {key: 'int_' + s.key, label: s.label}; })},
        {key: 'scope_ext',    label: 'Scan: External Scope',  expandable: true,
         subPhases: _SS3_SCOPE_SUB.map(function(s) { return {key: 'ext_' + s.key, label: s.label}; })}
    ],
    osift: [
        {key: 'os_init_tools',       label: 'INIT: Tool Discovery',              toolList: true},
        {key: 'phase1_dns',          label: 'Phase 1: DNS Enumeration',          toolList: true},
        {key: 'phase1_5_wave_a',     label: 'Phase 1.5: theHarvester/xurlfind3r',toolList: true},
        {key: 'phase1_5_wave_b',     label: 'Phase 1.5B: puredns/waybackurls',   toolList: true},
        {key: 'phase1_5_wave_c',     label: 'Phase 1.5C: Wappalyzer/cloud_enum', toolList: true},
        {key: 'phase2_amass',        label: 'Phase 2: Amass',                    toolList: true},
        {key: 'phase3_certs',        label: 'Phase 3: Certificates',             toolList: true},
        {key: 'phase4_ip',           label: 'Phase 4: IP Intelligence',          toolList: true},
        {key: 'phase4_5_shodan_cli', label: 'Phase 4.5: Shodan CLI',             toolList: true},
        {key: 'phase5_whois',        label: 'Phase 5: WHOIS',                    toolList: true},
        {key: 'phase6_company',      label: 'Phase 6: Company Intelligence',     toolList: true},
        {key: 'phase7_email',        label: 'Phase 7: Email & People OSINT',     toolList: true},
        {key: 'phase8_crawl',        label: 'Phase 8: Web Crawling',             toolList: true},
        {key: 'phase9_report',       label: 'Phase 9: Aggregation & Report'},
        {key: 'phase10_api',         label: 'Phase 10: OSINT API Intelligence',  toolList: true},
        {key: 'phase11_dns_enrich',  label: 'Phase 11: DNS Enrichment',          toolList: true},
        {key: 'phase12_trevorspray', label: 'Phase 12: o365spray',              toolList: true},
        {key: 'phase13_gitdorker',   label: 'Phase 13: GitDorker',              toolList: true},
        {key: 'phase14_dork',        label: 'Phase 14: People Dorking',         toolList: true},
        {key: 'phase15_dnstwist',    label: 'Phase 15: dnstwist',                toolList: true},
        {key: 'phase16_vt_sweep',    label: 'Phase 16: VT Reputation Sweep',     toolList: true},
        {key: 'pd_wave_a',           label: 'PD Wave A: Subfinder/Chaos',        toolList: true},
        {key: 'pd_wave_b',           label: 'PD Wave B: DNS Resolution',         toolList: true},
        {key: 'pd_wave_ce',          label: 'PD Wave C+E: TLS/CDN/Cloud',        toolList: true},
        {key: 'pd_wave_d',           label: 'PD Wave D: Katana Crawl',           toolList: true}
    ],
    fracture: [
        {key: 'recon',              label: 'Recon',                             toolList: true},
        {key: 'screenshot',         label: 'Screenshot',                        toolList: true},
        {key: 'webfiles',           label: 'Web Files',                         toolList: true},
        {key: 'tls',                label: 'TLS Analysis',                      toolList: true},
        {key: 'subdomain_takeover', label: 'Subdomain Takeover',                toolList: true},
        {key: 'ffuf',               label: 'ffuf',                              toolList: true},
        {key: 'headers',            label: 'Security Headers',                  toolList: true},
        {key: 'shcheck',            label: 'shcheck',                           toolList: true},
        {key: 'crawl',              label: 'Crawl',                             toolList: true},
        {key: 'vulnscan',           label: 'Vuln Scan',                         toolList: true},
        {key: 'zap',                label: 'ZAP Scan',                          toolList: true},
        {key: 'jwt',                label: 'JWT',                               toolList: true},
        {key: 'injection',          label: 'Injection Testing',                 toolList: true},
        {key: 'traversal',          label: 'Path Traversal',                    toolList: true},
        {key: 'business_logic',     label: 'Business Logic',                    toolList: true},
        {key: 'ssrf',               label: 'SSRF Testing',                      toolList: true},
        {key: 'auth_bypass',        label: 'Auth Bypass',                       toolList: true},
        {key: 'account_lockout',    label: 'Account Lockout',                   toolList: true},
        {key: 'files',              label: 'Sensitive Files',                   toolList: true},
        {key: 'graphql',            label: 'GraphQL',                           toolList: true},
        {key: 'logging_monitoring', label: 'Logging & Monitoring',              toolList: true},
        {key: 'auth_recon',         label: 'Auth Recon',                        toolList: true},
        {key: 'session',            label: 'Session Analysis',                  toolList: true},
        {key: 'csrf',               label: 'CSRF Testing',                      toolList: true},
        {key: 'open_redirect',      label: 'Open Redirect',                     toolList: true},
        {key: 'deserialization',     label: 'Deserialization',                   toolList: true},
        {key: 'request_smuggling',  label: 'Request Smuggling',                 toolList: true},
        {key: 'file_upload_info',   label: 'File Upload Info',                  toolList: true},
        {key: 'mass_assignment',    label: 'Mass Assignment',                   toolList: true},
        {key: 'websocket',          label: 'WebSocket Testing',                 toolList: true},
        {key: 'endpoint_tools',     label: 'Endpoint Tools',                    toolList: true},
        {key: 'authorization',      label: 'Authorization Testing',             toolList: true},
        {key: 'cross_user',         label: 'Cross-User Testing',                toolList: true},
        {key: 'access_matrix',      label: 'Access Matrix',                     toolList: true},
        {key: 'bfla',               label: 'BFLA Testing',                      toolList: true},
        {key: 'logout',             label: 'Logout Testing',                    toolList: true}
    ],
    siphon: [
        {key: 'discovery',          label: 'API Discovery',                     toolList: true},
        {key: 'chaining',           label: 'Request Chaining',                  toolList: true},
        {key: 'recon',              label: 'API Recon',                         toolList: true},
        {key: 'fuzzing',            label: 'Fuzzing',                           toolList: true},
        {key: 'injection',          label: 'Injection Testing',                 toolList: true},
        {key: 'auth_bypass',        label: 'Auth Bypass',                       toolList: true},
        {key: 'rate_limiting',      label: 'Rate Limiting',                     toolList: true},
        {key: 'mass_assignment',    label: 'Mass Assignment',                   toolList: true},
        {key: 'ssrf',               label: 'SSRF',                              toolList: true},
        {key: 'data_exposure',      label: 'Data Exposure',                     toolList: true},
        {key: 'graphql',            label: 'GraphQL',                           toolList: true},
        {key: 'business_flows',     label: 'Business Flows',                    toolList: true},
        {key: 'session',            label: 'Session Analysis',                  toolList: true},
        {key: 'jwt',                label: 'JWT',                               toolList: true},
        {key: 'sensitive_files',    label: 'Sensitive Files',                   toolList: true},
        {key: 'unsafe_consumption', label: 'Unsafe Consumption',                toolList: true},
        {key: 'verb_tampering',     label: 'Verb Tampering',                    toolList: true},
        {key: 'soap',               label: 'SOAP',                              toolList: true},
        {key: 'file_upload_info',   label: 'File Upload Info',                  toolList: true},
        {key: 'protocols',          label: 'Protocols',                         toolList: true},
        {key: 'tls',                label: 'TLS Analysis',                      toolList: true},
        {key: 'bola',               label: 'BOLA Testing',                      toolList: true},
        {key: 'bfla',               label: 'BFLA Testing',                      toolList: true},
        {key: 'cross_user',         label: 'Cross-User Testing',                toolList: true},
        {key: 'access_matrix',      label: 'Access Matrix',                     toolList: true}
    ],
    trawler: [
        {key: 'load_captures',      label: 'Load Captures',                     toolList: true},
        {key: 'threat_intel',       label: 'Threat Intelligence',               toolList: true}
    ],
    auger: [
        {key: 'connectivity',       label: 'Connectivity',                      toolList: true},
        {key: 'network',            label: 'Network / TLS',                     toolList: true},
        {key: 'mysql',              label: 'MySQL',                             toolList: true},
        {key: 'postgresql',         label: 'PostgreSQL',                        toolList: true},
        {key: 'mssql',              label: 'MSSQL',                             toolList: true},
        {key: 'mongodb',            label: 'MongoDB',                           toolList: true},
        {key: 'redis',              label: 'Redis',                             toolList: true},
        {key: 'cassandra',          label: 'Cassandra',                         toolList: true},
        {key: 'elasticsearch',      label: 'Elasticsearch',                     toolList: true},
        {key: 'oracle',             label: 'Oracle',                            toolList: true},
        {key: 'couchdb',            label: 'CouchDB',                           toolList: true},
        {key: 'influxdb',           label: 'InfluxDB',                          toolList: true},
        {key: 'neo4j',              label: 'Neo4j',                             toolList: true},
        {key: 'memcached',          label: 'Memcached',                         toolList: true}
    ],
    bastion: [
        {key: 'audit',              label: 'Firewall Audit',                    toolList: true},
        {key: 'threat_intel',       label: 'Threat Intelligence',               toolList: true}
    ],
    forge: [
        {key: 'aws',                label: 'AWS Account Audit',                 toolList: true},
        {key: 'azure',              label: 'Azure Subscription Audit',          toolList: true},
        {key: 'gcp',                label: 'GCP Project Audit',                 toolList: true}
    ],
    quill: [
        {key: 'extract',            label: 'App Extraction',                    toolList: true},
        {key: 'info_plist',         label: 'Info.plist Analysis',               toolList: true},
        {key: 'entitlements',       label: 'Entitlements',                      toolList: true},
        {key: 'manifest',           label: 'AndroidManifest.xml',               toolList: true},
        {key: 'permissions',        label: 'Permission Analysis',               toolList: true},
        {key: 'strings',            label: 'Secret Scan (iOS)',                 toolList: true},
        {key: 'strings_apk',       label: 'Secret Scan (APK)',                 toolList: true},
        {key: 'dynamic',            label: 'Dynamic Analysis',                  toolList: true}
    ],
    isotope: [],
    authprobe: [],
    dredge: [
        {key: 'Starting',   label: 'Initialization'},
        {key: 'Collecting',  label: 'Collection (WinRM)'},
        {key: 'Analyzing',   label: 'Security Analysis',        toolList: true},
        {key: 'Parsing',     label: 'Parsing Results'},
        {key: 'Enriching',   label: 'Threat Intel Enrichment'},
        {key: 'Complete',    label: 'Complete'}
    ],
    nessus: [],
    aether: [
        {key: 'p0_intel',           label: 'Phase 0: Intel Gathering',          toolList: true},
        {key: 'p0_wep',             label: 'Phase 0: WEP Detection',            toolList: true},
        {key: 'p_ctx',              label: 'Context Probing',                   toolList: true},
        {key: 'p1a_pmkid',          label: 'Phase 1a: PMKID Capture',           toolList: true},
        {key: 'p1b_wifite',         label: 'Phase 1b: Wifite',                  toolList: true},
        {key: 'p1c_deauth',         label: 'Phase 1c: Deauth Capture',          toolList: true},
        {key: 'p1c_pmkid_roam',     label: 'Phase 1c: PMKID Roam',              toolList: true},
        {key: 'p2_eaphammer',       label: 'Phase 2: EAPHammer',                toolList: true},
        {key: 'p3_dragonslayer',    label: 'Phase 3: Dragonslayer',              toolList: true},
        {key: 'p4_dragondrain',     label: 'Phase 4: Dragondrain',               toolList: true},
        {key: 'p5_krack',           label: 'Phase 5: KRACK',                     toolList: true},
        {key: 'p6_rogue_ap',        label: 'Phase 6: Rogue AP',                  toolList: true},
        {key: 'p6b_karma',          label: 'Phase 6b: Karma',                    toolList: true},
        {key: 'p6c_mana_loud',      label: 'Phase 6c: MANA Loud',                toolList: true},
        {key: 'p7_client',          label: 'Phase 7: Client Attacks',             toolList: true},
        {key: 'p8_eap_downgrade',   label: 'Phase 8: EAP Downgrade',              toolList: true},
        {key: 'p9_sae_downgrade',   label: 'Phase 9: SAE Downgrade',              toolList: true},
        {key: 'p10_post',           label: 'Phase 10: Post-Exploitation',         toolList: true},
        {key: 'p11_legacy',         label: 'Phase 11: Legacy Checks',             toolList: true}
    ],
    aether_b: [
        {key: 'passive_recon',      label: 'Passive Recon',                      toolList: true},
        {key: 'enumeration',        label: 'Enumeration',                        toolList: true},
        {key: 'key_recovery',       label: 'Key Recovery',                       toolList: true},
        {key: 'exploitation',       label: 'Exploitation',                       toolList: true},
        {key: 'firmware',           label: 'Firmware Analysis',                  toolList: true}
    ],
    aether_z: [
        {key: 'survey',             label: 'RF Survey',                          toolList: true},
        {key: 'key_recovery',       label: 'Key Recovery',                       toolList: true},
        {key: 'enumeration',        label: 'Enumeration',                        toolList: true},
        {key: 'attacks',            label: 'Active Attacks',                     toolList: true},
        {key: 'firmware',           label: 'Firmware Analysis',                  toolList: true}
    ],
    aether_u: [
        {key: 'survey',             label: 'RF Survey',                          toolList: true},
        {key: 'protocol_analysis',  label: 'Protocol Analysis',                  toolList: true},
        {key: 'active_interaction', label: 'Active Interaction',                 toolList: true},
        {key: 'physical_attacks',   label: 'Physical Attacks',                   toolList: true},
        {key: 'network_app',        label: 'Network & Application',              toolList: true}
    ]
};

var _TARGETS_SCOPES = {};

var _TOOL_GENERATORS = {
    fracture: ['osift', 'ss3'],
    siphon:   ['osift', 'ss3'],
    auger:    ['ss3'],
    ss3:      ['osift']
};

function _resolveOriginScope(toolId) {
    var gens = _TOOL_GENERATORS[toolId] || [];
    var extDN = SCOPE_DISPLAY_NAMES['external'];
    var intDN = SCOPE_DISPLAY_NAMES['internal'];
    for (var dn in _scopeToolsMap) {
        if (dn !== extDN && dn !== intDN) continue;
        var tools = _scopeToolsMap[dn];
        for (var i = 0; i < gens.length; i++) {
            if (tools.indexOf(gens[i]) !== -1) return dn;
        }
    }
    for (var dn in _scopeToolsMap) {
        var tools = _scopeToolsMap[dn];
        for (var i = 0; i < gens.length; i++) {
            if (tools.indexOf(gens[i]) !== -1) return dn;
        }
    }
    var scopeNames = Object.keys(_scopeToolsMap);
    return scopeNames.length ? scopeNames[0] : null;
}

function _addToolToIntelScope(toolId, scopeKey, originScope) {
    if (TOOL_SUBTABS[toolId] === undefined) return;
    var dn;
    if (scopeKey === 'multi') {
        if (originScope) {
            var odn = SCOPE_DISPLAY_NAMES[originScope] || originScope;
            if (_scopeToolsMap[odn]) {
                dn = odn;
            }
        }
        if (!dn) dn = _resolveOriginScope(toolId);
        if (!dn) return;
    } else {
        dn = SCOPE_DISPLAY_NAMES[scopeKey] || scopeKey;
    }
    if (!_scopeToolsMap[dn]) {
        _scopeToolsMap[dn] = [];
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'tab-btn';
        btn.setAttribute('data-scope', dn);
        btn.textContent = dn;
        intelScopeNav.appendChild(btn);
    }
    if (_scopeToolsMap[dn].indexOf(toolId) === -1) {
        _scopeToolsMap[dn].push(toolId);
    }
    if (!_activeScope) {
        selectScope(dn);
    } else if (_activeScope === dn) {
        selectScope(dn);
    }
}

function _syncIntelScopes() {
    var st = PROJECT.scope_tools || {};
    for (var sk in st) {
        if (!st[sk] || !st[sk].length) continue;
        if (sk === 'multi') continue;
        st[sk].forEach(function(t) {
            _addToolToIntelScope(t, sk);
        });
    }
}

(function() {
    var scopeTools = PROJECT.scope_tools || {};
    var origTools = PROJECT.tools || [];

    var autoAdded = PROJECT.auto_added_tools || [];
    origTools.forEach(function(t) {
        if (autoAdded.indexOf(t) !== -1) return;
        var nk = TOOL_NATIVE_SCOPES[t];
        if (!nk || TOOL_SUBTABS[t] === undefined) return;
        var inScopeTools = false;
        for (var sk in scopeTools) {
            if (sk === 'multi') continue;
            if ((scopeTools[sk] || []).indexOf(t) !== -1) { inScopeTools = true; break; }
        }
        if (inScopeTools) return;
        var dn = SCOPE_DISPLAY_NAMES[nk] || nk;
        if (!_scopeToolsMap[dn]) _scopeToolsMap[dn] = [];
        if (_scopeToolsMap[dn].indexOf(t) === -1) _scopeToolsMap[dn].push(t);
    });

    if (origTools.indexOf('ss3') !== -1) {
        var _cidrs = ((PROJECT.scope_definition || {}).network_cidrs) || [];
        var _hasPrivate = _cidrs.some(function(c) {
            var ip = c.split('/')[0];
            return ip.match(/^10\./) || ip.match(/^172\.(1[6-9]|2\d|3[01])\./) || ip.match(/^192\.168\./);
        });
        if (_hasPrivate) {
            var intDN = SCOPE_DISPLAY_NAMES['internal'];
            if (!_scopeToolsMap[intDN]) _scopeToolsMap[intDN] = [];
            if (_scopeToolsMap[intDN].indexOf('ss3') === -1) _scopeToolsMap[intDN].push('ss3');
        }
    }

    for (var sk in scopeTools) {
        if (sk === 'multi') continue;
        (scopeTools[sk] || []).forEach(function(t) {
            if (TOOL_SUBTABS[t] === undefined) return;
            var dn = SCOPE_DISPLAY_NAMES[sk] || sk;
            if (!_scopeToolsMap[dn]) _scopeToolsMap[dn] = [];
            if (_scopeToolsMap[dn].indexOf(t) === -1) _scopeToolsMap[dn].push(t);
        });
    }

    var scopeNames = Object.keys(_scopeToolsMap).sort();
    scopeNames.forEach(function(name) {
        if (!_scopeToolsMap[name] || !_scopeToolsMap[name].length) return;
        var exists = intelScopeNav.querySelector('[data-scope="' + name + '"]');
        if (!exists) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'tab-btn';
            btn.setAttribute('data-scope', name);
            btn.textContent = name;
            intelScopeNav.appendChild(btn);
        }
    });

    scopeNames = Object.keys(_scopeToolsMap).sort();
    if (scopeNames.length) selectScope(scopeNames[0]);
})();

function selectScope(scopeName) {
    _activeScope = scopeName;
    intelScopeNav.querySelectorAll('.tab-btn').forEach(function(b) {
        b.classList.toggle('active', b.getAttribute('data-scope') === scopeName);
    });
    var exportBtn = document.getElementById('btnExportIntel');
    if (exportBtn) exportBtn.hidden = !scopeName;

    intelSubNav.innerHTML = '';
    var tools = _scopeToolsMap[scopeName] || [];
    var hasTargets = _TARGETS_SCOPES.hasOwnProperty(scopeName);
    if (!tools.length && !hasTargets) return;

    var overviewBtn = document.createElement('button');
    overviewBtn.type = 'button';
    overviewBtn.className = 'tab-btn active';
    overviewBtn.setAttribute('data-intel', 'overview');
    overviewBtn.setAttribute('data-tool', tools[0] || '');
    overviewBtn.textContent = 'Overview';
    intelSubNav.appendChild(overviewBtn);

    if (hasTargets) {
        var tBtn = document.createElement('button');
        tBtn.type = 'button';
        tBtn.className = 'tab-btn';
        tBtn.setAttribute('data-intel', 'targets');
        tBtn.setAttribute('data-tool', '');
        tBtn.textContent = 'Targets';
        intelSubNav.appendChild(tBtn);
    }

    tools.forEach(function(t) {
        var subs = TOOL_SUBTABS[t] || [];
        subs.forEach(function(pair) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'tab-btn';
            btn.setAttribute('data-intel', pair[0]);
            btn.setAttribute('data-tool', t);
            var label = pair[1];
            if (label.indexOf('{scope}') !== -1) {
                var scopeLabel = (_activeScope || 'internal').charAt(0).toUpperCase() + (_activeScope || 'internal').slice(1);
                label = label.replace('{scope}', scopeLabel);
            }
            btn.textContent = label;
            intelSubNav.appendChild(btn);
        });
    });

    loadIntelPanel('overview', tools[0] || '');
}

intelScopeNav.addEventListener('click', function(e) {
    var btn = e.target.closest('.tab-btn');
    if (!btn) return;
    var scope = btn.getAttribute('data-scope');
    if (scope) selectScope(scope);
});

intelSubNav.addEventListener('click', function(e) {
    var btn = e.target.closest('.tab-btn');
    if (!btn) return;
    var sub = btn.getAttribute('data-intel');
    var tool = btn.getAttribute('data-tool');
    if (!sub) return;
    intelSubNav.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    loadIntelPanel(sub, tool);
});

document.getElementById('btnExportIntel').addEventListener('click', function() {
    if (!_activeScope) return;
    window.location.href = '/api/export-intel/' + PID + '?scope=' + encodeURIComponent(_activeScope);
});

function _refreshActiveIntel() {
    if (_activeIntelPanel) loadIntelPanel(_activeIntelPanel, _activeIntelTool);
}

function loadIntelPanel(panel, tool) {
    var body = document.getElementById('intelBody');
    var empty = document.getElementById('intelEmpty');
    _activeIntelPanel = panel;
    _activeIntelTool = tool;

    if (panel === 'targets') {
        _loadIntelTargets(body, empty);
        return;
    }

    if (panel === 'status') {
        renderStatusPanel(tool, body, empty);
        return;
    }

    if (panel === 'screenshots') {
        _loadScreenshotsPanel(body, empty, tool);
        return;
    }

    var urlMap = {
        overview: '/api/intel/' + PID,
        structure: '/api/structure/' + PID,
        access: '/api/access-matrix/' + PID,
        auth: '/api/auth-status/' + PID,
        api: '/api/api-inventory/' + PID,
        profile: '/api/target-profile/' + PID,
        'fw-rules': '/api/intel/fw-rules/' + PID,
        'fw-zones': '/api/intel/fw-zones/' + PID,
        'fw-compliance': '/api/intel/fw-compliance/' + PID,
        'fw-config': '/api/intel/fw-config/' + PID,
        'cloud-resources': '/api/intel/cloud-resources/' + PID,
        'cloud-iam': '/api/intel/cloud-iam/' + PID,
        'cloud-services': '/api/intel/cloud-services/' + PID,
        'mobile-components': '/api/intel/mobile-components/' + PID,
        'mobile-perms': '/api/intel/mobile-perms/' + PID,
        'mobile-hardening': '/api/intel/mobile-hardening/' + PID,
        'mobile-data': '/api/intel/mobile-data/' + PID,
        'mobile-domains': '/api/intel/mobile-domains/' + PID,
        'mobile-emails': '/api/intel/mobile-emails/' + PID,
        'mitm-cert': '/api/intel/mitm-cert/' + PID,
        'traffic-overview': '/api/intel/traffic-overview/' + PID,
        'traffic-convos': '/api/intel/traffic-convos/' + PID,
        'net-hosts': '/api/intel/net-hosts/' + PID,
        'net-services': '/api/intel/net-services/' + PID,
        'net-software': '/api/intel/net-software/' + PID,
        'net-ports': '/api/intel/net-ports/' + PID,
        'net-roles': '/api/intel/net-roles/' + PID,
        'net-hostname-env': '/api/intel/net-hostname-env/' + PID,
        'net-hostname-apps': '/api/intel/net-hostname-apps/' + PID,
        'net-hostname-hw': '/api/intel/net-hostname-hw/' + PID,
        'net-posture': '/api/intel/net-posture/' + PID,
        'osint-domains': '/api/intel/osint-domains/' + PID,
        'osint-dns': '/api/intel/osint-dns/' + PID,
        'osint-certs': '/api/intel/osint-certs/' + PID,
        'osint-emails': '/api/intel/osint-emails/' + PID,
        'osint-breaches': '/api/intel/osint-breaches/' + PID,
        'osint-people': '/api/intel/osint-people/' + PID,
        'osint-typosquat': '/api/intel/osint-typosquat/' + PID,
        'osint-wayback': '/api/intel/osint-wayback/' + PID,
        'db-schema': '/api/intel/db-schema/' + PID,
        'db-privs': '/api/intel/db-privs/' + PID,
        'iso-properties': '/api/intel/iso-properties/' + PID,
        'iso-entropy': '/api/intel/iso-entropy/' + PID,
        'iso-contents': '/api/intel/iso-contents/' + PID,
        'iso-strings': '/api/intel/iso-strings/' + PID,
        'iso-code': '/api/intel/iso-code/' + PID,
        'iso-metadata': '/api/intel/iso-metadata/' + PID,
        'iso-binary': '/api/intel/iso-binary/' + PID,
        'iso-secrets': '/api/intel/iso-secrets/' + PID,
        'iso-ioc': '/api/intel/iso-ioc/' + PID,
        'endpoint-overview': '/api/intel/endpoint-overview/' + PID,
        'endpoint-hardening': '/api/intel/endpoint-hardening/' + PID,
        'endpoint-software': '/api/intel/endpoint-software/' + PID,
        'endpoint-ad': '/api/intel/endpoint-ad/' + PID,
        'endpoint-network': '/api/intel/endpoint-network/' + PID,
        'endpoint-browser': '/api/intel/endpoint-browser/' + PID,
        'endpoint-disk': '/api/intel/endpoint-disk/' + PID,
        'endpoint-hardware': '/api/intel/endpoint-hardware/' + PID,
        'endpoint-cis': '/api/intel/endpoint-cis/' + PID,
        'endpoint-nist': '/api/intel/endpoint-nist/' + PID,
        'endpoint-stig': '/api/intel/endpoint-stig/' + PID,
        'cookies': '/api/intel/cookies/' + PID,
        'webapp-intel': '/api/webapp-intel/' + PID,
    };

    var url = urlMap[panel];
    if (!url) return;
    if (tool) url += (url.indexOf('?') === -1 ? '?' : '&') + 'tool=' + encodeURIComponent(tool) + '&scope=' + encodeURIComponent(_activeScope);

    body.innerHTML = '<div class="flex-center p-20"><div class="spinner"></div></div>';
    body.hidden = false;
    empty.style.display = 'none';

    if (panel === 'overview') {
        _loadScopeOverview(body, empty);
        return;
    }

    fetch(url, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!data || (Array.isArray(data) && !data.length) || (typeof data === 'object' && !Object.keys(data).length)) {
                body.hidden = true;
                empty.style.display = '';
                return;
            }
            body.innerHTML = _renderIntelPanel(panel, data);
        })
        .catch(function() {
            body.innerHTML = '<div class="empty-state"><div class="empty-state-text">Failed to load intelligence data.</div></div>';
        });
}

/* ── Intelligence Panel Renderers ─────────────────────────────── */
function _riskColor(r) {
    var m = {'critical':'var(--clr-critical)','high':'var(--clr-high)','medium':'var(--clr-medium)','low':'var(--clr-low)','info':'var(--clr-info)'};
    return m[(r||'info').toLowerCase()] || 'var(--text-secondary)';
}
function _intelTable(headers, rows) {
    var h = '<div style="overflow-x:auto;max-height:70vh;overflow-y:auto"><table class="tool-table" style="width:100%"><thead><tr>';
    headers.forEach(function(hd) { h += '<th>' + esc(hd) + '</th>'; });
    h += '</tr></thead><tbody>';
    rows.forEach(function(row) {
        h += '<tr>';
        row.forEach(function(cell, ci) {
            var s = '';
            if (ci === 0) s = ' style="font-family:var(--font-mono);white-space:nowrap"';
            h += '<td' + s + '>' + (cell || '') + '</td>';
        });
        h += '</tr>';
    });
    h += '</tbody></table></div>';
    return h;
}
function _intelCard(title, items) {
    var h = '<div style="margin-bottom:16px;padding:12px;background:var(--bg-card);border-radius:8px;border:1px solid var(--border)">';
    h += '<div style="font-weight:600;margin-bottom:8px">' + esc(title) + '</div>';
    items.forEach(function(pair) {
        h += '<div style="display:flex;gap:8px;padding:3px 0"><span style="color:var(--text-secondary);min-width:120px">' + esc(pair[0]) + '</span><span>' + (pair[1] || '') + '</span></div>';
    });
    h += '</div>';
    return h;
}

function _renderIntelPanel(panel, data) {
    var renderer = _INTEL_RENDERERS[panel];
    if (renderer) {
        try { return renderer(data); } catch(e) { /* fallback */ }
    }
    return _renderIntelGeneric(data);
}

function _renderIntelGeneric(data) {
    var payload = data;
    if (typeof data === 'object' && !Array.isArray(data)) {
        var keys = Object.keys(data).filter(function(k) { return k[0] !== '_'; });
        if (keys.length === 1 && data.available !== undefined) payload = data[keys[0]];
        else if (keys.length === 2 && data.available !== undefined) {
            var dk = keys.filter(function(k) { return k !== 'available'; })[0];
            payload = data[dk];
        }
    }
    if (!payload || (Array.isArray(payload) && !payload.length)) return '<div class="empty-state"><div class="empty-state-text">No data available for this panel.</div></div>';
    if (Array.isArray(payload) && payload.length && typeof payload[0] === 'object') return _renderArrayTable(payload);
    if (typeof payload === 'object' && !Array.isArray(payload)) return _renderObjectCards(payload);
    return '<pre style="max-height:60vh;overflow:auto">' + esc(JSON.stringify(payload, null, 2)) + '</pre>';
}

function _renderArrayTable(arr) {
    var allKeys = [];
    arr.forEach(function(obj) { Object.keys(obj).forEach(function(k) { if (allKeys.indexOf(k) === -1 && k[0] !== '_') allKeys.push(k); }); });
    var rows = arr.map(function(obj) {
        return allKeys.map(function(k) {
            var v = obj[k];
            if (v === null || v === undefined) return '';
            if (typeof v === 'boolean') return v ? 'Yes' : 'No';
            if (Array.isArray(v)) return esc(v.join(', '));
            if (typeof v === 'object') return esc(JSON.stringify(v));
            return esc(String(v));
        });
    });
    return _intelTable(allKeys, rows);
}

function _renderObjectCards(obj) {
    var h = '';
    Object.keys(obj).forEach(function(k) {
        if (k[0] === '_') return;
        var v = obj[k];
        if (typeof v === 'object' && v && !Array.isArray(v)) {
            var items = Object.keys(v).map(function(sk) {
                var sv = v[sk];
                if (typeof sv === 'object') sv = JSON.stringify(sv);
                return [sk, esc(String(sv != null ? sv : ''))];
            });
            h += _intelCard(k, items);
        } else if (Array.isArray(v) && v.length && typeof v[0] === 'object') {
            h += '<div style="margin-bottom:16px"><div style="font-weight:600;margin-bottom:8px">' + esc(k) + ' (' + v.length + ')</div>';
            h += _renderArrayTable(v);
            h += '</div>';
        } else {
            h += _intelCard(k, [['Value', esc(String(v != null ? v : ''))]]);
        }
    });
    return h || '<div class="empty-state"><div class="empty-state-text">No data available.</div></div>';
}

/* ── Specific Panel Renderers ──────────────────────────────────── */

var _WELL_KNOWN_PORTS = {
    20:'ftp-data',21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',67:'dhcp',68:'dhcp',
    69:'tftp',80:'http',88:'kerberos',110:'pop3',111:'rpcbind',119:'nntp',123:'ntp',
    135:'msrpc',137:'netbios-ns',138:'netbios-dgm',139:'netbios-ssn',143:'imap',161:'snmp',
    162:'snmptrap',179:'bgp',389:'ldap',443:'https',445:'smb',464:'kpasswd',465:'smtps',
    500:'isakmp',514:'syslog',515:'lpd',520:'rip',523:'ibm-db2',554:'rtsp',587:'smtp',
    593:'http-rpc',623:'ipmi',636:'ldaps',664:'amt',873:'rsync',902:'vmware',993:'imaps',
    995:'pop3s',1080:'socks',1433:'mssql',1434:'mssql-browser',1521:'oracle',1723:'pptp',
    2049:'nfs',2082:'cpanel',2083:'cpanel-ssl',2181:'zookeeper',2222:'ssh',3268:'ldap-gc',
    3269:'ldap-gc-ssl',3306:'mysql',3389:'rdp',3690:'svn',4443:'https-alt',5060:'sip',
    5432:'postgresql',5631:'pcanywhere',5632:'pcanywhere',5672:'amqp',5900:'vnc',5985:'winrm',
    5986:'winrm-ssl',6379:'redis',6443:'kubernetes',7001:'weblogic',8000:'http-alt',
    8008:'http-alt',8080:'http-proxy',8081:'http-alt',8443:'https-alt',8888:'http-alt',
    9000:'http-alt',9090:'http-alt',9200:'elasticsearch',9300:'elasticsearch',9443:'https-alt',
    11211:'memcached',27017:'mongodb',27018:'mongodb',50000:'sap'
};
function _resolveService(svc, port) {
    if (svc && svc !== 'unknown' && svc !== '?') return svc;
    return _WELL_KNOWN_PORTS[port] || svc || '';
}

function _renderNetHosts(data) {
    var payload = data.net_hosts || data;
    if (!payload) return _renderIntelGeneric(data);
    var hosts = payload.hosts || payload;
    if (typeof hosts === 'object' && !Array.isArray(hosts)) {
        var arr = [];
        Object.keys(hosts).forEach(function(ip) {
            var h = hosts[ip];
            if (typeof h !== 'object') return;
            var ports = h.ports || {};
            var portList = [];
            Object.keys(ports).forEach(function(p) {
                var pd = ports[p];
                if (!_isConfirmedPort(pd)) return;
                portList.push(p + '/' + (pd.protocol || 'tcp'));
            });
            if (!portList.length && h.alive === false) return;
            arr.push({
                ip: ip,
                hostname: h.hostname || '',
                os: h.os_hint || h.os || '',
                ports: portList,
                port_count: portList.length,
                risk: h.risk || '',
                tools: h.tools || []
            });
        });
        hosts = arr;
    }
    if (!Array.isArray(hosts) || !hosts.length) return _renderIntelGeneric(data);
    var rows = hosts.map(function(h) {
        var portStr = '';
        var confirmedCount = 0;
        if (h.ports && Array.isArray(h.ports)) {
            var confirmed = h.ports.filter(function(p) { return typeof p !== 'object' || _isConfirmedPort(p); });
            confirmedCount = confirmed.length;
            portStr = confirmed.map(function(p) {
                if (typeof p === 'object') {
                    return p.port + '/' + (p.protocol||'tcp');
                }
                return esc(String(p));
            }).join('<br>');
        } else if (typeof h.ports === 'string') {
            portStr = esc(h.ports);
        }
        var risk = h.risk || h.top_risk || '';
        var riskHtml = risk ? '<span class="risk-badge risk-' + risk.toLowerCase() + '">' + esc(risk) + '</span>' : '';
        var osVal = _cleanOS(h.os);
        var displayCount = h.port_count != null ? h.port_count : confirmedCount;
        return [
            esc(h.ip || ''),
            esc(h.hostname || ''),
            riskHtml,
            portStr,
            esc(String(displayCount || '')),
            esc((h.tools || []).join(', ')),
            esc(osVal || ''),
            esc(h.first_seen || '')
        ];
    });
    var label = 'Live Hosts (' + hosts.length + ')';
    return '<div style="margin-bottom:8px;font-weight:600">' + label + '</div>' +
        _intelTable(['IP', 'Hostname', 'Risk', 'Ports', '#Ports', 'Tools', 'OS', 'First Seen'], rows);
}

function _renderNetServices(data) {
    var payload = data.net_services || data;
    if (!payload) return _renderIntelGeneric(data);

    var svcMap = null;

    if (Array.isArray(payload)) {
        /* Plain array of host objects (e.g. targets.json) */
        svcMap = {};
        payload.filter(function(h) { return h && typeof h === 'object' && h.ip; }).forEach(function(h) {
            var ports = h.ports;
            if (!ports) return;
            var portArr = Array.isArray(ports) ? ports : Object.keys(ports).map(function(p) { var pd = ports[p]; pd.port = parseInt(p); return pd; });
            portArr.filter(_isConfirmedPort).forEach(function(p) {
                var svc = _resolveService(p.service || p.name || '', p.port);
                if (!svc) svc = 'unknown';
                svcMap[svc] = svcMap[svc] || [];
                svcMap[svc].push({ ip: h.ip, port: p.port, protocol: p.protocol || 'tcp', product: p.product || p.software || '', version: p.version || '' });
            });
        });
    } else if (typeof payload === 'object' && payload.hosts) {
        /* Build service matrix from hosts */
        svcMap = {};
        var hosts = payload.hosts;
        var hostList = Array.isArray(hosts) ? hosts : Object.keys(hosts).map(function(ip) { var h = hosts[ip]; h.ip = ip; return h; });
        hostList.forEach(function(h) {
            var ports = h.ports;
            if (!ports) return;
            var portArr = Array.isArray(ports) ? ports : Object.keys(ports).map(function(p) { var pd = ports[p]; pd.port = parseInt(p); return pd; });
            portArr.filter(_isConfirmedPort).forEach(function(p) {
                var svc = _resolveService(p.service || p.name || '', p.port);
                if (!svc) svc = 'unknown';
                svcMap[svc] = svcMap[svc] || [];
                svcMap[svc].push({ ip: h.ip, port: p.port, protocol: p.protocol || 'tcp', product: p.product || p.software || '', version: p.version || '' });
            });
        });
    } else if (typeof payload === 'object' && !Array.isArray(payload)) {
        /* Flat service map: {svcName: [{ip, port, protocol}, ...], ...} */
        svcMap = {};
        Object.keys(payload).forEach(function(svc) {
            var entries = payload[svc];
            if (!Array.isArray(entries) || !entries.length) return;
            var confirmed = entries.filter(_isConfirmedPort);
            if (!confirmed.length) return;
            var resolvedSvc = svc;
            if (confirmed[0] && (!svc || svc === 'unknown')) {
                resolvedSvc = _resolveService(svc, confirmed[0].port) || svc;
            }
            svcMap[resolvedSvc] = (svcMap[resolvedSvc] || []).concat(confirmed.map(function(e) {
                return { ip: e.ip || '', port: e.port || 0, protocol: e.protocol || 'tcp', product: e.product || e.software || '', version: e.version || '' };
            }));
        });
    }

    if (svcMap && Object.keys(svcMap).length) {
        var rows = [];
        Object.keys(svcMap).sort().forEach(function(svc) {
            svcMap[svc].forEach(function(e, i) {
                rows.push([
                    i === 0 ? '<strong>' + esc(svc) + ' (' + svcMap[svc].length + ')</strong>' : '',
                    esc(e.ip),
                    esc(String(e.port)),
                    esc(e.protocol),
                    esc(e.product + (e.version ? ' ' + e.version : ''))
                ]);
            });
        });
        return '<div style="margin-bottom:8px;font-weight:600">Service Matrix (' + Object.keys(svcMap).length + ' services)</div>' +
            _intelTable(['Service', 'IP', 'Port', 'Protocol', 'Product'], rows);
    }
    return _renderIntelGeneric(data);
}

function _renderNetSoftware(data) {
    var payload = data.net_software || data;
    if (!payload) return _renderIntelGeneric(data);
    var items = Array.isArray(payload) ? payload : (payload.items || payload._items || []);
    if (!items.length && typeof payload === 'object') {
        items = Object.values(payload).filter(function(v) { return Array.isArray(v); })[0] || [];
    }
    if (!items.length) return _renderIntelGeneric(data);
    var rows = items.map(function(s) {
        var osVal = _cleanOS(s.os);
        return [
            '<strong style="white-space:nowrap">' + esc(s.software || s.name || '') + '</strong>',
            '<span style="white-space:nowrap">' + esc(s.version || '') + '</span>',
            '<span style="white-space:nowrap;font-family:var(--font-mono)">' + esc(s.ip || '') + '</span>',
            esc(String(s.port || '')),
            '<span style="white-space:nowrap">' + esc(s.hostname || '') + '</span>',
            '<span style="white-space:nowrap">' + esc(s.method || s.source || '') + '</span>',
            '<span style="white-space:nowrap">' + esc(osVal) + '</span>'
        ];
    });
    return '<div style="margin-bottom:8px;font-weight:600">Software Inventory (' + items.length + ')</div>' +
        '<div style="overflow-x:auto;max-height:70vh;overflow-y:auto"><table class="tool-table" style="width:100%;min-width:800px"><thead><tr>' +
        '<th style="min-width:160px">Software</th><th style="min-width:80px">Version</th><th style="min-width:120px">IP</th><th>Port</th><th style="min-width:120px">Hostname</th><th style="min-width:120px">Detection</th><th style="min-width:80px">OS</th>' +
        '</tr></thead><tbody>' +
        rows.map(function(row) {
            return '<tr>' + row.map(function(cell, ci) {
                return '<td>' + (cell || '') + '</td>';
            }).join('') + '</tr>';
        }).join('') +
        '</tbody></table></div>';
}

function _renderNetRoles(data) {
    var payload = data.net_roles || data;
    if (!payload) return _renderIntelGeneric(data);
    var items = Array.isArray(payload) ? payload : (payload.items || []);
    if (!items.length) return _renderIntelGeneric(data);
    var roleCounts = {};
    items.forEach(function(r) {
        var role = r.role || 'Unknown';
        roleCounts[role] = (roleCounts[role] || 0) + 1;
    });
    var summaryCards = Object.keys(roleCounts).sort().map(function(role) {
        return '<span style="display:inline-block;padding:4px 10px;margin:2px 4px;' +
            'border-radius:4px;background:var(--accent,#4a9eff);color:#fff;' +
            'font-size:0.85em;white-space:nowrap">' +
            esc(role) + ' <strong>(' + roleCounts[role] + ')</strong></span>';
    }).join('');
    var rows = items.map(function(r) {
        return [
            '<strong style="white-space:nowrap">' + esc(r.role || '') + '</strong>',
            '<span style="white-space:nowrap;font-family:var(--font-mono)">' + esc(r.ip || '') + '</span>',
            '<span style="white-space:nowrap">' + esc(r.hostname || '') + '</span>',
            '<span style="white-space:nowrap">' + esc(r.os || '') + '</span>',
            '<span style="font-size:0.9em">' + esc(r.evidence || '') + '</span>'
        ];
    });
    return '<div style="margin-bottom:8px;font-weight:600">Server Roles (' + items.length + ' assignments across ' + Object.keys(roleCounts).length + ' role types)</div>' +
        '<div style="margin-bottom:12px">' + summaryCards + '</div>' +
        '<div style="overflow-x:auto;max-height:70vh;overflow-y:auto"><table class="tool-table" style="width:100%;min-width:800px"><thead><tr>' +
        '<th style="min-width:140px">Role</th><th style="min-width:120px">IP</th><th style="min-width:140px">Hostname</th><th style="min-width:140px">OS</th><th style="min-width:200px">Evidence</th>' +
        '</tr></thead><tbody>' +
        rows.map(function(row) {
            return '<tr>' + row.map(function(cell) {
                return '<td>' + (cell || '') + '</td>';
            }).join('') + '</tr>';
        }).join('') +
        '</tbody></table></div>';
}

function _renderNetPorts(data) {
    var payload = data.net_ports || data;
    if (!payload) return _renderIntelGeneric(data);
    var hostList = null;
    if (typeof payload === 'object' && payload.hosts) {
        var hosts = payload.hosts;
        hostList = Array.isArray(hosts) ? hosts : Object.keys(hosts).map(function(ip) { var h = hosts[ip]; h.ip = ip; return h; });
    } else if (Array.isArray(payload)) {
        hostList = payload.filter(function(h) { return h && typeof h === 'object' && h.ip; });
    }
    if (hostList && hostList.length) {
        var portMap = {};
        hostList.forEach(function(h) {
            var ports = h.ports;
            if (!ports) return;
            var portArr = Array.isArray(ports) ? ports : Object.keys(ports).map(function(p) { var pd = ports[p]; pd.port = parseInt(p); return pd; });
            var confirmed = portArr.filter(_isConfirmedPort);
            if (!confirmed.length) return;
            confirmed.forEach(function(p) {
                var pk = p.port + '/' + (p.protocol || 'tcp');
                var svc = _resolveService(p.service || '', p.port);
                portMap[pk] = portMap[pk] || { port: p.port, protocol: p.protocol || 'tcp', service: svc, hosts: [] };
                if (!portMap[pk].service && svc) portMap[pk].service = svc;
                portMap[pk].hosts.push(h.ip);
            });
        });
        var sorted = Object.values(portMap).sort(function(a, b) { return a.port - b.port; });
        if (sorted.length) {
            var rows = sorted.map(function(p) {
                return [
                    '<strong>' + esc(String(p.port)) + '</strong>',
                    esc(p.protocol),
                    esc(p.service),
                    esc(String(p.hosts.length)),
                    p.hosts.map(function(ip) { return esc(ip); }).join('<br>')
                ];
            });
            return '<div style="margin-bottom:8px;font-weight:600">Port Matrix (' + sorted.length + ' ports)</div>' +
                _intelTable(['Port', 'Protocol', 'Service', '# Hosts', 'Host IPs'], rows);
        }
    }
    return _renderIntelGeneric(data);
}

function _renderOsintDomains(data) {
    var payload = data.osint_domains || data;
    if (!payload) return _renderIntelGeneric(data);
    if (Array.isArray(payload)) {
        /* Simple subdomain list */
        if (typeof payload[0] === 'string') {
            var rows = payload.map(function(d) { return [esc(d)]; });
            return '<div style="margin-bottom:8px;font-weight:600">Discovered Subdomains (' + payload.length + ')</div>' +
                _intelTable(['Domain'], rows);
        }
        return _renderArrayTable(payload);
    }
    if (typeof payload === 'object') {
        var h = '';
        var rootDomains = {};
        if (payload.domain) rootDomains[payload.domain] = true;
        if (Array.isArray(payload.domains)) {
            payload.domains.forEach(function(d) { if (d) rootDomains[d] = true; });
        }
        if (payload.subdomains && payload.subdomains.length) {
            payload.subdomains.forEach(function(s) {
                var host = typeof s === 'string' ? s : (s.host || s.subdomain || s.domain || '');
                if (!host) return;
                var parts = host.split('.');
                if (parts.length >= 2) {
                    var root = parts.slice(-2).join('.');
                    if (root.indexOf('.') !== -1) rootDomains[root] = true;
                }
            });
        }
        var allRoots = Object.keys(rootDomains).sort();
        allRoots.forEach(function(d) {
            h += '<div style="display:inline-block;padding:6px 14px;margin:0 8px 8px 0;background:var(--clr-accent);color:#fff;border-radius:6px;font-weight:600;font-size:0.9rem">' + esc(d) + '</div>';
        });
        if (payload.company || payload.generated) {
            h += '<div style="margin-bottom:12px;color:var(--text-secondary);font-size:0.82rem">';
            if (payload.company) h += esc(payload.company);
            if (payload.company && payload.generated) h += ' · ';
            if (payload.generated) h += 'Generated: ' + esc(payload.generated);
            h += '</div>';
        }
        /* ── WHOIS / Registrar section ─────────────────────────────── */
        if (Array.isArray(payload.whois) && payload.whois.length) {
            h += '<div style="margin-top:18px;margin-bottom:10px;font-weight:700;font-size:1rem">Domain Registration</div>';
            payload.whois.forEach(function(w) {
                var privBadge = '';
                if (w.privacy_service) {
                    privBadge = '<span style="display:inline-block;padding:2px 8px;margin-left:8px;background:var(--clr-warning,#e67e22);color:#fff;border-radius:4px;font-size:0.78rem;font-weight:600">Privacy Proxy: ' + esc(w.privacy_service) + '</span>';
                }
                h += '<div style="margin-top:10px;padding:10px 14px;border:1px solid var(--border-color,#ddd);border-radius:6px;background:var(--bg-card,#fafafa)">';
                h += '<div style="font-weight:600;margin-bottom:6px">' + esc(w.domain) + privBadge + '</div>';
                h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:4px 16px;font-size:0.85rem">';
                if (w.registrar) h += '<div><span style="color:var(--text-secondary)">Registrar:</span> ' + esc(w.registrar) + '</div>';
                if (w.org) h += '<div><span style="color:var(--text-secondary)">Organization:</span> ' + esc(w.org) + '</div>';
                if (w.registrant) h += '<div><span style="color:var(--text-secondary)">Registrant:</span> ' + esc(w.registrant) + '</div>';
                if (w.creation_date) h += '<div><span style="color:var(--text-secondary)">Created:</span> ' + esc(w.creation_date) + '</div>';
                if (w.expiration_date) h += '<div><span style="color:var(--text-secondary)">Expires:</span> ' + esc(w.expiration_date) + '</div>';
                if (w.updated_date) h += '<div><span style="color:var(--text-secondary)">Updated:</span> ' + esc(w.updated_date) + '</div>';
                if (Array.isArray(w.name_servers) && w.name_servers.length) {
                    h += '<div style="grid-column:1/-1"><span style="color:var(--text-secondary)">Nameservers:</span> ' + w.name_servers.map(function(ns) { return esc(ns); }).join(', ') + '</div>';
                }
                if (Array.isArray(w.privacy_emails) && w.privacy_emails.length) {
                    h += '<div style="grid-column:1/-1"><span style="color:var(--text-secondary)">Privacy Contacts:</span> ' + w.privacy_emails.map(function(e) { return esc(e); }).join(', ') + '</div>';
                }
                h += '</div></div>';
            });
        }
        /* ── Subdomains section ────────────────────────────────────── */
        if (payload.subdomains && payload.subdomains.length) {
            var grouped = {};
            payload.subdomains.forEach(function(s) {
                var name = typeof s === 'string' ? s : (s.host || s.subdomain || s.domain || '');
                if (!name) return;
                var parts = name.split('.');
                var root = parts.length >= 2 ? parts.slice(-2).join('.') : name;
                if (!grouped[root]) grouped[root] = [];
                grouped[root].push(s);
            });
            var groupKeys = Object.keys(grouped).sort();
            groupKeys.forEach(function(root) {
                var subs = grouped[root];
                var srows = subs.map(function(s) {
                    if (typeof s === 'string') return [esc(s)];
                    var nm = s.host || s.subdomain || s.domain || '';
                    var ip = Array.isArray(s.ips) && s.ips.length ? s.ips.join(', ') : (s.ip || '');
                    var src = Array.isArray(s.sources) ? s.sources.join(', ') : (s.source || '');
                    var status = s.http_status != null ? String(s.http_status) : '';
                    var redir = s.redirect_to || (Array.isArray(s.redirects_to) && s.redirects_to.length ? s.redirects_to.join(', ') : '');
                    return [esc(nm), esc(ip), esc(src), esc(status), esc(s.first_seen || ''), esc(redir)];
                });
                var scols = typeof subs[0] === 'string' ? ['Subdomain'] : ['Subdomain', 'IP(s)', 'Sources', 'HTTP', 'First Seen', 'Redirects'];
                h += '<div style="margin-top:16px;margin-bottom:8px;font-weight:600;color:var(--clr-accent)">' + esc(root) + ' <span style="color:var(--text-secondary);font-weight:400">(' + subs.length + ' subdomains)</span></div>' + _intelTable(scols, srows);
            });
        }
        return h || _renderIntelGeneric(data);
    }
    return _renderIntelGeneric(data);
}

function _renderOsintDns(data) {
    var payload = data.osint_dns || data;
    if (!payload) return _renderIntelGeneric(data);
    if (typeof payload === 'object' && !Array.isArray(payload)) {
        var h = '';
        Object.keys(payload).sort().forEach(function(domain) {
            var records = payload[domain];
            h += '<div style="margin-bottom:16px"><div style="font-weight:600;margin-bottom:8px">' + esc(domain) + '</div>';
            if (Array.isArray(records)) {
                var rows = records.map(function(r) { return [esc(r.type || r.record_type || ''), esc(r.name || r.host || ''), esc(r.value || r.data || r.address || '')]; });
                h += _intelTable(['Type', 'Name', 'Value'], rows);
            } else if (typeof records === 'object') {
                Object.keys(records).forEach(function(rtype) {
                    var recs = records[rtype];
                    if (Array.isArray(recs)) {
                        var rows2 = recs.map(function(r) {
                            if (typeof r === 'string') return [esc(rtype), esc(r)];
                            return [esc(rtype), esc(r.host || r.name || ''), esc(r.value || r.data || r.address || JSON.stringify(r))];
                        });
                        h += _intelTable(typeof recs[0] === 'string' ? ['Type', 'Value'] : ['Type', 'Name', 'Value'], rows2);
                    }
                });
            }
            h += '</div>';
        });
        return h || _renderIntelGeneric(data);
    }
    return _renderIntelGeneric(data);
}

function _renderOsintCerts(data) {
    var payload = data.osint_certs || data;
    if (!payload) return _renderIntelGeneric(data);
    if (Array.isArray(payload)) {
        var rows = payload.map(function(c) {
            var subj = c.subject || c.common_name || c._host || '';
            var issuer = c.issuer || '';
            if (typeof subj === 'object') subj = subj.CN || subj.commonName || JSON.stringify(subj);
            if (typeof issuer === 'object') issuer = issuer.O || issuer.CN || JSON.stringify(issuer);
            var sans = c.san || c.subject_alternative_names || c.subjectAltName || [];
            if (Array.isArray(sans)) sans = sans.join(', ');
            return [
                esc(c._host || ''),
                esc(String(subj)),
                esc(String(issuer)),
                esc(c.not_before || c.notBefore || ''),
                esc(c.not_after || c.notAfter || ''),
                '<span style="max-width:200px;display:inline-block;overflow:hidden;text-overflow:ellipsis" title="' + esc(String(sans)) + '">' + esc(String(sans).substring(0, 60)) + '</span>'
            ];
        });
        return '<div style="margin-bottom:8px;font-weight:600">SSL/TLS Certificates (' + payload.length + ')</div>' +
            _intelTable(['Host', 'Subject', 'Issuer', 'Valid From', 'Valid Until', 'SANs'], rows);
    }
    return _renderIntelGeneric(data);
}

function _renderOsintEmails(data) {
    var payload = data.osint_emails || data;
    if (!payload) return _renderIntelGeneric(data);
    var emails = Array.isArray(payload) ? payload : (payload.emails || []);
    if (!emails.length) return '<div class="empty-state"><div class="empty-state-text">No email intelligence data available.</div></div>';
    var rootDomains = payload.root_domains || [];
    if (!rootDomains.length && payload.domain) rootDomains = [payload.domain];
    if (payload.domains) {
        payload.domains.forEach(function(d) {
            if (d && rootDomains.indexOf(d) === -1) rootDomains.push(d);
        });
    }
    var rootSet = {};
    rootDomains.forEach(function(d) { rootSet[d.toLowerCase()] = true; });
    function _isInScope(emailDomain) {
        var ld = emailDomain.toLowerCase();
        if (rootSet[ld]) return true;
        for (var rd in rootSet) {
            if (rootSet.hasOwnProperty(rd) && ld.length > rd.length && ld.indexOf('.' + rd) === ld.length - rd.length - 1) return true;
        }
        return false;
    }
    var inScope = {};
    var outScope = [];
    emails.forEach(function(e) {
        var email = typeof e === 'string' ? e : (e.email || '');
        if (!email) return;
        var domain = email.split('@')[1] || 'unknown';
        if (Object.keys(rootSet).length && !_isInScope(domain)) {
            outScope.push(e);
        } else {
            if (!inScope[domain]) inScope[domain] = [];
            inScope[domain].push(e);
        }
    });
    var inCount = emails.length - outScope.length;
    var h = '<div style="margin-bottom:12px;font-weight:600;font-size:1.1rem">Email Intelligence (' + inCount + ' in-scope addresses)</div>';
    var groupKeys = Object.keys(inScope).sort();
    groupKeys.forEach(function(domain) {
        var items = inScope[domain];
        h += '<div style="margin-top:16px;margin-bottom:8px;font-weight:600;color:var(--clr-accent)">' + esc(domain) + ' <span style="color:var(--text-secondary);font-weight:400">(' + items.length + ')</span></div>';
        var rows = items.map(function(e) {
            if (typeof e === 'string') return [esc(e), '', ''];
            var src = Array.isArray(e.sources) ? e.sources.join(', ') : (e.source || '');
            return [esc(e.email || ''), esc(src), esc(e.first_seen || '')];
        });
        h += _intelTable(['Email', 'Sources', 'First Seen'], rows);
    });
    if (outScope.length) {
        h += '<div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--border)">';
        h += '<div style="margin-bottom:8px;font-weight:600;color:var(--text-secondary)">Out-of-Scope (' + outScope.length + ')</div>';
        var oosRows = outScope.map(function(e) {
            if (typeof e === 'string') return [esc(e), '', ''];
            var src = Array.isArray(e.sources) ? e.sources.join(', ') : (e.source || '');
            return [esc(e.email || ''), esc(src), esc(e.first_seen || '')];
        });
        h += _intelTable(['Email', 'Sources', 'First Seen'], oosRows);
        h += '</div>';
    }
    return h;
}

function _renderOsintBreaches(data) {
    var payload = data.osint_breaches || data;
    if (!payload) return _renderIntelGeneric(data);
    var breaches = Array.isArray(payload) ? payload : (payload.breaches || payload.results || []);
    if (!breaches.length) return '<div class="empty-state"><div class="empty-state-text">No data breach intelligence available.</div></div>';
    var h = '<div style="margin-bottom:12px;font-weight:600;font-size:1.1rem">Data Breach Intelligence (' + breaches.length + ' records)</div>';
    var rows = breaches.map(function(b) {
        return [
            esc(b.email || b.username || ''),
            '<span style="font-family:var(--font-mono)">' + esc(b.database_name || b.database || b.source || '') + '</span>',
            esc(b.password || b.hashed_password ? '***' : ''),
            esc(b.date || b.breach_date || ''),
            esc(b.ip_address || '')
        ];
    });
    h += _intelTable(['Email / Username', 'Database', 'Has Credential', 'Breach Date', 'IP'], rows);
    return h;
}

function _renderProfile(data) {
    var payload = data.target_profile || data;
    if (!payload || (typeof payload === 'object' && payload.target_profile === null)) {
        return '<div class="empty-state"><div class="empty-state-text">No target profile data available. Run a scan to populate.</div></div>';
    }
    return _renderObjectCards(payload);
}

function _renderOverview(data) {
    if (!data || !Object.keys(data).length) {
        return '<div class="empty-state"><div class="empty-state-text">No intelligence data available yet. Start a scan to populate.</div></div>';
    }
    var h = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">';
    Object.keys(data).forEach(function(k) {
        if (k[0] === '_') return;
        var v = data[k];
        var count = Array.isArray(v) ? v.length : (typeof v === 'object' && v ? Object.keys(v).length : 1);
        var label = k.replace(/_/g, ' ').replace(/\b\w/g, function(l) { return l.toUpperCase(); });
        h += '<div style="padding:12px;background:var(--bg-card);border-radius:8px;border:1px solid var(--border)">' +
            '<div style="font-weight:600">' + esc(label) + '</div>' +
            '<div style="font-size:1.5rem;font-weight:700;color:var(--clr-accent)">' + count + '</div>' +
            '<div style="color:var(--text-secondary);font-size:0.8rem">' + (Array.isArray(v) ? 'entries' : 'fields') + '</div></div>';
    });
    h += '</div>';
    return h;
}

/* ── Scope-Specific Overview Dashboards ──────────────────────── */

var _SCOPE_KEY_FROM_DISPLAY = {};
Object.keys(SCOPE_DISPLAY_NAMES).forEach(function(k) { _SCOPE_KEY_FROM_DISPLAY[SCOPE_DISPLAY_NAMES[k]] = k; });

function _loadScopeOverview(body, empty) {
    var scopeKey = _activeScope;
    var _keys = Object.keys(SCOPE_DISPLAY_NAMES);
    for (var _ki = 0; _ki < _keys.length; _ki++) {
        if (SCOPE_DISPLAY_NAMES[_keys[_ki]] === _activeScope) { scopeKey = _keys[_ki]; break; }
    }
    body.innerHTML = '<div class="flex-center p-20"><div class="spinner"></div></div>';
    body.hidden = false;
    empty.style.display = 'none';
    Promise.all([
        fetch('/api/findings/v2/' + PID + '?per_page=100000', {credentials: 'same-origin'}).then(function(r) { return r.json(); }),
        fetch('/api/intel/' + PID, {credentials: 'same-origin'}).then(function(r) { return r.json(); }),
        fetch('/api/targets/' + PID, {credentials: 'same-origin'}).then(function(r) { return r.json(); })
    ]).then(function(results) {
        var fData = results[0] || {};
        var iData = results[1] || {};
        var tData = results[2] || {};
        var allFindings = fData.findings || [];
        var _scopeTools = _scopeToolsMap[_activeScope] || [];
        var scopeFindings = allFindings.filter(function(f) {
            var fs = (f.scope || '').toLowerCase();
            var ft = (f.tool || '').toLowerCase();
            var ftBase = ft.indexOf(':') !== -1 ? ft.substring(0, ft.indexOf(':')) : ft;
            if (fs === scopeKey) return true;
            if (scopeKey === 'external' && fs === 'ext') return true;
            if (scopeKey === 'internal' && fs === 'int') return true;
            if (_scopeTools.indexOf(ft) !== -1 || _scopeTools.indexOf(ftBase) !== -1) return true;
            return false;
        });
        var renderer = _SCOPE_OVERVIEW_RENDERERS[scopeKey] || _renderGenericScopeOverview;
        body.innerHTML = renderer(scopeFindings, iData, fData.summary || {}, scopeKey, tData);
    }).catch(function() {
        body.innerHTML = '<div class="empty-state"><div class="empty-state-text">Failed to load overview data.</div></div>';
    });
}

function _ovCard(label, value, subtitle, color) {
    var c = color || 'var(--clr-accent)';
    return '<div style="padding:16px;background:var(--bg-card);border-radius:8px;border:1px solid var(--border);border-left:3px solid ' + c + ';text-align:center">' +
        '<div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-secondary);margin-bottom:4px">' + esc(label) + '</div>' +
        '<div style="font-size:2rem;font-weight:700;color:' + c + '">' + value + '</div>' +
        (subtitle ? '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px">' + subtitle + '</div>' : '') +
        '</div>';
}

function _ovRiskBar(findings) {
    var counts = {critical:0, high:0, medium:0, low:0, info:0};
    findings.forEach(function(f) { var r = (f.risk||'info').toLowerCase(); if (counts[r] !== undefined) counts[r]++; });
    var total = findings.length || 1;
    var h = '<div style="display:flex;height:28px;border-radius:6px;overflow:hidden;margin-bottom:16px">';
    [['critical','var(--clr-critical)','C'],['high','var(--clr-high)','H'],['medium','var(--clr-medium)','M'],['low','var(--clr-low)','L'],['info','var(--clr-info)','I']].forEach(function(p) {
        var pct = (counts[p[0]] / total * 100);
        if (pct > 0) {
            var lbl = pct > 15 ? p[0].toUpperCase() + ' ' + counts[p[0]] : pct > 5 ? p[2] + counts[p[0]] : '' + counts[p[0]];
            h += '<div style="width:' + pct + '%;background:' + p[1] + ';display:flex;align-items:center;justify-content:center;color:#fff;font-size:0.7rem;font-weight:600" title="' + p[0].toUpperCase() + ': ' + counts[p[0]] + '">' + lbl + '</div>';
        }
    });
    h += '</div>';
    h += '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">';
    [['Critical','critical','var(--clr-critical)'],['High','high','var(--clr-high)'],['Medium','medium','var(--clr-medium)'],['Low','low','var(--clr-low)'],['Info','info','var(--clr-info)']].forEach(function(p) {
        h += '<span style="font-size:0.8rem"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + p[2] + ';margin-right:4px"></span>' + p[0] + ': <strong>' + counts[p[1]] + '</strong></span>';
    });
    h += '</div>';
    return h;
}

function _ovTopList(title, items, max, barColor) {
    if (!items.length) return '';
    var top = items.slice(0, max || 10);
    var bc = barColor || 'var(--clr-accent)';
    var h = '<div style="margin-top:16px"><div style="font-weight:600;margin-bottom:8px;color:' + bc + '">' + esc(title) + '</div>';
    h += '<div style="display:flex;flex-direction:column;gap:4px">';
    top.forEach(function(item) {
        var pct = (item.count / (items[0].count || 1) * 100);
        h += '<div style="display:flex;align-items:center;gap:8px">' +
            '<div style="flex:0 0 180px;font-size:0.8rem;font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(item.label) + '">' + esc(item.label) + '</div>' +
            '<div style="flex:1;height:16px;background:var(--bg-alt);border-radius:4px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:' + bc + ';border-radius:4px"></div></div>' +
            '<div style="flex:0 0 30px;text-align:right;font-size:0.8rem;font-weight:600">' + item.count + '</div></div>';
    });
    h += '</div></div>';
    return h;
}

function _countBy(findings, field) {
    var map = {};
    findings.forEach(function(f) {
        var v = f[field];
        if (!v) return;
        if (Array.isArray(v)) { v.forEach(function(vv) { if (vv) map[vv] = (map[vv]||0)+1; }); }
        else { map[v] = (map[v]||0) + 1; }
    });
    return Object.keys(map).map(function(k) { return {label: k, count: map[k]}; }).sort(function(a,b) { return b.count - a.count; });
}

function _countByFn(findings, fn) {
    var map = {};
    findings.forEach(function(f) {
        var v = fn(f);
        if (!v) return;
        map[v] = (map[v]||0) + 1;
    });
    return Object.keys(map).map(function(k) { return {label: k, count: map[k]}; }).sort(function(a,b) { return b.count - a.count; });
}

function _renderExternalOverview(findings, intel, summary, scopeKey, tData) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem;color:var(--clr-high)">External Attack Surface Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">High-level posture analysis for the external scope</div></div>';
    h += _ovRiskBar(findings);
    var liveIPs = 0; var totalPorts = 0; var uniqueServices = {};
    var netHosts = (tData && tData.targets && tData.targets.network) || [];
    netHosts.forEach(function(host) {
        if (!host.ip) return;
        var hs = (host.scope || '').toLowerCase();
        if (hs !== 'external' && hs !== 'ext') return;
        liveIPs++;
        var ports = (host.ports || []).filter(_isConfirmedPort);
        totalPorts += ports.length;
        ports.forEach(function(p) {
            var svc = (typeof p === 'object') ? (p.service || p.name || '') : '';
            if (svc && svc !== '—') uniqueServices[svc] = true;
        });
    });
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    h += _ovCard('Live IPs', liveIPs, 'hosts alive', 'var(--clr-hosts)');
    h += _ovCard('Open Ports', totalPorts, 'exposed ports', 'var(--clr-ports)');
    h += _ovCard('Services', Object.keys(uniqueServices).length, 'distinct types', 'var(--clr-services)');
    var sslFindings = findings.filter(function(f) { return (f.title||'').toLowerCase().indexOf('ssl') !== -1 || (f.title||'').toLowerCase().indexOf('tls') !== -1 || (f.title||'').toLowerCase().indexOf('certificate') !== -1; });
    h += _ovCard('SSL/TLS Issues', sslFindings.length, 'certificate & protocol', 'var(--clr-medium)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Top Affected Hosts', _countBy(findings, 'ip'), 10, 'var(--clr-hosts)') + '</div>';
    h += '<div>' + _ovTopList('Top Finding Categories', _countByFn(findings, _findingCategory), 10, 'var(--clr-high)') + '</div>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Exposed Services', _countByFn(findings, function(f){ return _resolveService(f.service || '', f.port) || ''; }), 10, 'var(--clr-services)') + '</div>';
    h += '<div>' + _ovTopList('Ports with Findings', _countBy(findings.filter(function(f){return f.port && f.port !== 0;}), 'port'), 10, 'var(--clr-ports)') + '</div>';
    h += '</div>';
    var headerFindings = findings.filter(function(f) { return (f.title||'').toLowerCase().indexOf('header') !== -1; });
    if (headerFindings.length) {
        h += '<div style="margin-top:20px">' + _ovTopList('Missing Security Headers', _countBy(headerFindings, 'title'), 10, 'var(--clr-medium)') + '</div>';
    }
    return h;
}

function _renderInternalOverview(findings, intel, summary, scopeKey, tData) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem;color:var(--clr-medium)">Internal Network Posture Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Security posture analysis for the internal network scope</div></div>';
    h += _ovRiskBar(findings);
    var liveIPs = 0; var totalPorts = 0; var uniqueServices = {};
    var netHosts = (tData && tData.targets && tData.targets.network) || [];
    netHosts.forEach(function(host) {
        if (!host.ip) return;
        var hs = (host.scope || '').toLowerCase();
        if (hs !== 'internal' && hs !== 'int') return;
        liveIPs++;
        var ports = (host.ports || []).filter(_isConfirmedPort);
        totalPorts += ports.length;
        ports.forEach(function(p) {
            var svc = (typeof p === 'object') ? (p.service || p.name || '') : '';
            if (svc && svc !== '—') uniqueServices[svc] = true;
        });
    });
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    h += _ovCard('Live IPs', liveIPs, 'hosts alive', 'var(--clr-hosts)');
    h += _ovCard('Open Ports', totalPorts, 'exposed ports', 'var(--clr-ports)');
    h += _ovCard('Services', Object.keys(uniqueServices).length, 'distinct types', 'var(--clr-services)');
    var smbFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('smb') !== -1 || (f.service||'').toLowerCase() === 'smb'; });
    h += _ovCard('SMB Issues', smbFindings.length, 'file sharing', 'var(--clr-high)');
    var rdpFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('rdp') !== -1 || f.port === 3389; });
    h += _ovCard('RDP Findings', rdpFindings.length, 'remote desktop', 'var(--clr-medium)');
    var sshFindings = findings.filter(function(f) { return f.port === 22 || (f.service||'').toLowerCase() === 'ssh'; });
    h += _ovCard('SSH Findings', sshFindings.length, 'secure shell', 'var(--clr-low)');
    var snmpFindings = findings.filter(function(f) { return (f.title||'').toLowerCase().indexOf('snmp') !== -1 || f.port === 161; });
    h += _ovCard('SNMP Issues', snmpFindings.length, 'network mgmt', 'var(--clr-medium)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Top Affected Hosts', _countBy(findings, 'ip'), 10, 'var(--clr-hosts)') + '</div>';
    h += '<div>' + _ovTopList('Top Finding Categories', _countByFn(findings, _findingCategory), 10, 'var(--clr-high)') + '</div>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Services Distribution', _countByFn(findings, function(f){ return _resolveService(f.service || '', f.port) || ''; }), 10, 'var(--clr-services)') + '</div>';
    h += '<div>' + _ovTopList('Port Distribution', _countBy(findings.filter(function(f){return f.port && f.port !== 0;}), 'port'), 10, 'var(--clr-ports)') + '</div>';
    h += '</div>';
    return h;
}

function _renderOsintOverview(findings, intel, summary, scopeKey, tData) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem;color:var(--clr-accent)">OSINT Intelligence Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Open-source intelligence gathering results</div></div>';
    h += _ovRiskBar(findings);
    var osint = intel.osint_targets || {};
    var scopeDomains = {};
    var primary = osint.domain || '';
    if (primary) scopeDomains[primary] = true;
    var domArr = osint.domains || [];
    domArr.forEach(function(d) {
        var name = typeof d === 'string' ? d : (d.domain || d.name || '');
        if (name) scopeDomains[name] = true;
    });
    var scopeDomainCount = Object.keys(scopeDomains).length;
    var subdomainArr = osint.subdomains || [];
    var subdomainCount = Array.isArray(subdomainArr) ? subdomainArr.length : Object.keys(subdomainArr).length;
    var emailArr = osint.emails || [];
    var emailCount = Array.isArray(emailArr) ? emailArr.length : Object.keys(emailArr).length;
    var breachArr = intel.osint_breaches || [];
    var breachCount = Array.isArray(breachArr) ? breachArr.length : 0;
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    h += _ovCard('Scope Domains', scopeDomainCount, scopeDomainCount === 1 ? '1 root domain' : scopeDomainCount + ' root domains', 'var(--clr-hosts)');
    h += _ovCard('Subdomains Identified', subdomainCount, 'discovered subdomains', 'var(--clr-accent)');
    h += _ovCard('Emails Identified', emailCount, 'email addresses found', 'var(--clr-sources)');
    var toolSourceMap = {};
    findings.forEach(function(f) {
        var src = f.sources || f.tool || '';
        if (typeof src === 'string') {
            src.split(/[,\n]/).forEach(function(s) {
                s = s.trim();
                if (s) toolSourceMap[s] = (toolSourceMap[s] || 0) + 1;
            });
        }
    });
    var toolSourceCount = Object.keys(toolSourceMap).length;
    h += _ovCard('Data Sources', toolSourceCount, toolSourceCount === 1 ? '1 tool contributed' : toolSourceCount + ' tools contributed', 'var(--clr-sources)');
    var dnsFindings = findings.filter(function(f) { return (f.title||'').toLowerCase().indexOf('dns') !== -1; });
    h += _ovCard('DNS Issues', dnsFindings.length, '', 'var(--clr-medium)');
    var certFindings = findings.filter(function(f) { return (f.title||'').toLowerCase().indexOf('cert') !== -1 || (f.title||'').toLowerCase().indexOf('ssl') !== -1 || (f.title||'').toLowerCase().indexOf('tls') !== -1; });
    h += _ovCard('Certificate Issues', certFindings.length, '', 'var(--clr-ports)');
    h += _ovCard('Leaked Creds', breachCount, breachCount === 1 ? '1 credential exposed' : breachCount + ' credentials exposed', 'var(--clr-critical)');
    var secretFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('secret') !== -1 || t.indexOf('api key') !== -1 || t.indexOf('gitdorker') !== -1 || t.indexOf('trufflehog') !== -1 || t.indexOf('exposed key') !== -1 || t.indexOf('exposed credential') !== -1; });
    h += _ovCard('Secrets Found', secretFindings.length, secretFindings.length === 1 ? '1 secret exposed' : 'keys / tokens / credentials', 'var(--clr-high)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Top Finding Categories', _countByFn(findings, _findingCategory), 10, 'var(--clr-high)') + '</div>';
    var hostList = _countByFn(findings, function(f) { return f.hostname || f.ip || ''; });
    h += '<div>' + _ovTopList('Affected Hosts/Domains', hostList, 10, 'var(--clr-hosts)') + '</div>';
    h += '</div>';
    var toolSourceItems = Object.keys(toolSourceMap).map(function(k) { return {label: k, count: toolSourceMap[k]}; }).sort(function(a,b) { return b.count - a.count; });
    if (toolSourceItems.length > 1) {
        h += _ovTopList('Data Sources', toolSourceItems, 10, 'var(--clr-sources)');
    }
    return h;
}

function _renderWebappOverview(findings, intel, summary) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">Web Application Security Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Vulnerability assessment for web application targets</div></div>';
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var owaspFindings = _countBy(findings.filter(function(f){return f.owasp;}), 'owasp');
    h += _ovCard('OWASP Categories', owaspFindings.length, 'distinct categories', 'var(--clr-sources)');
    var injections = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('inject') !== -1 || t.indexOf('sqli') !== -1 || t.indexOf('xss') !== -1 || t.indexOf('command') !== -1; });
    h += _ovCard('Injection Flaws', injections.length, 'SQLi / XSS / Cmd', (injections.length > 0 ? 'var(--clr-critical)' : 'var(--clr-accent)'));
    var authIssues = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('auth') !== -1 || t.indexOf('session') !== -1 || t.indexOf('cookie') !== -1 || t.indexOf('csrf') !== -1; });
    h += _ovCard('Auth/Session Issues', authIssues.length, '', 'var(--clr-high)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    if (owaspFindings.length) h += '<div>' + _ovTopList('OWASP Top 10 Distribution', owaspFindings, 10) + '</div>';
    h += '<div>' + _ovTopList('Top Vulnerability Types', _countBy(findings, 'title'), 10) + '</div>';
    h += '</div>';
    return h;
}

function _renderApiOverview(findings, intel, summary) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">API Security Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">API penetration testing results and endpoint analysis</div></div>';
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var authIssues = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('auth') !== -1 || t.indexOf('token') !== -1 || t.indexOf('api key') !== -1 || t.indexOf('jwt') !== -1; });
    h += _ovCard('Auth Issues', authIssues.length, 'API auth flaws', 'var(--clr-high)');
    var dataExposure = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('expos') !== -1 || t.indexOf('leak') !== -1 || t.indexOf('sensitive') !== -1 || t.indexOf('pii') !== -1; });
    h += _ovCard('Data Exposure', dataExposure.length, 'info leakage', 'var(--clr-high)');
    var rateLimiting = findings.filter(function(f) { return (f.title||'').toLowerCase().indexOf('rate') !== -1; });
    h += _ovCard('Rate Limiting', rateLimiting.length, '', 'var(--clr-medium)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Top Vulnerability Types', _countBy(findings, 'title'), 10) + '</div>';
    var endpoints = _countBy(findings.filter(function(f){return f.hostname || f.ip;}), 'hostname');
    if (!endpoints.length) endpoints = _countBy(findings, 'ip');
    h += '<div>' + _ovTopList('Affected Endpoints', endpoints, 10) + '</div>';
    h += '</div>';
    return h;
}

function _renderGenericScopeOverview(findings, intel, summary, scopeKey) {
    var scopeName = SCOPE_DISPLAY_NAMES[scopeKey] || scopeKey;
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">' + esc(scopeName) + ' Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Security assessment results for the ' + esc(scopeName.toLowerCase()) + ' scope</div></div>';
    if (!findings.length) {
        return h + '<div class="empty-state"><div class="empty-state-text">No findings for this scope yet. Start a scan to populate.</div></div>';
    }
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var uniqueTargets = {}; findings.forEach(function(f) { if (f.ip || f.hostname) uniqueTargets[f.ip || f.hostname] = true; });
    h += _ovCard('Targets Affected', Object.keys(uniqueTargets).length, '', 'var(--clr-hosts)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Top Finding Categories', _countByFn(findings, _findingCategory), 10) + '</div>';
    h += '<div>' + _ovTopList('Affected Targets', _countBy(findings, 'ip'), 10) + '</div>';
    h += '</div>';
    return h;
}

function _renderDatabaseOverview(findings, intel, summary) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">Database Security Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Database access, privilege, and configuration assessment</div></div>';
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var privFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('priv') !== -1 || t.indexOf('grant') !== -1 || t.indexOf('permission') !== -1; });
    h += _ovCard('Privilege Issues', privFindings.length, 'access control', 'var(--clr-high)');
    var configFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('config') !== -1 || t.indexOf('default') !== -1 || t.indexOf('audit') !== -1; });
    h += _ovCard('Config Issues', configFindings.length, 'hardening gaps', 'var(--clr-medium)');
    var authFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('auth') !== -1 || t.indexOf('password') !== -1 || t.indexOf('credential') !== -1; });
    h += _ovCard('Auth Findings', authFindings.length, 'credentials / access', 'var(--clr-high)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Top Finding Categories', _countByFn(findings, _findingCategory), 10) + '</div>';
    h += '<div>' + _ovTopList('Affected Targets', _countBy(findings, 'ip'), 10) + '</div>';
    h += '</div>';
    return h;
}

function _renderFirewallOverview(findings, intel, summary) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">Firewall Configuration Analysis Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Rule analysis, compliance, and policy assessment</div></div>';
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var ruleFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('rule') !== -1 || t.indexOf('acl') !== -1 || t.indexOf('policy') !== -1; });
    h += _ovCard('Rule Issues', ruleFindings.length, 'ACL / policy', 'var(--clr-high)');
    var complianceFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('compliance') !== -1 || t.indexOf('benchmark') !== -1 || t.indexOf('cis') !== -1; });
    h += _ovCard('Compliance Gaps', complianceFindings.length, 'benchmark deviations', 'var(--clr-medium)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Finding Categories', _countBy(findings, 'title'), 10) + '</div>';
    h += '</div>';
    return h;
}

function _renderCloudOverview(findings, intel, summary) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">Cloud Infrastructure Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Cloud resource configuration and access assessment</div></div>';
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var iamFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('iam') !== -1 || t.indexOf('role') !== -1 || t.indexOf('policy') !== -1 || t.indexOf('permission') !== -1; });
    h += _ovCard('IAM Issues', iamFindings.length, 'identity & access', 'var(--clr-high)');
    var storageFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('bucket') !== -1 || t.indexOf('storage') !== -1 || t.indexOf('blob') !== -1 || t.indexOf('s3') !== -1; });
    h += _ovCard('Storage Issues', storageFindings.length, 'data exposure', 'var(--clr-high)');
    var encryptFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('encrypt') !== -1 || t.indexOf('kms') !== -1; });
    h += _ovCard('Encryption Gaps', encryptFindings.length, '', 'var(--clr-medium)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Finding Categories', _countBy(findings, 'title'), 10) + '</div>';
    h += '<div>' + _ovTopList('Affected Resources', _countBy(findings, 'ip'), 10) + '</div>';
    h += '</div>';
    return h;
}

function _renderMobileOverview(findings, intel, summary) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">Mobile Application Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Mobile app binary analysis and runtime testing results</div></div>';

    if (!findings.length) {
        return h + '<div class="empty-state"><div class="empty-state-text">No findings for mobile scope yet. Start a Quill scan to populate.</div></div>';
    }

    h += _ovRiskBar(findings);

    var appMap = {};
    var iosCount = 0, androidCount = 0;
    findings.forEach(function(f) {
        var target = f.hostname || f.affected || '';
        if (!target) return;
        if (!appMap[target]) appMap[target] = {ios: false, android: false, count: 0};
        appMap[target].count++;
        var tl = target.toLowerCase();
        if (tl.indexOf('.ipa') !== -1) { appMap[target].ios = true; iosCount++; }
        else if (tl.indexOf('.apk') !== -1 || tl.indexOf('.aab') !== -1 || tl.indexOf('.xapk') !== -1) { appMap[target].android = true; androidCount++; }
    });
    var appCount = Object.keys(appMap).length;

    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    h += _ovCard('Applications', appCount, (iosCount > 0 ? 'iOS' : '') + (iosCount > 0 && androidCount > 0 ? ' + ' : '') + (androidCount > 0 ? 'Android' : ''), 'var(--clr-hosts)');

    var dataFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('data') !== -1 || t.indexOf('storage') !== -1 || t.indexOf('keychain') !== -1 || t.indexOf('shared_prefs') !== -1; });
    h += _ovCard('Data Storage', dataFindings.length, 'insecure storage', 'var(--clr-high)');
    var cryptoFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('crypto') !== -1 || t.indexOf('encrypt') !== -1 || t.indexOf('obfuscat') !== -1; });
    h += _ovCard('Crypto Issues', cryptoFindings.length, 'weak crypto', 'var(--clr-medium)');
    var permFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('permission') !== -1 || t.indexOf('privilege') !== -1; });
    h += _ovCard('Permissions', permFindings.length, 'excessive access', 'var(--clr-medium)');
    h += '</div>';

    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Finding Categories', _countByFn(findings, _findingCategory), 10) + '</div>';
    var appList = _countByFn(findings, function(f) { return f.hostname || f.affected || ''; });
    h += '<div>' + _ovTopList('Affected Applications', appList, 10, 'var(--clr-hosts)') + '</div>';
    h += '</div>';
    return h;
}

function _renderWirelessOverview(findings, intel, summary, scopeKey) {
    var labels = {wifi:'Wi-Fi (802.11)', bluetooth:'Bluetooth', zigbee:'Zigbee (802.15.4)', uwb:'UWB (802.15.4z)'};
    var label = labels[scopeKey] || SCOPE_DISPLAY_NAMES[scopeKey] || scopeKey;
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">' + esc(label) + ' Assessment Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Wireless security assessment results</div></div>';
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var networks = {}; findings.forEach(function(f) { if (f.ssid || f.bssid) networks[f.ssid || f.bssid] = true; });
    h += _ovCard('Networks', Object.keys(networks).length || '—', 'detected', 'var(--clr-accent)');
    var authFindings = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('wep') !== -1 || t.indexOf('wpa') !== -1 || t.indexOf('open') !== -1 || t.indexOf('auth') !== -1; });
    h += _ovCard('Auth Issues', authFindings.length, 'weak encryption/auth', 'var(--clr-high)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Finding Categories', _countBy(findings, 'title'), 10) + '</div>';
    h += '</div>';
    return h;
}

function _renderPcapOverview(findings, intel, summary) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">Traffic Analysis Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Network capture analysis and protocol inspection</div></div>';
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var cleartext = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('cleartext') !== -1 || t.indexOf('unencrypted') !== -1 || t.indexOf('plain') !== -1; });
    h += _ovCard('Cleartext Issues', cleartext.length, 'unencrypted data', 'var(--clr-critical)');
    var protocols = {}; findings.forEach(function(f) { if (f.service) protocols[f.service] = true; });
    h += _ovCard('Protocols', Object.keys(protocols).length, 'distinct protocols', 'var(--clr-accent)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Finding Categories', _countBy(findings, 'title'), 10) + '</div>';
    h += '</div>';
    return h;
}

function _renderFileOverview(findings, intel, summary) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">File Analysis Overview</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Static file analysis, entropy, secrets detection, and IOC matching</div></div>';
    h += _ovRiskBar(findings);
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">';
    h += _ovCard('Total Findings', findings.length, '', 'var(--clr-accent)');
    var crit = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'critical'; }).length;
    var high = findings.filter(function(f) { return (f.risk||'').toLowerCase() === 'high'; }).length;
    h += _ovCard('Critical + High', crit + high, crit + ' critical / ' + high + ' high', (crit > 0 ? 'var(--clr-critical)' : high > 0 ? 'var(--clr-high)' : 'var(--clr-accent)'));
    var secrets = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('secret') !== -1 || t.indexOf('credential') !== -1 || t.indexOf('key') !== -1 || t.indexOf('token') !== -1; });
    h += _ovCard('Secrets Found', secrets.length, 'credentials / keys', 'var(--clr-critical)');
    var iocs = findings.filter(function(f) { var t = (f.title||'').toLowerCase(); return t.indexOf('ioc') !== -1 || t.indexOf('malware') !== -1 || t.indexOf('indicator') !== -1; });
    h += _ovCard('IOC Matches', iocs.length, 'indicators of compromise', 'var(--clr-high)');
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px">';
    h += '<div>' + _ovTopList('Finding Categories', _countBy(findings, 'title'), 10) + '</div>';
    h += '</div>';
    return h;
}

/* ── Screenshots Tab ───────────────────────────────────────────────── */
function _loadScreenshotsPanel(body, empty, tool) {
    var scopeKey = _activeScope;
    var _keys = Object.keys(SCOPE_DISPLAY_NAMES);
    for (var _ki = 0; _ki < _keys.length; _ki++) {
        if (SCOPE_DISPLAY_NAMES[_keys[_ki]] === _activeScope) { scopeKey = _keys[_ki]; break; }
    }
    body.innerHTML = '<div class="flex-center p-20"><div class="spinner"></div></div>';
    body.hidden = false;
    empty.style.display = 'none';
    var ssUrl = '/api/screenshots/' + PID + '?scope=' + encodeURIComponent(scopeKey);
    if (tool) ssUrl += '&tool=' + encodeURIComponent(tool);
    fetch(ssUrl, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var items = data.screenshots || [];
            if (!items.length) {
                body.innerHTML = '<div class="empty-state"><div class="empty-state-text">No screenshots available for this scope.</div></div>';
                return;
            }
            var h = '<div style="margin-bottom:16px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">Screenshots <span style="font-weight:400;color:var(--text-secondary);font-size:0.85rem">(' + items.length + ')</span></h3>' +
                '<div style="color:var(--text-secondary);font-size:0.85rem">Click a row to view the screenshot</div></div>';
            var _isWebApp = (scopeKey === 'webapp' || tool === 'fracture');
            var _ipHeader = _isWebApp ? 'Base URL' : 'IP';
            h += '<div style="overflow-x:auto"><table class="data-table" style="width:100%"><thead><tr>' +
                '<th style="width:40px">#</th>' +
                '<th>URL</th>' +
                '<th>' + _ipHeader + '</th>' +
                '<th style="width:60px">Port</th>' +
                '<th>Page Title</th>' +
                '<th>Server</th>' +
                '<th style="width:60px">Status</th>' +
                '<th>Classification</th>' +
                '</tr></thead><tbody>';
            for (var i = 0; i < items.length; i++) {
                var s = items[i];
                var descClass = '';
                var dl = (s.description || '').toLowerCase();
                if (dl.indexOf('login') !== -1 || dl.indexOf('dashboard') !== -1) descClass = ' style="color:var(--clr-high);font-weight:600"';
                else if (dl.indexOf('default') !== -1 || dl.indexOf('blank') !== -1) descClass = ' style="color:var(--text-secondary)"';
                else if (dl.indexOf('directory') !== -1 || dl.indexOf('error') !== -1) descClass = ' style="color:var(--clr-medium)"';
                else if (dl.indexOf('restricted') !== -1 || dl.indexOf('admin') !== -1) descClass = ' style="color:var(--clr-critical)"';
                else if (dl.indexOf('landing') !== -1 || dl.indexOf('interesting') !== -1) descClass = ' style="color:var(--clr-info);font-weight:600"';
                var _sUrl = (s.url || '').split(/[\r\n]/)[0].trim();
                var _ipCell = _isWebApp ? (_sUrl ? _sUrl.replace(/^https?:\/\//, '').replace(/\/.*$/, '') : esc(s.ip)) : esc(s.ip);
                h += '<tr style="cursor:pointer" data-ss-path="' + esc(s.screenshot_path) + '" data-ss-url="' + esc(_sUrl) + '" data-ss-desc="' + esc((s.description || '').replace(/[\r\n]+/g, ' ')) + '" data-ss-ip="' + esc(s.ip) + '" data-ss-port="' + s.port + '" data-ss-server="' + esc(s.server || '') + '">' +
                    '<td>' + (i + 1) + '</td>' +
                    '<td style="font-family:var(--font-mono);font-size:0.8rem;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(_sUrl) + '">' + esc(_sUrl) + '</td>' +
                    '<td style="font-family:var(--font-mono);font-size:0.85rem">' + esc(_ipCell) + '</td>' +
                    '<td>' + s.port + '</td>' +
                    '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(s.title || '') + '">' + esc(s.title || '—') + '</td>' +
                    '<td style="font-size:0.85rem">' + esc(s.server || '—') + '</td>' +
                    '<td>' + (s.status_code || '—') + '</td>' +
                    '<td' + descClass + '>' + esc(s.description) + '</td>' +
                    '</tr>';
            }
            h += '</tbody></table></div>';
            body.innerHTML = h;
            body.querySelectorAll('tr[data-ss-path]').forEach(function(tr) {
                tr.addEventListener('click', function() {
                    _openScreenshot(
                        tr.getAttribute('data-ss-path'),
                        tr.getAttribute('data-ss-url'),
                        tr.getAttribute('data-ss-desc'),
                        tr.getAttribute('data-ss-ip'),
                        parseInt(tr.getAttribute('data-ss-port'), 10) || 0,
                        tr.getAttribute('data-ss-server')
                    );
                });
            });
        })
        .catch(function() {
            body.innerHTML = '<div class="empty-state"><div class="empty-state-text">Failed to load screenshots.</div></div>';
        });
}

function _openScreenshot(path, url, description, ip, port, server) {
    var imgUrl = '/api/file_serve/' + PID + '?path=' + encodeURIComponent(path);
    var modal = document.getElementById('screenshotModal');
    var img = document.getElementById('screenshotModalImg');
    var title = document.getElementById('screenshotModalTitle');
    var meta = document.getElementById('screenshotModalMeta');
    title.textContent = url;
    img.src = imgUrl;
    var metaParts = [description];
    if (ip && port) metaParts.push(ip + ':' + port);
    if (server) metaParts.push(server);
    meta.textContent = metaParts.join('  •  ');
    modal.classList.add('open');
}

var _SCOPE_OVERVIEW_RENDERERS = {
    'external': _renderExternalOverview,
    'internal': _renderInternalOverview,
    'osint': _renderOsintOverview,
    'webapp': _renderWebappOverview,
    'api': _renderApiOverview,
    'database': _renderDatabaseOverview,
    'firewall': _renderFirewallOverview,
    'cloud': _renderCloudOverview,
    'mobile': _renderMobileOverview,
    'wifi': _renderWirelessOverview,
    'bluetooth': _renderWirelessOverview,
    'zigbee': _renderWirelessOverview,
    'uwb': _renderWirelessOverview,
    'pcap': _renderPcapOverview,
    'file': _renderFileOverview
};

/* ── Structure Map Renderer (Fracture tree + Siphon API tree) ── */
function _renderFrStructureSingle(pathsObj) {
    var root = { _info: pathsObj['/'] || {}, _children: {} };
    for (var path in pathsObj) {
        if (path === '/' || path[0] === '_') continue;
        var parts = path.replace(/^\//, '').split('/').filter(function(p) { return p !== ''; });
        var node = root._children;
        for (var i = 0; i < parts.length; i++) {
            var part = parts[i];
            if (!node[part]) node[part] = { _info: {}, _children: {} };
            if (i === parts.length - 1) node[part]._info = pathsObj[path];
            node = node[part]._children;
        }
    }
    var ri = root._info;
    var rs = ri.status || '';
    var rsCls = !rs ? '' : rs < 300 ? 'struct-ok' : rs < 400 ? 'struct-redir' : 'struct-err';
    var rGrayed = rs && rs >= 300 ? ' struct-grayed' : '';
    var rRedir = ri.redirect_to ? '<span class="struct-redirect">→ ' + esc(ri.redirect_to) + '</span>' : '';
    var html = '<div class="struct-tree">';
    html += '<div class="struct-row' + rGrayed + '">';
    html += '<span class="struct-icon">📁</span>';
    html += '<span class="struct-path">/</span>';
    if (rs) html += '<span class="struct-status ' + rsCls + '">' + rs + '</span>';
    html += rRedir;
    html += '</div>';
    if (Object.keys(root._children).length > 0) {
        html += '<div class="struct-children">' + _renderFrStructureNode(root._children, '/') + '</div>';
    }
    html += '</div>';
    return html;
}

function _renderFrStructureTree(frMap) {
    if (!frMap) return '<div style="color:var(--text-muted);font-size:.85rem">Empty structure map.</div>';
    if (frMap.paths && Object.keys(frMap.paths).length > 0) {
        return _renderFrStructureSingle(frMap.paths);
    }
    var targetKeys = Object.keys(frMap).filter(function(k) { return k[0] !== '_'; });
    var html = '';
    var count = 0;
    for (var ti = 0; ti < targetKeys.length; ti++) {
        var target = targetKeys[ti];
        var td = frMap[target];
        if (!td || typeof td !== 'object') continue;
        var paths = td.paths || {};
        if (!Object.keys(paths).length) continue;
        count++;
        html += '<div style="margin-bottom:1.5rem">';
        html += '<div style="font-weight:600;margin-bottom:6px;font-size:.85rem;padding:5px 10px;background:var(--bg-card);border-radius:6px;border:1px solid var(--border)">';
        html += esc(target) + ' <span style="color:var(--text-muted);font-weight:400">(' + Object.keys(paths).length + ' paths)</span></div>';
        html += _renderFrStructureSingle(paths);
        html += '</div>';
    }
    if (count) return html;
    return '<div style="color:var(--text-muted);font-size:.85rem">Empty structure map.</div>';
}

function _renderFrStructureNode(node, prefix) {
    var html = '';
    var keys = Object.keys(node).sort();
    for (var ki = 0; ki < keys.length; ki++) {
        var name = keys[ki];
        var data = node[name];
        var info = data._info || {};
        var path = prefix === '/' ? '/' + name : prefix + '/' + name;
        var status = info.status || '';
        var authOnly = info.auth_only ? '<span class="struct-auth-tag" title="Only accessible when authenticated">🔒 ' + esc((info.auth_users || []).join(', ')) + '</span>' : '';
        var statusCls = !status ? '' : status < 300 ? 'struct-ok' : status < 400 ? 'struct-redir' : 'struct-err';
        var isDir = Object.keys(data._children).length > 0;
        var icon = isDir ? '📁' : '📄';
        var grayed = status && status >= 300 ? ' struct-grayed' : '';
        var redirectTo = info.redirect_to || '';
        var redirectTag = redirectTo ? '<span class="struct-redirect">→ ' + esc(redirectTo) + '</span>' : '';
        var sourceTag = info.source ? '<span class="struct-source-tag">' + esc(info.source) + '</span>' : '';
        html += '<div class="struct-row' + grayed + '">';
        html += '<span class="struct-icon">' + icon + '</span>';
        html += '<span class="struct-path">' + esc(isDir ? name + '/' : name) + '</span>';
        if (status) html += '<span class="struct-status ' + statusCls + '">' + status + '</span>';
        html += redirectTag;
        html += sourceTag;
        html += authOnly;
        html += '</div>';
        if (isDir) {
            html += '<div class="struct-children">' + _renderFrStructureNode(data._children, path) + '</div>';
        }
    }
    return html;
}

function _renderApiStructureTree(apiMap) {
    if (!apiMap || Object.keys(apiMap).length === 0) {
        return '<div style="color:var(--text-muted);font-size:.85rem">Empty API map.</div>';
    }
    var html = '<div style="font-weight:600;margin-bottom:8px;font-size:.9rem">API Endpoints</div>';
    html += '<div class="struct-tree">';
    for (var path in apiMap) {
        var info = apiMap[path];
        var isRogue = info.rogue;
        var fromSpec = info.from_spec;
        var methods = info.methods || {};
        var rogueTag = isRogue ? '<span class="struct-rogue-tag" title="Not documented in provided API spec">⚠ rogue</span>' : '';
        var specTag = fromSpec && !isRogue ? '<span class="struct-spec-tag" title="Documented in API spec">spec</span>' : '';
        html += '<div class="struct-ep-row' + (isRogue ? ' struct-rogue' : '') + '">';
        html += '<span class="struct-path">' + esc(path) + '</span>' + rogueTag + specTag;
        html += '<div class="struct-methods">';
        for (var method in methods) {
            var minfo = methods[method];
            var codes = (minfo.status_codes || []).join(', ');
            var authUsers = (minfo.auth_users || []).join(', ');
            var authTag = minfo.auth_required ? '<span class="struct-auth-tag" title="Auth required: ' + esc(authUsers) + '">🔒' + (authUsers ? ' ' + esc(authUsers) : '') + '</span>' : '';
            var mRogue = minfo.rogue ? '<span class="struct-rogue-tag">⚠</span>' : '';
            var codeCls = minfo.max_status && minfo.max_status < 300 ? 'struct-ok' : minfo.max_status && minfo.max_status < 400 ? 'struct-redir' : minfo.max_status ? 'struct-err' : '';
            html += '<span class="struct-method-pill ' + method.toLowerCase() + '">' + method + '</span>';
            if (codes) html += '<span class="struct-status ' + codeCls + '">' + codes + '</span>';
            html += authTag + mRogue + ' ';
        }
        html += '</div>';
        html += '</div>';
    }
    html += '</div>';
    return html;
}

var _INTEL_EMPTY_PLACEHOLDER = '<div class="empty-state"><div class="empty-state-text">Intelligence panels populate as tools run and discover data.</div></div>';

function _renderStructure(data) {
    var frMap = data.structure_map;
    var apiMap = data.api_map;
    if (!frMap && !apiMap) return _INTEL_EMPTY_PLACEHOLDER;
    var html = '';
    if (frMap) html += _renderFrStructureTree(frMap);
    if (apiMap) {
        if (frMap) html += '<div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border-color, var(--border))">';
        html += _renderApiStructureTree(apiMap);
        if (frMap) html += '</div>';
    }
    return html || _renderIntelGeneric(data);
}

/* ── Access Matrix Renderer ────────────────────────────────────── */
function _renderAccessMatrixSingle(matrix) {
    var roles = matrix.roles || [];
    var mostPriv = matrix.most_privileged || '';
    var counts = matrix.privilege_counts || {};
    var items = matrix.endpoints || matrix.paths || [];
    if (!roles.length && !items.length) return '';
    var _dispRole = function(r) { return r === 'unauthenticated' ? 'Unauthenticated' : r; };
    var html = '';
    if (mostPriv) {
        html += '<div style="margin-bottom:.75rem;font-size:.85rem;color:var(--text-muted)">';
        html += 'Most privileged role: <strong style="color:var(--text-primary)">' + esc(_dispRole(mostPriv)) + '</strong>';
        if (Object.keys(counts).length) {
            html += ' &nbsp;|&nbsp; Access counts: ';
            var cParts = [];
            for (var cr in counts) { cParts.push('<span style="color:var(--text-primary)">' + esc(_dispRole(cr)) + '</span>: ' + counts[cr]); }
            html += cParts.join(', ');
        }
        html += '</div>';
    }
    html += '<div style="overflow-x:auto"><table class="tool-table" style="width:100%;min-width:600px">';
    html += '<thead><tr><th style="text-align:left;padding:.4rem .6rem">Path / Endpoint</th>';
    for (var ri = 0; ri < roles.length; ri++) {
        var role = roles[ri];
        var isPriv = role === mostPriv;
        html += '<th style="text-align:center;padding:.4rem .6rem' + (isPriv ? ';color:#f0883e' : '') + '">';
        html += esc(_dispRole(role)) + (isPriv ? ' ★' : '') + '</th>';
    }
    html += '</tr></thead><tbody>';
    if (!items.length) {
        html += '<tr><td colspan="' + (roles.length + 1) + '" style="text-align:center;color:var(--text-muted);font-size:.85rem;padding:.75rem">No endpoints discovered yet.</td></tr>';
    } else {
        for (var ii = 0; ii < items.length; ii++) {
            var item = items[ii];
            var ipath = item.path || item.endpoint || '';
            var srcTag = (item.source === 'js-bundle') ? ' <span style="display:inline-block;padding:0 4px;border-radius:3px;font-size:.6rem;font-weight:700;background:rgba(88,166,255,.2);color:#58a6ff;vertical-align:middle;margin-left:4px" title="Discovered via JavaScript bundle analysis">JS</span>' : '';
            html += '<tr><td style="font-family:var(--font-mono);font-size:.82rem;padding:.35rem .6rem">' + esc(ipath) + srcTag + '</td>';
            for (var rj = 0; rj < roles.length; rj++) {
                var rr = roles[rj];
                var access = (item.access || {})[rr];
                var meta = ((item.access_meta || {})[rr]) || {};
                var cell = '—', cls = 'color:var(--text-muted)', pill = '';
                if (access !== undefined && access !== null) {
                    if (access === true || access === 'ok') { cell = '✓'; cls = 'color:#3fb950'; }
                    else if (access === false || access === 'denied') { cell = '✗'; cls = 'color:#f85149'; }
                    else if (typeof access === 'number') {
                        cell = String(access);
                        cls = access < 300 ? 'color:#3fb950' : access < 400 ? 'color:#d29922' : 'color:#f85149';
                        if (access >= 200 && access < 300) {
                            if (meta.body_denied) {
                                pill = '<span style="display:inline-block;margin-left:4px;padding:1px 5px;border-radius:3px;font-size:.68rem;font-weight:700;background:#f85149;color:#fff;vertical-align:middle" title="Response body contains access-denial indicators">DENIED</span>';
                            } else if (meta._size_restricted) {
                                pill = '<span style="display:inline-block;margin-left:4px;padding:1px 5px;border-radius:3px;font-size:.68rem;font-weight:700;background:#d29922;color:#000;vertical-align:middle" title="Response body significantly smaller than most-privileged role">RESTRICTED</span>';
                            }
                        }
                        if (meta.waf_blocked) {
                            pill = '<span style="display:inline-block;margin-left:4px;padding:1px 5px;border-radius:3px;font-size:.68rem;font-weight:700;background:#8957e5;color:#fff;vertical-align:middle" title="WAF/CDN blocked this request">WAF</span>';
                        }
                    } else { cell = String(access); }
                }
                html += '<td style="text-align:center;padding:.35rem .6rem;' + cls + '">' + cell + pill + '</td>';
            }
            html += '</tr>';
        }
    }
    html += '</tbody></table></div>';
    return html;
}

function _renderAccessMatrix(data) {
    var matrix = data.access_matrix;
    if (!matrix) return _INTEL_EMPTY_PLACEHOLDER;
    if (matrix.roles || matrix.endpoints || matrix.paths) {
        var single = _renderAccessMatrixSingle(matrix);
        return single || '<div class="empty-state"><div class="empty-state-text">No access matrix data.</div></div>';
    }
    var targetKeys = Object.keys(matrix).filter(function(k) { return k[0] !== '_'; });
    var html = '';
    var count = 0;
    for (var ti = 0; ti < targetKeys.length; ti++) {
        var target = targetKeys[ti];
        var td = matrix[target];
        if (!td || typeof td !== 'object') continue;
        if (!td.roles && !td.endpoints && !td.paths) continue;
        count++;
        html += '<div style="margin-bottom:1.5rem">';
        html += '<div style="font-weight:600;margin-bottom:6px;font-size:.85rem;padding:5px 10px;background:var(--bg-card);border-radius:6px;border:1px solid var(--border)">';
        html += esc(target);
        var epCount = (td.endpoints || td.paths || []).length;
        if (epCount) html += ' <span style="color:var(--text-muted);font-weight:400">(' + epCount + ' endpoints)</span>';
        html += '</div>';
        html += _renderAccessMatrixSingle(td);
        html += '</div>';
    }
    if (count) return html;
    return '<div class="empty-state"><div class="empty-state-text">No access matrix data.</div></div>';
}

/* ── Auth Status Renderer ──────────────────────────────────────── */
function _renderAuthStatus(data) {
    var entries = data.auth_status;
    if (!entries || !Array.isArray(entries) || !entries.length) return _INTEL_EMPTY_PLACEHOLDER;
    var html = '<div class="auth-role-grid">';
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        var role = e.role || '';
        var username = e.username || '';
        var status = (e.status || '').toLowerCase();
        var cookies = e.cookies || [];
        var headers = e.auth_headers || [];
        var sessionName = e.session_name || '';
        var statusCls = 'auth-status-unknown';
        if (status === 'success') statusCls = 'auth-status-success';
        else if (status === 'failed') statusCls = 'auth-status-failed';
        else if (status === 'unauthenticated') statusCls = 'auth-status-unauth';
        var dispRole = role === 'unauthenticated' ? 'Unauthenticated' : esc(role);
        html += '<div class="auth-role-card">';
        html += '<div class="auth-role-header">';
        html += '<span class="auth-role-name">' + dispRole + '</span>';
        html += '<span class="auth-status-badge ' + statusCls + '">' + esc(status || 'unknown') + '</span>';
        html += '</div>';
        if (username) {
            html += '<div class="auth-field-row"><span class="auth-field-label">Username</span><span class="auth-field-val">' + esc(username) + '</span></div>';
        }
        if (sessionName) {
            html += '<div class="auth-field-row"><span class="auth-field-label">Session</span><span class="auth-field-val" style="font-family:var(--font-mono);font-size:.8rem">' + esc(sessionName) + '</span></div>';
        }
        if (headers.length) {
            html += '<div class="auth-field-row auth-field-row-top"><span class="auth-field-label">Auth Headers</span><div class="auth-cookie-table-wrap"><table class="auth-cookie-table">';
            html += '<thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
            for (var hi = 0; hi < headers.length; hi++) {
                html += '<tr><td>' + esc(headers[hi].name || '') + '</td><td style="font-family:var(--font-mono);font-size:.78rem">' + esc(headers[hi].value || '') + '</td></tr>';
            }
            html += '</tbody></table></div></div>';
        }
        if (cookies.length) {
            html += '<div class="auth-field-row auth-field-row-top"><span class="auth-field-label">Cookies</span><div class="auth-cookie-table-wrap"><table class="auth-cookie-table">';
            html += '<thead><tr><th>Name</th><th>Value</th><th>Domain</th><th>Path</th><th>Secure</th><th>HttpOnly</th><th>Expires</th></tr></thead><tbody>';
            for (var ci = 0; ci < cookies.length; ci++) {
                var c = cookies[ci];
                var cval = c.value || '';
                var dispVal = cval.length > 40 ? cval.slice(0, 40) + '…' : cval;
                html += '<tr>';
                html += '<td style="font-family:var(--font-mono)">' + esc(c.name || '') + '</td>';
                html += '<td class="auth-cookie-val" style="font-family:var(--font-mono)" title="' + esc(cval) + '">' + esc(dispVal) + '</td>';
                html += '<td>' + esc(c.domain || '') + '</td>';
                html += '<td>' + esc(c.path || '') + '</td>';
                html += '<td>' + (c.secure ? '✓' : '') + '</td>';
                html += '<td>' + (c.httpOnly ? '✓' : '') + '</td>';
                html += '<td style="font-size:.75rem;color:var(--text-muted)">' + esc(c.expires || '') + '</td>';
                html += '</tr>';
            }
            html += '</tbody></table></div></div>';
        }
        html += '</div>';
    }
    html += '</div>';
    return html;
}

function _renderOsintPeople(data) {
    var payload = data.osint_people || data;
    if (!payload) return _renderIntelGeneric(data);
    var employees = payload.employees || [];
    var phones = payload.phone_numbers || [];
    if (!employees.length && !phones.length) return '<div class="empty-state"><div class="empty-state-text">No people intelligence data available.</div></div>';
    var h = '<div style="margin-bottom:12px;font-weight:600;font-size:1.1rem">People Intelligence (' + employees.length + ' employee' + (employees.length !== 1 ? 's' : '') + ')</div>';
    if (employees.length) {
        var rows = employees.map(function(e) {
            var linkedin = e.linkedin ? '<a href="' + esc(e.linkedin) + '" target="_blank" rel="noopener" style="color:var(--clr-accent)">Profile</a>' : '';
            return [
                esc(e.name || ((e.first_name || '') + ' ' + (e.last_name || '')).trim() || '—'),
                esc(e.title || e.position || '—'),
                esc(e.department || '—'),
                esc(e.email || '—'),
                esc(e.phone || e.phone_number || '—'),
                esc(e.source || '—'),
                linkedin
            ];
        });
        h += _intelTable(['Name', 'Title', 'Department', 'Email', 'Phone', 'Source', 'LinkedIn'], rows);
    }
    if (phones.length) {
        h += '<div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--border)">';
        h += '<div style="margin-bottom:8px;font-weight:600">Phone Numbers (' + phones.length + ')</div>';
        var phoneRows = phones.map(function(p) {
            if (typeof p === 'string') return [esc(p), '', ''];
            return [esc(p.number || p.phone || ''), esc(p.carrier || ''), esc(p.location || '')];
        });
        h += _intelTable(['Number', 'Carrier', 'Location'], phoneRows);
        h += '</div>';
    }
    return h;
}

function _renderOsintTyposquat(data) {
    var payload = data.osint_typosquat || data;
    if (!payload) return _renderIntelGeneric(data);
    var domains = payload.domains || [];
    if (!domains.length) return '<div class="empty-state"><div class="empty-state-text">No typosquatting data available.</div></div>';
    var high = 0, medium = 0, info = 0;
    domains.forEach(function(d) {
        var r = (d._risk || d.risk || 'info').toLowerCase();
        if (r === 'high') high++;
        else if (r === 'medium') medium++;
        else info++;
    });
    var h = '<div style="margin-bottom:12px;font-weight:600;font-size:1.1rem">Typosquatting / Domain Permutations (' + domains.length + ' registered)</div>';
    h += '<div style="display:flex;gap:16px;margin-bottom:16px">';
    if (high) h += '<div style="padding:6px 12px;border-radius:6px;background:var(--clr-high);color:#fff;font-weight:600">' + high + ' HIGH (MX)</div>';
    if (medium) h += '<div style="padding:6px 12px;border-radius:6px;background:var(--clr-medium);color:#fff;font-weight:600">' + medium + ' MEDIUM (live)</div>';
    if (info) h += '<div style="padding:6px 12px;border-radius:6px;background:var(--clr-info);color:#fff;font-weight:600">' + info + ' INFO</div>';
    h += '</div>';
    var rows = domains.map(function(d) {
        var risk = (d._risk || d.risk || 'INFO').toUpperCase();
        var riskBadge = '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;background:' + _riskColor(risk) + ';color:#fff">' + risk + '</span>';
        var ips = (d.dns_a || []).join(', ') || '—';
        var mx = (d.dns_mx || []).join(', ') || '—';
        return [
            '<span style="font-family:var(--font-mono)">' + esc(d.domain || '') + '</span>',
            riskBadge,
            esc(d.fuzzer || '—'),
            '<span style="font-family:var(--font-mono)">' + esc(ips) + '</span>',
            esc(mx),
            esc(d.whois_registrar || '—'),
            esc(d.whois_created || '—')
        ];
    });
    h += _intelTable(['Domain', 'Risk', 'Fuzzer', 'IP(s)', 'MX', 'Registrar', 'Created'], rows);
    return h;
}

function _renderOsintWayback(data) {
    var payload = data.osint_wayback || data;
    if (!payload) return _renderIntelGeneric(data);
    var domains = payload.domains || [];
    if (!domains.length) return '<div class="empty-state"><div class="empty-state-text">No Wayback Machine data available.</div></div>';
    var totalUrls = 0, totalEndpoints = 0;
    domains.forEach(function(d) { totalUrls += (d.url_count || 0); totalEndpoints += (d.endpoint_count || 0); });
    var h = '<div style="margin-bottom:12px;font-weight:600;font-size:1.1rem">Wayback Machine — Historical URLs</div>';
    h += '<div style="display:flex;gap:16px;margin-bottom:16px">';
    h += '<div style="padding:6px 12px;border-radius:6px;background:var(--accent-primary);color:#fff;font-weight:600">' + totalUrls + ' URLs</div>';
    if (totalEndpoints) h += '<div style="padding:6px 12px;border-radius:6px;background:var(--text-secondary);color:#fff;font-weight:600">' + totalEndpoints + ' Unique Endpoints</div>';
    h += '</div>';
    domains.forEach(function(d) {
        h += '<div style="margin-bottom:20px;padding:12px;background:var(--bg-card);border-radius:8px;border:1px solid var(--border)">';
        h += '<div style="font-weight:600;margin-bottom:8px;font-family:var(--font-mono)">' + esc(d.domain) + ' <span style="font-weight:400;color:var(--text-secondary)">(' + (d.url_count || 0) + ' URLs)</span></div>';
        if (d.endpoints && d.endpoints.length) {
            h += '<details style="margin-bottom:8px"><summary style="cursor:pointer;color:var(--accent-primary);font-weight:500;font-size:.85rem">Unique Endpoints (' + d.endpoints.length + ')</summary>';
            h += '<div style="max-height:300px;overflow-y:auto;margin-top:8px;padding:8px;background:var(--bg-secondary);border-radius:4px;font-family:var(--font-mono);font-size:.78rem;line-height:1.6">';
            d.endpoints.forEach(function(ep) { h += '<div>' + esc(ep) + '</div>'; });
            h += '</div></details>';
        }
        if (d.urls && d.urls.length) {
            h += '<details><summary style="cursor:pointer;color:var(--text-secondary);font-size:.85rem">All URLs (' + d.urls.length + ')</summary>';
            h += '<div style="max-height:400px;overflow-y:auto;margin-top:8px;padding:8px;background:var(--bg-secondary);border-radius:4px;font-family:var(--font-mono);font-size:.78rem;line-height:1.6">';
            d.urls.forEach(function(u) { h += '<div><a href="' + esc(u) + '" target="_blank" rel="noopener" style="color:var(--accent-primary);text-decoration:none">' + esc(u) + '</a></div>'; });
            h += '</div></details>';
        }
        h += '</div>';
    });
    return h;
}

function _renderApiInventory(data) {
    var inv = data.api_inventory;
    if (!inv) return _INTEL_EMPTY_PLACEHOLDER;
    if (Array.isArray(inv) && !inv.length) return _INTEL_EMPTY_PLACEHOLDER;
    if (typeof inv === 'object' && !Array.isArray(inv) && !Object.keys(inv).length) return _INTEL_EMPTY_PLACEHOLDER;
    return _renderIntelGeneric({api_inventory: inv, available: true});
}

function _renderIsoProperties(data) {
    var items = data.iso_properties || data;
    if (!items || !items.length) return '<div class="empty-state"><div class="empty-state-text">No file properties data available.</div></div>';
    var flat = [];
    items.forEach(function(entry) {
        if (Array.isArray(entry)) { entry.forEach(function(e) { flat.push(e); }); }
        else { flat.push(entry); }
    });
    if (!flat.length) return '<div class="empty-state"><div class="empty-state-text">No file properties data available.</div></div>';
    return '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px;padding:8px">' +
        flat.map(function(f) {
            var sz = f.size || 0;
            var szHuman = sz < 1024 ? sz + ' B' : sz < 1048576 ? (sz/1024).toFixed(1) + ' KB' : (sz/1048576).toFixed(1) + ' MB';
            var rows = [
                ['Filename', esc(f.filename || f._source_file || '')],
                ['Extension', esc(f.extension || '')],
                ['MIME Type', esc(f.mime || '')],
                ['Size', esc(sz.toLocaleString() + ' bytes (' + szHuman + ')')],
                ['Classification', esc(f.classification || '')],
                ['Magic', esc(f.magic_description || '')]
            ];
            if (f.is_code && f.code_language) rows.push(['Language', esc(f.code_language)]);
            if (f.line_count) rows.push(['Lines', esc(String(f.line_count))]);
            if (f.path) rows.splice(1, 0, ['Location', '<span style="word-break:break-all;font-size:12px">' + esc(f.path) + '</span>']);
            var flags = [];
            if (f.is_text) flags.push('Text');
            if (f.is_code) flags.push('Code');
            if (f.is_archive) flags.push('Archive');
            if (f.is_executable) flags.push('Executable');
            if (f.is_certificate) flags.push('Certificate');
            if (flags.length) rows.push(['Flags', flags.map(function(fl) { return '<span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:11px;background:var(--bg-tertiary);margin-right:4px">' + fl + '</span>'; }).join('')]);
            return '<div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:16px">' +
                '<div style="font-weight:600;font-size:14px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)">' + esc(f.filename || f._source_file || 'Unknown') + '</div>' +
                rows.map(function(r) { return '<div style="display:flex;gap:8px;padding:3px 0;font-size:13px"><span style="color:var(--text-secondary);min-width:100px;flex-shrink:0">' + r[0] + '</span><span style="flex:1">' + r[1] + '</span></div>'; }).join('') +
            '</div>';
        }).join('') +
    '</div>';
}

function _renderIsoEntropy(data) {
    var items = data.iso_entropy || data;
    if (!items || !items.length) return '<div class="empty-state"><div class="empty-state-text">No entropy analysis data available.</div></div>';
    var flat = [];
    items.forEach(function(entry) {
        if (Array.isArray(entry)) { entry.forEach(function(e) { flat.push(e); }); }
        else { flat.push(entry); }
    });
    if (!flat.length) return '<div class="empty-state"><div class="empty-state-text">No entropy analysis data available.</div></div>';
    function _eColor(v) {
        var t = Math.min(v / 8.0, 1.0);
        if (t < 0.25) return 'hsl(210,60%,' + (85 - t * 80) + '%)';
        if (t < 0.5)  return 'hsl(' + (210 - (t - 0.25) * 480) + ',65%,' + (65 - (t - 0.25) * 40) + '%)';
        if (t < 0.75) return 'hsl(' + (90 - (t - 0.5) * 360) + ',70%,' + (55 - (t - 0.5) * 20) + '%)';
        return 'hsl(' + (0 - (t - 0.75) * 40) + ',75%,' + (50 - (t - 0.75) * 20) + '%)';
    }
    function _eBadge(a) {
        var map = {not_encrypted:['Not Encrypted','var(--text-secondary)','var(--bg-tertiary)'],likely_encrypted:['Likely Encrypted','#c0392b','rgba(192,57,43,0.15)'],encrypted:['Encrypted','#c0392b','rgba(192,57,43,0.2)'],compressed:['Compressed','#d68910','rgba(214,137,16,0.15)'],random:['Random Data','#8e44ad','rgba(142,68,173,0.15)']};
        var m = map[a] || [a || 'Unknown','var(--text-secondary)','var(--bg-tertiary)'];
        return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:' + m[1] + ';background:' + m[2] + '">' + m[0] + '</span>';
    }
    function _szHuman(b) { return b < 1024 ? b + ' B' : b < 1048576 ? (b/1024).toFixed(1) + ' KB' : (b/1048576).toFixed(1) + ' MB'; }
    return '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:16px;padding:8px">' +
        flat.map(function(f) {
            var ent = (typeof f.overall_entropy === 'number') ? f.overall_entropy.toFixed(3) : '—';
            var map = f.entropy_map || [];
            var ws = f.window_size || 256;
            var bar = '';
            if (map.length) {
                bar = '<div style="margin:8px 0 4px"><div style="font-size:11px;color:var(--text-secondary);margin-bottom:4px">Byte-level entropy map (' + map.length + ' windows × ' + ws + ' bytes)</div>' +
                    '<div style="display:flex;height:28px;border-radius:4px;overflow:hidden;border:1px solid var(--border)">' +
                    map.map(function(w) {
                        var e = w.entropy || 0;
                        return '<div title="Offset ' + w.offset + ': ' + e.toFixed(3) + ' bits/byte" style="flex:1;background:' + _eColor(e) + ';min-width:1px"></div>';
                    }).join('') +
                    '</div>' +
                    '<div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-secondary);margin-top:2px">' +
                    '<span>0</span><span>' + _szHuman(f.file_size || map.length * ws) + '</span></div></div>';
            }
            var legend = '<div style="display:flex;gap:12px;margin-top:6px;font-size:10px;color:var(--text-secondary)">' +
                ['0-2 Structured','2-4 Text/Code','4-6 Mixed','6-7.5 Compressed','7.5-8 Encrypted/Random'].map(function(l,i) {
                    var colors = ['hsl(210,60%,85%)','hsl(150,65%,55%)','hsl(90,70%,55%)','hsl(30,75%,48%)','hsl(-10,75%,45%)'];
                    return '<span style="display:flex;align-items:center;gap:3px"><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:' + colors[i] + '"></span>' + l + '</span>';
                }).join('') + '</div>';
            return '<div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:16px">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)">' +
                '<span style="font-weight:600;font-size:14px">' + esc(f._source_file || f.filename || 'Unknown') + '</span>' +
                _eBadge(f.assessment) + '</div>' +
                '<div style="display:flex;gap:16px;font-size:13px;margin-bottom:8px">' +
                '<div><span style="color:var(--text-secondary)">Overall Entropy </span><strong>' + ent + '</strong> <span style="color:var(--text-secondary)">bits/byte</span></div>' +
                (f.file_size ? '<div><span style="color:var(--text-secondary)">Size </span>' + _szHuman(f.file_size) + '</div>' : '') +
                (f.estimated_method ? '<div><span style="color:var(--text-secondary)">Method </span>' + esc(f.estimated_method) + '</div>' : '') +
                '</div>' +
                bar + legend +
            '</div>';
        }).join('') +
    '</div>';
}

/* ── Endpoint Overview Renderer ───────────────────────────────── */

function _epBadge(ok, yesLabel, noLabel) {
    if (ok) return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;background:rgba(56,161,105,0.15);color:var(--risk-low,#38a169)">' + esc(yesLabel || 'Enabled') + '</span>';
    return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;background:rgba(229,62,62,0.15);color:var(--risk-high,#e53e3e)">' + esc(noLabel || 'Disabled') + '</span>';
}

function _epMetric(label, value, color) {
    return '<div style="flex:1;min-width:120px;padding:14px 16px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px;text-align:center">' +
        '<div style="font-size:26px;font-weight:700;color:' + (color || 'var(--text-primary)') + '">' + esc(String(value)) + '</div>' +
        '<div style="font-size:12px;color:var(--text-secondary);margin-top:2px">' + esc(label) + '</div></div>';
}

function _epSection(title, content) {
    return '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:10px">' + esc(title) + '</div>' + content + '</div>';
}

function _renderEndpointOverview(data) {
    var d = data.endpoint_overview || data;
    if (!d || !d.hostname) return '<div class="empty-state"><div class="empty-state-text">No endpoint overview data available.</div></div>';
    var h = '';

    // System identity card
    h += '<div style="margin-bottom:20px;padding:16px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:10px">';
    h += '<div style="font-size:20px;font-weight:700;margin-bottom:4px">' + esc(d.hostname) + '</div>';
    h += '<div style="font-size:14px;color:var(--text-secondary);margin-bottom:12px">' + esc(d.os_name || '') + (d.os_version ? ' — ' + esc(d.os_version) : '') + (d.os_build ? ' (Build ' + esc(String(d.os_build)) + ')' : '') + '</div>';
    h += '<div style="display:flex;flex-wrap:wrap;gap:10px">';
    h += '<div style="display:flex;align-items:center;gap:6px"><span style="color:var(--text-secondary);font-size:13px">Type:</span> <span style="font-weight:600;font-size:13px">' + esc(d.os_product_type || '?') + '</span></div>';
    h += '<div style="display:flex;align-items:center;gap:6px"><span style="color:var(--text-secondary);font-size:13px">Domain:</span> ' + _epBadge(d.domain_joined, 'Joined', 'Standalone') + ' <span style="font-size:13px">' + esc(d.domain_name || '') + '</span></div>';
    if (d.domain_role) h += '<div style="display:flex;align-items:center;gap:6px"><span style="color:var(--text-secondary);font-size:13px">Role:</span> <span style="font-size:13px">' + esc(d.domain_role) + '</span></div>';
    h += '<div style="display:flex;align-items:center;gap:6px"><span style="color:var(--text-secondary);font-size:13px">Uptime:</span> <span style="font-size:13px;font-weight:600">' + esc(String(d.uptime_days || 0)) + ' days</span></div>';
    h += '</div></div>';

    // Security posture
    h += _epSection('Security Posture', (function() {
        var s = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px">';
        s += '<div style="padding:12px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px"><div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px">Secure Boot</div>' + _epBadge(d.secure_boot) + '</div>';
        var tpm = d.tpm || {};
        var tpmOk = tpm.present || tpm.enabled || tpm.version;
        s += '<div style="padding:12px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px"><div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px">TPM</div>' + _epBadge(tpmOk, tpm.version ? 'v' + tpm.version : 'Present', 'Not Detected') + '</div>';
        s += '<div style="padding:12px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px"><div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px">Realtime Protection</div>' + _epBadge(!d.realtime_monitoring_disabled) + '</div>';
        s += '<div style="padding:12px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px"><div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px">AlwaysInstallElevated</div>' + _epBadge(!d.always_install_elevated, 'Not Set', 'SET — Vuln!') + '</div>';
        s += '</div>';
        return s;
    })());

    // Antivirus
    var av = d.antivirus || [];
    if (av.length) {
        var avRows = av.map(function(a) {
            var stateColor = (a.state || '').toLowerCase() === 'running' ? 'var(--risk-low,#38a169)' : 'var(--risk-high,#e53e3e)';
            return [esc(a.name || '?'), '<span style="color:' + stateColor + ';font-weight:600">' + esc(a.state || '?') + '</span>'];
        });
        h += _epSection('Antivirus Products', _intelTableRaw(['Product', 'State'], avRows));
    } else {
        h += _epSection('Antivirus Products', '<div style="padding:10px;background:rgba(229,62,62,0.08);border-radius:6px;color:var(--risk-high,#e53e3e);font-weight:600">No antivirus products detected</div>');
    }

    // Collection metadata
    h += _epSection('Collection', (function() {
        var items = [];
        if (d.collector_method) items.push(['Method', esc(d.collector_method)]);
        if (d.collection_timestamp) items.push(['Timestamp', esc(d.collection_timestamp)]);
        if (d.collection_duration_seconds) items.push(['Duration', esc(String(d.collection_duration_seconds)) + 's']);
        items.push(['Sections Collected', esc(String(d.sections_collected || 0))]);
        items.push(['Sections Failed', '<span style="color:' + (d.sections_failed > 0 ? 'var(--risk-high,#e53e3e)' : 'var(--risk-low,#38a169)') + '">' + esc(String(d.sections_failed || 0)) + '</span>']);
        if (d.bios_version) items.push(['BIOS', esc(d.bios_version)]);
        return _intelCard('Details', items);
    })());

    return h;
}

/* ── Endpoint Hardening Assessment Renderer ──────────────────── */

function _renderEndpointHardening(data) {
    var d = data.endpoint_hardening || data;
    if (!d) return '<div class="empty-state"><div class="empty-state-text">No hardening assessment data available.</div></div>';
    var h = '';

    var total = (d.compliant_count || 0) + (d.non_compliant_count || 0) + (d.unchecked_count || 0);

    // Compliance summary bar
    if (total > 0) {
        var pCompliant = Math.round((d.compliant_count / total) * 100);
        var pNonCompliant = Math.round((d.non_compliant_count / total) * 100);
        var pUnchecked = 100 - pCompliant - pNonCompliant;
        h += '<div style="margin-bottom:20px">';
        h += '<div style="display:flex;gap:12px;margin-bottom:10px;flex-wrap:wrap">';
        h += _epMetric('Compliant', d.compliant_count || 0, 'var(--risk-low,#38a169)');
        h += _epMetric('Non-Compliant', d.non_compliant_count || 0, 'var(--risk-high,#e53e3e)');
        h += _epMetric('Unchecked', d.unchecked_count || 0, 'var(--text-secondary)');
        h += '</div>';
        h += '<div style="height:10px;border-radius:5px;overflow:hidden;display:flex;background:var(--border-color,#e2e8f0)">';
        if (pCompliant > 0) h += '<div style="width:' + pCompliant + '%;background:var(--risk-low,#38a169)"></div>';
        if (pNonCompliant > 0) h += '<div style="width:' + pNonCompliant + '%;background:var(--risk-high,#e53e3e)"></div>';
        if (pUnchecked > 0) h += '<div style="width:' + pUnchecked + '%;background:var(--text-secondary,#a0aec0)"></div>';
        h += '</div></div>';
    }

    // Registry hardening table
    var items = d.registry_hardening || [];
    if (items.length) {
        var cols = ['Setting', 'Current', 'Recommended', 'Description', 'Status'];
        var rows = items.map(function(it) {
            var status, rowBg;
            if (it.compliant === true) {
                status = '<span style="color:var(--risk-low,#38a169);font-weight:600">Pass</span>';
                rowBg = '';
            } else if (it.compliant === false) {
                status = '<span style="color:var(--risk-high,#e53e3e);font-weight:600">Fail</span>';
                rowBg = '';
            } else {
                status = '<span style="color:var(--text-secondary)">—</span>';
                rowBg = '';
            }
            var curVal = it.current_value;
            if (curVal === null || curVal === undefined) curVal = '<span style="color:var(--text-secondary);font-style:italic">not set</span>';
            else curVal = esc(String(curVal));
            var recVal = it.recommended_value;
            if (recVal === null || recVal === undefined) recVal = '<span style="color:var(--text-secondary)">—</span>';
            else recVal = esc(String(recVal));
            return [esc(it.setting || ''), curVal, recVal, esc(it.recommendation || ''), status];
        });
        h += _epSection('Registry Hardening (' + items.length + ' settings)', _intelTableRaw(cols, rows));
    }

    // Password policy
    var pp = d.password_policy || {};
    if (pp && Object.keys(pp).length) {
        var ppItems = Object.keys(pp).map(function(k) {
            return [k.replace(/_/g, ' '), esc(String(pp[k] != null ? pp[k] : ''))];
        });
        h += _epSection('Password Policy', _intelCard('Settings', ppItems));
    }

    // Lockout policy
    var lp = d.lockout_policy || {};
    if (lp && Object.keys(lp).length) {
        var lpItems = Object.keys(lp).map(function(k) {
            return [k.replace(/_/g, ' '), esc(String(lp[k] != null ? lp[k] : ''))];
        });
        h += _epSection('Account Lockout Policy', _intelCard('Settings', lpItems));
    }

    return h || '<div class="empty-state"><div class="empty-state-text">No hardening assessment data collected.</div></div>';
}

/* ── Endpoint Software Inventory Renderer ────────────────────── */

function _renderEndpointSoftware(data) {
    var d = data.endpoint_software || data;
    if (!d) return '<div class="empty-state"><div class="empty-state-text">No software inventory data available.</div></div>';
    var h = '';

    // Summary metrics
    var ss = d.services_summary || {};
    h += '<div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap">';
    h += _epMetric('Installed Software', d.software_count || 0);
    h += _epMetric('Total Services', ss.total || 0);
    h += _epMetric('Running Services', ss.running || 0, 'var(--risk-low,#38a169)');
    h += _epMetric('Auto-Start', ss.auto_start || 0, 'var(--clr-medium,#dd6b20)');
    h += _epMetric('Scheduled Tasks', d.total_scheduled_tasks || 0);
    h += '</div>';

    // Software table with inline search
    var sw = d.software || [];
    if (sw.length) {
        var swId = 'epSoftFilter' + Date.now();
        h += '<div style="margin-bottom:20px">';
        h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><div style="font-weight:700;font-size:15px">Installed Software (' + sw.length + ')</div>';
        h += '<input id="' + swId + '" type="text" placeholder="Filter…" style="padding:4px 10px;border:1px solid var(--border-color,#e2e8f0);border-radius:6px;font-size:13px;background:var(--bg-card,#fff);color:var(--text-primary)" oninput="(function(el){var v=el.value.toLowerCase();var tbl=el.parentElement.nextElementSibling;if(!tbl)return;var rows=tbl.querySelectorAll(\'tbody tr\');for(var i=0;i<rows.length;i++){rows[i].style.display=rows[i].textContent.toLowerCase().indexOf(v)===-1?\'none\':\'\';}})(this)"></div>';
        var swCols = ['Name', 'Version', 'Publisher', 'Install Date'];
        var swRows = sw.map(function(s) {
            return [esc(s.name || ''), esc(s.version || ''), esc(s.publisher || ''), esc(s.install_date || '')];
        });
        h += _intelTableRaw(swCols, swRows);
        h += '</div>';
    }

    // Services table
    var svcs = d.services || [];
    if (svcs.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:10px">Services (' + svcs.length + ')</div>';
        var svcCols = ['Name', 'Display Name', 'State', 'Start Type', 'Account'];
        var svcRows = svcs.map(function(s) {
            var st = (s.state || '').toLowerCase();
            var stateBadge;
            if (st === 'running') stateBadge = '<span style="display:inline-block;padding:1px 7px;border-radius:4px;font-size:12px;font-weight:600;background:rgba(56,161,105,0.15);color:var(--risk-low,#38a169)">Running</span>';
            else if (st === 'stopped') stateBadge = '<span style="display:inline-block;padding:1px 7px;border-radius:4px;font-size:12px;color:var(--text-secondary)">Stopped</span>';
            else stateBadge = '<span style="font-size:12px">' + esc(s.state || '') + '</span>';
            var startBadge = (s.start_type || '').toLowerCase().indexOf('auto') !== -1
                ? '<span style="color:var(--clr-medium,#dd6b20);font-weight:600;font-size:12px">' + esc(s.start_type) + '</span>'
                : esc(s.start_type || '');
            return [esc(s.name || ''), esc(s.display_name || ''), stateBadge, startBadge, esc(s.account || '')];
        });
        h += _intelTableRaw(svcCols, svcRows);
        h += '</div>';
    }

    // Notable scheduled tasks
    var tasks = d.notable_tasks || [];
    if (tasks.length) {
        h += _epSection('Notable Scheduled Tasks (' + tasks.length + ' non-Microsoft)', (function() {
            var tCols = ['Task Name', 'Run As', 'Command', 'Status', 'Schedule'];
            var tRows = tasks.map(function(t) {
                var cmd = t.command || '';
                if (cmd.length > 80) cmd = cmd.substring(0, 77) + '...';
                return [esc(t.task_name || ''), esc(t.run_as || ''), '<span style="font-family:var(--font-mono);font-size:12px">' + esc(cmd) + '</span>', esc(t.status || ''), esc(t.schedule_type || '')];
            });
            return _intelTableRaw(tCols, tRows);
        })());
    }

    return h || '<div class="empty-state"><div class="empty-state-text">No software inventory data collected.</div></div>';
}

/* ── Endpoint Active Directory Renderer ──────────────────────── */

function _renderEndpointAD(data) {
    var d = data.endpoint_ad || data;
    if (!d) return '<div class="empty-state"><div class="empty-state-text">No Active Directory data available.</div></div>';
    var h = '';

    // Domain status card
    h += '<div style="margin-bottom:20px;padding:16px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:10px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">';
    h += '<div style="font-size:15px;font-weight:700">Domain Status</div>';
    h += _epBadge(d.domain_joined, 'Domain-Joined', 'Standalone');
    if (d.domain_name) h += '<span style="font-size:14px;font-weight:600">' + esc(d.domain_name) + '</span>';
    h += '</div>';

    // Domain controllers
    var dcs = d.domain_controllers || [];
    if (dcs.length) {
        var dcList = dcs.map(function(dc) {
            if (typeof dc === 'string') return esc(dc);
            if (typeof dc === 'object') return esc(dc.name || dc.hostname || JSON.stringify(dc));
            return esc(String(dc));
        }).join(', ');
        h += _epSection('Domain Controllers', '<div style="padding:10px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:6px;font-family:var(--font-mono);font-size:13px">' + dcList + '</div>');
    }

    // Privileged groups
    var da = d.domain_admins || [];
    var ea = d.enterprise_admins || [];
    if (da.length || ea.length) {
        var privH = '';
        if (da.length) {
            var daList = da.map(function(u) { return typeof u === 'string' ? esc(u) : esc(u.name || JSON.stringify(u)); });
            privH += '<div style="margin-bottom:10px"><div style="font-weight:600;font-size:13px;margin-bottom:4px;color:var(--risk-high,#e53e3e)">Domain Admins (' + da.length + ')</div>';
            privH += '<div style="padding:8px;border:1px solid var(--border-color,#e2e8f0);border-radius:6px;font-size:13px">' + daList.join(', ') + '</div></div>';
        }
        if (ea.length) {
            var eaList = ea.map(function(u) { return typeof u === 'string' ? esc(u) : esc(u.name || JSON.stringify(u)); });
            privH += '<div><div style="font-weight:600;font-size:13px;margin-bottom:4px;color:var(--clr-critical,#c53030)">Enterprise Admins (' + ea.length + ')</div>';
            privH += '<div style="padding:8px;border:1px solid var(--border-color,#e2e8f0);border-radius:6px;font-size:13px">' + eaList.join(', ') + '</div></div>';
        }
        h += _epSection('Privileged Groups', privH);
    }

    // Local administrators
    var adm = d.administrators_group || [];
    if (adm.length) {
        var admList = adm.map(function(a) { return esc(typeof a === 'string' ? a : (a.name || JSON.stringify(a))); }).join(', ');
        h += _epSection('Local Administrators (' + adm.length + ')', '<div style="padding:10px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:6px;font-size:13px">' + admList + '</div>');
    }

    // Local users table
    var users = d.local_users || [];
    if (users.length) {
        var uCols = ['Username', 'Enabled', 'Password Never Expires', 'Description'];
        var uRows = users.map(function(u) {
            var enabled = u.enabled ? '<span style="color:var(--risk-low,#38a169);font-weight:600">Yes</span>' : '<span style="color:var(--text-secondary)">No</span>';
            var pne = u.password_never_expires
                ? (u.enabled ? '<span style="color:var(--risk-high,#e53e3e);font-weight:600">Yes</span>' : '<span style="color:var(--clr-medium,#dd6b20)">Yes</span>')
                : '<span style="color:var(--risk-low,#38a169)">No</span>';
            return [esc(u.name || ''), enabled, pne, esc(u.description || '')];
        });
        h += _epSection('Local Users (' + users.length + ')', _intelTableRaw(uCols, uRows));
    }

    // LDAP Signing
    var ldap = d.ldap_signing || {};
    if (ldap && Object.keys(ldap).length) {
        var ldapItems = Object.keys(ldap).map(function(k) { return [k.replace(/_/g, ' '), esc(String(ldap[k] != null ? ldap[k] : ''))]; });
        h += _epSection('LDAP Signing', _intelCard('Configuration', ldapItems));
    }

    // AD CS
    if (d.adcs_available) {
        var caH = '';
        var cas = d.certificate_authorities || [];
        if (cas.length) {
            var caCols = ['Name', 'Type', 'Status'];
            var caRows = cas.map(function(ca) { return [esc(ca.name || ''), esc(ca.type || ''), esc(ca.status || '')]; });
            caH += _intelTableRaw(caCols, caRows);
        }
        var tmpls = d.certificate_templates || [];
        if (tmpls.length) {
            caH += '<div style="margin-top:10px"><div style="font-weight:600;font-size:13px;margin-bottom:4px">Certificate Templates (' + tmpls.length + ')</div>';
            var tCols = ['Name', 'OID'];
            var tRows = tmpls.map(function(t) { return [esc(t.name || ''), esc(t.oid || '')]; });
            caH += _intelTableRaw(tCols, tRows) + '</div>';
        }
        h += _epSection('Active Directory Certificate Services', caH || '<div style="color:var(--text-secondary);font-size:13px">ADCS available but no details collected.</div>');
    }

    // LAPS
    h += _epSection('LAPS (Local Admin Password Solution)', (function() {
        var s = '<div style="display:flex;gap:12px;flex-wrap:wrap">';
        s += '<div style="padding:10px 16px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px"><span style="color:var(--text-secondary);font-size:13px">LAPS Available: </span>' + _epBadge(d.laps_available) + '</div>';
        s += '<div style="padding:10px 16px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px"><span style="color:var(--text-secondary);font-size:13px">Legacy LAPS: </span>' + _epBadge(d.laps_legacy_installed, 'Installed', 'Not Installed') + '</div>';
        s += '<div style="padding:10px 16px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px"><span style="color:var(--text-secondary);font-size:13px">Windows LAPS: </span>' + _epBadge(d.laps_windows_installed, 'Installed', 'Not Installed') + '</div>';
        s += '</div>';
        return s;
    })());

    return h || '<div class="empty-state"><div class="empty-state-text">No Active Directory data collected.</div></div>';
}

/* ── Endpoint Network Posture Renderer ───────────────────────── */

function _renderEndpointNetwork(data) {
    var d = data.endpoint_network || data;
    if (!d) return '<div class="empty-state"><div class="empty-state-text">No network posture data available.</div></div>';
    var h = '';

    // Metrics row
    h += '<div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap">';
    h += _epMetric('Open Ports', d.open_ports_total || 0);
    h += _epMetric('High-Risk Ports', d.high_risk_port_count || 0, d.high_risk_port_count > 0 ? 'var(--risk-high,#e53e3e)' : 'var(--risk-low,#38a169)');
    h += _epMetric('Established', d.connections_established || 0);
    h += _epMetric('Unique Remote IPs', d.unique_remote_ips || 0);
    h += '</div>';

    // High-risk ports warning
    var hrp = d.high_risk_ports || [];
    if (hrp.length) {
        h += '<div style="margin-bottom:20px;padding:12px 16px;background:rgba(229,62,62,0.08);border:1px solid rgba(229,62,62,0.3);border-radius:8px">';
        h += '<div style="font-weight:700;font-size:14px;color:var(--risk-high,#e53e3e);margin-bottom:8px">High-Risk Listening Ports (' + hrp.length + ')</div>';
        var hrCols = ['Port', 'Service', 'Protocol', 'Process'];
        var hrRows = hrp.map(function(p) {
            return ['<span style="font-weight:700;color:var(--risk-high,#e53e3e)">' + esc(String(p.port)) + '</span>', esc(p.service || ''), esc(p.protocol || ''), esc(p.process || '')];
        });
        h += _intelTableRaw(hrCols, hrRows);
        h += '</div>';
    }

    // Firewall profiles
    var fw = d.firewall_profiles || {};
    var fwKeys = Object.keys(fw);
    if (fwKeys.length) {
        h += _epSection('Firewall Profiles', (function() {
            var s = '<div style="display:flex;gap:12px;flex-wrap:wrap">';
            fwKeys.forEach(function(pName) {
                var pData = fw[pName] || {};
                var enabled = pData.enabled;
                var isOn = enabled === true || enabled === 'ON' || enabled === 'True' || enabled === 1;
                s += '<div style="padding:12px 20px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:8px;min-width:140px;text-align:center">';
                s += '<div style="font-weight:600;font-size:13px;margin-bottom:6px">' + esc(pName) + '</div>';
                s += _epBadge(isOn);
                s += '</div>';
            });
            s += '</div>';
            return s;
        })());
    }

    // NetBIOS over TCP/IP
    if (d.netbios_over_tcpip) {
        h += '<div style="margin-bottom:14px;padding:8px 14px;background:rgba(221,107,32,0.08);border:1px solid rgba(221,107,32,0.3);border-radius:6px;font-size:13px;color:var(--clr-medium,#dd6b20)">';
        h += '<span style="font-weight:600">NetBIOS over TCP/IP:</span> Enabled — consider disabling to reduce attack surface</div>';
    }

    // Network adapters
    var adapters = d.adapters || [];
    if (adapters.length) {
        var aCols = ['Description', 'IP Address', 'Subnet', 'Gateway', 'MAC', 'DHCP'];
        var aRows = adapters.map(function(a) {
            return [esc(a.description || ''), '<span style="font-family:var(--font-mono)">' + esc(a.ip_address || '') + '</span>', esc(a.subnet || ''), esc(a.gateway || ''), '<span style="font-family:var(--font-mono);font-size:12px">' + esc(a.mac_address || '') + '</span>', a.dhcp_enabled ? 'Yes' : 'No'];
        });
        h += _epSection('Network Adapters (' + adapters.length + ')', _intelTableRaw(aCols, aRows));
    }

    // DNS
    var dns = d.dns_servers || [];
    if (dns.length) {
        var dnsList = dns.map(function(s) { return esc(typeof s === 'string' ? s : JSON.stringify(s)); }).join(', ');
        h += _epSection('DNS Servers', '<div style="padding:8px 12px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:6px;font-family:var(--font-mono);font-size:13px">' + dnsList + '</div>');
    }

    // DNS info
    var dnsInfo = d.dns || {};
    if (dnsInfo && Object.keys(dnsInfo).length) {
        var zones = dnsInfo.zones || [];
        if (zones.length) {
            h += _epSection('DNS Zones (' + zones.length + ')', _renderArrayTable(zones));
        }
    }

    return h || '<div class="empty-state"><div class="empty-state-text">No network posture data collected.</div></div>';
}

/* ── Endpoint Browser Security Renderer ──────────────────────── */

function _renderEndpointBrowser(data) {
    var d = data.endpoint_browser || data;
    if (!d) return '<div class="empty-state"><div class="empty-state-text">No browser security data available.</div></div>';

    var browsers = ['Chrome', 'Edge', 'Firefox'];
    var hasBrowser = false;
    var h = '';

    // Browser summary cards
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-bottom:20px">';
    browsers.forEach(function(name) {
        var b = d[name];
        if (!b) return;
        hasBrowser = true;
        var installed = b.installed;
        var bg = installed ? 'var(--bg-card,#fff)' : 'var(--bg-alt,#f7fafc)';
        h += '<div style="padding:16px;background:' + bg + ';border:1px solid var(--border-color,#e2e8f0);border-radius:10px">';
        h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">';
        h += '<div style="font-weight:700;font-size:16px">' + esc(name) + '</div>';
        h += _epBadge(installed, 'Installed', 'Not Installed');
        h += '</div>';
        if (installed) {
            h += '<div style="display:flex;gap:16px;flex-wrap:wrap;font-size:13px">';
            h += '<div><span style="color:var(--text-secondary)">Extensions: </span><span style="font-weight:600">' + (b.extension_count || 0) + '</span></div>';
            h += '<div><span style="color:var(--text-secondary)">History: </span><span style="font-weight:600">' + (b.history_entries || 0) + '</span></div>';
            var pwCount = b.saved_passwords || 0;
            var pwColor = pwCount > 0 ? 'color:var(--risk-high,#e53e3e);font-weight:700' : 'font-weight:600';
            h += '<div><span style="color:var(--text-secondary)">Saved Passwords: </span><span style="' + pwColor + '">' + pwCount + '</span></div>';
            h += '</div>';
            if (pwCount > 0) {
                h += '<div style="margin-top:8px;padding:6px 10px;background:rgba(229,62,62,0.08);border-radius:4px;font-size:12px;color:var(--risk-high,#e53e3e);font-weight:600">Credentials stored in browser — recommend password manager migration</div>';
            }
        }
        h += '</div>';
    });
    h += '</div>';

    // Extensions tables per browser
    browsers.forEach(function(name) {
        var b = d[name];
        if (!b || !b.installed) return;
        var exts = b.extensions || [];
        if (!exts.length) return;
        var eCols = ['Extension', 'ID', 'Version', 'Enabled'];
        var eRows = exts.map(function(e) {
            var en = e.enabled !== false
                ? '<span style="color:var(--risk-low,#38a169)">Yes</span>'
                : '<span style="color:var(--text-secondary)">No</span>';
            return [esc(e.name || ''), '<span style="font-family:var(--font-mono);font-size:12px">' + esc(e.id || '') + '</span>', esc(e.version || ''), en];
        });
        h += _epSection(name + ' Extensions (' + exts.length + ')', _intelTableRaw(eCols, eRows));
    });

    if (!hasBrowser) return '<div class="empty-state"><div class="empty-state-text">No browser data collected.</div></div>';
    return h;
}

/* ── Endpoint Disk & Storage Renderer ─────────────────────────── */

function _renderEndpointDisk(data) {
    var d = data.endpoint_disk || data;
    if (!d) return '<div class="empty-state"><div class="empty-state-text">No disk/storage data available. Requires Dredge v1.3.0+.</div></div>';
    var h = '';

    var rs = d.raid_summary || [];
    if (rs.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">RAID Configuration</div>';
        var rCols = ['source','name','raid_level','size_gb','health','status'];
        var rRows = rs.map(function(r) {
            return rCols.map(function(k) {
                var v = r[k]; if (v == null) return '';
                var s = String(v);
                if ((k === 'health' || k === 'status') && s.toLowerCase() !== 'healthy' && s.toLowerCase() !== 'optimal' && s.toLowerCase() !== 'ok')
                    return '<span style="color:var(--risk-high,#e53e3e);font-weight:600">' + esc(s) + '</span>';
                if (k === 'raid_level') return '<span style="font-weight:600">' + esc(s) + '</span>';
                return esc(s);
            });
        });
        h += _intelTableRaw(rCols.map(function(c) { return c.replace(/_/g,' '); }), rRows);
        h += '</div>';
    }

    var evts = d.disk_event_errors || [];
    if (evts.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px;color:var(--risk-high,#e53e3e)">Disk Event Log Errors (' + evts.length + ')</div>';
        var eCols = ['time','provider','event_id','level','message'];
        var eRows = evts.slice(0, 50).map(function(e) {
            return eCols.map(function(k) {
                var v = e[k]; if (v == null) return '';
                var s = String(v);
                if (k === 'level' && (s === 'Critical' || s === 'Error'))
                    return '<span style="color:var(--risk-high,#e53e3e);font-weight:600">' + esc(s) + '</span>';
                if (k === 'time' && s.length > 19) s = s.substring(0, 19).replace('T', ' ');
                return esc(s);
            });
        });
        h += _intelTableRaw(eCols.map(function(c) { return c.replace(/_/g,' '); }), eRows);
        h += '</div>';
    }

    if (d.physical_disks && d.physical_disks.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Physical Disks (' + d.physical_disks.length + ')</div>';
        h += _renderArrayTable(d.physical_disks);
        h += '</div>';
    }

    if (d.storage_module_disks && d.storage_module_disks.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Storage Module Disks (' + d.storage_module_disks.length + ')</div>';
        h += _renderArrayTable(d.storage_module_disks);
        h += '</div>';
    }

    if (d.logical_disks && d.logical_disks.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Logical Disks (' + d.logical_disks.length + ')</div>';
        h += _renderArrayTable(d.logical_disks);
        h += '</div>';
    }

    var ss = d.storage_spaces || {};
    if (ss.pools && ss.pools.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Storage Pools (' + ss.pools.length + ')</div>';
        ss.pools.forEach(function(pool) {
            var hc = pool.health && pool.health.toLowerCase() !== 'healthy' ? 'color:var(--risk-high,#e53e3e);font-weight:600' : 'color:var(--risk-low,#38a169)';
            h += '<div style="border:1px solid var(--border-color,#e2e8f0);border-radius:6px;padding:12px;margin-bottom:8px">';
            h += '<div style="font-weight:600;margin-bottom:6px">' + esc(pool.name) + ' <span style="' + hc + '">(' + esc(pool.health) + ')</span></div>';
            h += '<div style="font-size:13px;color:var(--text-secondary)">' + esc(pool.size_gb) + ' GB total, ' + esc(pool.allocated_gb) + ' GB allocated</div>';
            if (pool.disks && pool.disks.length) {
                h += '<div style="margin-top:8px">' + _renderArrayTable(pool.disks) + '</div>';
            }
            h += '</div>';
        });
        h += '</div>';
    }

    if (ss.virtual_disks && ss.virtual_disks.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Virtual Disks (' + ss.virtual_disks.length + ')</div>';
        h += _renderArrayTable(ss.virtual_disks);
        h += '</div>';
    }

    var hw = d.hardware_raid;
    if (hw && hw.detected_cli) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Hardware RAID</div>';
        h += '<div style="font-size:13px;margin-bottom:6px"><span style="color:var(--text-secondary)">Controller: </span>' + esc(hw.controller || '?') + '</div>';
        h += '<div style="font-size:13px;margin-bottom:8px"><span style="color:var(--text-secondary)">CLI: </span>' + esc(hw.cli) + '</div>';
        if (hw.virtual_drives && hw.virtual_drives.length) {
            h += _renderArrayTable(hw.virtual_drives);
        }
        h += '</div>';
    }

    if (d.controllers && d.controllers.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Storage Controllers (' + d.controllers.length + ')</div>';
        h += _renderArrayTable(d.controllers);
        h += '</div>';
    }

    return h || '<div class="empty-state"><div class="empty-state-text">No disk/storage data collected.</div></div>';
}

function _intelTableRaw(headers, rows) {
    var h = '<div style="overflow-x:auto"><table class="intel-table" style="width:100%;border-collapse:collapse;font-size:13px">';
    h += '<thead><tr>';
    headers.forEach(function(hd) { h += '<th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border-color,#e2e8f0);white-space:nowrap">' + esc(hd) + '</th>'; });
    h += '</tr></thead><tbody>';
    rows.forEach(function(row, i) {
        h += '<tr style="' + (i % 2 ? 'background:var(--bg-alt,#f7fafc)' : '') + '">';
        row.forEach(function(cell) { h += '<td style="padding:5px 10px;border-bottom:1px solid var(--border-color,#e2e8f0)">' + cell + '</td>'; });
        h += '</tr>';
    });
    h += '</tbody></table></div>';
    return h;
}

/* ── Endpoint Hardware Inventory Renderer ─────────────────────── */

function _renderEndpointHardware(data) {
    var d = data.endpoint_hardware || data;
    if (!d) return '<div class="empty-state"><div class="empty-state-text">No hardware inventory data available. Requires Dredge v1.3.0+.</div></div>';
    var h = '';

    var bb = d.baseboard;
    if (bb) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Motherboard</div>';
        h += '<div style="border:1px solid var(--border-color,#e2e8f0);border-radius:6px;padding:12px">';
        h += '<div><span style="color:var(--text-secondary)">Manufacturer: </span>' + esc(bb.manufacturer || '?') + '</div>';
        h += '<div><span style="color:var(--text-secondary)">Product: </span>' + esc(bb.product || '?') + '</div>';
        h += '<div><span style="color:var(--text-secondary)">Serial: </span>' + esc(bb.serial || '?') + '</div>';
        h += '</div></div>';
    }

    if (d.processors && d.processors.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Processors (' + d.processors.length + ')</div>';
        h += _renderArrayTable(d.processors);
        h += '</div>';
    }

    var mem = d.memory;
    if (mem) {
        var eccLabel = mem.ecc === true ? '<span style="color:var(--risk-low,#38a169)">Yes</span>' : (mem.ecc === false ? '<span style="color:var(--risk-medium,#dd6b20)">No</span>' : 'Unknown');
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Memory</div>';
        h += '<div style="border:1px solid var(--border-color,#e2e8f0);border-radius:6px;padding:12px;margin-bottom:8px">';
        h += '<div><span style="color:var(--text-secondary)">Total: </span>' + esc(String(mem.total_gb || 0)) + ' GB</div>';
        h += '<div><span style="color:var(--text-secondary)">Slots: </span>' + esc(String(mem.slot_count || 0)) + '</div>';
        h += '<div><span style="color:var(--text-secondary)">ECC: </span>' + eccLabel + '</div>';
        h += '</div>';
        if (mem.modules && mem.modules.length) {
            h += _renderArrayTable(mem.modules);
        }
        h += '</div>';
    }

    if (d.gpu_adapters && d.gpu_adapters.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">GPU Adapters (' + d.gpu_adapters.length + ')</div>';
        h += _renderArrayTable(d.gpu_adapters);
        h += '</div>';
    }

    if (d.network_adapters && d.network_adapters.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Network Adapters (' + d.network_adapters.length + ')</div>';
        h += _renderArrayTable(d.network_adapters);
        h += '</div>';
    }

    if (d.pci_devices && d.pci_devices.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">PCI Devices (' + d.pci_devices.length + ')</div>';
        h += _renderArrayTable(d.pci_devices);
        h += '</div>';
    }

    if (d.usb_devices && d.usb_devices.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">USB Devices (' + d.usb_devices.length + ')</div>';
        h += _renderArrayTable(d.usb_devices);
        h += '</div>';
    }

    if (d.batteries && d.batteries.length) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Batteries (' + d.batteries.length + ')</div>';
        h += _renderArrayTable(d.batteries);
        h += '</div>';
    }

    if (d.power_plan) {
        h += '<div style="margin-bottom:20px"><div style="font-weight:700;font-size:15px;margin-bottom:8px">Power Plan</div>';
        h += '<div style="border:1px solid var(--border-color,#e2e8f0);border-radius:6px;padding:12px">' + esc(d.power_plan) + '</div>';
        h += '</div>';
    }

    return h || '<div class="empty-state"><div class="empty-state-text">No hardware inventory data collected.</div></div>';
}

/* ── Compliance Framework Shared Helpers ────────────────────── */

function _complianceScoreGauge(score, rating) {
    var color = score >= 80 ? 'var(--risk-low,#38a169)' : score >= 60 ? 'var(--risk-medium,#d69e2e)' : score >= 40 ? 'var(--risk-high,#e53e3e)' : 'var(--risk-critical,#9b2c2c)';
    var ratingBg = score >= 80 ? 'rgba(56,161,105,0.12)' : score >= 60 ? 'rgba(214,158,46,0.12)' : score >= 40 ? 'rgba(229,62,62,0.12)' : 'rgba(155,44,44,0.15)';
    return '<div style="display:flex;align-items:center;gap:24px;padding:20px;background:var(--bg-card,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:10px;margin-bottom:20px">' +
        '<div style="position:relative;width:100px;height:100px">' +
        '<svg viewBox="0 0 36 36" style="width:100px;height:100px;transform:rotate(-90deg)">' +
        '<circle cx="18" cy="18" r="15.9" fill="none" stroke="var(--border-color,#e2e8f0)" stroke-width="3"/>' +
        '<circle cx="18" cy="18" r="15.9" fill="none" stroke="' + color + '" stroke-width="3" stroke-dasharray="' + score + ' ' + (100 - score) + '" stroke-linecap="round"/>' +
        '</svg>' +
        '<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:22px;font-weight:700;color:' + color + '">' + score + '%</div>' +
        '</div>' +
        '<div>' +
        '<div style="font-size:24px;font-weight:700;color:' + color + '">' + esc(rating) + '</div>' +
        '<div style="font-size:13px;color:var(--text-secondary);margin-top:2px">Compliance Score</div>' +
        '</div></div>';
}

function _complianceSummaryBar(summary) {
    var p = summary.pass || 0, f = summary.fail || 0;
    var nc = summary.not_configured || 0;
    var total = summary.total || (p + f + nc) || 1;
    var pPct = Math.round(p / total * 100), fPct = Math.round(f / total * 100);
    var ncPct = 100 - pPct - fPct;
    return '<div style="margin-bottom:20px">' +
        '<div style="display:flex;gap:10px;margin-bottom:8px;flex-wrap:wrap">' +
        '<span style="font-size:13px"><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--risk-low,#38a169);margin-right:4px"></span>Pass: <strong>' + p + '</strong></span>' +
        '<span style="font-size:13px"><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--risk-high,#e53e3e);margin-right:4px"></span>Fail: <strong>' + f + '</strong></span>' +
        (nc ? '<span style="font-size:13px"><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--text-secondary,#a0aec0);margin-right:4px"></span>Not Configured: <strong>' + nc + '</strong></span>' : '') +
        '</div>' +
        '<div style="display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--border-color,#e2e8f0)">' +
        '<div style="width:' + pPct + '%;background:var(--risk-low,#38a169)"></div>' +
        '<div style="width:' + fPct + '%;background:var(--risk-high,#e53e3e)"></div>' +
        '<div style="width:' + ncPct + '%;background:var(--text-secondary,#a0aec0)"></div>' +
        '</div></div>';
}

function _complianceControlsTable(controls, columns) {
    if (!controls || !controls.length) return '';
    var h = '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">';
    h += '<thead><tr>';
    for (var ci = 0; ci < columns.length; ci++) {
        h += '<th style="text-align:left;padding:8px 10px;border-bottom:2px solid var(--border-color,#e2e8f0);color:var(--text-secondary);font-weight:600;font-size:12px;text-transform:uppercase;white-space:nowrap">' + esc(columns[ci].label) + '</th>';
    }
    h += '</tr></thead><tbody>';
    for (var i = 0; i < controls.length; i++) {
        var c = controls[i];
        var rowBg = i % 2 === 0 ? 'transparent' : 'var(--bg-hover,rgba(0,0,0,0.02))';
        h += '<tr style="background:' + rowBg + '">';
        for (var j = 0; j < columns.length; j++) {
            var col = columns[j];
            var val = c[col.key];
            var td = '<td style="padding:8px 10px;border-bottom:1px solid var(--border-color,#e2e8f0);vertical-align:top';
            if (col.key === 'status') {
                var sColor = val === 'Pass' ? 'var(--risk-low,#38a169)' : val === 'Fail' ? 'var(--risk-high,#e53e3e)' : 'var(--text-secondary,#a0aec0)';
                var sBg = val === 'Pass' ? 'rgba(56,161,105,0.1)' : val === 'Fail' ? 'rgba(229,62,62,0.1)' : 'rgba(160,174,192,0.1)';
                td += ';white-space:nowrap">';
                td += '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:' + sBg + ';color:' + sColor + '">' + esc(val || '—') + '</span>';
            } else if (col.key === 'severity') {
                var svColor = val === 'CAT I' ? 'var(--risk-critical,#9b2c2c)' : val === 'CAT II' ? 'var(--risk-high,#e53e3e)' : val === 'L1' ? 'var(--risk-medium,#d69e2e)' : 'var(--text-secondary,#a0aec0)';
                td += ';white-space:nowrap">';
                td += '<span style="font-weight:600;color:' + svColor + '">' + esc(val || '—') + '</span>';
            } else if (col.nowrap) {
                td += ';white-space:nowrap">' + esc(String(val != null ? val : '—'));
            } else {
                td += '">' + esc(String(val != null ? val : '—'));
            }
            td += '</td>';
            h += td;
        }
        h += '</tr>';
    }
    h += '</tbody></table></div>';
    return h;
}

function _complianceSectionBreakdown(controls, sectionKey) {
    var sections = {};
    for (var i = 0; i < controls.length; i++) {
        var sec = controls[i][sectionKey] || 'Other';
        if (!sections[sec]) sections[sec] = {pass: 0, fail: 0, nc: 0, total: 0};
        sections[sec].total++;
        if (controls[i].status === 'Pass') sections[sec].pass++;
        else if (controls[i].status === 'Fail') sections[sec].fail++;
        else sections[sec].nc++;
    }
    var h = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin-bottom:20px">';
    var keys = Object.keys(sections);
    for (var k = 0; k < keys.length; k++) {
        var s = sections[keys[k]];
        var pct = s.total ? Math.round(s.pass / s.total * 100) : 0;
        var col = pct >= 80 ? 'var(--risk-low,#38a169)' : pct >= 60 ? 'var(--risk-medium,#d69e2e)' : 'var(--risk-high,#e53e3e)';
        h += '<div style="padding:12px;border:1px solid var(--border-color,#e2e8f0);border-radius:8px;background:var(--bg-card,#fff)">' +
            '<div style="font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="' + esc(keys[k]) + '">' + esc(keys[k]) + '</div>' +
            '<div style="font-size:20px;font-weight:700;color:' + col + '">' + pct + '%</div>' +
            '<div style="font-size:11px;color:var(--text-secondary)">' + s.pass + '/' + s.total + ' pass</div>' +
            '</div>';
    }
    h += '</div>';
    return h;
}

/* ── Compliance Assessment Renderer (shared) ───────────────── */

function _renderComplianceAssessment(data) {
    var d = data.endpoint_cis || data.endpoint_nist || data.endpoint_stig || data;
    if (!d || !d.categories) return '<div class="empty-state"><div class="empty-state-text">No compliance data available. Re-run Dredge to generate the assessment.</div></div>';

    var scorePct = d.score_percent || 0;
    var rating = d.overall_rating || 'Unknown';
    var gaugeColor = _complianceScoreColor(scorePct);
    var ratingBadge = _complianceRatingBadge(rating);

    var h = '';
    h += '<div style="display:flex;align-items:center;gap:24px;margin-bottom:20px;padding:16px;background:var(--bg-card,#1a1a2e);border:1px solid var(--border-color,#333);border-radius:10px;flex-wrap:wrap">';
    h += _complianceGauge(scorePct);
    h += '<div style="flex:1;min-width:180px"><div style="font-size:18px;font-weight:700;margin-bottom:4px">' + esc(d.framework || 'Compliance Assessment') + '</div>';
    if (d.scope) h += '<div style="font-size:13px;color:var(--text-secondary);margin-bottom:8px">' + esc(d.scope) + '</div>';
    h += '<div>' + ratingBadge + '</div></div>';
    h += '</div>';

    h += '<div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap">';
    h += _epMetric('Total', d.total_controls || 0, '#3498db');
    h += _epMetric('Pass', d.pass_count || 0, '#2ecc71');
    h += _epMetric('Fail', d.fail_count || 0, '#e74c3c');
    h += _epMetric('Not Assessed', d.not_assessed || 0, '#95a5a6');
    h += '</div>';

    var cats = d.categories || [];
    for (var ci = 0; ci < cats.length; ci++) {
        var cat = cats[ci];
        var catName = cat.name || ('Category ' + (ci + 1));
        var controls = cat.controls || [];
        var cPass = cat.pass_count || 0;
        var cFail = cat.fail_count || 0;
        var cNA = cat.not_assessed || 0;
        var cTotal = controls.length || 1;
        var secColor = cFail === 0 ? '#2ecc71' : cPass > cFail ? '#f39c12' : '#e74c3c';

        var inner = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">';
        inner += '<span style="font-weight:600">' + esc(catName) + '</span>';
        inner += '<span style="padding:2px 8px;border-radius:10px;background:' + secColor + ';color:#fff;font-size:12px">' + cPass + '/' + cTotal + '</span>';
        if (cNA) inner += '<span style="padding:2px 6px;border-radius:10px;background:#555;color:#aaa;font-size:11px">' + cNA + ' N/A</span>';
        inner += '</div>';

        inner += '<table style="width:100%;border-collapse:collapse;font-size:13px">';
        inner += '<tr style="border-bottom:1px solid var(--border-color,#333)">';
        inner += '<th style="text-align:left;padding:6px;color:var(--text-secondary)">ID</th>';
        inner += '<th style="text-align:left;padding:6px;color:var(--text-secondary)">Control</th>';
        inner += '<th style="padding:6px;color:var(--text-secondary)">Severity</th>';
        inner += '<th style="padding:6px;color:var(--text-secondary)">Status</th>';
        inner += '<th style="text-align:left;padding:6px;color:var(--text-secondary)">Current</th>';
        inner += '<th style="text-align:left;padding:6px;color:var(--text-secondary)">Expected</th>';
        inner += '</tr>';

        for (var ri = 0; ri < controls.length; ri++) {
            var r = controls[ri];
            var st = (r.status || 'Not Assessed').toUpperCase();
            var sc = st === 'PASS' ? '#2ecc71' : st === 'FAIL' ? '#e74c3c' : '#95a5a6';
            var rowBg = st === 'FAIL' ? 'rgba(231,76,60,0.06)' : 'transparent';
            inner += '<tr style="border-bottom:1px solid var(--border-color,#222);background:' + rowBg + '">';
            inner += '<td style="padding:5px 6px;color:#888;font-family:monospace;font-size:12px;white-space:nowrap">' + esc(r.id || '') + '</td>';
            inner += '<td style="padding:5px 6px">' + esc(r.title || '') + '</td>';
            inner += '<td style="padding:5px 6px;text-align:center"><span style="padding:1px 6px;border-radius:3px;background:#2a2a3e;color:#aaa;font-size:11px">' + esc(r.severity || '') + '</span></td>';
            inner += '<td style="padding:5px 6px;text-align:center"><span style="padding:2px 10px;border-radius:4px;background:' + sc + ';color:#fff;font-size:12px;font-weight:600">' + esc(r.status || 'N/A') + '</span></td>';
            inner += '<td style="padding:5px 6px;font-family:monospace;font-size:12px">' + esc(r.current_value != null ? String(r.current_value) : '') + '</td>';
            inner += '<td style="padding:5px 6px;color:#888;font-family:monospace;font-size:12px">' + esc(r.expected_value != null ? String(r.expected_value) : '') + '</td>';
            inner += '</tr>';
            if (st === 'FAIL' && r.remediation) {
                inner += '<tr style="background:rgba(231,76,60,0.04)"><td></td><td colspan="5" style="padding:4px 6px 8px;font-size:12px;color:#f39c12"><strong>Fix:</strong> ' + esc(r.remediation) + '</td></tr>';
            }
        }
        inner += '</table>';
        h += _epSection(catName + ' (' + cPass + '/' + cTotal + ')', inner);
    }

    return h;
}

function _renderEndpointCIS(data) { return _renderComplianceAssessment(data); }
function _renderEndpointNIST(data) { return _renderComplianceAssessment(data); }
function _renderEndpointSTIG(data) { return _renderComplianceAssessment(data); }

function _complianceScoreColor(score) {
    if (score >= 80) return '#2ecc71';
    if (score >= 60) return '#f39c12';
    if (score >= 40) return '#e67e22';
    return '#e74c3c';
}

function _complianceRatingBadge(rating) {
    var colors = {Good:'#2ecc71',Fair:'#f39c12',Poor:'#e67e22',Critical:'#e74c3c'};
    var c = colors[rating] || '#95a5a6';
    return '<span style="display:inline-block;padding:4px 14px;border-radius:4px;background:'+c+';color:#fff;font-weight:600;font-size:14px;">'+rating+'</span>';
}

function _complianceGauge(score) {
    var c = _complianceScoreColor(score);
    return '<div style="text-align:center;margin:12px 0;">' +
        '<div style="position:relative;display:inline-block;width:120px;height:120px;">' +
        '<svg width="120" height="120" viewBox="0 0 120 120">' +
        '<circle cx="60" cy="60" r="52" fill="none" stroke="#333" stroke-width="10"/>' +
        '<circle cx="60" cy="60" r="52" fill="none" stroke="'+c+'" stroke-width="10" ' +
        'stroke-dasharray="'+Math.round(score*3.27)+' 327" stroke-dashoffset="-81.75" ' +
        'stroke-linecap="round" transform="rotate(-90 60 60)"/>' +
        '</svg>' +
        '<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:26px;font-weight:700;color:'+c+';">'+score+'%</div>' +
        '</div></div>';
}

function _renderCookies(data) {
    var cookies = data.cookies;
    if (!cookies || typeof cookies !== 'object') return _renderIntelGeneric(data);
    var siteWide = cookies.site_wide || [];
    var perRole  = cookies.per_role  || {};
    var stats    = cookies.stats     || {};
    var allCk    = cookies.all       || [];
    if (!siteWide.length && !allCk.length && !Object.keys(perRole).length)
        return '<div class="empty-state"><div class="empty-state-text">No cookie data available. Run a scan with authentication enabled.</div></div>';

    var h = '';
    // Stats bar
    h += '<div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px">';
    var statItems = [
        ['Total Cookies', stats.total || 0],
        ['Site-Wide', stats.site_wide || 0],
        ['Role-Specific', stats.role_specific || 0],
        ['Missing HttpOnly', stats.missing_httponly || 0],
        ['Missing Secure', stats.missing_secure || 0],
        ['Missing SameSite', stats.missing_samesite || 0]
    ];
    for (var si = 0; si < statItems.length; si++) {
        var isWarn = si >= 3 && statItems[si][1] > 0;
        var statCol = isWarn ? 'var(--clr-high)' : 'var(--text-secondary)';
        h += '<div style="padding:10px 16px;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;min-width:120px;text-align:center">';
        h += '<div style="font-size:1.5rem;font-weight:700;color:' + statCol + '">' + statItems[si][1] + '</div>';
        h += '<div style="font-size:.75rem;color:var(--text-muted)">' + statItems[si][0] + '</div>';
        h += '</div>';
    }
    h += '</div>';

    function _ckFlag(val) {
        if (val === true) return '<span style="color:var(--clr-success)">✓</span>';
        if (val === false) return '<span style="color:var(--clr-high)">✗</span>';
        return '<span style="color:var(--text-muted)">—</span>';
    }
    function _ckExpiry(exp) {
        if (!exp && exp !== 0) return '<span style="color:var(--text-muted)">Session</span>';
        if (typeof exp === 'number') {
            try { return esc(new Date(exp * 1000).toISOString().slice(0, 19).replace('T', ' ')); } catch(e) {}
        }
        return esc(String(exp));
    }
    function _ckTable(items) {
        var t = '<div style="overflow-x:auto;max-height:50vh;overflow-y:auto"><table class="tool-table" style="width:100%"><thead><tr>';
        t += '<th>Name</th><th>Value</th><th>Domain</th><th>Path</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th><th>Expires</th>';
        if (items.length && items[0].roles) t += '<th>Roles</th>';
        t += '</tr></thead><tbody>';
        for (var ci = 0; ci < items.length; ci++) {
            var c = items[ci];
            var cv = c.value || '';
            var dv = cv.length > 50 ? cv.slice(0, 50) + '…' : cv;
            t += '<tr>';
            t += '<td style="font-family:var(--font-mono);white-space:nowrap">' + esc(c.name || '') + '</td>';
            t += '<td style="font-family:var(--font-mono);font-size:.78rem;max-width:200px;overflow:hidden;text-overflow:ellipsis" title="' + esc(cv) + '">' + esc(dv) + '</td>';
            t += '<td>' + esc(c.domain || '') + '</td>';
            t += '<td>' + esc(c.path || '') + '</td>';
            t += '<td style="text-align:center">' + _ckFlag(c.httpOnly) + '</td>';
            t += '<td style="text-align:center">' + _ckFlag(c.secure) + '</td>';
            t += '<td>' + esc(c.samesite || c.sameSite || '') + '</td>';
            t += '<td style="font-size:.75rem;color:var(--text-muted)">' + _ckExpiry(c.expires) + '</td>';
            if (c.roles) t += '<td style="font-size:.78rem">' + esc((c.roles || []).join(', ')) + '</td>';
            t += '</tr>';
        }
        t += '</tbody></table></div>';
        return t;
    }

    // Site-wide cookies
    if (siteWide.length) {
        h += '<div style="margin-bottom:24px">';
        h += '<div style="font-weight:600;font-size:1.05rem;margin-bottom:8px">Site-Wide Cookies <span style="color:var(--text-muted);font-weight:400;font-size:.85rem">(' + siteWide.length + ' — present across all authentication contexts)</span></div>';
        h += _ckTable(siteWide);
        h += '</div>';
    }

    // Per-role cookies
    var roleKeys = Object.keys(perRole);
    if (roleKeys.length) {
        h += '<div style="margin-bottom:24px">';
        h += '<div style="font-weight:600;font-size:1.05rem;margin-bottom:12px">Per-Role Cookies</div>';
        for (var ri = 0; ri < roleKeys.length; ri++) {
            var rk = roleKeys[ri];
            var rCookies = perRole[rk] || [];
            if (!rCookies.length) continue;
            h += '<div style="margin-bottom:16px">';
            h += '<div style="font-weight:500;margin-bottom:6px;padding:4px 8px;background:var(--bg-card);border-radius:4px;display:inline-block">' + esc(rk) + ' <span style="color:var(--text-muted)">(' + rCookies.length + ')</span></div>';
            h += _ckTable(rCookies);
            h += '</div>';
        }
        h += '</div>';
    }

    // All cookies (flat view)
    if (allCk.length && !siteWide.length && !roleKeys.length) {
        h += '<div style="margin-bottom:24px">';
        h += '<div style="font-weight:600;font-size:1.05rem;margin-bottom:8px">All Observed Cookies <span style="color:var(--text-muted);font-weight:400;font-size:.85rem">(' + allCk.length + ')</span></div>';
        h += _ckTable(allCk);
        h += '</div>';
    }

    return h;
}

/* ── Web Application Intelligence Renderer ───────────────────── */
function _renderWebappIntel(data) {
    var dns = data.dns;
    var infra = data.infrastructure || {};
    var tp = data.target_profile || {};
    if (!dns && !Object.keys(infra).length && !Object.keys(tp).length)
        return '<div class="empty-state"><div class="empty-state-text">No web application intelligence data available yet.<br>DNS resolution data will appear once Fracture begins testing.</div></div>';

    var h = '';

    /* ── DNS Resolution ────────────────── */
    if (dns) {
        h += '<div style="margin-bottom:20px">';
        h += '<div style="font-weight:600;font-size:15px;margin-bottom:10px">DNS Resolution</div>';
        h += '<div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:12px">';
        h += '<div style="padding:8px 14px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px">'
           + '<span style="color:var(--text-secondary)">Hostname:</span> <strong>' + esc(dns.hostname || '') + '</strong></div>';
        h += '<div style="padding:8px 14px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px">'
           + '<span style="color:var(--text-secondary)">Unique IPs:</span> <strong>' + (dns.total_unique_ips || 0) + '</strong></div>';
        var lbDet = dns.load_balancer_detected;
        var lbColor = lbDet ? 'var(--clr-medium)' : 'var(--clr-info)';
        h += '<div style="padding:8px 14px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px">'
           + '<span style="color:var(--text-secondary)">Load Balancer:</span> <strong style="color:' + lbColor + '">' + (lbDet ? 'Detected' : 'Not Detected') + '</strong></div>';
        if (dns.last_updated) {
            h += '<div style="padding:8px 14px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px">'
               + '<span style="color:var(--text-secondary)">Last Updated:</span> ' + esc(dns.last_updated) + '</div>';
        }
        h += '</div>';

        var ips = dns.resolved_ips || [];
        if (ips.length) {
            var rows = ips.map(function(entry) {
                var srcs = entry.sources || [];
                return [
                    '<span style="font-family:var(--font-mono)">' + esc(entry.ip || '') + '</span>',
                    esc(entry.first_seen || ''),
                    esc(entry.last_seen || ''),
                    srcs.map(function(s) {
                        return '<span style="display:inline-block;padding:2px 6px;margin:1px 2px;background:var(--bg-card);border:1px solid var(--border);border-radius:4px;font-size:12px">' + esc(s) + '</span>';
                    }).join(' ')
                ];
            });
            h += _intelTable(['IP Address', 'First Seen', 'Last Seen', 'Sources'], rows);
        }
        h += '</div>';
    }

    /* ── Infrastructure Summary ─────────── */
    var infraItems = [];
    if (infra.waf) infraItems.push(['WAF / Edge Security', esc(typeof infra.waf === 'object' ? JSON.stringify(infra.waf) : String(infra.waf))]);
    if (infra.edge_security) infraItems.push(['Edge Security', esc(String(infra.edge_security))]);
    if (infra.cdn) infraItems.push(['CDN', esc(String(infra.cdn))]);
    if (infra.load_balancer) infraItems.push(['Load Balancer', '<span style="color:var(--clr-medium)">Detected</span> (' + (infra.backend_ips || 0) + ' backend IPs)']);
    if (infra.tls_enabled !== undefined) infraItems.push(['TLS', infra.tls_enabled ? '<span style="color:var(--clr-low)">Enabled</span>' : '<span style="color:var(--clr-high)">Disabled</span>']);
    if (infra.tls_protocols) infraItems.push(['TLS Protocols', esc(Array.isArray(infra.tls_protocols) ? infra.tls_protocols.join(', ') : String(infra.tls_protocols))]);
    if (infra.cert_issuer) infraItems.push(['Certificate Issuer', esc(String(infra.cert_issuer))]);
    if (infra.cert_subject) infraItems.push(['Certificate Subject', esc(String(infra.cert_subject))]);
    if (infra.cert_expiry) infraItems.push(['Certificate Expiry', esc(String(infra.cert_expiry))]);
    if (infraItems.length) {
        h += _intelCard('Infrastructure', infraItems);
    }

    /* ── Target Profile extras ─────────── */
    var tpItems = [];
    if (tp.server) tpItems.push(['Server', esc(String(tp.server))]);
    if (tp.technologies && tp.technologies.length) tpItems.push(['Technologies', esc(tp.technologies.join(', '))]);
    if (tp.frameworks && tp.frameworks.length) tpItems.push(['Frameworks', esc(tp.frameworks.join(', '))]);
    if (tp.cms) tpItems.push(['CMS', esc(String(tp.cms))]);
    if (tp.programming_languages && tp.programming_languages.length) tpItems.push(['Languages', esc(tp.programming_languages.join(', '))]);
    if (tpItems.length) {
        h += _intelCard('Target Profile', tpItems);
    }

    return h || '<div class="empty-state"><div class="empty-state-text">No data available.</div></div>';
}

/* ── Hostname Intelligence Renderers ──────────────────────────── */
function _renderHostnameEnv(data) {
    var payload = data;
    if (!payload || !payload.hosts) return _renderIntelGeneric(data);
    var hosts = payload.hosts.filter(function(h) { return h.environment; });
    if (!hosts.length) return '<div class="empty-state"><div class="empty-state-text">No environment tiers inferred from hostnames.</div></div>';
    var summary = payload.summary && payload.summary.environments ? payload.summary.environments : {};
    var cards = Object.keys(summary).map(function(env) {
        var clr = env === 'Production' ? 'var(--clr-critical,#e53935)' : env === 'Disaster Recovery' ? 'var(--clr-high,#fb8c00)' : env === 'Pre-Production' ? 'var(--clr-medium,#fdd835)' : env === 'Test' || env === 'QA' || env === 'UAT' ? 'var(--clr-low,#43a047)' : 'var(--accent,#4a9eff)';
        return '<span style="display:inline-block;padding:6px 14px;margin:2px 4px;border-radius:6px;background:' + clr + ';color:#fff;font-size:0.9em;font-weight:600;white-space:nowrap">' + esc(env) + ' <strong>(' + summary[env] + ')</strong></span>';
    }).join('');
    var rows = hosts.map(function(h) {
        var envClr = h.environment === 'Production' ? 'var(--clr-critical,#e53935)' : h.environment === 'Disaster Recovery' ? 'var(--clr-high,#fb8c00)' : h.environment === 'Pre-Production' ? 'var(--clr-medium,#fdd835)' : 'var(--clr-low,#43a047)';
        return [
            '<span style="color:' + envClr + ';font-weight:600">' + esc(h.environment) + '</span>',
            '<span style="font-family:var(--font-mono);white-space:nowrap">' + esc(h.ip) + '</span>',
            '<span style="white-space:nowrap">' + esc(h.hostname) + '</span>',
            '<span style="font-size:0.9em">' + esc(h.environment_evidence || '') + '</span>',
            esc(h.domain || '')
        ];
    });
    return '<div style="margin-bottom:8px;font-weight:600">Environment Map (' + hosts.length + ' hosts classified)</div>' +
        '<div style="margin-bottom:12px">' + cards + '</div>' +
        '<div style="overflow-x:auto;max-height:70vh;overflow-y:auto"><table class="tool-table" style="width:100%;min-width:700px"><thead><tr>' +
        '<th>Environment</th><th>IP</th><th>Hostname</th><th>Evidence</th><th>Domain</th></tr></thead><tbody>' +
        rows.map(function(r) { return '<tr>' + r.map(function(c) { return '<td>' + (c||'') + '</td>'; }).join('') + '</tr>'; }).join('') +
        '</tbody></table></div>';
}

function _renderHostnameApps(data) {
    var payload = data;
    if (!payload || !payload.hosts) return _renderIntelGeneric(data);
    var hosts = payload.hosts.filter(function(h) { return h.applications && h.applications.length; });
    if (!hosts.length) return '<div class="empty-state"><div class="empty-state-text">No applications identified from hostnames.</div></div>';
    var summary = payload.summary && payload.summary.applications ? payload.summary.applications : {};
    var cards = Object.keys(summary).map(function(app) {
        return '<span style="display:inline-block;padding:4px 10px;margin:2px 4px;border-radius:4px;background:var(--accent,#4a9eff);color:#fff;font-size:0.85em;white-space:nowrap">' + esc(app) + ' <strong>(' + summary[app] + ')</strong></span>';
    }).join('');
    var rows = [];
    hosts.forEach(function(h) {
        h.applications.forEach(function(a) {
            rows.push([
                '<strong style="white-space:nowrap">' + esc(a.name) + '</strong>',
                '<span style="white-space:nowrap;color:var(--text-secondary)">' + esc(a.category) + '</span>',
                '<span style="font-family:var(--font-mono);white-space:nowrap">' + esc(h.ip) + '</span>',
                '<span style="white-space:nowrap">' + esc(h.hostname) + '</span>',
                esc(h.environment || ''),
                '<span style="font-size:0.9em">' + esc(a.evidence || '') + '</span>'
            ]);
        });
    });
    return '<div style="margin-bottom:8px;font-weight:600">Application Inventory (' + rows.length + ' detections across ' + Object.keys(summary).length + ' products)</div>' +
        '<div style="margin-bottom:12px">' + cards + '</div>' +
        '<div style="overflow-x:auto;max-height:70vh;overflow-y:auto"><table class="tool-table" style="width:100%;min-width:800px"><thead><tr>' +
        '<th>Application</th><th>Category</th><th>IP</th><th>Hostname</th><th>Environment</th><th>Evidence</th></tr></thead><tbody>' +
        rows.map(function(r) { return '<tr>' + r.map(function(c) { return '<td>' + (c||'') + '</td>'; }).join('') + '</tr>'; }).join('') +
        '</tbody></table></div>';
}

function _renderHostnameHw(data) {
    var payload = data;
    if (!payload || !payload.hosts) return _renderIntelGeneric(data);
    var hosts = payload.hosts.filter(function(h) { return h.hardware; });
    if (!hosts.length) return '<div class="empty-state"><div class="empty-state-text">No hardware models identified from hostnames.</div></div>';
    var summary = payload.summary && payload.summary.hardware_models ? payload.summary.hardware_models : {};
    var cards = Object.keys(summary).map(function(hw) {
        return '<span style="display:inline-block;padding:4px 10px;margin:2px 4px;border-radius:4px;background:var(--accent,#4a9eff);color:#fff;font-size:0.85em;white-space:nowrap">' + esc(hw) + ' <strong>(' + summary[hw] + ')</strong></span>';
    }).join('');
    var rows = hosts.map(function(h) {
        return [
            '<strong style="white-space:nowrap">' + esc(h.hardware.model) + '</strong>',
            '<span style="white-space:nowrap">' + esc(h.hardware.manufacturer) + '</span>',
            '<span style="font-family:var(--font-mono);white-space:nowrap">' + esc(h.ip) + '</span>',
            '<span style="white-space:nowrap">' + esc(h.hostname) + '</span>',
            esc(h.environment || ''),
            '<span style="font-size:0.9em">' + esc(h.hardware.evidence || '') + '</span>'
        ];
    });
    return '<div style="margin-bottom:8px;font-weight:600">Hardware Inventory (' + hosts.length + ' hosts with identified hardware)</div>' +
        '<div style="margin-bottom:12px">' + cards + '</div>' +
        '<div style="overflow-x:auto;max-height:70vh;overflow-y:auto"><table class="tool-table" style="width:100%;min-width:800px"><thead><tr>' +
        '<th>Model</th><th>Manufacturer</th><th>IP</th><th>Hostname</th><th>Environment</th><th>Evidence</th></tr></thead><tbody>' +
        rows.map(function(r) { return '<tr>' + r.map(function(c) { return '<td>' + (c||'') + '</td>'; }).join('') + '</tr>'; }).join('') +
        '</tbody></table></div>';
}

function _renderNetPosture(data) {
    if (!data || !data.subnets || !data.subnets.length) return '<div class="empty-state"><div class="empty-state-text">No network posture data available. Port scan results with state breakdowns are required.</div></div>';
    var segCount = data.segmented_count || 0;
    var subCount = data.subnet_count || 0;
    var summaryCards = '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">' +
        '<span style="display:inline-block;padding:6px 14px;border-radius:6px;background:var(--accent,#4a9eff);color:#fff;font-weight:600">' + subCount + ' Subnet' + (subCount !== 1 ? 's' : '') + '</span>';
    if (segCount > 0) {
        summaryCards += '<span style="display:inline-block;padding:6px 14px;border-radius:6px;background:var(--clr-high,#fb8c00);color:#fff;font-weight:600">' + segCount + ' Segmented</span>';
    }
    summaryCards += '</div>';
    var subnetBlocks = data.subnets.map(function(s) {
        var segBadge = s.segmented ? '<span style="display:inline-block;padding:2px 8px;border-radius:4px;background:var(--clr-high,#fb8c00);color:#fff;font-size:0.8em;margin-left:8px">SEGMENTED</span>' : '';
        var barTotal = s.host_count || 1;
        var openPct = (s.open_hosts / barTotal * 100).toFixed(0);
        var filtPct = (s.filtered_hosts / barTotal * 100).toFixed(0);
        var closedPct = (s.closed_hosts / barTotal * 100).toFixed(0);
        var bar = '<div style="display:flex;height:8px;border-radius:4px;overflow:hidden;margin:6px 0 10px">' +
            (s.open_hosts ? '<div style="width:' + openPct + '%;background:var(--clr-low,#43a047)" title="Open: ' + s.open_hosts + '"></div>' : '') +
            (s.closed_hosts ? '<div style="width:' + closedPct + '%;background:var(--accent,#4a9eff)" title="Closed: ' + s.closed_hosts + '"></div>' : '') +
            (s.filtered_hosts ? '<div style="width:' + filtPct + '%;background:var(--clr-high,#fb8c00)" title="Filtered: ' + s.filtered_hosts + '"></div>' : '') +
            '</div>';
        var legend = '<div style="display:flex;gap:12px;font-size:0.85em;margin-bottom:6px">' +
            '<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--clr-low,#43a047);vertical-align:middle;margin-right:4px"></span>Open: ' + s.open_hosts + '</span>' +
            '<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--accent,#4a9eff);vertical-align:middle;margin-right:4px"></span>Closed: ' + s.closed_hosts + '</span>' +
            '<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:var(--clr-high,#fb8c00);vertical-align:middle;margin-right:4px"></span>Filtered: ' + s.filtered_hosts + '</span>' +
            '</div>';
        var rows = (s.hosts || []).map(function(h) {
            var pClr = h.posture === 'filtered' ? 'var(--clr-high,#fb8c00)' : h.posture === 'open' ? 'var(--clr-low,#43a047)' : 'var(--accent,#4a9eff)';
            var pLabel = h.posture === 'filtered' ? 'Filtered' : h.posture === 'open' ? 'Open (' + h.open_port_count + ' svc)' : 'Closed';
            return '<tr>' +
                '<td style="font-family:var(--font-mono);white-space:nowrap">' + esc(h.ip) + '</td>' +
                '<td style="white-space:nowrap">' + esc(h.hostname || '') + '</td>' +
                '<td><span style="color:' + pClr + ';font-weight:600">' + pLabel + '</span></td>' +
                '<td style="text-align:right">' + h.open + '</td>' +
                '<td style="text-align:right">' + h.closed + '</td>' +
                '<td style="text-align:right">' + h.filtered + '</td>' +
                '<td style="text-align:right">' + h.scanned + '</td></tr>';
        }).join('');
        return '<div style="border:1px solid var(--border,#333);border-radius:8px;padding:12px;margin-bottom:12px">' +
            '<div style="font-weight:700;font-size:1.05em;font-family:var(--font-mono)">' + esc(s.cidr) + ' <span style="font-weight:400;font-size:0.9em;color:var(--text-secondary)">(' + s.host_count + ' host' + (s.host_count !== 1 ? 's' : '') + ')</span>' + segBadge + '</div>' +
            bar + legend +
            '<div style="overflow-x:auto"><table class="tool-table" style="width:100%;min-width:600px"><thead><tr>' +
            '<th>IP</th><th>Hostname</th><th>Posture</th><th style="text-align:right">Open</th><th style="text-align:right">Closed</th><th style="text-align:right">Filtered</th><th style="text-align:right">Scanned</th></tr></thead>' +
            '<tbody>' + rows + '</tbody></table></div></div>';
    }).join('');
    return '<div style="margin-bottom:8px;font-weight:600">Network Posture</div>' + summaryCards + subnetBlocks;
}

/* ── Cloud Intelligence Renderers ─────────────────────────────── */

function _cloudRiskBadge(val) {
    if (val === null || val === undefined || val === '') return '';
    var s = String(val).toUpperCase();
    var m = {CRITICAL:'risk-critical',HIGH:'risk-high',MEDIUM:'risk-medium',LOW:'risk-low',INFO:'risk-info',OK:'risk-low'};
    if (m[s]) return '<span class="risk-badge ' + m[s] + '">' + esc(s) + '</span>';
    return esc(String(val));
}

function _cloudCountCell(val, riskLevel) {
    var n = parseInt(val, 10);
    if (isNaN(n) || n === 0) return '<span style="opacity:0.3">0</span>';
    var m = {critical:'risk-critical',high:'risk-high',medium:'risk-medium',low:'risk-low',info:'risk-info'};
    var cls = m[riskLevel] || '';
    return cls ? '<span class="risk-badge ' + cls + '">' + n + '</span>' : esc(String(n));
}

function _cloudStatusBadge(val) {
    var s = String(val || '');
    if (s === 'Issues Found') return '<span style="color:var(--risk-high);font-weight:600">' + esc(s) + '</span>';
    if (s === 'OK') return '<span style="color:var(--risk-low);font-weight:600">' + esc(s) + '</span>';
    if (s === 'Access Denied') return '<span style="color:var(--risk-medium);font-weight:600">' + esc(s) + '</span>';
    if (s === 'No Resources') return '<span style="opacity:0.5">' + esc(s) + '</span>';
    return esc(s);
}

function _cloudAccessBadge(val) {
    var s = String(val || '');
    if (s === 'Access Denied') return '<span style="color:var(--risk-medium);font-weight:600">' + esc(s) + '</span>';
    if (s === 'Allowed') return '<span style="color:var(--risk-low)">' + esc(s) + '</span>';
    return esc(s);
}

function _cloudTable(headers, colKeys, rows, formatters) {
    var h = '<div style="overflow-x:auto;max-height:70vh;overflow-y:auto"><table class="tool-table" style="width:100%"><thead><tr>';
    headers.forEach(function(hd) { h += '<th>' + esc(hd) + '</th>'; });
    h += '</tr></thead><tbody>';
    rows.forEach(function(obj) {
        h += '<tr>';
        colKeys.forEach(function(k, ci) {
            var v = obj[k];
            var fmt = formatters[k];
            var cell = fmt ? fmt(v, k) : (v != null ? esc(String(v)) : '');
            var s = ci === 0 ? ' style="font-weight:600;white-space:nowrap"' : '';
            h += '<td' + s + '>' + cell + '</td>';
        });
        h += '</tr>';
    });
    h += '</tbody></table></div>';
    return h;
}

function _extractCloudPayload(data) {
    if (Array.isArray(data)) return data;
    if (typeof data === 'object' && data) {
        var keys = Object.keys(data).filter(function(k) { return k[0] !== '_' && k !== 'available'; });
        for (var i = 0; i < keys.length; i++) {
            if (Array.isArray(data[keys[i]])) return data[keys[i]];
        }
    }
    return null;
}

function _renderCloudServices(data) {
    var arr = _extractCloudPayload(data);
    if (!arr || !arr.length) return '<div class="empty-state"><div class="empty-state-text">No cloud service data available.</div></div>';
    var headers = ['Service', 'Status', 'Access', 'Findings', 'Resources', 'Critical', 'High', 'Medium', 'Low', 'Info'];
    var keys =    ['service', 'status', 'access', 'findings', 'resources', 'critical', 'high', 'medium', 'low', 'info'];
    var fmts = {
        status: _cloudStatusBadge,
        access: _cloudAccessBadge,
        critical: function(v) { return _cloudCountCell(v, 'critical'); },
        high: function(v) { return _cloudCountCell(v, 'high'); },
        medium: function(v) { return _cloudCountCell(v, 'medium'); },
        low: function(v) { return _cloudCountCell(v, 'low'); },
        info: function(v) { return _cloudCountCell(v, 'info'); },
        findings: function(v) { var n = parseInt(v,10); return isNaN(n)||n===0 ? '<span style="opacity:0.3">0</span>' : '<strong>'+n+'</strong>'; },
        resources: function(v) { var n = parseInt(v,10); return isNaN(n)||n===0 ? '<span style="opacity:0.3">0</span>' : String(n); },
    };
    return _cloudTable(headers, keys, arr, fmts);
}

function _renderCloudResources(data) {
    var arr = _extractCloudPayload(data);
    if (!arr || !arr.length) return '<div class="empty-state"><div class="empty-state-text">No cloud resource data available.</div></div>';
    var headers = ['Service', 'Name', 'Type', 'Resource ID', 'Region', 'Status', 'Findings', 'Risk'];
    var keys =    ['service', 'name', 'resource_type', 'resource_id', 'region', 'status', 'findings', 'risk'];
    var fmts = {
        risk: _cloudRiskBadge,
        findings: function(v) { var n = parseInt(v,10); return isNaN(n)||n===0 ? '<span style="opacity:0.3">0</span>' : '<strong>'+n+'</strong>'; },
        status: function(v) {
            var s = String(v||'');
            if (s === 'running' || s === 'active') return '<span style="color:var(--risk-low)">' + esc(s) + '</span>';
            if (s === 'stopped' || s === 'terminated') return '<span style="color:var(--risk-medium)">' + esc(s) + '</span>';
            return esc(s);
        },
    };
    return _cloudTable(headers, keys, arr, fmts);
}

function _renderCloudIAM(data) {
    var arr = _extractCloudPayload(data);
    if (!arr || !arr.length) return '<div class="empty-state"><div class="empty-state-text">No IAM data available.</div></div>';
    var headers = ['User', 'Password', 'MFA', 'Keys', 'Active Keys', 'Policies', 'Findings', 'Risk', 'Last Login'];
    var keys =    ['user', 'password_enabled', 'mfa_active', 'access_keys', 'active_keys', 'policies', 'findings', 'risk', 'last_login'];
    var fmts = {
        risk: _cloudRiskBadge,
        findings: function(v) { var n = parseInt(v,10); return isNaN(n)||n===0 ? '<span style="opacity:0.3">0</span>' : '<strong>'+n+'</strong>'; },
        mfa_active: function(v) {
            var s = String(v||'').toLowerCase();
            if (s === 'true') return '<span style="color:var(--risk-low);font-weight:600">true</span>';
            if (s === 'false') return '<span style="color:var(--risk-high);font-weight:600">false</span>';
            return esc(String(v||''));
        },
        password_enabled: function(v) {
            var s = String(v||'').toLowerCase();
            if (s === 'true') return '<span style="font-weight:600">true</span>';
            if (s === 'false') return '<span style="opacity:0.5">false</span>';
            return esc(String(v||''));
        },
    };
    return _cloudTable(headers, keys, arr, fmts);
}

/* ── Mobile Intelligence Tab Renderers ────────────────────────── */

function _mobileAppBadge(app) {
    var p = (app.platform || '').toLowerCase();
    var color = p === 'ios' ? '#007AFF' : p === 'android' ? '#3DDC84' : 'var(--text-secondary)';
    var label = p === 'ios' ? 'iOS' : p === 'android' ? 'Android' : (app.platform || 'Unknown');
    return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600;' +
        'background:' + color + '20;color:' + color + ';margin-left:6px">' + label + '</span>';
}

function _mobileAppHeader(app) {
    return '<div style="margin:16px 0 8px;padding:10px 14px;background:var(--bg-card);border:1px solid var(--border);' +
        'border-radius:8px;display:flex;align-items:center;gap:8px">' +
        '<span style="font-weight:700;font-size:0.95rem">' + esc(app.name || 'Unknown App') + '</span>' +
        _mobileAppBadge(app) +
        (app['package'] ? '<span style="font-size:0.75rem;color:var(--text-secondary);font-family:var(--font-mono);margin-left:auto">' + esc(app['package']) + '</span>' : '') +
        '</div>';
}

function _mobileExtractPayload(data, key) {
    var d = data[key] || data;
    if (!d) return null;
    if (d.apps && Array.isArray(d.apps)) return d;
    if (Array.isArray(d)) return {apps: d};
    return d;
}

function _renderMobileComponents(data) {
    var d = _mobileExtractPayload(data, 'mobile_components');
    if (!d || !d.apps || !d.apps.length) return '<div class="empty-state"><div class="empty-state-text">No component data available. Run Quill to populate.</div></div>';
    var h = '';
    d.apps.forEach(function(app) {
        h += _mobileAppHeader(app);
        var flags = app.flags || {};
        if (Object.keys(flags).length) {
            var flagItems = [];
            if (flags.debuggable !== undefined) flagItems.push(['Debuggable', flags.debuggable ? '<span style="color:var(--clr-critical);font-weight:600">true</span>' : '<span style="color:var(--clr-low)">false</span>']);
            if (flags.allowBackup !== undefined) flagItems.push(['Allow Backup', flags.allowBackup ? '<span style="color:var(--clr-high);font-weight:600">true</span>' : '<span style="color:var(--clr-low)">false</span>']);
            if (flags.usesCleartextTraffic !== undefined) flagItems.push(['Cleartext Traffic', flags.usesCleartextTraffic ? '<span style="color:var(--clr-high);font-weight:600">true</span>' : '<span style="color:var(--clr-low)">false</span>']);
            if (flags.networkSecurityConfig !== undefined) flagItems.push(['Network Security Config', flags.networkSecurityConfig ? '<span style="color:var(--clr-low)">' + esc(flags.networkSecurityConfig) + '</span>' : '<span style="color:var(--text-secondary)">none</span>']);
            if (flags.ats_enabled !== undefined) flagItems.push(['App Transport Security', flags.ats_enabled ? '<span style="color:var(--clr-low)">Configured</span>' : '<span style="color:var(--clr-high);font-weight:600">Not configured</span>']);
            if (flags.allows_arbitrary_loads !== undefined) flagItems.push(['Allows Arbitrary Loads', flags.allows_arbitrary_loads ? '<span style="color:var(--clr-high);font-weight:600">true</span>' : '<span style="color:var(--clr-low)">false</span>']);
            if (flags.minSdkVersion) flagItems.push(['Min SDK', esc(String(flags.minSdkVersion))]);
            if (flags.targetSdkVersion) flagItems.push(['Target SDK', esc(String(flags.targetSdkVersion))]);
            h += _intelCard('Application Flags', flagItems);
        }
        var components = app.components || [];
        if (components.length) {
            var exported = components.filter(function(c) { return c.exported; });
            var unprotected = exported.filter(function(c) { return !c.permission; });
            h += '<div style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:6px">' + components.length + ' components — <span style="color:var(--clr-medium)">' + exported.length + ' exported</span>' + (unprotected.length ? ' — <span style="color:var(--clr-high)">' + unprotected.length + ' unprotected</span>' : '') + '</div>';
            var rows = components.map(function(c) {
                var expCell = c.exported ? (!c.permission ? '<span style="color:var(--clr-high);font-weight:600">Yes (unprotected)</span>' : '<span style="color:var(--clr-medium)">Yes</span>') : '<span style="color:var(--text-secondary)">No</span>';
                return [esc(c.type || ''), '<span style="font-family:var(--font-mono);font-size:0.8rem">' + esc(c.name || '') + '</span>', expCell, c.permission ? esc(c.permission) : '<span style="color:var(--text-secondary)">—</span>', c.has_intent_filter ? 'Yes' : ''];
            });
            h += _intelTable(['Type', 'Name', 'Exported', 'Permission', 'Intent Filter'], rows);
        } else if ((app.platform || '').toLowerCase() === 'ios') {
            var ents = app.entitlements || [];
            if (ents.length) {
                h += '<div style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:6px">' + ents.length + ' entitlements</div>';
                var eRows = ents.map(function(e) { return [esc(e)]; });
                h += _intelTable(['Entitlement Key'], eRows);
            } else {
                h += '<div style="color:var(--text-secondary);padding:8px;font-size:0.85rem">No entitlements detected.</div>';
            }
        }
    });
    return h;
}

function _renderMobilePerms(data) {
    var d = _mobileExtractPayload(data, 'mobile_perms');
    if (!d || !d.apps || !d.apps.length) return '<div class="empty-state"><div class="empty-state-text">No permission data available. Run Quill to populate.</div></div>';
    var h = '';
    d.apps.forEach(function(app) {
        h += _mobileAppHeader(app);
        var perms = app.permissions || [];
        var dangerous = app.dangerous_count || 0;
        var total = app.total || perms.length;
        var platform = (app.platform || '').toLowerCase();
        h += '<div style="display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap">';
        h += _epMetric('Total', total, 'var(--text-primary)');
        h += _epMetric('Dangerous', dangerous, dangerous > 0 ? 'var(--clr-high)' : 'var(--clr-low)');
        h += _epMetric('Normal', total - dangerous, 'var(--text-secondary)');
        h += '</div>';
        if (perms.length) {
            var rows = perms.map(function(p) {
                var name = p.key || p.name || '';
                var isDangerous = p.dangerous !== undefined ? p.dangerous : (platform === 'ios' && p.key && /Camera|Microphone|Location|Contacts|Calendar|Photo|Health|Motion|FaceID/i.test(p.key));
                var dangerCell = isDangerous ? '<span style="color:var(--clr-high);font-weight:600">Dangerous</span>' : '<span style="color:var(--text-secondary)">Normal</span>';
                return ['<span style="font-family:var(--font-mono);font-size:0.8rem">' + esc(name) + '</span>', dangerCell, p.reason ? esc(p.reason) : '<span style="color:var(--text-secondary)">—</span>'];
            });
            h += _intelTable(['Permission', 'Classification', 'Reason / Description'], rows);
        }
    });
    return h;
}

function _renderMobileHardening(data) {
    var d = _mobileExtractPayload(data, 'mobile_hardening');
    if (!d || !d.apps || !d.apps.length) return '<div class="empty-state"><div class="empty-state-text">No hardening data available. Run Quill to populate.</div></div>';
    var h = '';
    d.apps.forEach(function(app) {
        h += _mobileAppHeader(app);
        var checks = app.checks || [];
        if (!checks.length) { h += '<div style="color:var(--text-secondary);padding:8px;font-size:0.85rem">No binary hardening checks available for this application.</div>'; return; }
        var pass = 0, fail = 0, skip = 0;
        checks.forEach(function(c) { var s = (c.status || '').toLowerCase(); if (s === 'pass' || s === 'enabled' || s === 'true' || s === 'yes') pass++; else if (s === 'fail' || s === 'disabled' || s === 'false' || s === 'no' || s === 'missing') fail++; else skip++; });
        var total = checks.length;
        h += '<div style="display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap">';
        h += _epMetric('Pass', pass, 'var(--risk-low,#38a169)');
        h += _epMetric('Fail', fail, fail > 0 ? 'var(--risk-high,#e53e3e)' : 'var(--text-secondary)');
        if (skip > 0) h += _epMetric('Skipped', skip, 'var(--text-secondary)');
        h += '</div>';
        if (total > 0) {
            var pPass = Math.round((pass / total) * 100), pFail = Math.round((fail / total) * 100), pSkip = 100 - pPass - pFail;
            h += '<div style="height:10px;border-radius:5px;overflow:hidden;display:flex;background:var(--border-color,#e2e8f0);margin-bottom:12px">';
            if (pPass > 0) h += '<div style="width:' + pPass + '%;background:var(--risk-low,#38a169)"></div>';
            if (pFail > 0) h += '<div style="width:' + pFail + '%;background:var(--risk-high,#e53e3e)"></div>';
            if (pSkip > 0) h += '<div style="width:' + pSkip + '%;background:var(--text-secondary,#a0aec0)"></div>';
            h += '</div>';
        }
        var rows = checks.map(function(c) {
            var s = (c.status || '').toLowerCase();
            var icon = (s === 'pass' || s === 'enabled' || s === 'true' || s === 'yes') ? '<span style="color:var(--risk-low,#38a169);font-weight:600">Pass</span>' : (s === 'fail' || s === 'disabled' || s === 'false' || s === 'no' || s === 'missing') ? '<span style="color:var(--risk-high,#e53e3e);font-weight:600">Fail</span>' : '<span style="color:var(--text-secondary)">' + esc(c.status || 'N/A') + '</span>';
            return [esc(c.name || ''), icon, c.details ? esc(c.details) : '<span style="color:var(--text-secondary)">—</span>'];
        });
        h += _intelTable(['Check', 'Status', 'Details'], rows);
    });
    return h;
}

function _renderMobileData(data) {
    var d = _mobileExtractPayload(data, 'mobile_data');
    if (!d || !d.apps || !d.apps.length) return '<div class="empty-state"><div class="empty-state-text">No data flow analysis available. Run Quill to populate.</div></div>';
    var h = '';
    d.apps.forEach(function(app) {
        h += _mobileAppHeader(app);
        var netCfg = app.network_config || app.network_security_config;
        if (netCfg && typeof netCfg === 'object') {
            var cfgItems = [];
            if (netCfg.cleartextTrafficPermitted !== undefined) cfgItems.push(['Cleartext Permitted', netCfg.cleartextTrafficPermitted ? '<span style="color:var(--clr-high);font-weight:600">Yes</span>' : '<span style="color:var(--clr-low)">No</span>']);
            if (netCfg.ats_enabled !== undefined) cfgItems.push(['App Transport Security', netCfg.ats_enabled ? '<span style="color:var(--clr-low)">Enabled</span>' : '<span style="color:var(--clr-high);font-weight:600">Disabled</span>']);
            if (netCfg.allows_arbitrary_loads !== undefined) cfgItems.push(['Allows Arbitrary Loads', netCfg.allows_arbitrary_loads ? '<span style="color:var(--clr-high);font-weight:600">Yes</span>' : '<span style="color:var(--clr-low)">No</span>']);
            if (netCfg.exception_domains) cfgItems.push(['Exception Domains', esc((netCfg.exception_domains || []).join(', ') || 'none')]);
            if (netCfg.base_config) cfgItems.push(['Base Config', esc(JSON.stringify(netCfg.base_config))]);
            if (netCfg.domain_configs) cfgItems.push(['Domain Configs', esc(String(netCfg.domain_configs.length || 0)) + ' rules']);
            if (netCfg.pin_set) cfgItems.push(['Certificate Pinning', '<span style="color:var(--clr-low)">Configured</span>']);
            if (cfgItems.length) h += _intelCard('Network Security Configuration', cfgItems);
        }
        var deepLinks = app.deep_links || [];
        if (deepLinks.length) {
            h += '<div style="font-weight:600;margin:12px 0 6px;font-size:0.9rem">Deep Links (' + deepLinks.length + ')</div>';
            var dlRows = deepLinks.map(function(dl) {
                if (typeof dl === 'string') return [esc(dl), '', ''];
                return ['<span style="font-family:var(--font-mono);font-size:0.8rem">' + esc(dl.scheme || dl.url || dl.host || '') + '</span>', esc(dl.host || ''), esc(dl.path || dl.pathPrefix || dl.pathPattern || '')];
            });
            h += _intelTable(['Scheme / URL', 'Host', 'Path'], dlRows);
        }
        var firebase = app.firebase;
        if (firebase && typeof firebase === 'object' && Object.keys(firebase).length) {
            var fbItems = [];
            if (firebase.database_url) fbItems.push(['Database URL', '<span style="font-family:var(--font-mono);font-size:0.8rem">' + esc(firebase.database_url) + '</span>']);
            if (firebase.api_key) fbItems.push(['API Key', '<span style="font-family:var(--font-mono);font-size:0.8rem;color:var(--clr-high)">' + esc(firebase.api_key) + '</span>']);
            if (firebase.project_id) fbItems.push(['Project ID', esc(firebase.project_id)]);
            if (firebase.storage_bucket) fbItems.push(['Storage Bucket', esc(firebase.storage_bucket)]);
            if (firebase.open_database !== undefined) fbItems.push(['Database Open', firebase.open_database ? '<span style="color:var(--clr-critical);font-weight:600">Yes (publicly accessible)</span>' : '<span style="color:var(--clr-low)">No</span>']);
            if (fbItems.length) h += _intelCard('Firebase Configuration', fbItems);
        }
        var trackers = app.trackers || [];
        if (trackers.length) {
            h += '<div style="font-weight:600;margin:12px 0 6px;font-size:0.9rem">Trackers / Third-Party SDKs (' + trackers.length + ')</div>';
            var trRows = trackers.map(function(tr) {
                if (typeof tr === 'string') return [esc(tr), '', ''];
                return [esc(tr.name || tr.id || ''), esc(tr.category || ''), tr.url ? '<a href="' + esc(tr.url) + '" target="_blank" rel="noopener">' + esc(tr.url) + '</a>' : ''];
            });
            h += _intelTable(['Tracker', 'Category', 'Reference'], trRows);
        }
        if (!netCfg && !deepLinks.length && !(firebase && Object.keys(firebase).length) && !trackers.length) {
            h += '<div style="color:var(--text-secondary);padding:8px;font-size:0.85rem">No data flow analysis results for this application.</div>';
        }
    });
    return h;
}

function _renderMobileDomains(data) {
    var d = _mobileExtractPayload(data, 'mobile_domains');
    if (!d || !d.apps || !d.apps.length) return '<div class="empty-state"><div class="empty-state-text">No domain/URL data available. Run Quill to populate.</div></div>';
    var h = '';
    d.apps.forEach(function(app) {
        h += _mobileAppHeader(app);
        h += '<div style="display:flex;gap:16px;margin-bottom:12px;flex-wrap:wrap">';
        h += '<div style="background:var(--bg-secondary);padding:8px 14px;border-radius:6px"><span style="font-size:1.3rem;font-weight:700">' + (app.unique_domains || 0) + '</span><div style="font-size:0.75rem;color:var(--text-secondary)">Unique Domains</div></div>';
        h += '<div style="background:var(--bg-secondary);padding:8px 14px;border-radius:6px"><span style="font-size:1.3rem;font-weight:700">' + (app.unique_urls || 0) + '</span><div style="font-size:0.75rem;color:var(--text-secondary)">Unique URLs</div></div>';
        h += '</div>';
        var domains = app.domains || [];
        if (domains.length) {
            h += '<div style="font-weight:600;margin:12px 0 6px;font-size:0.9rem">Top Domains (' + domains.length + ')</div>';
            var domRows = domains.slice(0, 200).map(function(d) {
                return ['<span style="font-family:var(--font-mono);font-size:0.8rem">' + esc(d.domain || '') + '</span>', String(d.count || 0)];
            });
            h += _intelTable(['Domain', 'References'], domRows);
        }
        var urls = app.urls || [];
        if (urls.length) {
            h += '<div style="font-weight:600;margin:12px 0 6px;font-size:0.9rem">URLs (' + urls.length + (urls.length >= 500 ? '+' : '') + ')</div>';
            var urlRows = urls.slice(0, 200).map(function(u) {
                return ['<span style="font-family:var(--font-mono);font-size:0.78rem;word-break:break-all">' + esc(u) + '</span>'];
            });
            h += _intelTable(['URL'], urlRows);
        }
        if (!domains.length && !urls.length) {
            h += '<div style="color:var(--text-secondary);padding:8px;font-size:0.85rem">No domains or URLs detected in this application.</div>';
        }
    });
    return h;
}

function _renderMobileEmails(data) {
    var d = _mobileExtractPayload(data, 'mobile_emails');
    if (!d || !d.apps || !d.apps.length) return '<div class="empty-state"><div class="empty-state-text">No email data available. Run Quill to populate.</div></div>';
    var h = '';
    d.apps.forEach(function(app) {
        h += _mobileAppHeader(app);
        h += '<div style="background:var(--bg-secondary);padding:8px 14px;border-radius:6px;margin-bottom:12px;display:inline-block"><span style="font-size:1.3rem;font-weight:700">' + (app.unique_emails || 0) + '</span><div style="font-size:0.75rem;color:var(--text-secondary)">Unique Emails</div></div>';
        var emails = app.emails || [];
        if (emails.length) {
            var emRows = emails.map(function(e) {
                var parts = e.split('@');
                return ['<span style="font-family:var(--font-mono);font-size:0.8rem">' + esc(e) + '</span>', parts.length > 1 ? esc(parts[1]) : ''];
            });
            h += _intelTable(['Email Address', 'Domain'], emRows);
        } else {
            h += '<div style="color:var(--text-secondary);padding:8px;font-size:0.85rem">No email addresses detected in this application.</div>';
        }
    });
    return h;
}


function _renderMitmCert(data) {
    var h = '<div style="margin-bottom:20px"><h3 style="margin:0 0 4px 0;font-size:1.1rem">MITM Proxy CA Certificate</h3>' +
        '<div style="color:var(--text-secondary);font-size:0.85rem">Auto-generated by Quill when a MITM capture starts. ' +
        'Install this CA on the device under test so it trusts intercepted traffic.</div></div>';

    if (!data || !data.available || !data.pem) {
        h += '<div class="empty-state"><div class="empty-state-text">' +
            'No mitmproxy CA certificate found.<br>' +
            '<span style="font-size:0.85rem;color:var(--text-secondary)">Start a Quill MITM capture first — the certificate is auto-generated and copied to the project on capture start.</span>' +
            '</div></div>';
        return h;
    }

    /* ── Certificate card ── */
    h += '<div style="background:var(--bg-card,var(--bg-secondary));border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px">';
    h += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">';
    h += '<div style="width:44px;height:44px;border-radius:8px;background:var(--clr-accent,#4a90d9);display:flex;align-items:center;justify-content:center;font-size:1.5rem;color:#fff">🔐</div>';
    h += '<div><div style="font-weight:600;font-size:1rem">mitmproxy-ca-cert.pem</div>';
    h += '<div style="font-size:0.8rem;color:var(--text-secondary)">PEM-encoded X.509 CA certificate</div></div></div>';

    h += '<div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">';
    h += '<a href="/api/intel/mitm-cert/' + PID + '/download" class="btn btn-primary" style="text-decoration:none;display:inline-flex;align-items:center;gap:6px">' +
         '<span style="font-size:1.1em">⬇</span> Download PEM</a>';
    h += '<button onclick="_copyMitmCertPem()" class="btn btn-secondary" style="display:inline-flex;align-items:center;gap:6px">' +
         '<span style="font-size:1.1em">📋</span> Copy PEM to Clipboard</button>';
    h += '</div>';

    h += '<details><summary style="cursor:pointer;font-size:0.85rem;color:var(--text-secondary);user-select:none">Show certificate PEM</summary>';
    h += '<pre id="mitmCertPem" style="margin-top:8px;padding:12px;background:var(--bg-code,var(--bg-tertiary,#1a1a2e));border:1px solid var(--border);border-radius:6px;' +
         'font-size:0.78rem;line-height:1.4;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto">' +
         esc(data.pem) + '</pre></details>';
    h += '</div>';

    /* ── Proxy chain reference ── */
    h += '<div style="background:var(--bg-card,var(--bg-secondary));border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px">';
    h += '<div style="font-weight:600;margin-bottom:4px">Proxy Chain Architecture</div>';
    h += '<div style="font-size:0.82rem;color:var(--text-secondary);margin-bottom:14px">' +
         'Quill supports two proxy configurations. Choose the one that matches your setup.</div>';

    h += '<div style="font-weight:600;font-size:0.9rem;margin-bottom:6px">Standalone (no upstream proxy)</div>';
    h += '<div style="padding:10px 14px;background:var(--bg-code,var(--bg-tertiary,#1a1a2e));border:1px solid var(--border);border-radius:6px;margin-bottom:14px">';
    h += '<code style="font-size:0.85rem">Device → Quill MITM (mitmdump) → Internet</code></div>';
    h += '<div style="font-size:0.82rem;color:var(--text-secondary);margin-bottom:16px">' +
         'Install this CA on the device. No other configuration needed.</div>';

    h += '<div style="font-weight:600;font-size:0.9rem;margin-bottom:6px">With upstream proxy (Burp, ZAP, Charles, etc.)</div>';
    h += '<div style="padding:10px 14px;background:var(--bg-code,var(--bg-tertiary,#1a1a2e));border:1px solid var(--border);border-radius:6px;margin-bottom:14px">';
    h += '<code style="font-size:0.85rem">Device → Quill MITM (mitmdump) → Proxy → Internet</code></div>';
    h += '<div style="font-size:0.82rem;color:var(--text-secondary);margin-bottom:8px">' +
         'Configure the upstream proxy URL in project settings (MITM → Upstream Proxy field). ' +
         'Quill forwards all intercepted traffic through your proxy for additional inspection.</div>';
    h += '<div style="font-size:0.82rem;color:var(--text-secondary);margin-bottom:8px">' +
         '<b>Optional — single CA:</b> Export your proxy\'s CA as a PEM file containing both the certificate and private key, ' +
         'and set it in the Proxy CA Certificate field. Quill will sign intercepted traffic with that CA, ' +
         'so the device only needs one CA installed instead of two.</div>';
    h += '<div style="margin-top:10px;padding:10px 14px;background:var(--clr-accent-bg,rgba(74,144,217,.1));border-radius:6px;font-size:0.85rem">' +
         '<b>Burp Suite:</b> Proxy settings → Import/Export CA Certificate → Export → Certificate and Private Key in PEM format.<br>' +
         '<b>ZAP:</b> Tools → Options → Dynamic SSL Certificates → Save.<br>' +
         '<b>Charles:</b> Help → SSL Proxying → Export Charles Root Certificate and Private Key.</div>';
    h += '</div>';

    /* ── Device CA install ── */
    h += '<div style="background:var(--bg-card,var(--bg-secondary));border:1px solid var(--border);border-radius:8px;padding:20px">';
    h += '<div style="font-weight:600;margin-bottom:4px">Install CA on Device</div>';
    h += '<div style="font-size:0.82rem;color:var(--text-secondary);margin-bottom:12px">' +
         'The device must trust this CA (or your proxy\'s CA if using the single-CA option above) for MITM interception to work.</div>';
    h += '<ol style="margin:0;padding-left:20px;line-height:1.8;font-size:0.9rem">';
    h += '<li>Transfer <code>mitmproxy-ca-cert.pem</code> to the device</li>';
    h += '<li><b>Android:</b> Settings → Security → Encryption → Install from storage → select the PEM</li>';
    h += '<li><b>iOS:</b> AirDrop or email the PEM → Settings → General → VPN & Device Management → install profile → Settings → General → About → Certificate Trust Settings → enable</li>';
    h += '</ol></div>';

    return h;
}

function _copyMitmCertPem() { _copyElText('mitmCertPem', 'Certificate PEM'); }

function _copyElText(elId, label) {
    var el = document.getElementById(elId);
    if (!el) return;
    var text = el.textContent || el.innerText;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() {
            toast('success', (label || 'Text') + ' copied to clipboard.');
        }).catch(function() {
            toast('error', 'Failed to copy — select and copy manually.');
        });
    } else {
        toast('error', 'Clipboard API not available — select and copy manually.');
    }
}


var _INTEL_RENDERERS = {
    'cookies': _renderCookies,
    'net-hosts': _renderNetHosts,
    'net-services': _renderNetServices,
    'net-software': _renderNetSoftware,
    'net-ports': _renderNetPorts,
    'net-roles': _renderNetRoles,
    'net-hostname-env': _renderHostnameEnv,
    'net-hostname-apps': _renderHostnameApps,
    'net-hostname-hw': _renderHostnameHw,
    'net-posture': _renderNetPosture,
    'osint-domains': _renderOsintDomains,
    'osint-dns': _renderOsintDns,
    'osint-certs': _renderOsintCerts,
    'osint-emails': _renderOsintEmails,
    'osint-people': _renderOsintPeople,
    'osint-breaches': _renderOsintBreaches,
    'osint-typosquat': _renderOsintTyposquat,
    'osint-wayback': _renderOsintWayback,
    'structure': _renderStructure,
    'access': _renderAccessMatrix,
    'auth': _renderAuthStatus,
    'api': _renderApiInventory,
    'profile': _renderProfile,
    'overview': _renderOverview,
    'iso-properties': _renderIsoProperties,
    'iso-entropy': _renderIsoEntropy,
    'endpoint-overview': _renderEndpointOverview,
    'endpoint-hardening': _renderEndpointHardening,
    'endpoint-software': _renderEndpointSoftware,
    'endpoint-ad': _renderEndpointAD,
    'endpoint-network': _renderEndpointNetwork,
    'endpoint-browser': _renderEndpointBrowser,
    'endpoint-disk': _renderEndpointDisk,
    'endpoint-hardware': _renderEndpointHardware,
    'endpoint-cis': _renderEndpointCIS,
    'endpoint-nist': _renderEndpointNIST,
    'endpoint-stig': _renderEndpointSTIG,
    'webapp-intel': _renderWebappIntel,
    'cloud-resources': _renderCloudResources,
    'cloud-iam': _renderCloudIAM,
    'cloud-services': _renderCloudServices,
    'mobile-components': _renderMobileComponents,
    'mobile-perms': _renderMobilePerms,
    'mobile-hardening': _renderMobileHardening,
    'mobile-data': _renderMobileData,
    'mobile-domains': _renderMobileDomains,
    'mobile-emails': _renderMobileEmails,
    'mitm-cert': _renderMitmCert,
};


/* ── Status Panel — Phase-Tree Renderer ────────────────────────── */

function _stPhaseIcon(status) {
    var map = {running:'⟳', complete:'✓', skipped:'—', error:'✗', idle:'○', pending:'◉', cancelled:'✗', killed:'✗', failed:'✗', halted:'⊘'};
    return map[status] || '○';
}

function _stBuildPhaseRow(tool, spec, isChild) {
    var key = spec.key;
    var indent = isChild ? ' st-child-row' : '';
    var hasExp = spec.expandable || spec.toolList;
    var expBtn = hasExp
        ? '<button class="st-row-expand-btn" aria-expanded="false" onclick="stToggleBody(this)" title="Expand"><span class="st-row-chevron"></span></button>'
        : '<span class="st-row-expand-ph"></span>';

    var rowHtml = '<div class="st-phase-row st-phase-idle' + indent + '" id="st-row-' + tool + '-' + key + '" data-status="idle">' +
        expBtn +
        '<span class="st-phase-icon">○</span>' +
        '<span class="st-phase-label">' + esc(spec.label) + '</span>' +
        '<span class="st-phase-step" id="st-step-' + tool + '-' + key + '"></span>' +
        '<span class="st-spacer"></span>' +
        '<span class="st-badge st-badge-idle" id="st-badge-' + tool + '-' + key + '">idle</span>' +
    '</div>';

    var bodyHtml = '';
    if (spec.toolList) {
        bodyHtml = '<div class="st-phase-body hidden" id="st-body-' + tool + '-' + key + '">' +
            '<div class="st-tool-list" id="st-tools-' + tool + '-' + key + '">' +
                '<div class="st-tool-placeholder">Waiting for tool data…</div>' +
            '</div></div>';
    } else if (spec.expandable && spec.subPhases) {
        var subRows = spec.subPhases.map(function(s) { return _stBuildPhaseRow(tool, s, true); }).join('');
        bodyHtml = '<div class="st-phase-body hidden" id="st-body-' + tool + '-' + key + '">' + subRows + '</div>';
    }

    return rowHtml + bodyHtml;
}

function stToggleBody(btn) {
    var expanded = btn.getAttribute('aria-expanded') === 'true';
    btn.setAttribute('aria-expanded', String(!expanded));
    var row = btn.closest('.st-phase-row');
    var body = row && row.nextElementSibling;
    if (body && body.classList.contains('st-phase-body')) {
        body.classList.toggle('hidden', expanded);
    }
    var chevron = btn.querySelector('.st-row-chevron');
    if (chevron) chevron.style.transform = expanded ? '' : 'rotate(90deg)';
}

function _stUpdatePhaseRow(tool, phaseKey, phaseData) {
    var status = phaseData.status || 'idle';
    var step = phaseData.step || '';
    var row = document.getElementById('st-row-' + tool + '-' + phaseKey);
    var badge = document.getElementById('st-badge-' + tool + '-' + phaseKey);
    var stepEl = document.getElementById('st-step-' + tool + '-' + phaseKey);
    if (!row) return;

    var isChild = row.classList.contains('st-child-row');
    row.className = 'st-phase-row st-phase-' + status + (isChild ? ' st-child-row' : '');
    row.dataset.status = status;
    var icon = row.querySelector('.st-phase-icon');
    if (icon) icon.textContent = _stPhaseIcon(status);
    if (badge) { badge.className = 'st-badge st-badge-' + status; badge.textContent = status; }
    if (stepEl) stepEl.textContent = step ? '· ' + step : '';

    if (phaseData.tools) {
        _stRenderToolList(tool, phaseKey, phaseData.tools);
        _stAutoExpand(tool, phaseKey, row);
    } else if (phaseData.active_tools && phaseData.active_tools.length) {
        _stRenderActiveTools(tool, phaseKey, phaseData.active_tools, status);
        _stAutoExpand(tool, phaseKey, row);
    } else if (status !== 'idle' && status !== 'pending' && status !== 'running') {
        var tlc = document.getElementById('st-tools-' + tool + '-' + phaseKey);
        if (tlc) {
            var msg = status === 'complete' ? 'Phase complete.' :
                      status === 'skipped' ? 'Phase skipped.' :
                      'Phase ended (' + status + ').';
            if (step) msg = step;
            tlc.innerHTML = '<div class="st-tool-placeholder" style="color:var(--text-secondary)">' + esc(msg) + '</div>';
        }
    }

    if (status === 'running' && (phaseKey === 'scope_int' || phaseKey === 'scope_ext')) {
        _stAutoExpand(tool, phaseKey, row);
    }
}

function _stAutoExpand(tool, phaseKey, row) {
    var body = document.getElementById('st-body-' + tool + '-' + phaseKey);
    var btn = row.querySelector('.st-row-expand-btn');
    if (body && body.classList.contains('hidden')) {
        body.classList.remove('hidden');
        if (btn) {
            btn.setAttribute('aria-expanded', 'true');
            var ch = btn.querySelector('.st-row-chevron');
            if (ch) ch.style.transform = 'rotate(90deg)';
        }
    }
}

function _stRenderActiveTools(tool, key, activeTools, phaseStatus) {
    var container = document.getElementById('st-tools-' + tool + '-' + key);
    if (!container) return;
    if (!activeTools.length) {
        container.innerHTML = '<div class="st-tool-placeholder">No active tools.</div>';
        return;
    }
    var html = activeTools.map(function(name) {
        var cls, ico;
        if (phaseStatus === 'complete') { cls = 'st-tool-ok'; ico = '●'; }
        else if (phaseStatus === 'running') { cls = 'st-tool-ok'; ico = '⟳'; }
        else if (phaseStatus === 'error') { cls = 'st-tool-warn'; ico = '⚠'; }
        else { cls = 'st-tool-skip'; ico = '○'; }
        return '<div class="st-tool-item ' + cls + '">' +
            '<span class="st-tool-dot">' + ico + '</span>' +
            '<span class="st-tool-name">' + esc(typeof name === 'string' ? name : (name.name || '')) + '</span>' +
        '</div>';
    }).join('');
    container.innerHTML = html;
}

function _stRenderToolList(tool, key, tools) {
    var container = document.getElementById('st-tools-' + tool + '-' + key);
    if (!container || !tools) return;
    var names = Object.keys(tools).sort(function(a, b) {
        var order = {running: 0, complete: 1, error: 2, idle: 3};
        var sa = (tools[a].status || '').toLowerCase();
        var sb = (tools[b].status || '').toLowerCase();
        var oa = order[sa] !== undefined ? order[sa] : 5;
        var ob = order[sb] !== undefined ? order[sb] : 5;
        if (oa !== ob) return oa - ob;
        return a.localeCompare(b);
    });
    if (!names.length) {
        container.innerHTML = '<div class="st-tool-placeholder">No tool data.</div>';
        return;
    }
    var html = names.map(function(name) {
        var t = tools[name];
        var st = (t.status || '').toLowerCase();
        var ok = t.installed;
        var result = t.result || null;
        var cls, ico;
        if (st === 'running')                                       { cls = 'st-tool-running';  ico = '⟳'; }
        else if (st === 'complete')                                  { cls = 'st-tool-ok';       ico = '✓'; }
        else if (st === 'error' || st === 'failed')                  { cls = 'st-tool-warn';     ico = '✗'; }
        else if (st === 'skipped')                                   { cls = 'st-tool-skip';     ico = '—'; }
        else if (result) {
            if (result === 'updated')                                { cls = 'st-tool-ok';       ico = '●'; }
            else if (result === 'not-installed')                     { cls = 'st-tool-missing';  ico = '○'; }
            else if (result === 'failed' || result === 'timed out')  { cls = 'st-tool-warn';     ico = '⚠'; }
            else                                                     { cls = 'st-tool-skip';     ico = '–'; }
        } else if (ok !== undefined) {
            cls = ok ? 'st-tool-ok' : 'st-tool-missing';
            ico = ok ? '●' : '○';
        } else {
            cls = 'st-tool-idle';
            ico = '○';
        }
        var badge = '';
        if (st && st !== 'idle') {
            badge = '<span class="st-tool-result st-tool-result-' + st.replace(/[^a-z]/g,'-') + '">' + esc(st) + '</span>';
        } else if (result && result !== 'not-installed') {
            badge = '<span class="st-tool-result st-tool-result-' + result.replace(/[^a-z]/g,'-') + '">' + esc(result) + '</span>';
        }
        return '<div class="st-tool-item ' + cls + '">' +
            '<span class="st-tool-dot">' + ico + '</span>' +
            '<span class="st-tool-name">' + esc(name) + '</span>' +
            badge +
        '</div>';
    }).join('');
    container.innerHTML = html;
}

function _stUpdateCompletion(tool, specs) {
    var phases = toolPhases[tool] || {};
    var overallSt = (toolStatuses[tool] || {}).status || '';
    var total = 0;
    var done = 0;
    var running = false;

    function _countSpec(specList) {
        for (var i = 0; i < specList.length; i++) {
            var s = specList[i];
            if (s.subPhases) {
                _countSpec(s.subPhases);
            } else {
                total++;
                var pd = phases[s.key] || {};
                if (pd.status === 'complete' || pd.status === 'skipped') done++;
                if (pd.status === 'running') running = true;
            }
        }
    }
    _countSpec(specs);

    var tag = document.getElementById('st-comp-' + tool);
    if (!tag) return;
    if (overallSt === 'complete') {
        tag.className = 'st-comp-tag st-comp-complete';
        tag.textContent = (done && total) ? done + '/' + total + ' complete' : 'complete';
    } else if (overallSt === 'error' || overallSt === 'killed' || overallSt === 'cancelled' || overallSt === 'halted') {
        tag.className = 'st-comp-tag st-comp-error';
        tag.textContent = overallSt;
    } else if (done === total && total > 0) {
        tag.className = 'st-comp-tag st-comp-complete';
        tag.textContent = done + '/' + total + ' complete';
    } else if (running) {
        tag.className = 'st-comp-tag st-comp-running';
        tag.textContent = done + '/' + total + ' complete';
    } else if (done > 0) {
        tag.className = 'st-comp-tag st-comp-partial';
        tag.textContent = done + '/' + total + ' complete';
    } else if (overallSt && overallSt !== 'idle') {
        tag.className = 'st-comp-tag st-comp-' + overallSt;
        tag.textContent = overallSt;
    } else {
        tag.className = 'st-comp-tag';
        tag.textContent = 'not started';
    }
}

function _stBuildDynamicRows(tool) {
    var phases = toolPhases[tool] || {};
    var keys = Object.keys(phases);
    if (!keys.length) return '';
    keys.sort(function(a, b) {
        var pa = phases[a], pb = phases[b];
        var ta = pa.ts || '', tb = pb.ts || '';
        return ta < tb ? -1 : ta > tb ? 1 : 0;
    });
    return keys.map(function(k) {
        var pd = phases[k];
        var label = pd.label || k;
        return _stBuildPhaseRow(tool, {key: k, label: label}, false);
    }).join('');
}

function _mtTargetPill(url, perTarget, activeTarget) {
    var tPhases = perTarget[url] || {};
    var keys = Object.keys(tPhases);
    var total = keys.length, done = 0, running = false, errored = false;
    keys.forEach(function(k) {
        var s = (tPhases[k].status || '').toLowerCase();
        if (s === 'complete' || s === 'skipped') done++;
        if (s === 'running') running = true;
        if (s === 'error' || s === 'failed') errored = true;
    });
    var pillClass = 'st-mt-idle';
    var pillText = 'pending';
    if (errored) { pillClass = 'st-mt-error'; pillText = 'error'; }
    else if (running) { pillClass = 'st-mt-running'; pillText = done + '/' + total; }
    else if (done > 0 && done >= total) { pillClass = 'st-mt-complete'; pillText = 'complete'; }
    else if (done > 0) { pillClass = 'st-mt-partial'; pillText = done + '/' + total; }
    var sel = url === activeTarget ? ' st-mt-selected' : '';
    try { var u = new URL(url); var short = u.hostname + (u.port && u.port !== '443' && u.port !== '80' ? ':' + u.port : ''); }
    catch(e) { var short = url; }
    return '<div class="st-mt-item' + sel + '" data-mt-target="' + esc(url) + '" title="' + esc(url) + '">' +
        '<span class="st-mt-label">' + esc(short) + '</span>' +
        '<span class="st-mt-pill ' + pillClass + '">' + pillText + '</span>' +
    '</div>';
}

function _mtSelectTarget(tool, url) {
    _mtActiveTarget[tool] = url;
    var body = document.getElementById('intelBody');
    var empty = document.getElementById('intelEmpty');
    if (body) renderStatusPanel(tool, body, empty);
}

function switchStatusScope(baseTool, scopeKey) {
    _activeIntelTool = scopeKey;
    var body = document.getElementById('intelBody');
    var empty = document.getElementById('intelEmpty');
    if (body) renderStatusPanel(scopeKey, body, empty);
}

function renderStatusPanel(tool, body, empty) {
    var st = toolStatuses[tool] || {};
    var _baseTool3 = tool.indexOf(':') !== -1 ? tool.substring(0, tool.indexOf(':')) : tool;
    var cfg = TOOLS_CFG[tool] || TOOLS_CFG[_baseTool3] || {};
    var overallStatus = (st.status || 'idle').toLowerCase();
    var key = cfg.key || _baseTool3.toUpperCase().substring(0,2);
    var phases = toolPhases[tool] || {};
    if (tool.indexOf(':') !== -1 && Object.keys(phases).length === 0) {
        phases = toolPhases[_baseTool3] || {};
    }
    var _scopeKeys = Object.keys(toolPhases).filter(function(k) {
        return k.indexOf(_baseTool3 + ':') === 0 && Object.keys(toolPhases[k] || {}).length > 0;
    });
    var specs = CRUCIBLE_PHASE_SPECS[tool] || CRUCIBLE_PHASE_SPECS[_baseTool3] || null;
    var mt = _multiTargetState[_baseTool3];
    var isMulti = mt && mt.targets.length > 1;

    body.hidden = false;
    empty.style.display = 'none';

    var elapsed = '';
    if (st.started_at) {
        var _startMs = typeof st.started_at === 'number'
            ? st.started_at * 1000
            : new Date(st.started_at).getTime();
        if (_startMs && !isNaN(_startMs)) {
            var secs = Math.floor((Date.now() - _startMs) / 1000);
            if (secs < 0) secs = 0;
            var h = Math.floor(secs / 3600);
            var m = Math.floor((secs % 3600) / 60);
            var s = secs % 60;
            elapsed = (h ? h + 'h ' : '') + (m ? m + 'm ' : '') + s + 's';
        }
    }

    var headerHtml =
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">' +
            '<span class="tool-badge tool-' + key.toLowerCase() + '" style="font-size:16px;width:40px;height:40px;display:flex;align-items:center;justify-content:center">' + esc(key) + '</span>' +
            '<div style="flex:1">' +
                '<div style="font-size:18px;font-weight:600">' + esc(cfg.name || tool) + '</div>' +
                '<div style="font-size:13px;color:var(--text-muted)">' +
                    '<span class="status-badge status-' + esc(overallStatus) + '">' + esc(overallStatus) + '</span>' +
                    (elapsed ? ' · ' + esc(elapsed) : '') +
                    (isMulti ? ' · ' + mt.targets.length + ' targets' : '') +
                '</div>' +
            '</div>' +
            (specs ? '<span class="st-comp-tag" id="st-comp-' + tool + '">not started</span>' : '') +
        '</div>';

    if (isMulti) {
        var selTarget = _mtActiveTarget[tool] || mt.activeTarget || mt.targets[0];
        var selPhases = mt.perTarget[selTarget] || {};

        var leftHtml = '<div class="st-mt-sidebar">' +
            '<div class="st-mt-header">Targets</div>' +
            mt.targets.map(function(t) { return _mtTargetPill(t, mt.perTarget, selTarget); }).join('') +
        '</div>';

        var rightHtml = '<div class="st-mt-detail">';
        try { var _su = new URL(selTarget); var _short = _su.hostname + (_su.port && _su.port !== '443' && _su.port !== '80' ? ':' + _su.port : ''); }
        catch(e) { var _short = selTarget; }
        var isActive = mt.activeTarget === selTarget;
        rightHtml += '<div style="font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text-primary)">' +
            esc(_short) + (isActive ? ' <span style="font-size:11px;font-weight:400;color:var(--text-muted)">(active)</span>' : '') +
        '</div>';

        if (specs) {
            rightHtml += '<div class="st-section"><div class="st-sect-body" id="st-rows-' + tool + '">' +
                specs.map(function(s) { return _stBuildPhaseRow(tool, s, false); }).join('') +
            '</div></div>';
        } else if (Object.keys(selPhases).length > 0) {
            rightHtml += '<div class="st-section"><div class="st-sect-body" id="st-rows-' + tool + '">' +
                _stBuildDynamicRows(tool) +
            '</div></div>';
        } else {
            rightHtml += '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px">No phase data for this target yet.</div>';
        }

        rightHtml += '</div>';

        body.innerHTML = '<div style="max-width:900px;margin:0 auto;padding:20px">' + headerHtml +
            '<div class="st-mt-layout">' + leftHtml + rightHtml + '</div></div>';

        body.querySelectorAll('.st-mt-item').forEach(function(el) {
            el.addEventListener('click', function() {
                _mtSelectTarget(tool, el.getAttribute('data-mt-target'));
            });
        });

        if (specs) {
            var phKeys = Object.keys(selPhases);
            for (var pi = 0; pi < phKeys.length; pi++) {
                _stUpdatePhaseRow(tool, phKeys[pi], selPhases[phKeys[pi]]);
            }
            _stUpdateCompletion(tool, specs);
        }
        return;
    }

    var scopeSelectorHtml = '';
    if (_scopeKeys.length > 1) {
        var _activeScopeKey = tool;
        if (tool.indexOf(':') === -1) {
            _activeScopeKey = _scopeKeys[0];
            for (var _sk = 0; _sk < _scopeKeys.length; _sk++) {
                if ((toolStatuses[_scopeKeys[_sk]] || {}).status === 'running') {
                    _activeScopeKey = _scopeKeys[_sk];
                    break;
                }
            }
            phases = toolPhases[_activeScopeKey] || {};
        }
        scopeSelectorHtml = '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
        for (var _ski = 0; _ski < _scopeKeys.length; _ski++) {
            var _skScope = _scopeKeys[_ski].split(':')[1];
            var _skStatus = (toolStatuses[_scopeKeys[_ski]] || {}).status || 'idle';
            var _skActive = _scopeKeys[_ski] === _activeScopeKey;
            scopeSelectorHtml += '<button class="btn btn-sm ' + (_skActive ? 'btn-primary' : 'btn-outline') + '" ' +
                'onclick="switchStatusScope(\'' + esc(_baseTool3) + '\',\'' + esc(_scopeKeys[_ski]) + '\')" ' +
                'style="font-size:12px;padding:4px 10px">' +
                '<span class="status-dot status-' + esc(_skStatus) + '"></span> ' +
                esc(_skScope) +
            '</button>';
        }
        scopeSelectorHtml += '</div>';
    }

    var treeHtml = '';
    if (specs) {
        treeHtml = '<div class="st-section"><div class="st-sect-body" id="st-rows-' + tool + '">' +
            specs.map(function(s) { return _stBuildPhaseRow(tool, s, false); }).join('') +
        '</div></div>';
    } else if (Object.keys(phases).length > 0) {
        treeHtml = '<div class="st-section"><div class="st-sect-body" id="st-rows-' + tool + '">' +
            _stBuildDynamicRows(tool) +
        '</div></div>';
    } else {
        var infoRows = [];
        if (st.phase || st.last_phase) infoRows.push(_stInfoRow('Phase', esc(st.phase || st.last_phase)));
        if (st.label) infoRows.push(_stInfoRow('Current Step', esc(st.label)));
        if (st.step) infoRows.push(_stInfoRow('Step Detail', esc(st.step)));
        if (st.pid) infoRows.push(_stInfoRow('PID', esc(String(st.pid))));
        if (st.returncode !== undefined && st.returncode !== null) {
            var rc = st.returncode;
            var rcStyle = rc === 0 ? 'color:var(--green)' : 'color:var(--red)';
            infoRows.push(_stInfoRow('Exit Code', '<span style="' + rcStyle + ';font-weight:600">' + esc(String(rc)) + '</span>'));
        }
        if (infoRows.length) {
            treeHtml = '<div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:16px">' +
                infoRows.join('') + '</div>';
        } else {
            treeHtml = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px">No status data yet. Start the tool to see phase progress.</div>';
        }
    }

    var mitmBtnHtml = '';
    if ((st._mitm_active) && overallStatus === 'running') {
        mitmBtnHtml = '<div style="margin-bottom:16px;padding:12px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;display:flex;align-items:center;gap:12px">' +
            '<span style="font-size:13px;color:var(--text-muted);flex:1">MITM capture is active — exercise the app, then stop when ready.</span>' +
            '<button class="btn btn-danger btn-sm" id="mitmStopBtn" style="white-space:nowrap">' +
                '<i class="bi bi-stop-circle"></i> Stop MITM Capture' +
            '</button>' +
        '</div>';
    } else if (st._mitm_paused) {
        mitmBtnHtml = '<div style="margin-bottom:16px;padding:12px;background:rgba(255,192,0,.12);border:1px solid rgba(255,192,0,.35);border-radius:8px;display:flex;align-items:center;gap:12px">' +
            '<span style="font-size:13px;color:var(--text-primary);flex:1"><strong>MITM paused</strong> — memory threshold reached. Resume the tool to continue capture.</span>' +
        '</div>';
    }

    body.innerHTML = '<div style="max-width:640px;margin:0 auto;padding:20px">' + headerHtml + scopeSelectorHtml + mitmBtnHtml + treeHtml + '</div>';

    var _mitmBtn = document.getElementById('mitmStopBtn');
    if (_mitmBtn) {
        _mitmBtn.addEventListener('click', function() {
            _mitmBtn.disabled = true;
            _mitmBtn.textContent = 'Stopping…';
            fetch('/api/mitm_stop', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({project_id: PID, tool_id: tool})
            }).then(function(r) { return r.json(); }).then(function(j) {
                if (j.ok) {
                    _mitmBtn.textContent = 'Stop signal sent';
                    if (toolStatuses[tool]) toolStatuses[tool]._mitm_active = false;
                } else {
                    _mitmBtn.textContent = j.error || 'Failed';
                    _mitmBtn.disabled = false;
                }
            }).catch(function() {
                _mitmBtn.textContent = 'Error';
                _mitmBtn.disabled = false;
            });
        });
    }

    if (specs) {
        var phaseKeys = Object.keys(phases);
        var terminal = overallStatus === 'complete' || overallStatus === 'killed'
                     || overallStatus === 'failed' || overallStatus === 'cancelled' || overallStatus === 'halted';
        if (terminal && !_checkpointFetched[tool]) {
            if (!phaseKeys.length) {
                _checkpointFetched[tool] = true;
                _fetchCheckpointPhases(tool, overallStatus);
            } else {
                _fallbackFillPhases(tool, overallStatus);
            }
        }
        phaseKeys = Object.keys(toolPhases[tool] || {});
        for (var i = 0; i < phaseKeys.length; i++) {
            _stUpdatePhaseRow(tool, phaseKeys[i], (toolPhases[tool] || {})[phaseKeys[i]]);
        }
        if (terminal) _stAutoExpandAll(tool, specs);
        _stUpdateCompletion(tool, specs);
    }
}

function _stFillAllPhases(tool, specs, status) {
    if (!toolPhases[tool]) toolPhases[tool] = {};
    function _fill(specList) {
        for (var i = 0; i < specList.length; i++) {
            var s = specList[i];
            if (s.subPhases) {
                _fill(s.subPhases);
                if (!toolPhases[tool][s.key]) {
                    toolPhases[tool][s.key] = {status: status, step: '', label: s.label, ts: ''};
                }
            } else {
                if (!toolPhases[tool][s.key]) {
                    toolPhases[tool][s.key] = {status: status, step: '', label: s.label, ts: ''};
                }
            }
            if (s.toolList) {
                var container = document.getElementById('st-tools-' + tool + '-' + s.key);
                if (container) {
                    var ph = container.querySelector('.st-tool-placeholder');
                    if (ph) ph.textContent = status === 'complete' ? 'Completed' : status === 'error' ? 'Failed' : status === 'halted' ? 'Halted' : 'No tool data received';
                }
            }
        }
    }
    _fill(specs);
}

function _stAutoExpandAll(tool, specs) {
    for (var i = 0; i < specs.length; i++) {
        var s = specs[i];
        if (s.expandable || s.toolList) {
            var bdy = document.getElementById('st-body-' + tool + '-' + s.key);
            var row = document.getElementById('st-row-' + tool + '-' + s.key);
            if (bdy && bdy.classList.contains('hidden')) {
                bdy.classList.remove('hidden');
                var btn = row ? row.querySelector('.st-row-expand-btn') : null;
                if (btn) {
                    btn.setAttribute('aria-expanded', 'true');
                    var ch = btn.querySelector('.st-row-chevron');
                    if (ch) ch.style.transform = 'rotate(90deg)';
                }
            }
        }
    }
}

function _stInfoRow(label, value) {
    return '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">' +
        '<span style="font-size:13px;color:var(--text-muted)">' + label + '</span>' +
        '<span style="font-size:13px">' + value + '</span>' +
    '</div>';
}


/* ══════════════════════════════════════════════════════════════════
   10. SETTINGS TAB
   ══════════════════════════════════════════════════════════════════ */
var settingsInitialised = false;
var _settingsOriginal = {};

var SCOPE_REQUIRED_FIELDS = {
    external: [{key:'network_cidrs',label:'External IPs / CIDRs',type:'textarea',placeholder:'One IP or CIDR per line'}],
    internal: [{key:'network_cidrs',label:'Internal IPs / CIDRs',type:'textarea',placeholder:'One IP or CIDR per line'}],
    webapp:   [{key:'target_urls',label:'Web Application URLs',type:'textarea',placeholder:'One URL per line'}],
    api:      [{key:'api_urls',label:'API Base URLs',type:'textarea',placeholder:'One URL per line'}],
    osint:    [{key:'domains',label:'Domains',type:'textarea',placeholder:'One domain per line'}],
    database: [{key:'db_targets',label:'Database Targets',type:'textarea',placeholder:'One target per line (e.g. mysql://10.0.0.5:3306)'}],
    pcap:     [{key:'trawler_targets',label:'Target IPs (within capture)',type:'textarea',placeholder:'One IP per line'}],
    wifi:     [{key:'wireless_ssids',label:'Target SSIDs',type:'textarea',placeholder:'One SSID per line'}],
    bluetooth:[{key:'wireless_ssids',label:'Target Devices',type:'textarea',placeholder:'One device per line'}],
    zigbee:   [{key:'wireless_ssids',label:'Target Devices',type:'textarea',placeholder:'One device per line'}],
    uwb:      [{key:'wireless_ssids',label:'Target Devices',type:'textarea',placeholder:'One device per line'}],
    firewall: [{key:'firewall_vendor',label:'Vendor',type:'select',options:['','palo_alto','cisco','fortigate','checkpoint','juniper','sophos','other']}],
    cloud:    [{key:'cloud_provider',label:'Cloud Provider',type:'select',options:['','aws','azure','gcp']}],
    mobile:   [{key:'mobile_platform',label:'Platform',type:'select',options:[{value:'',label:'-- Select --'},{value:'auto',label:'Auto-Detect'},{value:'android',label:'Android'},{value:'ios',label:'iOS'}]}],
    file:     []
};

var SETTINGS_INVALIDATING_KEYS = {
    ss3: ['network_cidrs','timing_profile','scan_intensity','port_range'],
    fracture: ['target_url','auth_method','scan_profile'],
    siphon: ['api_base_url','auth_method','scan_profile'],
    osift: ['domains','scan_depth'],
    auger: ['db_targets','auger_mode','auger_db_type'],
    trawler: ['trawler_targets'],
    bastion: ['firewall_vendor'],
    forge: ['cloud_provider','aws_profile','azure_subscription','gcp_project'],
    quill: ['mobile_platform'],
    isotope: ['isotope_modules']
};

function initSettingsTabs() {
    if (settingsInitialised) return;
    settingsInitialised = true;

    var nav = document.getElementById('settingsSubNav');
    nav.innerHTML = '';

    var engBtn = document.createElement('button');
    engBtn.type = 'button';
    engBtn.className = 'tab-btn active';
    engBtn.setAttribute('data-stool', '__engagement__');
    engBtn.textContent = 'Engagement';
    nav.appendChild(engBtn);

    PROJECT_TOOLS.slice().sort(function(a,b) {
        return ((TOOLS_CFG[a]||{}).name||a).localeCompare((TOOLS_CFG[b]||{}).name||b);
    }).forEach(function(tid) {
        var cfg = TOOLS_CFG[tid] || {};
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'tab-btn';
        btn.setAttribute('data-stool', tid);
        btn.textContent = cfg.name || tid;
        nav.appendChild(btn);
    });

    showEngagementPanel();
}

function showEngagementPanel() {
    settingsActiveTool = null;
    document.getElementById('settingsBody').hidden = true;
    document.getElementById('settingsEmpty').style.display = 'none';
    var eng = document.getElementById('settingsEngagement');
    eng.hidden = false;

    var p = PROJECT;
    var con = p.consultant || {};
    var poc = p.client_poc || p.poc || {};
    document.getElementById('seClientName').textContent = p.client_name || '--';
    document.getElementById('seClientShort').textContent = p.client_short || '--';
    document.getElementById('seEngName').textContent = p.name || '--';
    document.getElementById('seScope').textContent = SCOPE_DISPLAY_NAMES[p.scope] || p.scope || '--';
    document.getElementById('seStartDate').textContent = p.start_date || '--';
    document.getElementById('seEndDate').textContent = p.end_date || '--';
    document.getElementById('seConsultName').textContent = (typeof con === 'object' ? con.name : con) || '--';
    document.getElementById('seConsultTitle').textContent = (typeof con === 'object' ? con.title : '') || '--';
    document.getElementById('seConsultEmail').textContent = (typeof con === 'object' ? con.email : '') || '--';
    document.getElementById('sePocName').textContent = (typeof poc === 'object' ? poc.name : poc) || '--';
    document.getElementById('sePocTitle').textContent = (typeof poc === 'object' ? poc.title : '') || '';
    document.getElementById('sePocPhone').textContent = (typeof poc === 'object' ? poc.phone : '') || '';
    document.getElementById('sePocEmail').textContent = (typeof poc === 'object' ? poc.email : '') || '';

    document.getElementById('seAutoQueue').checked = !!p.auto_queue;

    var _beaconUrl = document.getElementById('seBeaconUrl');
    var _beaconEnabled = document.getElementById('seBeaconEnabled');
    if (_beaconUrl) _beaconUrl.value = p.beacon_url || '';
    if (_beaconEnabled) _beaconEnabled.checked = !!p.beacon_enabled;

    var oosVal = p.oos_handling || 'explicit';
    var oosRadio = document.querySelector('input[name="seOosHandling"][value="' + oosVal + '"]');
    if (oosRadio) oosRadio.checked = true;

    var container = document.getElementById('seScopeChecks');
    container.innerHTML = '';
    var SCOPE_TOOLS_REVERSE = {
        external:['ss3','osift','trawler','auger','isotope'],
        internal:['ss3','trawler','auger','isotope'],
        webapp:['fracture'], api:['siphon'], osint:['osift'], database:['auger'],
        pcap:['trawler'], wifi:['aether'], bluetooth:['aether_b'],
        zigbee:['aether_z'], uwb:['aether_u'], firewall:['bastion'],
        cloud:['forge'], mobile:['quill'], file:['isotope']
    };
    var existingScopes = p.active_scopes;
    var _needInfer = !existingScopes || !existingScopes.length
        || (existingScopes.length === 1 && existingScopes[0] === 'multi');
    if (_needInfer) {
        existingScopes = [];
        var pt = PROJECT_TOOLS;
        var allScopeKeys = Object.keys(SCOPE_TOOLS_REVERSE);
        allScopeKeys.forEach(function(s) {
            var tools = SCOPE_TOOLS_REVERSE[s];
            if (tools.some(function(t) { return pt.indexOf(t) !== -1; })) {
                existingScopes.push(s);
            }
        });
        if (!existingScopes.length && p.scope && p.scope !== 'multi') existingScopes = [p.scope];
    }
    _engagementExistingScopes = existingScopes.slice();
    var allScopes = ['external','internal','webapp','api','osint','database','pcap','wifi','bluetooth','zigbee','uwb','firewall','cloud','mobile','file'];
    allScopes.sort(function(a,b){ return (SCOPE_DISPLAY_NAMES[a]||a).localeCompare(SCOPE_DISPLAY_NAMES[b]||b); });
    allScopes.forEach(function(s) {
        var isActive = existingScopes.indexOf(s) !== -1;
        var div = document.createElement('div');
        div.className = 'form-check';
        div.innerHTML = '<input type="checkbox" id="scope_' + s + '" value="' + s + '"' +
            (isActive ? ' checked' : '') + '>' +
            '<label for="scope_' + s + '">' + esc(SCOPE_DISPLAY_NAMES[s] || s) + '</label>';
        container.appendChild(div);
    });
}

document.getElementById('settingsSubNav').addEventListener('click', function(e) {
    var btn = e.target.closest('.tab-btn');
    if (!btn) return;
    var tid = btn.getAttribute('data-stool');
    if (!tid) return;
    document.getElementById('settingsSubNav').querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    if (tid === '__engagement__') { showEngagementPanel(); return; }
    loadToolSettings(tid);
});

function _renderToolDetails(container, tid) {
    var toolDir = (PROJECT.tool_dirs || {})[tid] || '';
    var scope = TOOL_NATIVE_SCOPES[tid] || '';
    var scopeLabel = (SCOPE_DISPLAY_NAMES[scope] || scope || 'Unknown').replace(/^\w/, function(c){return c.toUpperCase();});
    var engDir = PROJECT.engagement_dir || PROJECT.project_dir || '';
    var rows = [
        {label: 'Scope', value: scopeLabel},
        {label: 'Tool Directory', value: toolDir || '(not assigned)'},
        {label: 'Engagement Directory', value: engDir || '(unknown)'},
    ];
    var html = '<div class="tool-details-panel">';
    html += '<div class="tool-details-header">Tool Details</div>';
    rows.forEach(function(r) {
        html += '<div class="tool-details-row">'
             +  '<span class="tool-details-label">' + r.label + '</span>'
             +  '<span class="tool-details-value">' + (r.value ? r.value.replace(/</g,'&lt;') : '') + '</span>'
             + '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
}

function loadToolSettings(tid) {
    settingsActiveTool = tid;
    document.getElementById('settingsEngagement').hidden = true;
    var body = document.getElementById('settingsBody');
    var empty = document.getElementById('settingsEmpty');
    var fields = document.getElementById('settingsFields');
    var advFields = document.getElementById('settingsAdvancedFields');
    var advToggle = document.getElementById('settingsAdvancedToggle');

    body.hidden = false;
    empty.style.display = 'none';
    fields.innerHTML = '<div class="form-grid-full flex-center p-20"><div class="spinner"></div></div>';
    advFields.innerHTML = '';
    advFields.hidden = true;
    advToggle.hidden = true;

    var detailsEl = document.getElementById('settingsToolDetails');
    if (!detailsEl) {
        detailsEl = document.createElement('div');
        detailsEl.id = 'settingsToolDetails';
        fields.parentNode.insertBefore(detailsEl, fields);
    }
    _renderToolDetails(detailsEl, tid);

    fetch('/api/settings/' + PID + '/' + tid, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            fields.innerHTML = '';
            if (!data || typeof data !== 'object') {
                fields.innerHTML = '<div class="form-grid-full"><span class="text-muted">No settings available.</span></div>';
                return;
            }
            var settings = data.settings || data;
            var schema = data.schema || null;
            _settingsOriginal = JSON.parse(JSON.stringify(settings));
            var advanced = {};
            var curated = {};
            for (var key in settings) {
                if (!settings.hasOwnProperty(key)) continue;
                var fs = schema && schema[key] ? schema[key] : {};
                if (fs.advanced) advanced[key] = settings[key];
                else curated[key] = settings[key];
            }
            renderSettingsFields(fields, curated, schema);
            if (Object.keys(advanced).length) {
                renderSettingsFields(advFields, advanced, schema);
                advToggle.hidden = false;
            }
        })
        .catch(function() {
            fields.innerHTML = '<div class="form-grid-full"><span class="text-error">Failed to load settings.</span></div>';
        });
}

function renderSettingsFields(container, settings, schema) {
    var sFlat = schema || {};
    if (sFlat.fields && Array.isArray(sFlat.fields)) {
        var tmp = {};
        var _ord = [];
        sFlat.fields.forEach(function(f) { tmp[f.key] = f; _ord.push(f.key); });
        tmp._ordered = _ord;
        sFlat = tmp;
    }
    var orderedKeys = Object.keys(settings);
    if (sFlat._ordered) orderedKeys = sFlat._ordered.filter(function(k) { return k in settings || (sFlat[k] && sFlat[k].type === 'section'); });
    for (var _ki = 0; _ki < orderedKeys.length; _ki++) {
        var key = orderedKeys[_ki];
        var fieldSchema = sFlat[key] || {};

        if (fieldSchema.type === 'section') {
            var sec = document.createElement('div');
            sec.className = 'form-grid-full';
            sec.innerHTML = '<h4 style="margin:20px 0 4px;padding-bottom:6px;border-bottom:1px solid var(--border-subtle);font-size:0.82rem;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);">' + esc(fieldSchema.label) + '</h4>';
            container.appendChild(sec);
            continue;
        }

        if (!settings.hasOwnProperty(key) && fieldSchema.type !== 'ssid_scan') continue;
        var val = settings[key];
        if (val !== null && typeof val === 'object' && !Array.isArray(val) && fieldSchema.type !== 'phase_toggles') continue;
        var label = fieldSchema.label || key.replace(/_/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
        var type = fieldSchema.type || (typeof val === 'boolean' ? 'checkbox' : typeof val === 'number' ? 'number' : 'text');

        var group = document.createElement('div');
        group.className = 'form-group';

        if (type === 'file_list') {
            var files = Array.isArray(val) ? val : [];
            var accept = fieldSchema.accept || '*';
            group.className += ' form-grid-full';
            group.innerHTML =
                '<span class="form-label">' + esc(label) + '</span>' +
                '<div class="file-list-widget" data-key="' + esc(key) + '">' +
                    '<ul class="file-list-items" style="list-style:none;padding:0;margin:0 0 8px 0;font-size:0.82rem"></ul>' +
                    '<div style="display:flex;gap:6px;align-items:center;margin-bottom:6px">' +
                        '<input type="text" class="form-control file-list-path-input" placeholder="Server path" style="flex:1;font-size:0.82rem">' +
                        '<button type="button" class="btn btn-xs btn-primary file-list-add-path">+ Add</button>' +
                    '</div>' +
                    '<input type="file" class="file-list-input" multiple accept="' + esc(accept) + '" style="font-size:0.82rem">' +
                    '<button type="button" class="btn btn-sm btn-secondary file-list-upload" style="margin-top:6px">Upload</button>' +
                    '<input type="hidden" name="' + esc(key) + '" value="' + esc(JSON.stringify(files)) + '">' +
                '</div>';
            (function(k, grp) {
                var _flFiles = files.slice();
                var _flHidden = grp.querySelector('input[name="' + k + '"]');
                var _flUl = grp.querySelector('.file-list-items');
                function _flRender() {
                    _flUl.innerHTML = _flFiles.map(function(f, i) {
                        return '<li style="padding:2px 0;display:flex;align-items:center;gap:6px">' +
                            '<span style="flex:1;word-break:break-all">' + esc(f) + '</span>' +
                            '<button type="button" class="file-remove" data-idx="' + i + '" style="background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:.9rem;padding:0 4px" title="Remove">&times;</button></li>';
                    }).join('');
                    _flHidden.value = JSON.stringify(_flFiles);
                    _flUl.querySelectorAll('.file-remove').forEach(function(btn) {
                        btn.addEventListener('click', function() {
                            _flFiles.splice(parseInt(this.dataset.idx), 1);
                            _flRender();
                        });
                    });
                }
                _flRender();
                var _flAddBtn = grp.querySelector('.file-list-add-path');
                var _flPathInp = grp.querySelector('.file-list-path-input');
                if (_flAddBtn && _flPathInp) {
                    _flAddBtn.addEventListener('click', function() {
                        var v = _flPathInp.value.trim();
                        if (v && _flFiles.indexOf(v) === -1) { _flFiles.push(v); _flRender(); }
                        _flPathInp.value = '';
                    });
                    _flPathInp.addEventListener('keydown', function(e) {
                        if (e.key === 'Enter') { e.preventDefault(); _flAddBtn.click(); }
                    });
                }
            })(key, group);
        } else if (type === 'multi_check') {
            var opts = fieldSchema.options || [];
            var checked = Array.isArray(val) ? val : [];
            group.className += ' form-grid-full';
            var html = '<span class="form-label">' + esc(label) + '</span><div style="display:flex;flex-wrap:wrap;gap:6px 16px">';
            opts.forEach(function(o) {
                html += '<div class="form-check">' +
                    '<label><input type="checkbox" class="mc-' + esc(key) + '" value="' + esc(o) + '"' +
                    (checked.indexOf(o) !== -1 ? ' checked' : '') + '> ' +
                    esc(o) + '</label></div>';
            });
            html += '</div><input type="hidden" name="' + esc(key) + '" value="' + esc(JSON.stringify(checked)) + '">';
            group.innerHTML = html;
            (function(k) {
                group.addEventListener('change', function() {
                    var vals = [];
                    group.querySelectorAll('.mc-' + k + ':checked').forEach(function(cb) { vals.push(cb.value); });
                    group.querySelector('input[name="' + k + '"]').value = JSON.stringify(vals);
                });
            })(key);
        } else if (type === 'checkbox_group') {
            var opts = fieldSchema.options || [];
            var checked = Array.isArray(val) ? val : [];
            group.className += ' form-grid-full';
            var html = '<span class="form-label">' + esc(label) + '</span>';
            if (fieldSchema.hint) html += '<span class="form-hint" style="display:block;margin-bottom:8px">' + esc(fieldSchema.hint) + '</span>';
            html += '<div style="display:flex;flex-direction:column;gap:6px">';
            opts.forEach(function(o) {
                var oVal = (typeof o === 'object' && o !== null) ? (o.value || '') : o;
                var oLabel = (typeof o === 'object' && o !== null) ? (o.label || oVal) : o;
                var oHint = (typeof o === 'object' && o !== null) ? (o.hint || '') : '';
                html += '<label style="font-weight:400;display:flex;align-items:center;gap:6px">' +
                    '<input type="checkbox" class="cg-' + esc(key) + '" value="' + esc(oVal) + '"' +
                    (checked.indexOf(oVal) !== -1 ? ' checked' : '') + '> ' +
                    esc(oLabel);
                if (oHint) html += '<span class="form-hint" style="margin-left:auto;font-size:0.75rem">' + esc(oHint) + '</span>';
                html += '</label>';
            });
            html += '</div>';
            html += '<div style="margin-top:6px;display:flex;gap:8px">' +
                '<button type="button" class="btn btn-secondary btn-sm cg-all-' + esc(key) + '">Select All</button>' +
                '<button type="button" class="btn btn-secondary btn-sm cg-none-' + esc(key) + '">Deselect All</button></div>';
            html += '<input type="hidden" name="' + esc(key) + '" value="' + esc(JSON.stringify(checked)) + '">';
            group.innerHTML = html;
            (function(k) {
                function _sync() {
                    var vals = [];
                    group.querySelectorAll('.cg-' + k + ':checked').forEach(function(cb) { vals.push(cb.value); });
                    group.querySelector('input[name="' + k + '"]').value = JSON.stringify(vals);
                }
                group.addEventListener('change', _sync);
                var allBtn = group.querySelector('.cg-all-' + k);
                var noneBtn = group.querySelector('.cg-none-' + k);
                if (allBtn) allBtn.addEventListener('click', function() {
                    group.querySelectorAll('.cg-' + k).forEach(function(cb) { cb.checked = true; }); _sync();
                });
                if (noneBtn) noneBtn.addEventListener('click', function() {
                    group.querySelectorAll('.cg-' + k).forEach(function(cb) { cb.checked = false; }); _sync();
                });
            })(key);
        } else if (type === 'frida_device_select') {
            group.innerHTML =
                '<label class="form-label">' + esc(label) + '</label>' +
                '<div style="display:flex;gap:6px;align-items:center">' +
                    '<select class="form-control" name="' + esc(key) + '" id="s_' + esc(key) + '" style="flex:1">' +
                        (val ? '<option value="' + esc(val) + '" selected>' + esc(val) + '</option>' : '') +
                        '<option value="">-- Click Refresh to scan --</option>' +
                    '</select>' +
                    '<button type="button" class="btn btn-xs btn-secondary _frida-refresh-btn" title="Scan for connected devices">&#x21bb; Refresh</button>' +
                '</div>' +
                '<div class="_frida-status" hidden style="margin-top:6px;font-size:0.8rem;padding:8px 10px;border-radius:4px"></div>';
            (function(grp, savedVal) {
                var sel = grp.querySelector('select');
                var btn = grp.querySelector('._frida-refresh-btn');
                var sts = grp.querySelector('._frida-status');
                function _msg(t, m) {
                    sts.hidden = false;
                    sts.style.background = t === 'error' ? 'var(--bg-error, #3a1c1c)' : t === 'warn' ? 'var(--bg-warn, #3a2e1c)' : 'var(--bg-info, #1c2a3a)';
                    sts.style.color = t === 'error' ? 'var(--text-error, #ff6b6b)' : t === 'warn' ? 'var(--text-warn, #ffb347)' : 'var(--text-info, #6bc5ff)';
                    sts.innerHTML = m;
                }
                function _scan() {
                    sel.innerHTML = '<option value="">Scanning...</option>';
                    sel.disabled = true;
                    sts.hidden = true;
                    fetch('/api/frida-devices', {credentials: 'same-origin'})
                        .then(function(r) { return r.json(); })
                        .then(function(data) {
                            sel.disabled = false;
                            sel.innerHTML = '';
                            if (!data.ok) {
                                if (data.error === 'frida_not_installed') {
                                    sel.innerHTML = '<option value="">(Frida not installed)</option>';
                                    _msg('error', '<strong>Frida is not installed.</strong><br>' +
                                        'Install: <code>pip3 install frida-tools frida</code><br>' +
                                        'Then download <code>frida-server</code> for your device from ' +
                                        '<a href="https://github.com/frida/frida/releases" target="_blank" style="color:inherit;text-decoration:underline">GitHub releases</a>.<br>' +
                                        'Push to device: <code>adb push frida-server /data/local/tmp/ &amp;&amp; adb shell chmod 755 /data/local/tmp/frida-server &amp;&amp; adb shell su -c \'/data/local/tmp/frida-server -D &amp;\'</code>');
                                } else if (data.error === 'no_devices') {
                                    sel.innerHTML = '<option value="">(No devices found)</option>';
                                    _msg('warn', '<strong>No mobile devices detected.</strong><br>' +
                                        'Connect your Android or iOS device via USB and ensure USB debugging is enabled. ' +
                                        'Frida-server must be running on the device.');
                                } else {
                                    sel.innerHTML = '<option value="">(Error)</option>';
                                    _msg('error', data.message || 'Unknown error');
                                }
                                return;
                            }
                            sel.innerHTML = '<option value="">-- Select device --</option>';
                            (data.devices || []).forEach(function(d) {
                                var o = document.createElement('option');
                                o.value = d.id;
                                o.textContent = d.name + ' (' + d.id + ')';
                                sel.appendChild(o);
                            });
                            if (savedVal) sel.value = savedVal;
                            if (data.devices && data.devices.length === 1) sel.value = data.devices[0].id;
                            sts.hidden = true;
                        })
                        .catch(function() {
                            sel.disabled = false;
                            sel.innerHTML = '<option value="">(Scan failed)</option>';
                            _msg('error', 'Failed to reach server.');
                        });
                }
                btn.addEventListener('click', _scan);
            })(group, val || '');
        } else if (type === 'checkbox') {
            group.innerHTML =
                '<div class="form-check">' +
                    '<input type="checkbox" name="' + esc(key) + '" id="s_' + esc(key) + '"' + (val ? ' checked' : '') + '>' +
                    '<label for="s_' + esc(key) + '">' + esc(label) + '</label>' +
                '</div>';
        } else if (type === 'select' && fieldSchema.options) {
            var opts = fieldSchema.options.map(function(o) {
                var oVal = (typeof o === 'object' && o !== null) ? (o.value != null ? o.value : '') : o;
                var oLabel = (typeof o === 'object' && o !== null) ? (o.label || oVal) : o;
                return '<option value="' + esc(oVal) + '"' + (oVal == val ? ' selected' : '') + '>' + esc(oLabel) + '</option>';
            }).join('');
            group.innerHTML =
                '<label class="form-label" for="s_' + esc(key) + '">' + esc(label) + '</label>' +
                '<select class="form-control" name="' + esc(key) + '" id="s_' + esc(key) + '">' + opts + '</select>';
        } else if (type === 'textarea') {
            group.className += ' form-grid-full';
            group.innerHTML =
                '<label class="form-label" for="s_' + esc(key) + '">' + esc(label) + '</label>' +
                '<textarea class="form-control" name="' + esc(key) + '" id="s_' + esc(key) + '" rows="3">' + esc(val || '') + '</textarea>';
        } else if (type === 'interface_picker') {
            group.innerHTML =
                '<label class="form-label" for="s_' + esc(key) + '">' + esc(label) + '</label>' +
                '<div style="display:flex;gap:6px">' +
                  '<select class="form-control" name="' + esc(key) + '" id="s_' + esc(key) + '" style="flex:1">' +
                    '<option value="">Loading...</option>' +
                  '</select>' +
                  '<button type="button" class="btn btn-secondary btn-sm st-refresh-ifaces" data-target="s_' + esc(key) + '" title="Refresh">&#x21bb;</button>' +
                '</div>' +
                '<span class="form-hint st-iface-info" id="s_' + esc(key) + '_info"></span>';
            (function(k, savedVal) {
                var selId = 's_' + k;
                _stLoadWifiInterfaces(selId, savedVal);
            })(key, val || '');
        } else if (type === 'ssid_scan') {
            group.className += ' form-grid-full';
            group.innerHTML =
                '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
                  '<span class="form-label" style="margin:0">' + esc(label) + '</span>' +
                  '<button type="button" class="btn btn-secondary btn-sm st-scan-ssids">Scan SSIDs</button>' +
                  '<span class="form-hint st-scan-status"></span>' +
                '</div>' +
                '<div class="st-scan-results" hidden>' +
                  '<table class="findings-table" style="font-size:0.82rem;margin-bottom:10px">' +
                    '<thead><tr>' +
                      '<th style="width:30px;text-align:center"><input type="checkbox" class="st-ssid-all" title="Select all"></th>' +
                      '<th>SSID</th>' +
                      '<th style="width:70px;text-align:center">Signal</th>' +
                      '<th style="width:45px;text-align:center">Ch</th>' +
                      '<th style="width:140px">Security</th>' +
                      '<th style="width:90px;text-align:center">Assign</th>' +
                    '</tr></thead>' +
                    '<tbody class="st-ssid-body"></tbody>' +
                  '</table>' +
                  '<button type="button" class="btn btn-primary btn-sm st-apply-ssids">Apply Selected</button>' +
                '</div>';
            (function(grp) {
                var scanBtn = grp.querySelector('.st-scan-ssids');
                var status = grp.querySelector('.st-scan-status');
                var results = grp.querySelector('.st-scan-results');
                var body = grp.querySelector('.st-ssid-body');
                var allCb = grp.querySelector('.st-ssid-all');
                var applyBtn = grp.querySelector('.st-apply-ssids');
                scanBtn.addEventListener('click', function() {
                    var ifSel = document.querySelector('[name="interface"]');
                    var iface = ifSel ? ifSel.value : '';
                    scanBtn.disabled = true;
                    status.textContent = 'Scanning...';
                    fetch('/api/wifi-scan' + (iface ? '?interface=' + encodeURIComponent(iface) : ''), {credentials: 'same-origin'})
                        .then(function(r) { return r.json(); })
                        .then(function(d) {
                            var nets = d.networks || [];
                            if (!nets.length) { status.textContent = 'No networks found.'; scanBtn.disabled = false; return; }
                            var bySSID = {};
                            nets.forEach(function(n) {
                                var ssid = n.ssid || '(hidden)';
                                var prev = bySSID[ssid];
                                if (!prev || (n.signal || 0) > (prev.signal || 0)) {
                                    bySSID[ssid] = {ssid: ssid, signal: n.signal, channel: n.channel,
                                        security: n.security || (n.encrypted ? 'Encrypted' : 'Open'),
                                        count: prev ? prev.count + 1 : 1};
                                } else { prev.count = (prev.count || 1) + 1; }
                            });
                            var unique = Object.keys(bySSID).map(function(k) { return bySSID[k]; });
                            unique.sort(function(a, b) { return (b.signal || 0) - (a.signal || 0); });
                            status.textContent = unique.length + ' unique SSID(s) (' + nets.length + ' APs)';
                            body.innerHTML = '';
                            unique.forEach(function(n) {
                                var ssid = n.ssid;
                                var countBadge = n.count > 1 ? ' <span style="color:var(--text-muted);font-size:.72rem">(' + n.count + ' APs)</span>' : '';
                                var tr = document.createElement('tr');
                                tr.dataset.ssid = ssid;
                                tr.innerHTML =
                                    '<td style="text-align:center"><input type="checkbox" class="st-ssid-check" checked></td>' +
                                    '<td>' + esc(ssid) + countBadge + '</td>' +
                                    '<td style="text-align:center">' + (n.signal != null ? n.signal + ' dBm' : '') + '</td>' +
                                    '<td style="text-align:center">' + esc(String(n.channel || '')) + '</td>' +
                                    '<td>' + esc(n.security || '') + '</td>' +
                                    '<td style="text-align:center"><select class="st-ssid-assign form-control" style="font-size:.78rem;padding:2px 4px">' +
                                      '<option value="active" selected>Active</option><option value="passive">Passive</option></select></td>';
                                body.appendChild(tr);
                            });
                            results.hidden = false;
                            scanBtn.disabled = false;
                        })
                        .catch(function(err) { status.textContent = 'Failed: ' + (err.message || ''); scanBtn.disabled = false; });
                });
                if (allCb) allCb.addEventListener('change', function() {
                    body.querySelectorAll('.st-ssid-check').forEach(function(c) { c.checked = allCb.checked; });
                });
                if (applyBtn) applyBtn.addEventListener('click', function() {
                    var activeTa = document.querySelector('#s_target_ssids_ta');
                    var passiveTa = document.querySelector('#s_passive_ssids_ta');
                    var activeHid = document.querySelector('input[name="target_ssids"]');
                    var passiveHid = document.querySelector('input[name="passive_ssids"]');
                    var aList = activeTa ? activeTa.value.split('\n').filter(Boolean) : [];
                    var pList = passiveTa ? passiveTa.value.split('\n').filter(Boolean) : [];
                    var aSet = {}; aList.forEach(function(s) { aSet[s] = true; });
                    var pSet = {}; pList.forEach(function(s) { pSet[s] = true; });
                    body.querySelectorAll('tr').forEach(function(row) {
                        var cb = row.querySelector('.st-ssid-check');
                        var assign = row.querySelector('.st-ssid-assign');
                        if (!cb || !cb.checked || !assign) return;
                        var ssid = row.dataset.ssid;
                        if (!ssid || ssid === '(hidden)') return;
                        if (assign.value === 'active' && !aSet[ssid]) { aList.push(ssid); aSet[ssid] = true; }
                        else if (assign.value === 'passive' && !pSet[ssid]) { pList.push(ssid); pSet[ssid] = true; }
                    });
                    if (activeTa) activeTa.value = aList.join('\n');
                    if (passiveTa) passiveTa.value = pList.join('\n');
                    if (activeHid) activeHid.value = JSON.stringify(aList);
                    if (passiveHid) passiveHid.value = JSON.stringify(pList);
                    toast('success', 'SSIDs applied to scope lists.');
                });
            })(group);
        } else if (type === 'tag_list') {
            var tags = Array.isArray(val) ? val : (val ? String(val).split('\n').filter(Boolean) : []);
            group.className += ' form-grid-full';
            group.innerHTML =
                '<label class="form-label" for="s_' + esc(key) + '_ta">' + esc(label) + '</label>' +
                '<textarea class="form-control" id="s_' + esc(key) + '_ta" rows="3" placeholder="One item per line">' + esc(tags.join('\n')) + '</textarea>' +
                '<input type="hidden" name="' + esc(key) + '" value="' + esc(JSON.stringify(tags)) + '">';
            (function(k) {
                var ta = group.querySelector('#s_' + k + '_ta');
                var hid = group.querySelector('input[name="' + k + '"]');
                if (ta && hid) {
                    ta.addEventListener('input', function() {
                        var arr = ta.value.split('\n').map(function(l){return l.trim();}).filter(Boolean);
                        hid.value = JSON.stringify(arr);
                    });
                }
            })(key);
        } else if (type === 'phase_toggles') {
            var phases = (typeof val === 'object' && val && !Array.isArray(val)) ? val : {};
            group.className += ' form-grid-full';
            var phHtml = '<label class="form-label">' + esc(label) + '</label>' +
                '<div style="display:flex;flex-wrap:wrap;gap:6px 16px">';
            Object.keys(phases).forEach(function(pk) {
                var pLabel = pk.replace(/_/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
                phHtml += '<label style="font-weight:400;display:flex;align-items:center;gap:4px;font-size:0.85rem">' +
                    '<input type="checkbox" class="pt-' + esc(key) + '" value="' + esc(pk) + '"' +
                    (phases[pk] ? ' checked' : '') + '> ' + esc(pLabel) + '</label>';
            });
            phHtml += '</div><input type="hidden" name="' + esc(key) + '" value="' + esc(JSON.stringify(phases)) + '">';
            group.innerHTML = phHtml;
            (function(k) {
                group.addEventListener('change', function() {
                    var obj = {};
                    group.querySelectorAll('.pt-' + k).forEach(function(cb) {
                        obj[cb.value] = cb.checked;
                    });
                    group.querySelector('input[name="' + k + '"]').value = JSON.stringify(obj);
                });
            })(key);
        } else {
            group.innerHTML =
                '<label class="form-label" for="s_' + esc(key) + '">' + esc(label) + '</label>' +
                '<input type="' + type + '" class="form-control" name="' + esc(key) + '" id="s_' + esc(key) + '" value="' + esc(val || '') + '">';
        }

        if (fieldSchema.hint) {
            group.innerHTML += '<span class="form-hint">' + esc(fieldSchema.hint) + '</span>';
        }

        if (fieldSchema.depends_on) {
            group.dataset.dependsOn = JSON.stringify(fieldSchema.depends_on);
        }

        container.appendChild(group);
    }

    _applySettingsDeps();
}

/* ── Settings: wireless interface picker helpers ──────────── */
function _stLoadWifiInterfaces(selId, preselect) {
    var sel = document.getElementById(selId);
    if (!sel) return;
    sel.innerHTML = '<option value="">Loading...</option>';
    fetch('/api/wifi-interfaces', {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var ifaces = d.interfaces || [];
            sel.innerHTML = '<option value="">— Select interface —</option>';
            if (!ifaces.length) {
                sel.innerHTML = '<option value="">No wireless interfaces detected</option>';
                return;
            }
            ifaces.forEach(function(iface) {
                var lbl = iface.interface;
                var det = [];
                if (iface.bus && iface.bus !== 'Unknown') det.push(iface.bus);
                if (iface.manufacturer) det.push(iface.manufacturer);
                if (det.length) lbl += ' (' + det.join(' — ') + ')';
                if (iface.mode && iface.mode !== 'unknown') lbl += ' [' + iface.mode + ']';
                if (iface.channel) lbl += ' ch' + iface.channel;
                var opt = document.createElement('option');
                opt.value = iface.interface;
                opt.textContent = lbl;
                sel.appendChild(opt);
            });
            if (preselect) sel.value = preselect;
            var info = document.getElementById(selId + '_info');
            if (info && sel.value) {
                var m = ifaces.find(function(i) { return i.interface === sel.value; });
                if (m) {
                    var parts = [];
                    if (m.manufacturer) parts.push(m.manufacturer);
                    if (m.bus && m.bus !== 'Unknown') parts.push(m.bus);
                    if (m.mode && m.mode !== 'unknown') parts.push('Mode: ' + m.mode);
                    if (m.channel) parts.push('Channel: ' + m.channel);
                    info.textContent = parts.join(' · ');
                }
            }
        })
        .catch(function() {
            sel.innerHTML = '<option value="">— Failed to load —</option>';
        });
}

document.addEventListener('click', function(e) {
    var btn = e.target.closest('.st-refresh-ifaces');
    if (!btn) return;
    var targetId = btn.dataset.target;
    if (targetId) _stLoadWifiInterfaces(targetId, '');
});

function _applySettingsDeps() {
    var allGroups = document.querySelectorAll('#settingsFields .form-group[data-depends-on], #settingsAdvancedFields .form-group[data-depends-on]');
    var depKeys = {};
    allGroups.forEach(function(g) {
        var deps = JSON.parse(g.dataset.dependsOn);
        Object.keys(deps).forEach(function(k) { depKeys[k] = true; });
    });

    function evalDeps() {
        allGroups.forEach(function(g) {
            var deps = JSON.parse(g.dataset.dependsOn);
            var visible = true;
            Object.keys(deps).forEach(function(k) {
                var el = document.querySelector('[name="' + k + '"]');
                if (!el) { visible = false; return; }
                var val = el.type === 'checkbox' ? (el.checked ? 'true' : 'false') : el.value;
                if (deps[k].indexOf(val) === -1) visible = false;
            });
            g.hidden = !visible;
        });
    }

    Object.keys(depKeys).forEach(function(k) {
        var el = document.querySelector('#settingsFields [name="' + k + '"], #settingsAdvancedFields [name="' + k + '"]');
        if (el) el.addEventListener('change', evalDeps);
    });
    evalDeps();
}

function _collectSettingsForm() {
    var formData = {};
    ['settingsFields','settingsAdvancedFields'].forEach(function(cid) {
        var inputs = document.getElementById(cid).querySelectorAll('[name]');
        inputs.forEach(function(el) {
            if (el.type === 'checkbox' && !el.closest('.file-list-widget') && !el.className.match(/^mc-|^cg-/)) {
                formData[el.name] = el.checked;
            } else if (el.type === 'hidden') {
                try { formData[el.name] = JSON.parse(el.value); } catch(e) { formData[el.name] = el.value; }
            } else if (el.type === 'number') {
                formData[el.name] = parseFloat(el.value) || 0;
            } else {
                formData[el.name] = el.value;
            }
        });
    });
    return formData;
}

/* ── File list upload handler ──────────────────────────────────── */
document.addEventListener('click', function(e) {
    var btn = e.target.closest('.file-list-upload');
    if (!btn) return;
    var widget = btn.closest('.file-list-widget');
    var input = widget.querySelector('.file-list-input');
    var hidden = widget.querySelector('input[type="hidden"]');
    var listEl = widget.querySelector('.file-list-items');
    if (!input.files.length) { toast('info', 'Select files first.'); return; }
    btn.disabled = true;
    btn.textContent = 'Uploading...';
    var existing = [];
    try { existing = JSON.parse(hidden.value); } catch(e) {}
    var uploads = Array.from(input.files);
    var done = 0;
    uploads.forEach(function(file) {
        var fd = new FormData();
        fd.append('file', file);
        fd.append('project_id', PID);
        fd.append('tool_id', settingsActiveTool);
        fetch('/api/upload_tool_file', {method: 'POST', credentials: 'same-origin', body: fd})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok && d.filename) {
                if (existing.indexOf(d.filename) === -1) {
                    existing.push(d.filename);
                    var li = document.createElement('li');
                    li.style.padding = '2px 0';
                    li.textContent = d.filename;
                    listEl.appendChild(li);
                }
            } else { toast('error', d.error || 'Upload failed for ' + file.name); }
        })
        .catch(function() { toast('error', 'Upload failed for ' + file.name); })
        .finally(function() {
            done++;
            if (done === uploads.length) {
                hidden.value = JSON.stringify(existing);
                input.value = '';
                btn.disabled = false;
                btn.textContent = 'Upload';
                toast('success', done + ' file(s) uploaded.');
            }
        });
    });
});

function _checkInvalidation(tid, formData) {
    var keys = SETTINGS_INVALIDATING_KEYS[tid] || [];
    var changed = [];
    keys.forEach(function(k) {
        var oldVal = _settingsOriginal[k];
        var newVal = formData[k];
        if (oldVal === undefined && newVal === undefined) return;
        if (String(oldVal || '') !== String(newVal || '')) changed.push(k);
    });
    return changed;
}

function _doSaveSettings(formData, archive) {
    var payload = formData;
    if (archive) payload.__archive_and_rescan = true;
    if (settingsActiveTool === 'fracture' && Object.keys(_stcPerTargetAuth).length) {
        var cleanPta = {};
        for (var u in _stcPerTargetAuth) {
            if (_stcPerTargetAuth.hasOwnProperty(u)) {
                var a = {}; for (var k in _stcPerTargetAuth[u]) { if (k !== '_tested') a[k] = _stcPerTargetAuth[u][k]; }
                cleanPta[u] = a;
            }
        }
        payload.per_target_auth = cleanPta;
    }
    fetch('/api/settings/' + PID + '/' + settingsActiveTool, {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) {
            toast('success', archive ? 'Settings saved. Old results archived, re-scan queued.' : 'Settings saved.');
            _settingsOriginal = JSON.parse(JSON.stringify(formData));
            delete _settingsOriginal.__archive_and_rescan;
        } else toast('error', d.error || 'Failed to save settings.');
    });
}

var _pendingSaveData = null;

document.getElementById('settingsForm').addEventListener('submit', function(e) {
    e.preventDefault();
    if (!settingsActiveTool) return;

    var formData = _collectSettingsForm();
    var changed = _checkInvalidation(settingsActiveTool, formData);

    if (changed.length) {
        _pendingSaveData = formData;
        var toolName = (TOOLS_CFG[settingsActiveTool] || {}).name || settingsActiveTool;
        document.getElementById('settingsInvalidateMsg').textContent =
            'Changing ' + changed.join(', ').replace(/_/g, ' ') + ' for ' + toolName +
            ' will invalidate current results. Existing output will be archived and a new scan will be queued.';
        document.getElementById('settingsInvalidateModal').classList.add('open');
        return;
    }

    _doSaveSettings(formData, false);
});

document.getElementById('btnInvalidateConfirm').addEventListener('click', function() {
    document.getElementById('settingsInvalidateModal').classList.remove('open');
    if (_pendingSaveData) {
        _doSaveSettings(_pendingSaveData, true);
        _pendingSaveData = null;
    }
});

document.getElementById('btnInvalidateCancel').addEventListener('click', function() {
    document.getElementById('settingsInvalidateModal').classList.remove('open');
    _pendingSaveData = null;
});

document.getElementById('btnSettingsReset').addEventListener('click', function() {
    if (settingsActiveTool) loadToolSettings(settingsActiveTool);
});

document.getElementById('btnAdvancedToggle').addEventListener('click', function() {
    var adv = document.getElementById('settingsAdvancedFields');
    var showing = adv.hidden;
    adv.hidden = !showing;
    this.textContent = showing ? 'Hide Advanced' : 'Advanced Settings';
});

/* ── Scope addition/removal ──────────────────────────────────────── */
var _engagementExistingScopes = [];
var _pendingScopeQueue = [];
var _pendingScopeData = {};
var _desiredScopes = [];
var _removedScopes = [];

document.getElementById('btnSaveScopes').addEventListener('click', function() {
    var checks = document.getElementById('seScopeChecks').querySelectorAll('input[type="checkbox"]');
    var checked = [];
    checks.forEach(function(cb) { if (cb.checked) checked.push(cb.value); });

    var added = checked.filter(function(s) { return _engagementExistingScopes.indexOf(s) === -1; });
    var removed = _engagementExistingScopes.filter(function(s) { return checked.indexOf(s) === -1; });

    if (!added.length && !removed.length) { toast('info', 'No scope changes.'); return; }

    _desiredScopes = checked;
    _removedScopes = removed;
    _pendingScopeData = {};

    var needModal = added.filter(function(s) {
        return (SCOPE_REQUIRED_FIELDS[s] || []).length > 0;
    });

    if (needModal.length) {
        _pendingScopeQueue = needModal.slice();
        _showNextScopeModal();
    } else {
        _submitScopeChanges();
    }
});

function _showNextScopeModal() {
    if (!_pendingScopeQueue.length) { _submitScopeChanges(); return; }
    var scopeKey = _pendingScopeQueue[0];
    var modal = document.getElementById('scopeAddModal');
    document.getElementById('scopeModalTitle').textContent = SCOPE_DISPLAY_NAMES[scopeKey] || scopeKey;
    var container = document.getElementById('scopeModalFields');
    container.innerHTML = '';
    var fields = SCOPE_REQUIRED_FIELDS[scopeKey] || [];
    fields.forEach(function(f) {
        var group = document.createElement('div');
        group.className = 'form-group form-grid-full';
        if (f.type === 'textarea') {
            group.innerHTML = '<label class="form-label" for="scopeModal_' + f.key + '">' + esc(f.label) + '</label>' +
                '<textarea class="form-control" id="scopeModal_' + f.key + '" rows="4" placeholder="' + esc(f.placeholder || '') + '"></textarea>';
        } else if (f.type === 'select') {
            var opts = (f.options || []).map(function(o) { var v=(typeof o==='object'&&o!==null)?(o.value!=null?o.value:''):o; var l=(typeof o==='object'&&o!==null)?(o.label||v):v; return '<option value="' + esc(v) + '">' + esc(l || '-- Select --') + '</option>'; }).join('');
            group.innerHTML = '<label class="form-label" for="scopeModal_' + f.key + '">' + esc(f.label) + '</label>' +
                '<select class="form-control" id="scopeModal_' + f.key + '">' + opts + '</select>';
        } else {
            group.innerHTML = '<label class="form-label" for="scopeModal_' + f.key + '">' + esc(f.label) + '</label>' +
                '<input type="text" class="form-control" id="scopeModal_' + f.key + '" placeholder="' + esc(f.placeholder || '') + '">';
        }
        container.appendChild(group);
    });
    modal.classList.add('open');
}

document.getElementById('btnScopeModalSave').addEventListener('click', function() {
    if (!_pendingScopeQueue.length) return;
    var scopeKey = _pendingScopeQueue.shift();
    var fields = SCOPE_REQUIRED_FIELDS[scopeKey] || [];
    fields.forEach(function(f) {
        var el = document.getElementById('scopeModal_' + f.key);
        if (el) _pendingScopeData[f.key] = f.type === 'textarea' ? el.value.split('\n').map(function(l){return l.trim();}).filter(function(l){return l;}) : el.value.trim();
    });
    document.getElementById('scopeAddModal').classList.remove('open');
    _showNextScopeModal();
});

function _submitScopeChanges() {
    fetch('/api/update_scopes/' + PID, {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({desired_scopes: _desiredScopes, scope_data: _pendingScopeData})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) { toast('success', 'Scopes updated.'); window.location.reload(); }
        else toast('error', d.error || 'Failed to update scopes.');
    });
}

document.getElementById('btnScopeModalCancel').addEventListener('click', function() {
    document.getElementById('scopeAddModal').classList.remove('open');
    _pendingScopeQueue = [];
    _pendingScopeData = {};
});

/* ── Auto-Queue toggle ──────────────────────────────────────────── */
document.getElementById('seAutoQueue').addEventListener('change', function() {
    var enabled = this.checked;
    var cb = this;
    fetch('/api/auto_queue/' + PID, {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: enabled})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) {
            PROJECT.auto_queue = enabled;
            toast('success', enabled ? 'Auto-Queue enabled' : 'Auto-Queue disabled');
        } else {
            cb.checked = !enabled;
            toast('error', d.error || 'Failed to toggle auto-queue.');
        }
    })
    .catch(function() {
        cb.checked = !enabled;
        toast('error', 'Network error toggling auto-queue.');
    });
});

/* ── Beacon status server ─────────────────────────────────────── */
(function() {
    function _saveBeacon() {
        var url = (document.getElementById('seBeaconUrl') || {}).value || '';
        var enabled = !!(document.getElementById('seBeaconEnabled') || {}).checked;
        fetch('/api/update_project/' + PID, {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({beacon_url: url, beacon_enabled: enabled})
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) {
                PROJECT.beacon_url = url;
                PROJECT.beacon_enabled = enabled;
                toast('success', 'Status server settings saved.');
            } else {
                toast('error', d.error || 'Failed to save status server settings.');
            }
        })
        .catch(function() { toast('error', 'Network error saving status server settings.'); });
    }
    var _bUrl = document.getElementById('seBeaconUrl');
    var _bEnabled = document.getElementById('seBeaconEnabled');
    if (_bUrl) _bUrl.addEventListener('change', _saveBeacon);
    if (_bEnabled) _bEnabled.addEventListener('change', _saveBeacon);

    var _bTest = document.getElementById('btnBeaconTest');
    if (_bTest) _bTest.addEventListener('click', function() {
        var url = (document.getElementById('seBeaconUrl') || {}).value || '';
        var result = document.getElementById('seBeaconTestResult');
        if (!url) {
            if (result) result.innerHTML = '<span style="color:var(--risk-high)">URL is required</span>';
            return;
        }
        if (result) result.innerHTML = '<span class="text-muted">Testing...</span>';
        fetch('/api/beacon/test', {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url, project_id: PID})
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) {
                result.innerHTML = '<span style="color:var(--risk-low)">Connected</span>';
            } else {
                result.innerHTML = '<span style="color:var(--risk-high)">' + esc(d.error || 'Failed') + '</span>';
            }
        })
        .catch(function() {
            result.innerHTML = '<span style="color:var(--risk-high)">Request failed</span>';
        });
    });
})();

/* ── OOS Handling toggle ────────────────────────────────────────── */
(function() {
    var radios = document.querySelectorAll('input[name="seOosHandling"]');
    var modal = document.getElementById('seOosConfirmModal');
    var pendingVal = null;

    function saveOos(mode) {
        fetch('/api/oos_handling/' + PID, {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({mode: mode})
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) {
                PROJECT.oos_handling = mode;
                var labels = {explicit:'Explicit In-Scope Only', separated:'Separated OOS Results', combined:'Combined Results'};
                toast('success', 'Out-of-Scope Handling: ' + (labels[mode] || mode));
            } else {
                document.querySelector('input[name="seOosHandling"][value="' + (PROJECT.oos_handling || 'explicit') + '"]').checked = true;
                toast('error', d.error || 'Failed to update OOS handling.');
            }
        })
        .catch(function() {
            document.querySelector('input[name="seOosHandling"][value="' + (PROJECT.oos_handling || 'explicit') + '"]').checked = true;
            toast('error', 'Network error updating OOS handling.');
        });
    }

    radios.forEach(function(r) {
        r.addEventListener('change', function() {
            if (this.value === 'explicit') {
                saveOos('explicit');
            } else {
                pendingVal = this.value;
                document.getElementById('seOosModalSeparated').hidden = (this.value !== 'separated');
                document.getElementById('seOosModalCombined').hidden = (this.value !== 'combined');
                modal.classList.add('open');
            }
        });
    });

    document.getElementById('seOosModalConfirm').addEventListener('click', function() {
        modal.classList.remove('open');
        if (pendingVal) saveOos(pendingVal);
        pendingVal = null;
    });

    function cancelOos() {
        modal.classList.remove('open');
        document.querySelector('input[name="seOosHandling"][value="' + (PROJECT.oos_handling || 'explicit') + '"]').checked = true;
        pendingVal = null;
    }
    document.getElementById('seOosModalCancel').addEventListener('click', cancelOos);
    document.getElementById('seOosModalDeny').addEventListener('click', cancelOos);
})();

/* ── Exclude IP ────────────────────────────────────────────────────── */
(function() {
    var modal = document.getElementById('seExcludeIpModal');
    var pendingIp = null;

    function renderExcludedList() {
        var container = document.getElementById('seExcludedIpsList');
        if (!container) return;
        var excl = ((PROJECT.scope_definition || {}).exclusions || []);
        if (!excl.length) {
            container.innerHTML = '<span class="text-muted text-sm">No IPs excluded.</span>';
            return;
        }
        var html = '<div style="display:flex;flex-wrap:wrap;gap:6px">';
        excl.forEach(function(ip) {
            html += '<span class="badge" style="background:var(--red-100);color:var(--red-800);padding:4px 10px;border-radius:4px;font-size:.8rem;display:inline-flex;align-items:center;gap:6px">'
                + esc(ip)
                + '<button type="button" class="btn-icon-xs" data-unexclude="' + esc(ip) + '" title="Remove from exclusion list" style="background:none;border:none;cursor:pointer;font-size:1rem;line-height:1;color:var(--red-600);padding:0">&times;</button>'
                + '</span>';
        });
        html += '</div>';
        container.innerHTML = html;
    }

    document.getElementById('btnExcludeIp').addEventListener('click', function() {
        var input = document.getElementById('seExcludeIpInput');
        var ip = (input.value || '').trim();
        if (!ip) { toast('error', 'Enter an IP address to exclude.'); return; }
        pendingIp = ip;
        document.getElementById('seExcludeIpModalAddr').textContent = ip;
        modal.classList.add('open');
    });

    document.getElementById('seExcludeIpModalConfirm').addEventListener('click', function() {
        modal.classList.remove('open');
        if (!pendingIp) return;
        var ip = pendingIp;
        pendingIp = null;
        fetch('/api/exclude_ip/' + PID, {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: ip})
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) {
                if (!PROJECT.scope_definition) PROJECT.scope_definition = {};
                PROJECT.scope_definition.exclusions = d.exclusions;
                document.getElementById('seExcludeIpInput').value = '';
                renderExcludedList();
                toast('success', 'IP ' + ip + ' excluded. ' + d.removed_findings + ' finding(s) removed, ' + d.modified_nessus + ' Nessus file(s) modified.');
            } else {
                toast('error', d.error || 'Failed to exclude IP.');
            }
        })
        .catch(function() { toast('error', 'Network error excluding IP.'); });
    });

    function cancelExclude() {
        modal.classList.remove('open');
        pendingIp = null;
    }
    document.getElementById('seExcludeIpModalCancel').addEventListener('click', cancelExclude);
    document.getElementById('seExcludeIpModalDeny').addEventListener('click', cancelExclude);

    document.getElementById('seExcludedIpsList').addEventListener('click', function(e) {
        var btn = e.target.closest('[data-unexclude]');
        if (!btn) return;
        var ip = btn.getAttribute('data-unexclude');
        if (!confirm('Remove ' + ip + ' from the exclusion list?\n\nNote: Previously removed findings and Nessus data will NOT be restored.')) return;
        fetch('/api/unexclude_ip/' + PID, {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: ip})
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.ok) {
                PROJECT.scope_definition.exclusions = d.exclusions;
                renderExcludedList();
                toast('success', 'IP ' + ip + ' removed from exclusion list.');
            } else {
                toast('error', d.error || 'Failed to remove exclusion.');
            }
        })
        .catch(function() { toast('error', 'Network error removing exclusion.'); });
    });

    var _origShowEngPanel = showEngagementPanel;
    showEngagementPanel = function() {
        _origShowEngPanel();
        renderExcludedList();
    };
})();

/* ── Settings tab test connection ─────────────────────────────────── */
var STC_TOOLS = new Set(['fracture', 'siphon', 'nessus']);

function updateSettingsTestConn() {
    var panel = document.getElementById('settingsTestConn');
    panel.hidden = !settingsActiveTool || !STC_TOOLS.has(settingsActiveTool);
    document.getElementById('settingsTestConnResult').hidden = true;
    document.getElementById('stcFingerprintArea').hidden = true;
    document.getElementById('btnStcFingerprint').disabled = true;
    document.getElementById('stcFpResultArea').hidden = true;
    document.getElementById('stcFpReminder').hidden = true;
    var stcSaveA = document.getElementById('stcSaveArea');
    if (stcSaveA) stcSaveA.hidden = true;
    var stcSt = document.getElementById('stcSaveStatus');
    if (stcSt) stcSt.textContent = '';
}

var _origLoadToolSettings = loadToolSettings;
loadToolSettings = function(tid) {
    _origLoadToolSettings(tid);
    updateSettingsTestConn();
    if (tid === 'fracture') {
        setTimeout(function() {
            var urls = [];
            var tgtEl = document.querySelector('#settingsFields [name="target_url"]');
            if (tgtEl && tgtEl.value) {
                tgtEl.value.split(/[\n,]+/).forEach(function(u) {
                    u = u.trim(); if (u && urls.indexOf(u) === -1) urls.push(u);
                });
            }
            var ptaInput = document.querySelector('#settingsFields [name="per_target_auth"]');
            if (ptaInput && ptaInput.value) {
                try { _stcPerTargetAuth = JSON.parse(ptaInput.value); } catch(e) { _stcPerTargetAuth = {}; }
                for (var u in _stcPerTargetAuth) {
                    if (_stcPerTargetAuth.hasOwnProperty(u)) {
                        _stcPerTargetAuth[u]._tested = true;
                        if (urls.indexOf(u) === -1) urls.push(u);
                    }
                }
            } else { _stcPerTargetAuth = {}; }
            _stcTargetUrls = urls;
            stcUpdatePerTargetTable();
        }, 250);
    } else {
        _stcPerTargetAuth = {};
        _stcTargetUrls = [];
    }
};

/* ── Settings tab: Per-target auth state ──────────────────────────── */
var _stcPerTargetAuth = {};
var _stcTargetUrls = [];

function stcUpdatePerTargetTable() {
    var section = document.getElementById('stcPerTargetSection');
    var tbody = document.getElementById('stcPerTargetBody');
    var sel = document.getElementById('stcTargetSelect');
    if (!section || !tbody || !sel) return;
    var urls = _stcTargetUrls || [];
    section.hidden = urls.length < 2;
    tbody.innerHTML = '';
    var prevVal = sel.value;
    sel.innerHTML = '';
    urls.forEach(function(url) {
        var auth = _stcPerTargetAuth[url] || {};
        var tested = auth._tested;
        var method = auth.method || 'auto';
        var preview = method === 'auto' ? 'Auto-Detect' : method;
        if (auth.username) preview += ' (' + auth.username.substring(0, 20) + ')';
        var tr = document.createElement('tr');
        tr.style.borderBottom = '1px solid var(--border-subtle, var(--border))';
        tr.innerHTML =
            '<td style="padding:4px 8px;word-break:break-all">' + esc(url.length > 60 ? url.substring(0, 57) + '…' : url) + '</td>' +
            '<td style="padding:4px 8px;text-align:center;color:' + (tested ? 'var(--status-success, #22c55e)' : 'var(--text-muted, #888)') + ';font-weight:600">' + (tested ? '✓' : '—') + '</td>' +
            '<td style="padding:4px 8px;color:var(--text-muted, #888)">' + esc(preview) + '</td>';
        tbody.appendChild(tr);
        var opt = document.createElement('option');
        opt.value = url; opt.textContent = url;
        if (url === prevVal) opt.selected = true;
        sel.appendChild(opt);
    });
}

document.getElementById('btnSettingsTestConn').addEventListener('click', function() {
    if (!settingsActiveTool || !STC_TOOLS.has(settingsActiveTool)) return;

    var btn = this;
    btn.disabled = true;
    btn.textContent = 'Testing...';

    if (settingsActiveTool === 'nessus') {
        fetch('/api/nessus/test/' + PID, {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type': 'application/json'},
            body: '{}'
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var resDiv = document.getElementById('settingsTestConnResult');
            resDiv.hidden = false;
            var label = document.getElementById('stcResultLabel');
            var badge = document.getElementById('stcResultBadge');
            var body = document.getElementById('stcResultBody');
            if (d.ok) {
                label.textContent = 'Connection Successful';
                badge.innerHTML = '<span class="status-badge" style="background:var(--status-success);color:#fff">OK</span>';
            } else {
                label.textContent = 'Connection Failed';
                badge.innerHTML = '<span class="status-badge" style="background:var(--status-error);color:#fff">FAIL</span>';
            }
            body.textContent = d.message || '';
        })
        .catch(function(e) {
            var resDiv = document.getElementById('settingsTestConnResult');
            resDiv.hidden = false;
            document.getElementById('stcResultLabel').textContent = 'Error';
            document.getElementById('stcResultBadge').innerHTML = '<span class="status-badge" style="background:var(--status-error);color:#fff">ERR</span>';
            document.getElementById('stcResultBody').textContent = e.message || 'Request failed';
        })
        .finally(function() {
            btn.disabled = false;
            btn.textContent = 'Run Test';
        });
        return;
    }

    var formData = {};
    var inputs = document.getElementById('settingsFields').querySelectorAll('[name]');
    inputs.forEach(function(el) {
        if (el.type === 'checkbox') formData[el.name] = el.checked;
        else if (el.type === 'number') formData[el.name] = parseFloat(el.value) || 0;
        else formData[el.name] = el.value;
    });

    var stcSel = document.getElementById('stcTargetSelect');
    var target = '';
    if (settingsActiveTool === 'fracture' && stcSel && stcSel.value) {
        target = stcSel.value;
    } else {
        target = formData.target_url || formData.api_base_url || '';
    }
    if (!target) {
        toast('error', 'No target URL configured in settings.');
        return;
    }

    var payload = {
        target: target,
        auth: formData.auth || {},
        verify_ssl: formData.verify_ssl,
        proxy: formData.proxy || '',
        timeout: formData.timeout || 30,
        probe: true
    };

    fetch('/api/test-connection/' + settingsActiveTool, {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        var resDiv = document.getElementById('settingsTestConnResult');
        resDiv.hidden = false;
        var label = document.getElementById('stcResultLabel');
        var badge = document.getElementById('stcResultBadge');
        var body = document.getElementById('stcResultBody');

        if (d.ok) {
            label.textContent = 'Connection Successful';
            badge.innerHTML = '<span class="status-badge" style="background:var(--status-success);color:#fff">OK</span>';
        } else {
            label.textContent = 'Connection Failed';
            badge.innerHTML = '<span class="status-badge" style="background:var(--status-error);color:#fff">FAIL</span>';
            if (settingsActiveTool === 'fracture') {
                document.getElementById('stcFingerprintArea').hidden = false;
                document.getElementById('btnStcFingerprint').disabled = false;
                document.getElementById('btnStcFingerprint').title = 'Record auth flow via monitored browser';
            }
        }

        var stcSaveA = document.getElementById('stcSaveArea');
        if (stcSaveA) stcSaveA.hidden = !(d.ok && settingsActiveTool === 'fracture' && _stcTargetUrls.length > 1);

        if (d.result) {
            body.textContent = JSON.stringify(d.result, null, 2);
        } else {
            body.textContent = (d.stdout || '') + (d.stderr ? '\n--- stderr ---\n' + d.stderr : '') + (d.error ? '\nError: ' + d.error : '');
        }
    })
    .catch(function(e) {
        var resDiv = document.getElementById('settingsTestConnResult');
        resDiv.hidden = false;
        document.getElementById('stcResultLabel').textContent = 'Error';
        document.getElementById('stcResultBadge').innerHTML = '<span class="status-badge" style="background:var(--status-error);color:#fff">ERR</span>';
        document.getElementById('stcResultBody').textContent = e.message || 'Request failed';
        var stcSaveA2 = document.getElementById('stcSaveArea');
        if (stcSaveA2) stcSaveA2.hidden = true;
        if (settingsActiveTool === 'fracture') {
            document.getElementById('stcFingerprintArea').hidden = false;
            document.getElementById('btnStcFingerprint').disabled = false;
            document.getElementById('btnStcFingerprint').title = 'Record auth flow via monitored browser';
        }
    })
    .finally(function() {
        btn.disabled = false;
        btn.textContent = 'Run Test';
    });
});

/* ── Settings tab: Fingerprint Auth button ──────────────────────── */
document.getElementById('btnStcFingerprint').addEventListener('click', function() {
    var btn = this;
    btn.disabled = true;
    btn.textContent = 'Recording…';
    document.getElementById('stcFpStatus').textContent = 'Starting monitored browser…';
    document.getElementById('stcFpResultArea').hidden = true;
    document.getElementById('stcFpReminder').hidden = true;

    var inputs = document.getElementById('settingsFields').querySelectorAll('[name]');
    var formData = {};
    inputs.forEach(function(el) {
        if (el.type === 'checkbox') formData[el.name] = el.checked;
        else formData[el.name] = el.value;
    });

    var fpStcSel = document.getElementById('stcTargetSelect');
    var target = (fpStcSel && fpStcSel.value) ? fpStcSel.value : (formData.target_url || '');
    if (!target) {
        document.getElementById('stcFpStatus').textContent = 'No target URL configured.';
        btn.disabled = false;
        btn.textContent = 'Fingerprint Auth';
        return;
    }

    fetch('/api/fingerprint-auth', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, target_url: target})
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        document.getElementById('stcFpResultArea').hidden = false;
        var body = document.getElementById('stcFpResultBody');
        if (d.ok && d.fingerprint) {
            document.getElementById('stcFpStatus').textContent = 'Fingerprint recorded';
            body.textContent = JSON.stringify(d.fingerprint, null, 2);
            document.getElementById('stcFpReminder').hidden = false;
            if (d.fingerprint.fracture_auth_config) {
                var ac = d.fingerprint.fracture_auth_config;
                var authSel = document.querySelector('#settingsFields [name="auth"]');
                if (authSel && ac.auth_method) authSel.value = ac.auth_method;
            }
        } else {
            document.getElementById('stcFpStatus').textContent = 'Fingerprint failed';
            body.textContent = (d.stdout || '') + (d.stderr ? '\n--- stderr ---\n' + d.stderr : '') + (d.error || '');
        }
    })
    .catch(function(e) {
        document.getElementById('stcFpResultArea').hidden = false;
        document.getElementById('stcFpStatus').textContent = 'Error';
        document.getElementById('stcFpResultBody').textContent = e.message || 'Request failed';
    })
    .finally(function() {
        btn.disabled = false;
        btn.textContent = 'Fingerprint Auth';
    });
});

/* ── Settings tab: Save per-target auth ──────────────────────────── */
var _btnStcSave = document.getElementById('btnStcSaveAuth');
if (_btnStcSave) {
    _btnStcSave.addEventListener('click', function() {
        var stcSel = document.getElementById('stcTargetSelect');
        var url = stcSel ? stcSel.value : '';
        if (!url) { toast('warning', 'Select a target URL first.'); return; }
        var formData = {};
        document.getElementById('settingsFields').querySelectorAll('[name]').forEach(function(el) {
            if (el.type === 'checkbox') formData[el.name] = el.checked;
            else formData[el.name] = el.value;
        });
        var auth = {};
        try { auth = typeof formData.auth === 'string' ? JSON.parse(formData.auth) : (formData.auth || {}); } catch(e) { auth = {}; }
        auth._tested = true;
        _stcPerTargetAuth[url] = auth;
        stcUpdatePerTargetTable();
        var stEl = document.getElementById('stcSaveStatus');
        if (stEl) { stEl.textContent = 'Auth saved for ' + url; setTimeout(function() { stEl.textContent = ''; }, 4000); }
    });
}

/* ══════════════════════════════════════════════════════════════════
   11. LOGS TAB
   ══════════════════════════════════════════════════════════════════ */
function loadLogs() {
    var params = buildTimeParams('logsFrom', 'logsTo');
    var tool = document.getElementById('logsFilterTool').value;
    if (tool) params += (params ? '&' : '?') + 'tool=' + encodeURIComponent(tool);
    var level = document.getElementById('logsFilterLevel').value;
    if (level) params += (params ? '&' : '?') + 'level=' + encodeURIComponent(level);

    fetch('/api/logs/' + PID + params, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            allLogs = data.entries || data || [];
            allLogs._loaded = true;
            populateToolFilter('logsFilterTool', allLogs);
            updateLogsPill();
            renderLogs();
        });
}

function renderLogs() {
    var tbody = document.getElementById('logsTableBody');
    var empty = document.getElementById('logsEmpty');
    var pag = document.getElementById('logsPagination');

    if (!allLogs.length) {
        tbody.innerHTML = '';
        empty.style.display = '';
        pag.hidden = true;
        return;
    }
    empty.style.display = 'none';

    var start = (logsPage - 1) * LOGS_PER_PAGE;
    var page = allLogs.slice(start, start + LOGS_PER_PAGE);

    tbody.innerHTML = '';
    page.forEach(function(l) {
        var level = (l.level || l.severity || 'INFO').toUpperCase();
        var levelCls = 'log-level-' + level.toLowerCase().replace(/_/g, '-');
        var tr = document.createElement('tr');
        tr.innerHTML =
            '<td class="col-ts">' + formatTsHtml(l.timestamp || l.ts || l.datetime || '') + '</td>' +
            '<td class="col-level"><span class="log-level ' + levelCls + '">' + esc(level) + '</span></td>' +
            '<td class="col-tool-log text-sm">' + esc(l.tool || '--') + '</td>' +
            '<td class="col-message">' + esc(l.message || l.text || '') + '</td>';
        tbody.appendChild(tr);
    });

    renderPagination(pag, allLogs.length, LOGS_PER_PAGE, logsPage, function(p) { logsPage = p; renderLogs(); });
}

function updateLogsPill() {
    /* Logs tab has no pill counter — intentionally no-op */
}

document.getElementById('logsFilterTool').addEventListener('change', loadLogs);
document.getElementById('logsFilterLevel').addEventListener('change', loadLogs);
document.getElementById('logsFrom').addEventListener('change', loadLogs);
document.getElementById('logsTo').addEventListener('change', loadLogs);
document.getElementById('btnLogsClearRange').addEventListener('click', function() {
    document.getElementById('logsFrom').value = '';
    document.getElementById('logsTo').value = '';
    loadLogs();
});

document.getElementById('btnCopyLogs').addEventListener('click', function() {
    var text = allLogs.map(function(l) {
        var ts = l.timestamp || l.ts || l.datetime || '';
        var level = (l.level || l.severity || 'INFO').toUpperCase();
        var src = l.tool || '';
        var msg = l.message || l.text || '';
        return ts + ' [' + level + ']' + (src ? ' [' + src + ']' : '') + ' ' + msg;
    }).join('\n');
    navigator.clipboard.writeText(text).then(function() {
        toast('success', 'Logs copied to clipboard.');
    }).catch(function() {
        toast('error', 'Failed to copy to clipboard.');
    });
});

document.getElementById('btnClearLogs').addEventListener('click', function() {
    if (!confirm('Clear all log entries?')) return;
    fetch('/api/clear-logs/' + PID, {method: 'POST', credentials: 'same-origin'})
        .then(function() { allLogs = []; allLogs._loaded = true; updateLogsPill(); renderLogs(); });
});


/* ══════════════════════════════════════════════════════════════════
   12. ERRORS TAB
   ══════════════════════════════════════════════════════════════════ */
function loadErrors() {
    var params = buildTimeParams('errorsFrom', 'errorsTo');
    var tool = document.getElementById('errorsFilterTool').value;
    if (tool) params += (params ? '&' : '?') + 'tool=' + encodeURIComponent(tool);

    fetch('/api/errors/' + PID + params, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            allErrors = data.entries || data || [];
            allErrors._loaded = true;
            populateToolFilter('errorsFilterTool', allErrors);
            updateErrorsPill();
            renderErrors();
        });
}

function renderErrors() {
    var tbody = document.getElementById('errorsTableBody');
    var empty = document.getElementById('errorsEmpty');
    var pag = document.getElementById('errorsPagination');

    if (!allErrors.length) {
        tbody.innerHTML = '';
        empty.style.display = '';
        pag.hidden = true;
        return;
    }
    empty.style.display = 'none';

    var start = (errorsPage - 1) * ERRORS_PER_PAGE;
    var page = allErrors.slice(start, start + ERRORS_PER_PAGE);

    tbody.innerHTML = '';
    page.forEach(function(l) {
        var level = (l.level || l.severity || 'ERROR').toUpperCase();
        var levelCls = 'log-level-' + level.toLowerCase().replace(/_/g, '-');
        var tr = document.createElement('tr');
        tr.innerHTML =
            '<td class="col-ts">' + formatTsHtml(l.timestamp || l.ts || l.datetime || '') + '</td>' +
            '<td class="col-level"><span class="log-level ' + levelCls + '">' + esc(level) + '</span></td>' +
            '<td class="col-tool-log text-sm">' + esc(l.tool || '--') + '</td>' +
            '<td class="col-message">' + esc(l.message || l.text || '') + '</td>';
        tbody.appendChild(tr);
    });

    renderPagination(pag, allErrors.length, ERRORS_PER_PAGE, errorsPage, function(p) { errorsPage = p; renderErrors(); });
}

function updateErrorsPill() {
    document.getElementById('errorsPill').textContent = allErrors.length || '';
}

document.getElementById('errorsFilterTool').addEventListener('change', loadErrors);
document.getElementById('errorsFrom').addEventListener('change', loadErrors);
document.getElementById('errorsTo').addEventListener('change', loadErrors);
document.getElementById('btnErrorsClearRange').addEventListener('click', function() {
    document.getElementById('errorsFrom').value = '';
    document.getElementById('errorsTo').value = '';
    loadErrors();
});

document.getElementById('btnCopyErrors').addEventListener('click', function() {
    var text = allErrors.map(function(e) {
        var ts = e.ts || '';
        var src = e.source || e.tool_id || '';
        var msg = e.message || e.text || '';
        return ts + (src ? ' [' + src + ']' : '') + ' ' + msg;
    }).join('\n');
    navigator.clipboard.writeText(text).then(function() {
        toast('success', 'Errors copied to clipboard.');
    }).catch(function() {
        toast('error', 'Failed to copy to clipboard.');
    });
});

document.getElementById('btnClearErrors').addEventListener('click', function() {
    if (!confirm('Clear all error entries?')) return;
    fetch('/api/clear-errors/' + PID, {method: 'POST', credentials: 'same-origin'})
        .then(function() { allErrors = []; allErrors._loaded = true; updateErrorsPill(); renderErrors(); });
});


/* ══════════════════════════════════════════════════════════════════
   13. PROMPT + SUDO MODALS
   ══════════════════════════════════════════════════════════════════ */
document.getElementById('btnPromptSubmit').addEventListener('click', function() {
    if (!promptContext) return;
    socket.emit('prompt_answer', {
        project_id: promptContext.project_id,
        tool_id: promptContext.tool_id,
        answer: document.getElementById('promptInput').value
    });
    document.getElementById('promptModal').classList.remove('open');
    promptContext = null;
});

document.getElementById('btnPromptCancel').addEventListener('click', function() {
    document.getElementById('promptModal').classList.remove('open');
    promptContext = null;
});

document.getElementById('promptInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('btnPromptSubmit').click();
    }
});

document.getElementById('btnSudoSubmit').addEventListener('click', function() {
    if (!sudoContext) return;
    socket.emit('sudo_password', {
        project_id: sudoContext.project_id,
        tool_id: sudoContext.tool_id,
        password: document.getElementById('sudoPasswordInput').value
    });
    document.getElementById('sudoModal').classList.remove('open');
    sudoContext = null;
});

document.getElementById('btnSudoCancel').addEventListener('click', function() {
    document.getElementById('sudoModal').classList.remove('open');
    sudoContext = null;
});

document.getElementById('sudoPasswordInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('btnSudoSubmit').click();
    }
});

/* ── Escape closes modals ──────────────────────────────────────── */
document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    document.querySelectorAll('.modal-overlay.open').forEach(function(m) {
        m.classList.remove('open');
    });
    promptContext = null;
    sudoContext = null;
    riskOverrideCtx = null;
    notesCtx = null;
});

/* ── Click outside modal closes it ─────────────────────────────── */
document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) {
            overlay.classList.remove('open');
        }
    });
    overlay.addEventListener('touchend', function(e) {
        if (e.target === overlay) {
            overlay.classList.remove('open');
        }
    });
});

/* ── Orientation change: force open modals to re-layout ────────── */
window.addEventListener('orientationchange', function() {
    setTimeout(function() {
        document.querySelectorAll('.modal-overlay.open .modal-box').forEach(function(box) {
            box.style.display = 'none';
            box.offsetHeight;
            box.style.display = '';
        });
    }, 150);
});


/* ══════════════════════════════════════════════════════════════════
   14. UTILITY FUNCTIONS
   ══════════════════════════════════════════════════════════════════ */

/* HTML escape */
function esc(s) {
    if (s == null) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function _renderNoteMd(raw) {
    var s = esc(raw);
    s = s.replace(/```([\s\S]*?)```/g, '<pre style="background:var(--bg-main);padding:4px 8px;border-radius:4px;overflow-x:auto;margin:4px 0"><code>$1</code></pre>');
    s = s.replace(/`([^`]+)`/g, '<code style="background:var(--bg-main);padding:1px 4px;border-radius:3px">$1</code>');
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
    s = s.replace(/\n/g, '<br>');
    return s;
}

/* Debounce */
function debounce(fn, ms) {
    var t;
    return function() {
        var ctx = this, args = arguments;
        clearTimeout(t);
        t = setTimeout(function() { fn.apply(ctx, args); }, ms);
    };
}

/* Format ISO timestamp for display */
function formatTs(ts) {
    if (!ts) return '';
    try {
        var d = new Date(ts);
        if (isNaN(d.getTime())) return ts;
        var pad = function(n) { return n < 10 ? '0' + n : n; };
        return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) + ' ' +
               pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    } catch(e) { return ts; }
}

function formatTsHtml(ts) {
    var s = formatTs(ts);
    if (!s) return '';
    var idx = s.indexOf(' ');
    if (idx > 0) return '<span class="ts-date">' + esc(s.substring(0, idx)) + '</span> <span class="ts-time">' + esc(s.substring(idx + 1)) + '</span>';
    return esc(s);
}

/* Build time-range query params */
function buildTimeParams(fromId, toId) {
    var f = document.getElementById(fromId).value;
    var t = document.getElementById(toId).value;
    var parts = [];
    if (f) parts.push('from=' + encodeURIComponent(f));
    if (t) parts.push('to=' + encodeURIComponent(t));
    return parts.length ? '?' + parts.join('&') : '';
}

/* Populate tool filter dropdown from data */
function _toolDisplayName(tid) {
    if (TOOLS_CFG[tid]) return TOOLS_CFG[tid].name;
    var base = tid.split(':')[0];
    var scope = tid.indexOf(':') >= 0 ? tid.split(':').slice(1).join(':') : '';
    var name = TOOLS_CFG[base] ? TOOLS_CFG[base].name : base;
    return scope ? name + ' [' + scope + ']' : name;
}

function populateToolFilter(selectId, entries) {
    var sel = document.getElementById(selectId);
    var existing = new Set();
    sel.querySelectorAll('option').forEach(function(o) { if (o.value) existing.add(o.value); });
    entries.forEach(function(e) {
        var t = e.tool || '';
        if (t && !existing.has(t)) {
            existing.add(t);
            var o = document.createElement('option');
            o.value = t;
            o.textContent = _toolDisplayName(t);
            sel.appendChild(o);
        }
    });
}

/* Render pagination controls */
function renderPagination(container, totalItems, perPage, currentPage, onChange) {
    var totalPages = Math.ceil(totalItems / perPage);
    if (totalPages <= 1) { container.hidden = true; return; }
    container.hidden = false;
    container.innerHTML = '';

    /* prev */
    var prev = document.createElement('button');
    prev.className = 'pagination-btn';
    prev.textContent = '<';
    prev.disabled = currentPage <= 1;
    prev.addEventListener('click', function() { if (currentPage > 1) onChange(currentPage - 1); });
    container.appendChild(prev);

    /* info */
    var info = document.createElement('span');
    info.className = 'pagination-info';
    info.textContent = 'Page ' + currentPage + ' of ' + totalPages;
    container.appendChild(info);

    /* next */
    var next = document.createElement('button');
    next.className = 'pagination-btn';
    next.textContent = '>';
    next.disabled = currentPage >= totalPages;
    next.addEventListener('click', function() { if (currentPage < totalPages) onChange(currentPage + 1); });
    container.appendChild(next);
}

/* Toast notification */
function toast(type, message) {
    var container = document.getElementById('toastContainer');
    var el = document.createElement('div');
    el.className = 'toast toast-' + type;
    el.innerHTML =
        '<div class="toast-body"><div class="toast-message">' + esc(message) + '</div></div>' +
        '<button class="toast-close" onclick="this.parentElement.remove()">' +
            '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>' +
        '</button>';
    container.appendChild(el);
    setTimeout(function() {
        el.classList.add('toast-exit');
        setTimeout(function() { el.remove(); }, 300);
    }, 5000);
}

function _fmtIso(iso) {
    if (!iso) return '--';
    try {
        var d = new Date(iso);
        if (isNaN(d.getTime())) return '--';
        return d.toLocaleString(undefined, {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false
        });
    } catch(e) { return '--'; }
}
function _populateEngagementTiming(data) {
    var startEl = document.getElementById('engagementStartTime');
    var endEl = document.getElementById('engagementEndTime');
    if (!startEl || !endEl) return;
    if (data.engagement_start_time) {
        if (startEl.textContent === '--' || !startEl._isoVal || data.engagement_start_time < startEl._isoVal) {
            startEl.textContent = _fmtIso(data.engagement_start_time);
            startEl._isoVal = data.engagement_start_time;
        }
    }
    if (data.engagement_end_time) {
        if (endEl.textContent === '--' || !endEl._isoVal || data.engagement_end_time > endEl._isoVal) {
            endEl.textContent = _fmtIso(data.engagement_end_time);
            endEl._isoVal = data.engagement_end_time;
        }
    }
}

/* ── Load summary data on init ─────────────────────────────────── */
fetch('/api/summary/' + PID, {credentials: 'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.risk_counts) {
            _serverSummary = data.risk_counts;
            _serverTotal = data.total || data.findings_count || 0;
            updateRiskOverview();
        }
        _populateEngagementTiming(data);
    })
    .catch(function() { /* summary not critical */ });

/* ══════════════════════════════════════════════════════════════════
   IMPORT TAB
   ══════════════════════════════════════════════════════════════════ */
var _impState = {
    _loaded: false,
    jobs: [],
    activeJobId: null,
    consoleBuffers: {},
    autoScroll: true
};

function initImportTab() {
    if (_impState._loaded) return;
    _impState._loaded = true;
    _impLoadToolList();
    _impLoadJobs();
    _impBindEvents();
}

function _impLoadToolList() {
    fetch('/api/import/tools')
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (!d.tools || !d.tools.length) {
                console.warn('Import: no tool parsers returned', d);
                return;
            }
            var sel = document.getElementById('importToolSelect');
            d.tools.forEach(function(t) {
                var o = document.createElement('option');
                o.value = t.name;
                o.textContent = t.name + ' (' + (t.formats || []).join(', ') + ')';
                sel.appendChild(o);
            });
        })
        .catch(function(e) { console.error('Import tool list failed:', e); });
}

function _impLoadJobs() {
    fetch('/api/import/' + PID + '/jobs')
        .then(function(r) { return r.json(); })
        .then(function(d) {
            _impState.jobs = d.jobs || [];
            _impRenderFeed();
        })
        .catch(function() {});
}

function _impBindEvents() {
    var fileInput = document.getElementById('importFileInput');
    document.getElementById('btnImportFile').addEventListener('click', function() {
        fileInput.click();
    });
    fileInput.addEventListener('change', function() {
        if (!fileInput.files.length) return;
        var toolOverride = document.getElementById('importToolSelect').value;
        var hasBurpWizard = typeof window._openBurpWizard === 'function';

        if (fileInput.files.length === 1 && hasBurpWizard) {
            var file = fileInput.files[0];
            if (toolOverride === 'burp') {
                window._openBurpWizard(file);
                fileInput.value = '';
                return;
            }
            if (!toolOverride && file.name.toLowerCase().endsWith('.xml')) {
                var reader = new FileReader();
                reader.onload = function() {
                    var chunk = reader.result || '';
                    if (chunk.indexOf('<issues') !== -1 && chunk.indexOf('<issue>') !== -1) {
                        window._openBurpWizard(file);
                    } else {
                        _impUploadFile(file, toolOverride);
                    }
                    fileInput.value = '';
                };
                reader.readAsText(file.slice(0, 8192));
                return;
            }
        }

        Array.from(fileInput.files).forEach(function(f) {
            _impUploadFile(f, toolOverride);
        });
        fileInput.value = '';
    });

    document.getElementById('btnImportFolder').addEventListener('click', function() {
        var inp = document.createElement('input');
        inp.type = 'file';
        inp.webkitdirectory = true;
        inp.multiple = true;
        inp.addEventListener('change', function() {
            if (!inp.files.length) return;
            var toolOverride = document.getElementById('importToolSelect').value;
            var files = Array.from(inp.files);
            toast(files.length + ' file(s) found — uploading...');
            var queued = 0;
            files.forEach(function(f) {
                _impUploadFile(f, toolOverride);
                queued++;
            });
        });
        inp.click();
    });

    document.getElementById('btnImportConsoleCopy').addEventListener('click', function() {
        var body = document.getElementById('importConsoleBody');
        var text = body.innerText || body.textContent;
        navigator.clipboard.writeText(text).then(function() { toast('success', 'Copied'); });
    });

    document.getElementById('importAutoScrollToggle').addEventListener('change', function() {
        _impState.autoScroll = this.checked;
    });

    socket.on('import_job_updated', function(d) {
        if (d.project_id !== PID) return;
        var found = false;
        for (var i = 0; i < _impState.jobs.length; i++) {
            if (_impState.jobs[i].id === d.job.id) {
                _impState.jobs[i] = d.job;
                found = true;
                break;
            }
        }
        if (!found) _impState.jobs.push(d.job);
        _impRenderFeed();
        if (_impState.activeJobId === d.job.id) {
            _impUpdateConsoleTitle(d.job);
        }
        var j = d.job;
        if (j.status === 'IMPORTED') {
            var c = j.counts || {};
            var parts = [];
            if (c.findings) parts.push(c.findings + ' findings');
            if (c.targets) parts.push(c.targets + ' targets');
            if (c.ports) parts.push(c.ports + ' ports');
            var summary = parts.length ? parts.join(', ') : '0 items';
            toast('success', 'Import complete: ' + (j.tool || 'file') + ' — ' + summary);
            if (allFindings._loaded) loadFindings(true);
        } else if (j.status === 'FAILED') {
            toast('error', 'Import failed: ' + (j.tool || 'file') + ' — ' + (j.error || 'unknown error'));
        }
    });

    socket.on('import_console_line', function(d) {
        if (d.project_id !== PID) return;
        if (!_impState.consoleBuffers[d.job_id]) _impState.consoleBuffers[d.job_id] = [];
        _impState.consoleBuffers[d.job_id].push(d.line);
        if (_impState.activeJobId === d.job_id) {
            _impAppendConsoleLine(d.line);
        }
    });
}

function _impUploadFile(file, toolOverride) {
    var fd = new FormData();
    fd.append('file', file);
    if (toolOverride) fd.append('tool', toolOverride);
    fetch('/api/import/' + PID + '/file', {method: 'POST', body: fd})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.error) { toast('error', d.error); return; }
            toast('info', 'Queued: ' + (d.filename || file.name));
            _impLoadJobs();
        })
        .catch(function() { toast('error', 'Upload failed: ' + file.name); });
}

function _impRenderFeed() {
    var feed = document.getElementById('importJobFeed');
    var empty = document.getElementById('importEmptyState');
    if (!_impState.jobs.length) {
        empty.style.display = '';
        feed.querySelectorAll('.feed-item').forEach(function(el) { el.remove(); });
        return;
    }
    empty.style.display = 'none';
    var sorted = _impState.jobs.slice().sort(function(a, b) {
        var order = {PARSING: 0, QUEUED: 1, IMPORTED: 2, FAILED: 3, DUPLICATE: 4};
        var oa = order[a.status] !== undefined ? order[a.status] : 5;
        var ob = order[b.status] !== undefined ? order[b.status] : 5;
        if (oa !== ob) return oa - ob;
        return (b.created || '').localeCompare(a.created || '');
    });
    var html = '';
    sorted.forEach(function(j) {
        var statusCls = 'status-idle';
        if (j.status === 'PARSING') statusCls = 'status-running';
        else if (j.status === 'QUEUED') statusCls = 'status-queued';
        else if (j.status === 'IMPORTED') statusCls = 'status-complete';
        else if (j.status === 'FAILED') statusCls = 'status-failed';
        else if (j.status === 'DUPLICATE') statusCls = 'status-idle';
        var toolKey = (j.tool_id || '').toUpperCase().slice(0, 2);
        var active = _impState.activeJobId === j.id ? ' active' : '';
        html += '<div class="feed-item' + active + '" data-job-id="' + esc(j.id) + '">'
            + '<div class="feed-item-icon tool-badge">' + esc(toolKey || '??') + '</div>'
            + '<div class="feed-item-body">'
            + '<div class="feed-item-name">' + esc(j.filename || '—') + '</div>'
            + '<div class="feed-item-preview">' + esc(j.tool || j.tool_id || 'unknown') + '</div>'
            + '</div>'
            + '<div class="feed-item-actions">'
            + '<button type="button" class="btn btn-xs btn-ghost import-detail-btn" data-job-id="' + esc(j.id) + '">Details</button>'
            + '</div>'
            + '<div class="feed-item-status"><span class="status-badge ' + statusCls + '">' + esc(j.status) + '</span></div>'
            + '</div>';
    });
    var items = feed.querySelectorAll('.feed-item');
    items.forEach(function(el) { el.remove(); });
    feed.insertAdjacentHTML('beforeend', html);

    feed.querySelectorAll('.feed-item').forEach(function(el) {
        el.addEventListener('click', function(e) {
            if (e.target.closest('.import-detail-btn')) return;
            var jid = el.getAttribute('data-job-id');
            _impSelectJob(jid);
        });
    });
    feed.querySelectorAll('.import-detail-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var jid = btn.getAttribute('data-job-id');
            _impShowDetail(jid);
        });
    });
}

function _impSelectJob(jobId) {
    _impState.activeJobId = jobId;
    document.querySelectorAll('#importJobFeed .feed-item').forEach(function(el) {
        el.classList.toggle('active', el.getAttribute('data-job-id') === jobId);
    });
    var body = document.getElementById('importConsoleBody');
    body.innerHTML = '';
    document.getElementById('btnImportConsoleCopy').disabled = false;
    var job = _impFindJob(jobId);
    if (job) _impUpdateConsoleTitle(job);
    var lines = _impState.consoleBuffers[jobId];
    if (lines && lines.length) {
        lines.forEach(function(ln) { _impAppendConsoleLine(ln); });
    } else {
        socket.emit('import_get_console', {project_id: PID, job_id: jobId});
        socket.once('import_console_buffer', function(d) {
            if (d.job_id !== jobId) return;
            _impState.consoleBuffers[jobId] = d.lines || [];
            if (_impState.activeJobId === jobId) {
                body.innerHTML = '';
                (d.lines || []).forEach(function(ln) { _impAppendConsoleLine(ln); });
            }
        });
    }
}

function _impUpdateConsoleTitle(job) {
    var badge = document.getElementById('importConsoleTitleBadge');
    var title = document.getElementById('importConsoleTitle');
    var statusBadge = document.getElementById('importConsoleStatusBadge');
    var toolKey = (job.tool_id || '').toUpperCase().slice(0, 2);
    badge.className = 'tool-badge';
    badge.textContent = toolKey || '??';
    title.textContent = job.filename || '—';
    var statusCls = 'status-idle';
    if (job.status === 'PARSING') statusCls = 'status-running';
    else if (job.status === 'QUEUED') statusCls = 'status-queued';
    else if (job.status === 'IMPORTED') statusCls = 'status-complete';
    else if (job.status === 'FAILED') statusCls = 'status-failed';
    statusBadge.className = 'status-badge ' + statusCls;
    statusBadge.textContent = job.status;
}

function _impAppendConsoleLine(line) {
    var body = document.getElementById('importConsoleBody');
    var div = document.createElement('div');
    div.className = 'console-line';
    div.textContent = line;
    body.appendChild(div);
    if (_impState.autoScroll) body.scrollTop = body.scrollHeight;
}

function _impFindJob(jobId) {
    for (var i = 0; i < _impState.jobs.length; i++) {
        if (_impState.jobs[i].id === jobId) return _impState.jobs[i];
    }
    return null;
}

function _impShowDetail(jobId) {
    var job = _impFindJob(jobId);
    if (!job) return;
    document.getElementById('idFile').textContent = job.filename || '—';
    document.getElementById('idTool').textContent = job.tool || job.tool_id || '—';
    document.getElementById('idScope').textContent = (job.scopes || []).join(', ') || '—';
    var statusCls = 'status-idle';
    if (job.status === 'PARSING') statusCls = 'status-running';
    else if (job.status === 'QUEUED') statusCls = 'status-queued';
    else if (job.status === 'IMPORTED') statusCls = 'status-complete';
    else if (job.status === 'FAILED') statusCls = 'status-failed';
    document.getElementById('idStatus').innerHTML = '<span class="status-badge ' + statusCls + '">' + esc(job.status) + '</span>';
    document.getElementById('idStarted').textContent = job.started || '—';
    document.getElementById('idFinished').textContent = job.finished || '—';
    var dur = '—';
    if (job.started && job.finished) {
        var ms = new Date(job.finished) - new Date(job.started);
        dur = (ms / 1000).toFixed(1) + 's';
    }
    document.getElementById('idDuration').textContent = dur;
    var c = job.counts || {};
    document.getElementById('idFindings').textContent = c.findings !== undefined ? c.findings : '—';
    document.getElementById('idTargets').textContent = c.targets !== undefined ? c.targets : '—';
    document.getElementById('idDestDir').textContent = job.file_path || '—';
    var errWrap = document.getElementById('idErrorWrap');
    var errPre = document.getElementById('idError');
    if (job.error) {
        errWrap.style.display = '';
        errPre.textContent = job.error;
    } else {
        errWrap.style.display = 'none';
    }
    var cancelBtn = document.getElementById('idCancelBtn');
    var retryBtn = document.getElementById('idRetryBtn');
    cancelBtn.style.display = (job.status === 'PARSING' || job.status === 'QUEUED') ? '' : 'none';
    retryBtn.style.display = (job.status === 'FAILED') ? '' : 'none';
    cancelBtn.onclick = function() {
        fetch('/api/import/' + PID + '/job/' + jobId, {method: 'DELETE'})
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.error) toast('error', d.error);
                else { toast('info', 'Cancelled'); closeImportDetail(); _impLoadJobs(); }
            });
    };
    retryBtn.onclick = function() {
        fetch('/api/import/' + PID + '/job/' + jobId + '/retry', {method: 'POST'})
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.error) toast('error', d.error);
                else { toast('info', 'Retrying'); closeImportDetail(); _impLoadJobs(); }
            });
    };
    document.getElementById('importDetailModal').classList.add('open');
}

function closeImportDetail() {
    document.getElementById('importDetailModal').classList.remove('open');
}

/* ── Expose IIFE-scoped functions to global scope for inline onclick ── */
window.closeFindingDetail = closeFindingDetail;
window.closeBulkActionModal = closeBulkActionModal;
window.openBulkActionModal = openBulkActionModal;
window._bulkExecute = _bulkExecute;
window._bulkSelectAll = _bulkSelectAll;
window.closeEvidenceViewer = closeEvidenceViewer;
window._evHlNav = _evHlNav;
window.closeRiskOverride = closeRiskOverride;
/* ── Engagement hours ─────────────────────────────────────── */
var _engToggle = document.getElementById('seEngagementEnabled');
if (_engToggle) {
    _engToggle.addEventListener('change', function() {
        var cfg = document.getElementById('engagementConfig');
        if (cfg) cfg.style.display = this.checked ? 'flex' : 'none';
    });
}

function _loadEngagementHours() {
    fetch('/api/engagement_hours/' + PID)
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (!d || !d.enabled) return;
            var toggle = document.getElementById('seEngagementEnabled');
            if (toggle) { toggle.checked = true; toggle.dispatchEvent(new Event('change')); }
            var s = document.getElementById('seEngagementStart');
            var e = document.getElementById('seEngagementEnd');
            var tz = document.getElementById('seEngagementTz');
            if (s && d.start_time) s.value = d.start_time;
            if (e && d.end_time) e.value = d.end_time;
            if (tz && d.timezone) tz.value = d.timezone;
            if (d.days) {
                document.querySelectorAll('.seEngDay').forEach(function(cb) {
                    cb.checked = d.days.indexOf(parseInt(cb.value)) !== -1;
                });
            }
        }).catch(function() {});
}

function _saveEngagementHours() {
    var days = [];
    document.querySelectorAll('.seEngDay:checked').forEach(function(cb) {
        days.push(parseInt(cb.value));
    });
    fetch('/api/engagement_hours', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            project_id: PID,
            enabled: document.getElementById('seEngagementEnabled').checked,
            start_time: document.getElementById('seEngagementStart').value,
            end_time: document.getElementById('seEngagementEnd').value,
            timezone: document.getElementById('seEngagementTz').value,
            days: days
        })
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) toast('success', 'Engagement hours saved');
        else toast('error', d.error || 'Failed to save');
    });
}

/* ── Scheduled engagement start ────────────────────────────── */
function _loadScheduledStarts() {
    fetch('/api/scheduled_starts/' + PID)
        .then(function(r) { return r.json(); })
        .then(function(d) {
            _renderScheduledStarts(d.schedules || []);
        }).catch(function() {});
}

function _renderScheduledStarts(schedules) {
    var el = document.getElementById('scheduledStartsList');
    if (!el) return;
    if (!schedules.length) {
        el.innerHTML = '<span class="text-muted text-sm">No scheduled starts</span>';
        return;
    }
    var html = '';
    schedules.forEach(function(s) {
        var dt = new Date(s.scheduled_at);
        var details = '';
        if (s.status === 'launched' && s.launched_tools) {
            details = 'Launched: ' + s.launched_tools.join(', ');
            if (s.queued_tools && s.queued_tools.length) details += ' | Queued: ' + s.queued_tools.join(', ');
        } else if (s.status === 'deferred') {
            details = 'Waiting for engagement window to open';
        } else if (s.error) {
            details = s.error;
        }
        var canRemove = s.status === 'pending' || s.status === 'deferred';
        html += '<div style="display:flex;align-items:center;gap:12px;padding:8px 12px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;margin-bottom:6px">' +
            '<span style="font-weight:600;font-size:0.88rem;min-width:180px">' + esc(dt.toLocaleString()) + '</span>' +
            '<span class="status-badge status-' + esc(s.status) + '" style="font-size:0.78rem;text-transform:uppercase">' + esc(s.status) + '</span>' +
            (details ? '<span style="font-size:0.82rem;color:var(--text-secondary)">' + esc(details) + '</span>' : '') +
            (canRemove ? '<button class="btn btn-xs btn-ghost" style="margin-left:auto" onclick="_removeScheduledStart(\'' + esc(s.id) + '\')" title="Remove">&#10005;</button>' : '') +
            '</div>';
    });
    el.innerHTML = html;
}

function _scheduleEngagement() {
    var at = document.getElementById('seSchedAt').value;
    if (!at) { toast('error', 'Select a date and time'); return; }
    fetch('/api/schedule_engagement', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            project_id: PID,
            scheduled_at: new Date(at).toISOString()
        })
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) { toast('success', 'Engagement start scheduled'); _loadScheduledStarts(); }
        else toast('error', d.error || 'Failed');
    });
}

function _removeScheduledStart(schedId) {
    fetch('/api/remove_scheduled_start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({project_id: PID, sched_id: schedId})
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) _loadScheduledStarts();
    });
}

_loadEngagementHours();
_loadScheduledStarts();


/* ══════════════════════════════════════════════════════════════════
   SESSIONS TAB
   ══════════════════════════════════════════════════════════════════ */

function _sesStatusDot(s) {
    if (s.status === 'dead') return '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--red-500)"></span>';
    if (s.status === 'expiring') return '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--amber-500)"></span>';
    return '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--emerald-500)"></span>';
}

function _sesTTL(s) {
    if (s.ttl_seconds == null) return '<span class="text-muted">—</span>';
    var t = s.ttl_seconds;
    if (t <= 0) return '<span style="color:var(--red-500)">expired</span>';
    if (t < 300) return '<span style="color:var(--amber-500)">' + Math.floor(t/60) + 'm ' + (t%60) + 's</span>';
    if (t < 3600) return Math.floor(t/60) + 'm';
    return Math.floor(t/3600) + 'h ' + Math.floor((t%3600)/60) + 'm';
}

function _sesTime(iso) {
    if (!iso) return '—';
    try {
        var d = new Date(iso);
        return d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    } catch(e) { return iso; }
}

function _sesDate(iso) {
    if (!iso) return '—';
    try {
        var d = new Date(iso);
        return d.toLocaleDateString([], {month:'short',day:'numeric'}) + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
    } catch(e) { return iso; }
}

function _sesLived(started, died) {
    if (!started || !died) return '—';
    try {
        var ms = new Date(died) - new Date(started);
        var s = Math.floor(ms/1000);
        if (s < 60) return s + 's';
        if (s < 3600) return Math.floor(s/60) + 'm ' + (s%60) + 's';
        return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
    } catch(e) { return '—'; }
}

function loadSessions() {
    fetch('/api/sessions/' + PID, {credentials:'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            _sessState.sessions = d.sessions || [];
            _sessState._loaded = true;
            _renderSessions();
            _updateSessionPill(d.counts);
            if (!_sessState.refreshTimer) {
                _sessState.refreshTimer = setInterval(function() {
                    if (document.querySelector('.tab-content[data-tab="sessions"].active')) {
                        loadSessions();
                    }
                }, 10000);
            }
        })
        .catch(function() {});
}

function _updateSessionPill(counts) {
    var pill = document.getElementById('sessionsPill');
    if (!pill) return;
    var n = counts ? counts.live : 0;
    pill.textContent = n > 0 ? n : '';
}

function _renderSessions() {
    var live = [];
    var dead = [];
    _sessState.sessions.forEach(function(s) {
        if (s.status === 'dead') dead.push(s);
        else live.push(s);
    });

    var liveBody = document.getElementById('sessionsLiveBody');
    var deadBody = document.getElementById('sessionsDeadBody');
    var liveEmpty = document.getElementById('sessionsLiveEmpty');
    var deadEmpty = document.getElementById('sessionsDeadEmpty');
    var liveTable = document.getElementById('sessionsLiveTable');
    var deadTable = document.getElementById('sessionsDeadTable');

    if (live.length === 0) {
        liveTable.hidden = true; liveEmpty.hidden = false;
    } else {
        liveTable.hidden = false; liveEmpty.hidden = true;
        liveBody.innerHTML = live.map(function(s) {
            return '<tr style="cursor:pointer" onclick="showSessionDetail(\'' + esc(s.id) + '\')">'
                + '<td>' + _sesStatusDot(s) + '</td>'
                + '<td class="font-medium">' + esc(s.label) + '</td>'
                + '<td>' + esc(s.auth_type) + '</td>'
                + '<td>' + esc(s.framework || '—') + '</td>'
                + '<td style="font-family:monospace;font-size:0.75rem">' + esc(s.token_preview || '—') + '</td>'
                + '<td>' + esc(s.origin_tool || '—') + '</td>'
                + '<td>' + esc(s.scope || '—') + '</td>'
                + '<td>' + _sesDate(s.started_at) + '</td>'
                + '<td>' + _sesTime(s.last_refresh) + '</td>'
                + '<td>' + _sesTime(s.expires_at) + '</td>'
                + '<td>' + _sesTTL(s) + '</td>'
                + '<td onclick="event.stopPropagation()">'
                + '<button class="btn btn-xs btn-ghost" onclick="refreshSession(\'' + esc(s.id) + '\')" title="Refresh">↻</button> '
                + '<button class="btn btn-xs btn-danger" onclick="killSession(\'' + esc(s.id) + '\')" title="Kill">Kill</button>'
                + '</td>'
                + '</tr>';
        }).join('');
    }

    if (dead.length === 0) {
        deadTable.hidden = true; deadEmpty.hidden = false;
    } else {
        deadTable.hidden = false; deadEmpty.hidden = true;
        deadBody.innerHTML = dead.map(function(s) {
            return '<tr style="opacity:0.6;cursor:pointer" onclick="showSessionDetail(\'' + esc(s.id) + '\')">'
                + '<td>' + _sesStatusDot(s) + '</td>'
                + '<td>' + esc(s.label) + '</td>'
                + '<td>' + esc(s.auth_type) + '</td>'
                + '<td>' + esc(s.framework || '—') + '</td>'
                + '<td>' + _sesDate(s.died_at) + '</td>'
                + '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(s.death_reason || '') + '">' + esc(s.death_reason || '—') + '</td>'
                + '<td>' + esc(s.origin_tool || '—') + '</td>'
                + '<td>' + esc(s.scope || '—') + '</td>'
                + '<td>' + _sesLived(s.started_at, s.died_at) + '</td>'
                + '<td onclick="event.stopPropagation()">'
                + '<button class="btn btn-xs btn-ghost" onclick="deleteSession(\'' + esc(s.id) + '\')" title="Delete">✕</button>'
                + '</td>'
                + '</tr>';
        }).join('');
    }
}

function showSessionDetail(sessId) {
    fetch('/api/sessions/' + PID + '/' + sessId, {credentials:'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.error) { toast('error', d.error); return; }
            var panel = document.getElementById('sessionDetailPanel');
            var title = document.getElementById('sessionDetailTitle');
            var body = document.getElementById('sessionDetailBody');
            title.textContent = d.label || 'Session Details';
            var html = '<div class="form-grid" style="gap:10px 24px">';

            html += '<div class="form-group"><span class="form-label">Auth Type</span><span>' + esc(d.auth_type) + '</span></div>';
            html += '<div class="form-group"><span class="form-label">Framework</span><span>' + esc(d.framework || '—') + '</span></div>';
            html += '<div class="form-group"><span class="form-label">Status</span><span>' + _sesStatusDot(d) + ' ' + esc(d.status) + '</span></div>';
            html += '<div class="form-group"><span class="form-label">Origin Tool</span><span>' + esc(d.origin_tool || '—') + '</span></div>';
            html += '<div class="form-group"><span class="form-label">Scope</span><span>' + esc(d.scope || '—') + '</span></div>';
            html += '<div class="form-group"><span class="form-label">Target URL</span><span style="word-break:break-all">' + esc(d.target_url || '—') + '</span></div>';
            html += '<div class="form-group"><span class="form-label">Has Refresh Token</span><span>' + (d.has_refresh_token ? 'Yes' : 'No') + '</span></div>';
            html += '<div class="form-group"><span class="form-label">Refresh Endpoint</span><span style="word-break:break-all">' + esc(d.refresh_endpoint || '—') + '</span></div>';
            html += '<div class="form-group"><span class="form-label">Heartbeat URL</span><span style="word-break:break-all">' + esc(d.heartbeat_url || '—') + '</span></div>';

            if (d.consumers && d.consumers.length > 0) {
                html += '<div class="form-group" style="grid-column:1/-1"><span class="form-label">Consumers</span><span>' + d.consumers.map(esc).join(', ') + '</span></div>';
            }

            if (d.jwt_claims && Object.keys(d.jwt_claims).length > 0) {
                html += '<div class="form-group" style="grid-column:1/-1"><span class="form-label">JWT Claims</span>'
                    + '<pre style="max-height:160px;overflow:auto;font-size:0.75rem;margin:0;background:var(--bg-2);padding:8px;border-radius:6px">'
                    + esc(JSON.stringify(d.jwt_claims, null, 2)) + '</pre></div>';
            }

            if (d.cookies && Object.keys(d.cookies).length > 0) {
                html += '<div class="form-group" style="grid-column:1/-1"><span class="form-label">Cookies</span>'
                    + '<pre style="max-height:100px;overflow:auto;font-size:0.75rem;margin:0;background:var(--bg-2);padding:8px;border-radius:6px">'
                    + esc(JSON.stringify(d.cookies, null, 2)) + '</pre></div>';
            }

            if (d.headers && Object.keys(d.headers).length > 0) {
                html += '<div class="form-group" style="grid-column:1/-1"><span class="form-label">Injected Headers</span>'
                    + '<pre style="max-height:100px;overflow:auto;font-size:0.75rem;margin:0;background:var(--bg-2);padding:8px;border-radius:6px">'
                    + esc(JSON.stringify(d.headers, null, 2)) + '</pre></div>';
            }

            if (d.refresh_history && d.refresh_history.length > 0) {
                html += '<div class="form-group" style="grid-column:1/-1"><span class="form-label">Refresh History (last 50)</span>'
                    + '<div style="max-height:150px;overflow:auto;font-size:0.75rem">';
                d.refresh_history.slice().reverse().forEach(function(h) {
                    var color = h.outcome === 'success' ? 'var(--emerald-500)' : 'var(--red-500)';
                    html += '<div style="padding:2px 0;border-bottom:1px solid var(--border)">'
                        + '<span style="color:' + color + '">' + esc(h.outcome) + '</span> '
                        + '<span class="text-muted">' + _sesTime(h.ts) + '</span>';
                    if (h.new_expiry) html += ' → exp ' + _sesTime(h.new_expiry);
                    if (h.reason) html += ' <span style="color:var(--red-400)">' + esc(h.reason) + '</span>';
                    html += '</div>';
                });
                html += '</div></div>';
            }

            html += '</div>';
            body.innerHTML = html;
            panel.hidden = false;
        })
        .catch(function(e) { toast('error', 'Failed to load session details'); });
}

function killSession(sessId) {
    fetch('/api/sessions/' + PID + '/' + sessId + '/kill', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'}
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) { toast('success', 'Session killed'); loadSessions(); }
        else toast('error', d.error || 'Failed');
    });
}

function killAllSessions() {
    if (!confirm('Kill ALL active sessions?')) return;
    fetch('/api/sessions/' + PID + '/kill-all', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'}
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) { toast('success', 'All sessions killed'); loadSessions(); }
    });
}

function refreshSession(sessId) {
    fetch('/api/sessions/' + PID + '/' + sessId + '/refresh', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'}
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) { toast('success', 'Session refreshed'); loadSessions(); }
        else toast('error', d.error || 'Refresh failed');
    });
}

function deleteSession(sessId) {
    if (!confirm('Delete this dead session?')) return;
    fetch('/api/sessions/' + PID + '/' + sessId + '/kill', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'}
    }).then(function() { loadSessions(); });
}

function _openAddSessionModal() {
    document.getElementById('sesAddLabel').value = '';
    document.getElementById('sesAddType').value = 'oauth2';
    document.getElementById('sesAddFramework').value = '';
    document.getElementById('sesAddOrigin').value = '';
    document.getElementById('sesAddScope').value = '';
    document.getElementById('sesAddTarget').value = '';
    document.getElementById('sesAddToken').value = '';
    document.getElementById('sesAddRefresh').value = '';
    document.getElementById('sesAddTokenEP').value = '';
    document.getElementById('sesAddHeartbeat').value = '';
    document.getElementById('sesAddExpiresIn').value = '';
    document.getElementById('addSessionModal').classList.add('active');
}

function _saveNewSession() {
    var payload = {
        label: document.getElementById('sesAddLabel').value.trim(),
        auth_type: document.getElementById('sesAddType').value,
        framework: document.getElementById('sesAddFramework').value.trim(),
        origin_tool: document.getElementById('sesAddOrigin').value.trim(),
        scope: document.getElementById('sesAddScope').value.trim(),
        target_url: document.getElementById('sesAddTarget').value.trim(),
        access_token: document.getElementById('sesAddToken').value.trim(),
        refresh_token: document.getElementById('sesAddRefresh').value.trim(),
        token_endpoint: document.getElementById('sesAddTokenEP').value.trim(),
        heartbeat_url: document.getElementById('sesAddHeartbeat').value.trim(),
    };
    var ei = document.getElementById('sesAddExpiresIn').value.trim();
    if (ei) payload.expires_in = parseInt(ei, 10);

    fetch('/api/sessions/' + PID, {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload)
    }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.id) {
            toast('success', 'Session added');
            document.getElementById('addSessionModal').classList.remove('active');
            loadSessions();
        } else {
            toast('error', d.error || 'Failed to add session');
        }
    });
}

(function _initSessionBindings() {
    var btn = document.getElementById('btnAddSession');
    if (btn) btn.addEventListener('click', _openAddSessionModal);
    var killAll = document.getElementById('btnKillAllSessions');
    if (killAll) killAll.addEventListener('click', killAllSessions);
    var save = document.getElementById('btnSaveSession');
    if (save) save.addEventListener('click', _saveNewSession);
})();

fetch('/api/sessions/' + PID + '/count', {credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(d) { _updateSessionPill(d); })
    .catch(function() {});


window.closeNotesModal = closeNotesModal;
window._toggleOOS = _toggleOOS;
window._toggleResets = _toggleResets;
window._confirmReset = _confirmReset;
window._execWithSettings = _execWithSettings;
window.loadActionItems = loadActionItems;
window.loadSystemInfo = loadSystemInfo;
window.stToggleBody = stToggleBody;
window.toast = toast;
window.esc = esc;
window.closeImportDetail = closeImportDetail;
window._openScreenshot = _openScreenshot;
window._pauseAll = _pauseAll;
window._resumeAll = _resumeAll;
window._saveEngagementHours = _saveEngagementHours;
window._scheduleEngagement = _scheduleEngagement;
window._removeScheduledStart = _removeScheduledStart;
window.showSessionDetail = showSessionDetail;
window.killSession = killSession;
window.killAllSessions = killAllSessions;
window.refreshSession = refreshSession;
window.deleteSession = deleteSession;
window.loadSessions = loadSessions;

/* ── Attack Surface tab ─────────────────────────────────────── */
var _asLoaded = false;
var _asData = null;
var _asExpanded = {};

window._initAttackSurface = function() {
    if (!_asLoaded) {
        _asLoaded = true;
        _asBindEvents();
    }
    _asLoad();
};

function _asBindEvents() {
    var sortSel = document.getElementById('asSortSelect');
    var filterSel = document.getElementById('asFilterRisk');
    if (sortSel) sortSel.addEventListener('change', function() { _asLoad(); });
    if (filterSel) filterSel.addEventListener('change', function() { _asLoad(); });
}

function _asLoad() {
    var sort = (document.getElementById('asSortSelect') || {}).value || 'severity';
    var risk = (document.getElementById('asFilterRisk') || {}).value || '';
    var url = '/api/attack-surface/' + PID + '?sort=' + sort;
    if (risk) url += '&filter_risk=' + encodeURIComponent(risk);

    fetch(url, {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            _asData = data;
            _asRenderSummary(data.summary || {});
            _asRenderHosts(data.hosts || []);
        })
        .catch(function(err) {
            console.warn('Attack surface load failed:', err);
        });
}

function _asRenderSummary(s) {
    var se = function(id, v) { var el = document.getElementById(id); if (el) el.textContent = v; };
    se('asTotalHosts', s.total_hosts || 0);
    se('asTotalPorts', s.total_ports || 0);
    se('asTotalFindings', s.total_findings || 0);
    se('asCritical', (s.severity || {}).CRITICAL || 0);
    se('asHigh', (s.severity || {}).HIGH || 0);
    se('asMedium', (s.severity || {}).MEDIUM || 0);
    se('asLow', (s.severity || {}).LOW || 0);
    se('asCoverage', (s.coverage_pct || 0) + '%');
}

function _asRenderHosts(hosts) {
    var container = document.getElementById('asHostTable');
    var empty = document.getElementById('asEmpty');
    if (!hosts.length) {
        container.innerHTML = '';
        if (empty) empty.hidden = false;
        return;
    }
    if (empty) empty.hidden = true;

    var html = '<table class="data-table"><thead><tr>';
    html += '<th>IP</th><th>Hostname</th><th>Ports</th><th>Services</th>';
    html += '<th style="min-width:120px">Severity</th>';
    html += '<th>Findings</th><th>Tools</th><th>Coverage</th>';
    html += '</tr></thead><tbody>';

    hosts.forEach(function(h, idx) {
        var svcs = [];
        h.ports.forEach(function(p) { if (p.service && svcs.indexOf(p.service) === -1) svcs.push(p.service); });
        var sc = h.severity_counts || {};
        var total = (sc.CRITICAL||0) + (sc.HIGH||0) + (sc.MEDIUM||0) + (sc.LOW||0) + (sc.INFO||0);
        var barHtml = _asSeverityBar(sc, total);
        var covCls = h.coverage_pct >= 80 ? 'risk-low' : h.coverage_pct >= 50 ? 'risk-medium' : 'risk-high';
        var hasMissing = h.ports.some(function(p) { return p.missing_tools && p.missing_tools.length; });

        html += '<tr class="as-host-row" data-as-idx="' + idx + '" style="cursor:pointer">';
        html += '<td class="font-mono text-sm">' + esc(h.ip) + '</td>';
        html += '<td class="text-sm">' + esc(h.hostname || '') + '</td>';
        html += '<td class="text-sm">' + h.port_count + '</td>';
        html += '<td class="text-sm text-truncate" style="max-width:200px">' + esc(svcs.join(', ')) + '</td>';
        html += '<td>' + barHtml + '</td>';
        html += '<td class="text-sm">' + h.total_findings + '</td>';
        html += '<td class="text-sm">' + h.tools.length + '</td>';
        html += '<td class="text-sm"><span class="' + covCls + '">' + h.coverage_pct + '%</span>' +
                (hasMissing ? ' <span class="as-gap-badge" title="Coverage gaps detected">!</span>' : '') + '</td>';
        html += '</tr>';

        html += '<tr class="as-detail-row" data-as-detail="' + idx + '" ' + (_asExpanded[idx] ? '' : 'hidden') + '>';
        html += '<td colspan="8" style="padding:0"><div class="as-detail-inner">' + _asRenderPortDetail(h) + '</div></td>';
        html += '</tr>';
    });

    html += '</tbody></table>';
    container.innerHTML = html;

    container.querySelectorAll('.as-host-row').forEach(function(row) {
        row.addEventListener('click', function() {
            var idx = parseInt(row.getAttribute('data-as-idx'));
            var detail = container.querySelector('[data-as-detail="' + idx + '"]');
            if (detail) {
                detail.hidden = !detail.hidden;
                _asExpanded[idx] = !detail.hidden;
            }
        });
    });
}

function _asSeverityBar(sc, total) {
    if (!total) return '<span class="text-secondary text-sm">—</span>';
    var w = function(n) { return Math.max(total > 0 ? (n / total * 100) : 0, n > 0 ? 4 : 0); };
    var html = '<div class="as-sev-bar">';
    if (sc.CRITICAL) html += '<div class="as-sev-seg risk-bg-critical" style="width:' + w(sc.CRITICAL) + '%" title="Critical: ' + sc.CRITICAL + '">' + sc.CRITICAL + '</div>';
    if (sc.HIGH) html += '<div class="as-sev-seg risk-bg-high" style="width:' + w(sc.HIGH) + '%" title="High: ' + sc.HIGH + '">' + sc.HIGH + '</div>';
    if (sc.MEDIUM) html += '<div class="as-sev-seg risk-bg-medium" style="width:' + w(sc.MEDIUM) + '%" title="Medium: ' + sc.MEDIUM + '">' + sc.MEDIUM + '</div>';
    if (sc.LOW) html += '<div class="as-sev-seg risk-bg-low" style="width:' + w(sc.LOW) + '%" title="Low: ' + sc.LOW + '">' + sc.LOW + '</div>';
    if (sc.INFO) html += '<div class="as-sev-seg risk-bg-info" style="width:' + w(sc.INFO) + '%" title="Info: ' + sc.INFO + '">' + sc.INFO + '</div>';
    html += '</div>';
    return html;
}

function _asRenderPortDetail(host) {
    var html = '<table class="data-table data-table-nested"><thead><tr>';
    html += '<th>Port</th><th>Service</th><th>Proto</th>';
    html += '<th>Findings</th><th>Tools</th><th>Gaps</th>';
    html += '</tr></thead><tbody>';

    host.ports.forEach(function(p) {
        var findingsList = '';
        if (p.findings && p.findings.length) {
            findingsList = p.findings.map(function(f) {
                var cls = 'risk-' + (f.risk || 'info').toLowerCase();
                return '<span class="risk-badge ' + cls + '" style="font-size:0.6rem">' + esc(f.risk) + '</span> ' +
                       '<a href="#" class="as-finding-link" data-fid="' + esc(f.id || '') + '">' + esc(f.title) + '</a>' +
                       (f.kev ? ' <span class="kev-badge">KEV</span>' : '');
            }).join('<br>');
        }
        var gapHtml = '';
        if (p.missing_tools && p.missing_tools.length) {
            gapHtml = p.missing_tools.map(function(t) {
                return '<span class="as-gap-tool">' + esc(t) + ' not run</span>';
            }).join(' ');
        }

        html += '<tr>';
        html += '<td class="font-mono text-sm">' + p.port + '</td>';
        html += '<td class="text-sm">' + esc(p.service || '') + '</td>';
        html += '<td class="text-sm">' + esc(p.protocol || 'tcp') + '</td>';
        html += '<td class="text-sm">' + (findingsList || '<span class="text-secondary">—</span>') + '</td>';
        html += '<td class="text-sm">' + (p.tools || []).join(', ') + '</td>';
        html += '<td class="text-sm">' + (gapHtml || '<span style="color:var(--status-success)">✓</span>') + '</td>';
        html += '</tr>';
    });

    html += '</tbody></table>';
    return html;
}

})();
