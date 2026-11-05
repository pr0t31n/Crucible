/* ══════════════════════════════════════════════════════════════════
   AI SURFACE TAB — Discovered AI services, model inventory,
   key exposure, and pAIn test status
   ══════════════════════════════════════════════════════════════════ */

(function() {
    'use strict';

    var _loaded = false;
    var _data = null;

    function esc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

    function _riskClass(r) {
        r = (r || 'INFO').toUpperCase();
        return 'risk-' + r.toLowerCase();
    }

    function _riskBadge(r) {
        return '<span class="risk-badge ' + _riskClass(r) + '">' + esc(r) + '</span>';
    }

    window._initAiSurface = function() {
        if (_loaded) return;
        _loaded = true;
        _loadAiSurface();
    };

    window._refreshAiSurface = function() {
        _loadAiSurface();
    };

    function _loadAiSurface() {
        fetch('/api/ai_surface/' + PID, {credentials: 'same-origin'})
            .then(function(r) { return r.json(); })
            .then(function(data) {
                _data = data;
                _renderAll(data);
                var pill = document.getElementById('aiSurfacePill');
                if (pill) pill.textContent = (data.summary || {}).total_findings || '';
            })
            .catch(function(err) {
                console.warn('AI Surface load failed:', err);
            });
    }

    function _renderAll(d) {
        var s = d.summary || {};
        _renderSummaryCards(s);
        _renderServices(d.services || []);
        _renderModels(d.model_inventory || []);
        _renderFindings(d.findings || []);
        _renderKeyExposure(d.key_exposure || []);
        _renderPainStatus(d.pain_status);

        var empty = document.getElementById('aiSurfaceEmpty');
        var body = document.getElementById('aiSurfaceBody');
        if (s.total_findings || (d.services || []).length || (d.key_exposure || []).length) {
            if (empty) empty.hidden = true;
            if (body) body.hidden = false;
        } else {
            if (empty) empty.hidden = false;
            if (body) body.hidden = true;
        }
    }

    function _renderSummaryCards(s) {
        var se = function(id, v) { var el = document.getElementById(id); if (el) el.textContent = v; };
        se('aiTotalServices', s.total_services || 0);
        se('aiUnauthServices', s.unauth_services || 0);
        se('aiTotalModels', s.total_models || 0);
        se('aiTotalFindings', s.total_findings || 0);

        var el = document.getElementById('aiUnauthServices');
        if (el) {
            el.style.color = (s.unauth_services || 0) > 0 ? 'var(--red-500)' : '';
            el.style.fontWeight = (s.unauth_services || 0) > 0 ? '700' : '';
        }

        var severity = s.findings_by_severity || {};
        se('aiCritical', severity.CRITICAL || 0);
        se('aiHigh', severity.HIGH || 0);
        se('aiMedium', severity.MEDIUM || 0);
        se('aiLow', severity.LOW || 0);
        se('aiInfo', severity.INFO || 0);
    }

    function _renderServices(services) {
        var container = document.getElementById('aiServicesTable');
        if (!container) return;
        if (!services.length) {
            container.innerHTML = '<div class="text-muted text-sm" style="padding:12px">No AI services discovered yet.</div>';
            return;
        }
        var h = '<table class="data-table"><thead><tr>';
        h += '<th>IP</th><th>Port</th><th>Service</th><th>Auth</th><th>Models</th><th>Source</th>';
        h += '</tr></thead><tbody>';
        services.forEach(function(s) {
            var authCls = s.auth_status === 'no' ? 'risk-critical' : s.auth_status === 'yes' ? 'risk-low' : 'text-muted';
            var authTxt = s.auth_status === 'no' ? 'NONE' : s.auth_status === 'yes' ? 'Yes' : '—';
            h += '<tr>';
            h += '<td class="font-mono text-sm">' + esc(s.ip) + '</td>';
            h += '<td class="font-mono text-sm">' + s.port + '</td>';
            h += '<td><span class="ai-svc-badge">' + esc(s.service_type) + '</span></td>';
            h += '<td><span class="' + authCls + ' font-bold text-sm">' + authTxt + '</span></td>';
            h += '<td class="text-sm">' + (s.models.length ? esc(s.models.join(', ')) : '<span class="text-muted">—</span>') + '</td>';
            h += '<td class="text-sm">' + esc(s.source) + '</td>';
            h += '</tr>';
        });
        h += '</tbody></table>';
        container.innerHTML = h;
    }

    function _renderModels(models) {
        var container = document.getElementById('aiModelsTable');
        if (!container) return;
        if (!models.length) {
            container.innerHTML = '<div class="text-muted text-sm" style="padding:12px">No AI models enumerated yet.</div>';
            return;
        }
        var h = '<table class="data-table"><thead><tr>';
        h += '<th>Model Name</th><th>Endpoint</th><th>Service</th>';
        h += '</tr></thead><tbody>';
        models.forEach(function(m) {
            h += '<tr>';
            h += '<td class="font-mono text-sm">' + esc(m.name) + '</td>';
            h += '<td class="font-mono text-sm">' + esc(m.endpoint) + '</td>';
            h += '<td class="text-sm">' + esc(m.service_type) + '</td>';
            h += '</tr>';
        });
        h += '</tbody></table>';
        container.innerHTML = h;
    }

    function _renderFindings(findings) {
        var container = document.getElementById('aiFindingsTable');
        if (!container) return;
        if (!findings.length) {
            container.innerHTML = '<div class="text-muted text-sm" style="padding:12px">No AI-related findings yet.</div>';
            return;
        }
        var h = '<table class="data-table"><thead><tr>';
        h += '<th>Finding</th><th>IP</th><th>Port</th><th>Risk</th><th>Tool</th>';
        h += '</tr></thead><tbody>';
        findings.forEach(function(f) {
            h += '<tr>';
            h += '<td class="text-sm">' + esc(f.title) + '</td>';
            h += '<td class="font-mono text-sm">' + esc(f.ip) + '</td>';
            h += '<td class="font-mono text-sm">' + (f.port || '') + '</td>';
            h += '<td>' + _riskBadge(f.risk) + '</td>';
            h += '<td class="text-sm">' + esc(f.tool) + '</td>';
            h += '</tr>';
        });
        h += '</tbody></table>';
        container.innerHTML = h;
    }

    function _renderKeyExposure(keys) {
        var container = document.getElementById('aiKeyExposureTable');
        if (!container) return;
        if (!keys.length) {
            container.innerHTML = '<div class="text-muted text-sm" style="padding:12px">No exposed AI API keys found.</div>';
            return;
        }
        var h = '<table class="data-table"><thead><tr>';
        h += '<th>Key Type</th><th>Location</th><th>Risk</th><th>Tool</th>';
        h += '</tr></thead><tbody>';
        keys.forEach(function(k) {
            h += '<tr>';
            h += '<td class="text-sm">' + esc(k.title) + '</td>';
            h += '<td class="font-mono text-sm text-truncate" style="max-width:300px">' + esc(k.location) + '</td>';
            h += '<td>' + _riskBadge(k.risk) + '</td>';
            h += '<td class="text-sm">' + esc(k.tool) + '</td>';
            h += '</tr>';
        });
        h += '</tbody></table>';
        container.innerHTML = h;
    }

    function _renderPainStatus(status) {
        var container = document.getElementById('aiPainStatus');
        if (!container) return;
        if (!status) {
            container.innerHTML = '<div class="text-muted text-sm" style="padding:12px">pAIn has not been run against this project yet.</div>';
            return;
        }
        var rc = status.risk_counts || {};
        var h = '<div class="flex gap-12 flex-wrap" style="padding:8px 0">';
        h += '<div class="text-sm"><strong>Targets Tested:</strong> ' + (status.targets_tested || 0) + '</div>';
        h += '<div class="text-sm"><strong>Total Findings:</strong> ' + (status.total_findings || 0) + '</div>';
        h += '</div>';
        h += '<div class="flex gap-8 flex-wrap" style="padding:4px 0">';
        h += '<span class="risk-badge risk-critical">CRITICAL ' + (rc.CRITICAL || 0) + '</span>';
        h += '<span class="risk-badge risk-high">HIGH ' + (rc.HIGH || 0) + '</span>';
        h += '<span class="risk-badge risk-medium">MEDIUM ' + (rc.MEDIUM || 0) + '</span>';
        h += '<span class="risk-badge risk-low">LOW ' + (rc.LOW || 0) + '</span>';
        h += '<span class="risk-badge risk-info">INFO ' + (rc.INFO || 0) + '</span>';
        h += '</div>';
        container.innerHTML = h;
    }

    if (typeof socket !== 'undefined') {
        socket.on('tool_finding', function(data) {
            if (data.project_id !== PID) return;
            if (!_loaded) return;
            var f = data;
            var title = (f.title || '').toLowerCase();
            var tool = f.tool || '';
            var owasp = f.owasp || '';
            if (tool === 'pain' || owasp.startsWith('LLM') ||
                _AI_SVC_RE_JS.test(title) || title.indexOf('ai model') >= 0 ||
                title.indexOf('ai service') >= 0 || title.indexOf('prompt injection') >= 0) {
                clearTimeout(_aiDebounce);
                _aiDebounce = setTimeout(function() { _loadAiSurface(); }, 3000);
            }
        });
    }

    var _aiDebounce = null;
    var _AI_SVC_RE_JS = /ollama|gradio|streamlit|mlflow|vllm|triton|bentoml|litellm|torchserve|huggingface|langflow|comfyui|jupyter|dify|chromadb|milvus|qdrant|weaviate/i;

})();
