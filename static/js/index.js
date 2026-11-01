(function(){
  /* ── FindingsDB dependency check ───────────────────────── */
  var _fdbAvailable = null;
  fetch('/api/findings-db-status', {credentials: 'same-origin'})
    .then(function(r){ return r.json(); })
    .then(function(d){ _fdbAvailable = !!d.available; })
    .catch(function(){ _fdbAvailable = false; });

  function _showDepModal(){
    document.getElementById('fdbDepModal').classList.add('open');
  }
  function _showConvertModal(pid, href){
    document.getElementById('fdbConvertModal').classList.add('open');
    var convertBtn = document.getElementById('fdbConvertBtn');
    var skipBtn = document.getElementById('fdbSkipBtn');
    var statusEl = document.getElementById('fdbConvertStatus');
    statusEl.textContent = '';
    convertBtn.disabled = false;
    convertBtn.textContent = 'Convert Now';
    convertBtn.onclick = function(){
      convertBtn.disabled = true;
      convertBtn.textContent = 'Converting...';
      statusEl.textContent = 'Migrating findings to database...';
      statusEl.style.color = 'var(--text-secondary)';
      fetch('/api/convert-engagement/' + pid, {method: 'POST', credentials: 'same-origin'})
        .then(function(r){ return r.json().then(function(d){ return {ok: r.ok, data: d}; }); })
        .then(function(res){
          if(res.ok && res.data.ok){
            statusEl.textContent = res.data.message || 'Conversion complete';
            statusEl.style.color = 'var(--status-success)';
            setTimeout(function(){ window.location.href = href; }, 600);
          } else {
            var errMsg = 'Error: ' + (res.data.error || 'Unknown error');
            if(res.data.traceback){
              errMsg += '\n\n' + res.data.traceback;
            }
            statusEl.style.whiteSpace = 'pre-wrap';
            statusEl.style.fontFamily = 'monospace';
            statusEl.style.fontSize = '11px';
            statusEl.style.maxHeight = '300px';
            statusEl.style.overflow = 'auto';
            statusEl.textContent = errMsg;
            statusEl.style.color = 'var(--status-error)';
            convertBtn.disabled = false;
            convertBtn.textContent = 'Retry';
          }
        })
        .catch(function(e){
          statusEl.textContent = 'Network error: ' + e.message;
          statusEl.style.color = 'var(--status-error)';
          convertBtn.disabled = false;
          convertBtn.textContent = 'Retry';
        });
    };
    skipBtn.onclick = function(){
      window._closeConvertModal();
      window.location.href = href;
    };
  }
  window._closeDepModal = function(){
    document.getElementById('fdbDepModal').classList.remove('open');
  };
  window._closeConvertModal = function(){
    document.getElementById('fdbConvertModal').classList.remove('open');
  };

  function _navigateProject(pid, href){
    if(_fdbAvailable === false){
      _showDepModal();
      return;
    }
    fetch('/api/project-db-status/' + pid, {credentials: 'same-origin'})
      .then(function(r){ return r.json(); })
      .then(function(d){
        if(d.has_db){
          window.location.href = href;
        } else {
          _showConvertModal(pid, href);
        }
      })
      .catch(function(){
        window.location.href = href;
      });
  }

  /* ── Intercept "Create New Engagement" button ──────────── */
  var newEngBtn = document.querySelector('.btn-new-engagement');
  if(newEngBtn){
    newEngBtn.removeAttribute('onclick');
    newEngBtn.addEventListener('click', function(e){
      e.preventDefault();
      if(_fdbAvailable === false){
        _showDepModal();
      } else {
        window.location.href = '/new_project';
      }
    });
  }

  /* ── Intercept project card clicks ─────────────────────── */
  document.querySelectorAll('.project-card[data-href]').forEach(function(card) {
    card.addEventListener('click', function(e) {
      if (e.target.closest('.project-card-actions')) return;
      var pid = card.dataset.id;
      var href = card.dataset.href;
      _navigateProject(pid, href);
    });
  });

  /* ── Escape key for new modals ─────────────────────────── */
  document.addEventListener('keydown', function(e){
    if(e.key !== 'Escape') return;
    var dep = document.getElementById('fdbDepModal');
    var conv = document.getElementById('fdbConvertModal');
    if(dep && dep.classList.contains('open')) window._closeDepModal();
    if(conv && conv.classList.contains('open')) window._closeConvertModal();
  });

  /* ── Delete modal (unchanged) ──────────────────────────── */
  var deleteModal     = document.getElementById('deleteModal');
  var deleteNameEl    = document.getElementById('deleteProjectName');
  var deleteFilesChk  = document.getElementById('deleteFilesCheck');
  var deleteConfirm   = document.getElementById('deleteConfirmBtn');
  var deleteCancelBtn = document.getElementById('deleteCancelBtn');
  var deleteCloseBtn  = document.getElementById('deleteCloseBtn');
  var pendingDeleteId = null;

  function openDeleteModal() { deleteModal.classList.add('open'); }
  function closeDeleteModal() { deleteModal.classList.remove('open'); pendingDeleteId = null; }

  window.clearProject = function(id){
    if(!confirm('Clear all results for this engagement? Tool output and findings will be removed.')) return;
    fetch('/api/clear_project/' + id, {method:'POST', credentials:'same-origin'})
      .then(function(r){ if(r.ok) window.location.reload(); })
      .catch(function(e){ console.error(e); });
  };

  window.deleteProject = function(id, name){
    pendingDeleteId = id;
    deleteNameEl.textContent = name;
    deleteFilesChk.checked = false;
    openDeleteModal();
  };

  deleteConfirm.addEventListener('click', function(){
    if(!pendingDeleteId) return;
    var qs = deleteFilesChk.checked ? '?files=1' : '';
    fetch('/api/delete_project/' + pendingDeleteId + qs, {method:'DELETE', credentials:'same-origin'})
      .then(function(r){
        if(r.ok) window.location.reload();
        else r.json().then(function(d){ alert(d.error || 'Delete failed'); });
      })
      .catch(function(e){ console.error(e); });
  });

  deleteCancelBtn.addEventListener('click', closeDeleteModal);
  deleteCloseBtn.addEventListener('click', closeDeleteModal);

  deleteModal.addEventListener('click', function(e){
    if(e.target === deleteModal) closeDeleteModal();
  });

  document.addEventListener('keydown', function(e){
    if(e.key === 'Escape') closeDeleteModal();
  });

  function _esc(s){ var d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

  window.loadHomeSystemInfo = function(){
    fetch('/api/system_info', {credentials: 'same-origin'})
      .then(function(r){ return r.json(); })
      .then(function(d){
        var grid = document.getElementById('homeSystemInfoGrid');
        grid.innerHTML = '';
        var osStr = '--';
        if(d.os){
          if(typeof d.os === 'object'){
            osStr = d.os.os_name || (d.os.system + ' ' + d.os.release) || JSON.stringify(d.os);
          } else {
            osStr = String(d.os);
          }
        }
        var fields = [
          ['Host', d.hostname],
          ['OS', osStr],
          ['IP', d.ip || (d.interface && d.interface.ip)],
          ['CPU', d.cpu && (typeof d.cpu === 'object' ? d.cpu.model : d.cpu)],
          ['RAM', d.ram && (typeof d.ram === 'object' ? d.ram.total_human : d.ram)]
        ];
        fields.forEach(function(f){
          grid.innerHTML += '<span class="sysinfo-label">' + _esc(f[0]) + '</span>'
            + '<span class="sysinfo-value">' + _esc(f[1] || '--') + '</span>';
        });
      })
      .catch(function(){
        document.getElementById('homeSystemInfoGrid').innerHTML =
          '<span class="sysinfo-label" style="color:var(--text-muted)">Failed to load</span><span></span>';
      });
  };
  loadHomeSystemInfo();
})();
