(function(){
  document.querySelectorAll('.project-card[data-href]').forEach(function(card) {
    card.addEventListener('click', function(e) {
      if (e.target.closest('.project-card-actions')) return;
      window.location.href = card.dataset.href;
    });
  });

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
