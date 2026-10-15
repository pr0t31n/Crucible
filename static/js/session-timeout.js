(function(){
  /* ── Session timeout ─────────────────────────────── */
  var cfgEl     = document.getElementById('sessionConfig');
  if (!cfgEl) return;
  var SESSION_MS  = parseInt(cfgEl.dataset.sessionMs, 10) || 1800000;
  var WARNING_MS  = parseInt(cfgEl.dataset.warningMs, 10) || 300000;
  var overlay     = document.getElementById('sessionOverlay');
  var countdown   = document.getElementById('sessionCountdown');
  var continueBtn = document.getElementById('sessionContinueBtn');
  if (!overlay) return;
  var warnTimer, expireTimer, tickInterval;
  var expireAt;

  function doLogout(){
    fetch('/logout', {credentials:'same-origin'}).finally(function(){
      window.location.href = '/login';
    });
  }

  function resetTimers(){
    clearTimeout(warnTimer);
    clearTimeout(expireTimer);
    clearInterval(tickInterval);
    overlay.classList.remove('visible');
    var now = Date.now();
    expireAt = now + SESSION_MS;
    warnTimer = setTimeout(showWarning, SESSION_MS - WARNING_MS);
    expireTimer = setTimeout(doLogout, SESSION_MS);
  }

  function showWarning(){
    overlay.classList.add('visible');
    tickInterval = setInterval(function(){
      var left = Math.max(0, expireAt - Date.now());
      var m = Math.floor(left / 60000);
      var s = Math.floor((left % 60000) / 1000);
      countdown.textContent = m + ':' + (s < 10 ? '0' : '') + s;
      if(left <= 0){ clearInterval(tickInterval); }
    }, 1000);
  }

  if(continueBtn){
    continueBtn.addEventListener('click', function(){
      fetch('/api/session_ping', {method:'POST', credentials:'same-origin'})
        .then(function(r){
          if(!r.ok) { doLogout(); return; }
          resetTimers();
        })
        .catch(function(){ doLogout(); });
    });
  }

  resetTimers();

  /* Reset on user activity */
  ['click','keydown','mousemove','scroll','touchstart'].forEach(function(evt){
    document.addEventListener(evt, function(){
      if(overlay.classList.contains('visible')) return;
      resetTimers();
    }, {passive:true});
  });
})();
