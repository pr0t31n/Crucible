/* Reload on bfcache restore to get a fresh CSRF token */
window.addEventListener('pageshow', function(e){
  if(e.persisted) window.location.reload();
});
