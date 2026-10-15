(function(){
  var V=['tuxedo','blueprint','forge','bloom','ember','coruscant','neuromancer','synthwave','espresso','sage'];
  try{
    var p=localStorage.getItem('crucible-palette');
    var m=localStorage.getItem('crucible-mode');
    if(p&&V.indexOf(p)!==-1) document.documentElement.setAttribute('data-palette',p);
    if(m==='dark'||m==='light') document.documentElement.setAttribute('data-mode',m);
  }catch(e){}
})();
