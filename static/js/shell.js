(function(){
  var statusEl = document.getElementById('shellStatus');
  var reconnectBtn = document.getElementById('shellReconnect');
  var termEl = document.getElementById('terminal');

  var term = new Terminal({
    cursorBlink: true,
    fontSize: 14,
    fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", "Source Code Pro", "Menlo", monospace',
    theme: {
      background: '#0a0a0a',
      foreground: '#e0e0e0',
      cursor: '#4fc3f7',
      selectionBackground: 'rgba(79, 195, 247, 0.3)',
    },
    scrollback: 10000,
    convertEol: true,
  });

  var fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(termEl);

  setTimeout(function(){ fitAddon.fit(); }, 50);

  var socket = io({transports: ['websocket']});
  var shellOpen = false;

  function openShell() {
    fitAddon.fit();
    socket.emit('shell_open', {cols: term.cols, rows: term.rows});
    shellOpen = true;
    statusEl.textContent = 'Connected';
    statusEl.className = 'shell-status connected';
    reconnectBtn.hidden = true;
  }

  socket.on('connect', function(){
    if (!shellOpen) {
      statusEl.textContent = 'Connected — opening shell...';
      openShell();
    }
  });

  socket.on('shell_output', function(msg){
    term.write(msg.data);
  });

  socket.on('shell_exit', function(){
    term.write('\r\n\x1b[33m[Shell session ended]\x1b[0m\r\n');
    statusEl.textContent = 'Disconnected';
    statusEl.className = 'shell-status disconnected';
    shellOpen = false;
    reconnectBtn.hidden = false;
  });

  socket.on('disconnect', function(){
    term.write('\r\n\x1b[31m[Connection lost]\x1b[0m\r\n');
    statusEl.textContent = 'Disconnected';
    statusEl.className = 'shell-status disconnected';
    shellOpen = false;
    reconnectBtn.hidden = false;
  });

  term.onData(function(data){
    if (shellOpen) {
      socket.emit('shell_input', {data: data});
    }
  });

  term.onResize(function(size){
    if (shellOpen) {
      socket.emit('shell_resize', {cols: size.cols, rows: size.rows});
    }
  });

  var resizeTimer;
  window.addEventListener('resize', function(){
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function(){ fitAddon.fit(); }, 100);
  });

  document.getElementById('shellClear').addEventListener('click', function(){
    term.clear();
  });

  document.getElementById('shellDisconnect').addEventListener('click', function(){
    socket.emit('shell_close');
    shellOpen = false;
    window.location.href = '/';
  });

  reconnectBtn.addEventListener('click', function(){
    term.reset();
    openShell();
  });

  term.focus();
})();
