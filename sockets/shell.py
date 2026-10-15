"""SocketIO shell events — interactive web shell via PTY."""

import logging
import os
import sys
import shutil
import subprocess
import threading
import pty
import select

_shells = {}
_lock = threading.Lock()
_log = logging.getLogger("crucible.shell")


def register_shell_events(socketio):

    @socketio.on("shell_open")
    def on_shell_open(data=None):
        from flask import request as req
        sid = req.sid
        with _lock:
            if sid in _shells:
                return

        shell_cmd = shutil.which("zsh") or shutil.which("bash") or "/bin/sh"
        env = dict(os.environ)
        env["TERM"] = "xterm-256color"
        cols = data.get("cols", 120) if data else 120
        rows = data.get("rows", 40) if data else 40
        env["COLUMNS"] = str(cols)
        env["LINES"] = str(rows)

        master_fd, slave_fd = pty.openpty()

        import struct, fcntl, termios
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)

        proc = subprocess.Popen(
            [shell_cmd, "-l"],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            preexec_fn=os.setsid, env=env, close_fds=True,
        )
        os.close(slave_fd)

        def reader():
            try:
                while True:
                    r, _, _ = select.select([master_fd], [], [], 0.1)
                    if r:
                        try:
                            chunk = os.read(master_fd, 4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        socketio.emit("shell_output",
                                      {"data": chunk.decode("utf-8", errors="replace")},
                                      to=sid)
            except Exception:
                pass
            finally:
                socketio.emit("shell_exit", {}, to=sid)
                _cleanup(sid)

        t = threading.Thread(target=reader, daemon=True,
                             name=f"shell-{sid[:8]}")
        t.start()

        with _lock:
            _shells[sid] = {"proc": proc, "master_fd": master_fd, "thread": t}
        _log.info("Shell opened: sid=%s pid=%s shell=%s", sid[:8], proc.pid, shell_cmd)

    @socketio.on("shell_input")
    def on_shell_input(data):
        from flask import request as req
        with _lock:
            info = _shells.get(req.sid)
        if not info:
            return
        text = data.get("data", "")
        if text:
            try:
                os.write(info["master_fd"], text.encode("utf-8"))
            except OSError:
                pass

    @socketio.on("shell_resize")
    def on_shell_resize(data):
        from flask import request as req
        with _lock:
            info = _shells.get(req.sid)
        if not info:
            return
        import struct, fcntl, termios
        cols = data.get("cols", 120)
        rows = data.get("rows", 40)
        try:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(info["master_fd"], termios.TIOCSWINSZ, winsize)
        except (OSError, Exception):
            pass

    @socketio.on("shell_close")
    def on_shell_close(data=None):
        from flask import request as req
        _cleanup(req.sid)

    @socketio.on("disconnect")
    def on_shell_disconnect():
        from flask import request as req
        _cleanup(req.sid)


def _cleanup(sid):
    with _lock:
        info = _shells.pop(sid, None)
    if not info:
        return
    _log.info("Shell closed: sid=%s pid=%s", sid[:8], info["proc"].pid)
    try:
        os.close(info["master_fd"])
    except OSError:
        pass
    proc = info["proc"]
    if proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
