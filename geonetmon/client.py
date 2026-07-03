"""GUI-side client for the GeoNetMon daemon.

Connects to the daemon's Unix socket, runs a background reader thread, and
marshals incoming messages onto the GTK main loop via GLib.idle_add. The GUI
uses this to receive prompts/events and to send decisions and rule edits.

If the daemon isn't running or the socket isn't accessible, ``connect()``
returns False and the GUI stays in passive-monitor mode.
"""

import socket
import threading

from gi.repository import GLib

from . import ipc


class DaemonClient:
    def __init__(self, on_prompt=None, on_event=None, on_status=None,
                 on_rules=None, on_disconnect=None, on_dns=None,
                 socket_path=None):
        self.on_prompt = on_prompt
        self.on_event = on_event
        self.on_status = on_status
        self.on_rules = on_rules
        self.on_disconnect = on_disconnect
        self.on_dns = on_dns
        self.sock_path = socket_path or ipc.default_socket_path()
        self._sock = None
        self._thread = None
        self._running = False
        self._send_lock = threading.Lock()
        self.connected = False

    def connect(self, timeout=2.0):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(self.sock_path)
            s.settimeout(None)
        except OSError:
            return False
        self._sock = s
        self.connected = True
        self._running = True
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        self.send({"type": "hello"})
        return True

    def _reader(self):
        reader = ipc.MessageReader()
        while self._running:
            try:
                data = self._sock.recv(8192)
            except OSError:
                break
            if not data:
                break
            for msg in reader.feed(data):
                GLib.idle_add(self._dispatch, msg)
        self.connected = False
        if self.on_disconnect:
            GLib.idle_add(self.on_disconnect)

    def _dispatch(self, msg):
        t = msg.get("type")
        if t == "prompt" and self.on_prompt:
            self.on_prompt(msg.get("prompt_id"), msg.get("flow", {}))
        elif t == "event" and self.on_event:
            self.on_event(msg)
        elif t in ("status", "welcome") and self.on_status:
            self.on_status(msg)
        elif t == "rules" and self.on_rules:
            self.on_rules(msg.get("rules", []))
        elif t == "dns" and self.on_dns:
            self.on_dns(msg.get("map", {}))
        return False

    # ---- commands -------------------------------------------------------
    def send(self, msg):
        if not self._sock:
            return False
        with self._send_lock:
            return ipc.send_msg(self._sock, msg)

    def decide(self, prompt_id, action, scope, scope_by):
        self.send({"type": "decide", "prompt_id": prompt_id, "action": action,
                   "scope": scope, "scope_by": scope_by})

    def set_enforce(self, on):
        self.send({"type": "set_enforce", "on": bool(on)})

    def get_rules(self):
        self.send({"type": "get_rules"})

    def get_status(self):
        self.send({"type": "get_status"})

    def get_dns(self):
        self.send({"type": "get_dns"})

    def set_config(self, key, value):
        self.send({"type": "set_config", "key": key, "value": value})

    def add_rule(self, flow, action, scope, scope_by):
        self.send({"type": "add_rule", "flow": flow, "action": action,
                   "scope": scope, "scope_by": scope_by})

    def rule_remove(self, rid):
        self.send({"type": "rule_remove", "id": rid})

    def rule_enable(self, rid, on):
        self.send({"type": "rule_enable", "id": rid, "on": bool(on)})

    def rule_move(self, rid, delta):
        self.send({"type": "rule_move", "id": rid, "delta": delta})

    def close(self):
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        self.connected = False
