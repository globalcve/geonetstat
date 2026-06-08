"""geonetmond — the privileged GeoNetMon daemon.

Runs as root. Owns the NFQUEUE enforcement engine, the authoritative rule set,
the DNS cache, the integrity store, and system-firewall (nft) management. The
unprivileged GUI connects over a Unix socket and exchanges newline-JSON
messages (see ipc.py).

Socket: created at ipc.default_socket_path() with mode 0660 and, if the
``geonetmon`` group exists, owned by that group so members can connect without
root. Otherwise it stays root-only.

Protocol (GUI -> daemon):
  {"type":"hello"}                              -> {"type":"welcome", ...}
  {"type":"get_rules"}                          -> {"type":"rules", "rules":[...]}
  {"type":"get_status"}                         -> {"type":"status", ...}
  {"type":"set_enforce","on":bool}              -> status
  {"type":"decide","prompt_id":..,"action":"allow|deny",
                    "scope":"once|session|forever|no_rule",
                    "scope_by":"app_host|..."}
  {"type":"rule_remove","id":..}  {"type":"rule_enable","id":..,"on":bool}
  {"type":"rule_move","id":..,"delta":-1|1}
  {"type":"block_ip","ip":..}     {"type":"unblock_ip","ip":..}

Protocol (daemon -> GUI):
  {"type":"prompt","prompt_id":..,"flow":{...}}     (asks for a decision)
  {"type":"event","flow":{...},"action":..,"auto":bool,"rule":..}
  {"type":"status",...}   {"type":"rules",...}   {"type":"welcome",...}
"""

import grp
import os
import socket
import threading
import time

from . import collector
from . import ipc
from .config import Config
from .rules import Rules
from .procmap import ProcMap
from .dnscap import DNSCache
from .integrity import Integrity
from .netfilter import Engine
from . import firewall as fw_mod


class Daemon:
    def __init__(self, socket_path=None):
        self.config = Config()
        self.rules = Rules(self.config)
        self.procmap = ProcMap()
        self.dns = DNSCache()
        self.integrity = Integrity()
        self.firewall = fw_mod.Firewall(self.config)
        self.engine = Engine(
            self.config, self.rules, self.procmap, self.dns, self.integrity,
            on_prompt=self._on_prompt, on_event=self._on_event,
        )
        self.sock_path = socket_path or ipc.default_socket_path()
        self._server = None
        self._clients = []          # list of (sock, lock)
        self._clients_lock = threading.Lock()
        self._running = False

    # ---- client registry ------------------------------------------------
    def _broadcast(self, msg):
        dead = []
        with self._clients_lock:
            clients = list(self._clients)
        for entry in clients:
            sock, lock = entry
            with lock:
                if not ipc.send_msg(sock, msg):
                    dead.append(entry)
        if dead:
            with self._clients_lock:
                for d in dead:
                    if d in self._clients:
                        self._clients.remove(d)

    # ---- engine callbacks (called from engine thread) -------------------
    def _on_prompt(self, prompt_id, flow):
        self._broadcast({"type": "prompt", "prompt_id": prompt_id,
                         "flow": _clean(flow)})

    def _on_event(self, flow, action, auto, rule_summary):
        self._broadcast({"type": "event", "flow": _clean(flow),
                         "action": action, "auto": auto, "rule": rule_summary})

    # ---- request handling -----------------------------------------------
    def _status(self):
        return {
            "type": "status",
            "enforcing": self.engine.running,
            "available": self.engine.available(),
            "engine_status": self.engine.status_text(),
            "pending": self.engine.pending_count(),
            "rule_count": len(self.rules.rules),
            "default_action": self.config.get("enforce_default_action"),
        }

    def _rules_msg(self):
        return {"type": "rules",
                "rules": [r.to_dict() | {"summary": r.summary()}
                          for r in self.rules.rules]}

    def _handle(self, msg, sock, lock):
        mtype = msg.get("type")
        if mtype == "hello":
            return {"type": "welcome", "version": _version(),
                    "socket": self.sock_path} | {
                    k: v for k, v in self._status().items() if k != "type"}
        if mtype == "get_status":
            return self._status()
        if mtype == "get_rules":
            return self._rules_msg()
        if mtype == "set_enforce":
            if msg.get("on"):
                ok, info = self.engine.start()
                self.config["enforce_enabled"] = ok
            else:
                self.engine.stop()
                self.config["enforce_enabled"] = False
            self.config.save()
            self._broadcast(self._status())
            return self._status()
        if mtype == "decide":
            self.engine.resolve_prompt(
                msg.get("prompt_id"), msg.get("action", "deny"),
                msg.get("scope", "no_rule"), msg.get("scope_by", "exact"))
            self._broadcast(self._rules_msg())
            return None
        if mtype == "add_rule":
            self.rules.build_from_choice(
                msg.get("flow", {}), msg.get("action", "deny"),
                msg.get("scope", "forever"), msg.get("scope_by", "app_any"))
            self._broadcast(self._rules_msg())
            return None
        if mtype == "rule_remove":
            self.rules.remove(msg.get("id"))
            self._broadcast(self._rules_msg())
            return None
        if mtype == "rule_enable":
            self.rules.set_enabled(msg.get("id"), msg.get("on", True))
            self._broadcast(self._rules_msg())
            return None
        if mtype == "rule_move":
            self.rules.move(msg.get("id"), int(msg.get("delta", 0)))
            self._broadcast(self._rules_msg())
            return None
        if mtype == "block_ip":
            self.firewall.block(msg.get("ip", ""))
            return {"type": "ok", "op": "block_ip"}
        if mtype == "unblock_ip":
            self.firewall.unblock(msg.get("ip", ""))
            return {"type": "ok", "op": "unblock_ip"}
        if mtype == "set_config":
            key, val = msg.get("key"), msg.get("value")
            if key in self.config:
                self.config[key] = val
                self.config.save()
            return {"type": "ok", "op": "set_config"}
        return {"type": "error", "error": f"unknown type {mtype!r}"}

    def _serve_client(self, sock):
        lock = threading.Lock()
        entry = (sock, lock)
        with self._clients_lock:
            self._clients.append(entry)
        reader = ipc.MessageReader()
        try:
            while self._running:
                try:
                    data = sock.recv(8192)
                except OSError:
                    break
                if not data:
                    break
                for msg in reader.feed(data):
                    try:
                        reply = self._handle(msg, sock, lock)
                    except Exception as exc:  # noqa: BLE001 — never drop the
                        # client connection over one bad message; the GUI needs
                        # this socket alive to receive enforcement prompts.
                        reply = {"type": "error",
                                 "error": f"{type(exc).__name__}: {exc}"}
                    if reply is not None:
                        with lock:
                            ipc.send_msg(sock, reply)
        finally:
            with self._clients_lock:
                if entry in self._clients:
                    self._clients.remove(entry)
            try:
                sock.close()
            except OSError:
                pass

    # ---- lifecycle ------------------------------------------------------
    def _make_socket(self):
        if os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except OSError:
                pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.sock_path)
        srv.listen(8)
        # group-accessible if a 'geonetmon' group exists
        try:
            gid = grp.getgrnam("geonetmon").gr_gid
            os.chown(self.sock_path, 0, gid)
            os.chmod(self.sock_path, 0o660)
        except (KeyError, PermissionError, OSError):
            os.chmod(self.sock_path, 0o600)
        return srv

    def run(self):
        if not self.engine.available():
            print(f"[geonetmond] warning: {self.engine.status_text()}")
        self._running = True
        if self.config.get("enforce_enabled"):
            ok, info = self.engine.start()
            print(f"[geonetmond] enforcement: {info}")
        self._server = self._make_socket()
        # Publish process attribution for the unprivileged GUI (so it never
        # needs root just to see process names). Runs as root here, writes a
        # world-readable file the GUI reads.
        threading.Thread(target=self._procs_loop, daemon=True).start()
        print(f"[geonetmond] listening on {self.sock_path}")
        try:
            while self._running:
                try:
                    client, _ = self._server.accept()
                except OSError:
                    break
                threading.Thread(target=self._serve_client,
                                 args=(client,), daemon=True).start()
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def _procs_loop(self):
        """Republish the socket->process map ~every 2s, and expire any
        'while the app is running' rules whose program has quit."""
        while self._running:
            try:
                collector.write_proc_map(collector.collect())
            except Exception:  # noqa: BLE001 — never let this kill the daemon
                pass
            try:
                if self.rules.prune_processes():
                    self._broadcast(self._rules_msg())
            except Exception:  # noqa: BLE001
                pass
            time.sleep(2.0)

    def shutdown(self):
        self._running = False
        try:
            if os.path.exists(collector.DAEMON_PROC_FILE):
                os.unlink(collector.DAEMON_PROC_FILE)
        except OSError:
            pass
        self.engine.stop()
        self.rules.save()
        self.integrity.save()
        self.firewall.save()
        self.config.save()
        try:
            if self._server:
                self._server.close()
            if os.path.exists(self.sock_path):
                os.unlink(self.sock_path)
        except OSError:
            pass


def _clean(flow):
    """Keep only JSON-safe, GUI-relevant fields from a flow dict."""
    keys = ("proto", "direction", "src_ip", "src_port", "dst_ip", "dst_port",
            "dst_host", "process", "process_path", "pid", "integrity",
            "org", "country", "city")
    return {k: flow[k] for k in keys if k in flow}


def _version():
    try:
        from . import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "0"


def main():
    import sys
    sock = None
    for i, a in enumerate(sys.argv):
        if a == "--socket" and i + 1 < len(sys.argv):
            sock = sys.argv[i + 1]
    Daemon(sock).run()


if __name__ == "__main__":
    main()
