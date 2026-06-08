"""Detail window shown when a row is double-clicked."""

import os
import signal
import subprocess
import threading

from gi.repository import Gtk, Gdk, GLib

from . import ports
from .models import human_bytes, human_rate


class DetailWindow(Gtk.Window):
    def __init__(self, parent, obj, firewall=None, window=None):
        super().__init__(title="Connection details", transient_for=parent)
        self.set_default_size(560, 640)
        self.obj = obj
        self.firewall = firewall
        self._window = window  # MainWindow ref for daemon IPC / deny action

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_child(outer)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer.append(scroll)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(16)
        box.set_margin_bottom(8)
        box.set_margin_start(16)
        box.set_margin_end(16)
        scroll.set_child(box)

        # --- connection fields ---
        grid = Gtk.Grid(column_spacing=14, row_spacing=8)
        box.append(grid)

        cc = (obj.country or "").upper()
        risk = "—"
        if getattr(obj, "risk", -1) >= 0:
            risk = f"{obj.risk}/100 (AbuseIPDB)"
        rows = [
            ("Remote IP",       obj.ip),
            ("Protocol",        obj.proto.upper()),
            ("Direction",       obj.direction),
            ("State",           obj.state),
            ("Application",     obj.application),
            ("PID",             str(obj.pid) if obj.pid else "—"),
            ("Local",           f"{obj.local_ip}:{obj.local_port}"),
            ("Remote",          f"{obj.remote_ip}:{obj.remote_port}"),
            ("Service port",    str(obj.port)),
            ("Service",         obj.service),
            ("Encryption",      obj.encryption),
            ("Throughput ↑",    human_rate(obj.rate_up) or "idle"),
            ("Throughput ↓",    human_rate(obj.rate_down) or "idle"),
            ("Total sent/recv", f"{human_bytes(obj.total_up) or '0'} / "
                                f"{human_bytes(obj.total_down) or '0'}"),
            ("Risk score",      risk),
            ("Organization",    obj.org),
            ("Location",        obj.location),
            ("Country",         f"{ports.flag_emoji(cc)} {ports.country_name(cc)}"
                                if cc else "—"),
            ("Reverse DNS",     obj.rdns),
            ("GeoNetMon rule",  obj.verdict or "—"),
        ]
        for i, (label, value) in enumerate(rows):
            key = Gtk.Label(label=label, xalign=0)
            key.add_css_class("dim-label")
            val = Gtk.Label(label=value or "—", xalign=0, selectable=True, wrap=True)
            grid.attach(key, 0, i, 1, 1)
            grid.attach(val, 1, i, 1, 1)

        raw_label = Gtk.Label(label="Raw ss line", xalign=0)
        raw_label.add_css_class("dim-label")
        box.append(raw_label)
        raw = Gtk.Label(label=obj.raw or "", xalign=0, selectable=True, wrap=True)
        raw.add_css_class("mono")
        box.append(raw)

        # --- process info expander ---
        if obj.pid:
            box.append(self._build_proc_expander(obj.pid))

        # --- buttons ---
        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btns.set_halign(Gtk.Align.END)
        btns.set_margin_top(8)
        btns.set_margin_bottom(8)
        btns.set_margin_start(16)
        btns.set_margin_end(16)
        outer.append(btns)

        copy_ip = Gtk.Button(label="Copy IP")
        copy_ip.connect("clicked", lambda *_: self._copy(obj.ip))
        btns.append(copy_ip)

        ipinfo = Gtk.Button(label="ipinfo.io ↗")
        ipinfo.connect("clicked", self._open_ipinfo)
        btns.append(ipinfo)

        # Deny app rule — always show for non-listening connections when we have
        # a window reference; allow the user to deny even if already "Allowed".
        if window is not None and obj.direction not in ("LISTEN", ""):
            if obj.verdict == "allow":
                deny_btn = Gtk.Button(label="Deny app")
                deny_btn.add_css_class("destructive-action")
                deny_btn.connect("clicked", self._on_deny_app)
                btns.append(deny_btn)
            else:
                allow_btn = Gtk.Button(label="Allow app forever")
                allow_btn.add_css_class("suggested-action")
                allow_btn.connect("clicked", self._on_allow_app)
                btns.append(allow_btn)

        # IP-level firewall block (public IPs only)
        self._block_btn = None
        if self.firewall is not None and self._blockable(obj.ip):
            self._block_btn = Gtk.Button()
            self._refresh_block_label()
            self._block_btn.add_css_class("destructive-action")
            self._block_btn.connect("clicked", self._on_block)
            btns.append(self._block_btn)

        if obj.pid:
            kill = Gtk.Button(label=f"Kill PID {obj.pid}")
            kill.add_css_class("destructive-action")
            kill.connect("clicked", self._kill)
            btns.append(kill)

        close = Gtk.Button(label="Close")
        close.connect("clicked", lambda *_: self.close())
        btns.append(close)

    # ------------------------------------------------------------------
    # Process info expander
    # ------------------------------------------------------------------
    def _build_proc_expander(self, pid):
        exp = Gtk.Expander(label=f"Process info  (PID {pid})")
        exp.set_margin_top(4)

        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_margin_top(6)
        inner.set_margin_start(8)
        exp.set_child(inner)

        # Static /proc info
        proc_grid = Gtk.Grid(column_spacing=12, row_spacing=4)
        inner.append(proc_grid)

        proc_rows = self._read_proc(pid)
        for i, (k, v) in enumerate(proc_rows):
            lbl = Gtk.Label(label=k, xalign=0)
            lbl.add_css_class("dim-label")
            val = Gtk.Label(label=v, xalign=0, selectable=True, wrap=True)
            val.add_css_class("mono")
            proc_grid.attach(lbl, 0, i, 1, 1)
            proc_grid.attach(val, 1, i, 1, 1)

        # lsof section
        lsof_hdr = Gtk.Label(label="Open files / sockets  (lsof)", xalign=0)
        lsof_hdr.add_css_class("dim-label")
        lsof_hdr.set_margin_top(6)
        inner.append(lsof_hdr)

        self._lsof_buf = Gtk.TextBuffer()
        self._lsof_buf.set_text("Running lsof…")
        tv = Gtk.TextView(buffer=self._lsof_buf, editable=False,
                          monospace=True, wrap_mode=Gtk.WrapMode.NONE)
        sw = Gtk.ScrolledWindow()
        sw.set_child(tv)
        sw.set_min_content_height(160)
        sw.set_max_content_height(280)
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        inner.append(sw)

        threading.Thread(target=self._run_lsof, args=(pid,), daemon=True).start()
        return exp

    @staticmethod
    def _read_proc(pid):
        rows = []
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            rows.append(("Exe", exe))
        except OSError:
            rows.append(("Exe", "—"))
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
            rows.append(("Command", cmd or "—"))
        except OSError:
            pass
        try:
            with open(f"/proc/{pid}/status") as f:
                status = {k: v.strip() for line in f
                          for k, _, v in [line.partition(":")]}
            rows.append(("State",  status.get("State", "—")))
            rows.append(("Threads", status.get("Threads", "—")))
            rows.append(("RSS",    status.get("VmRSS", "—")))
            rows.append(("User",   status.get("Uid", "—").split()[0]))
        except OSError:
            pass
        return rows

    def _run_lsof(self, pid):
        try:
            result = subprocess.run(
                ["lsof", "-p", str(pid), "-n", "-P"],
                capture_output=True, text=True, timeout=8,
            )
            out = result.stdout or result.stderr or "(no output)"
        except FileNotFoundError:
            out = "lsof not found — install lsof to enable this view"
        except subprocess.TimeoutExpired:
            out = "(lsof timed out)"
        except Exception as exc:  # noqa: BLE001
            out = f"(error: {exc})"
        GLib.idle_add(self._lsof_done, out)

    def _lsof_done(self, text):
        if self._lsof_buf:
            self._lsof_buf.set_text(text)
        return False

    # ------------------------------------------------------------------
    # Deny / Allow app rule helpers
    # ------------------------------------------------------------------
    def _on_deny_app(self, *_):
        self._apply_app_rule("deny")

    def _on_allow_app(self, *_):
        self._apply_app_rule("allow")

    def _apply_app_rule(self, action):
        win = self._window
        obj = self.obj
        exe = ""
        if obj.pid:
            try:
                exe = os.readlink(f"/proc/{obj.pid}/exe")
            except OSError:
                pass
        flow = {
            "process": obj.application,
            "process_path": exe,
            "dst_host": obj.rdns or obj.ip,
            "dst_ip": obj.ip,
            "dst_port": obj.port,
            "proto": obj.proto,
        }
        if win.using_daemon:
            win.daemon.add_rule(flow, action, "forever", "app_any")
        else:
            win.rules.build_from_choice(flow, action, "forever", "app_any")
        key = (obj.ip, obj.port, (obj.proto or "").lower())
        win._verdicts[key] = action
        obj.verdict = action
        self.close()

    # ------------------------------------------------------------------
    # IP-level firewall block
    # ------------------------------------------------------------------
    def _blockable(self, ip):
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (addr.is_loopback or addr.is_private or addr.is_unspecified
                    or addr.is_link_local)

    def _refresh_block_label(self):
        if not self._block_btn:
            return
        blocked = self.firewall.is_blocked(self.obj.ip)
        self._block_btn.set_label(
            f"Unblock {self.obj.ip}" if blocked else f"Block {self.obj.ip}")

    def _on_block(self, _btn):
        ip = self.obj.ip
        if self.firewall.is_blocked(ip):
            self._block_btn.set_sensitive(False)
            self.firewall.unblock(ip, on_done=self._block_done)
            return
        dialog = Gtk.AlertDialog()
        dialog.set_message(f"Block {ip} at the firewall?")
        dialog.set_detail(
            f"Adds DROP rules (in + out) for {ip} via "
            f"{self.firewall.resolve_backend() or 'no backend'}. "
            "You'll be prompted for authorisation."
        )
        dialog.set_buttons(["Cancel", "Block"])
        dialog.set_cancel_button(0)
        dialog.choose(self, None, self._block_confirm, ip)

    def _block_confirm(self, dialog, result, ip):
        try:
            idx = dialog.choose_finish(result)
        except GLib.Error:
            return
        if idx != 1:
            return
        self._block_btn.set_sensitive(False)
        self.firewall.block(ip, on_done=self._block_done)

    def _block_done(self, ok, msg):
        if self._block_btn:
            self._block_btn.set_sensitive(True)
            self._refresh_block_label()
        self._toast(("✓ " if ok else "✗ ") + msg)
        return False

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------
    def _copy(self, text):
        Gdk.Display.get_default().get_clipboard().set(text or "")

    def _open_ipinfo(self, *_):
        if not self.obj.ip:
            return
        Gtk.UriLauncher.new(f"https://ipinfo.io/{self.obj.ip}").launch(
            self, None, None, None)

    def _kill(self, *_):
        pid = self.obj.pid
        dialog = Gtk.AlertDialog()
        dialog.set_message(f"Terminate PID {pid}?")
        dialog.set_detail(
            f"Sends SIGTERM to {self.obj.application} (PID {pid}). "
            "You can only kill processes you own unless running as root."
        )
        dialog.set_buttons(["Cancel", "Terminate"])
        dialog.set_cancel_button(0)
        dialog.set_default_button(0)
        dialog.choose(self, None, self._kill_response, pid)

    def _kill_response(self, dialog, result, pid):
        try:
            idx = dialog.choose_finish(result)
        except GLib.Error:
            return
        if idx != 1:
            return
        try:
            os.kill(pid, signal.SIGTERM)
            self._toast(f"Sent SIGTERM to PID {pid}")
        except ProcessLookupError:
            self._toast("Process already gone")
        except PermissionError:
            self._toast("Permission denied")
        except OSError as exc:
            self._toast(f"Failed: {exc}")

    def _toast(self, text):
        info = Gtk.AlertDialog()
        info.set_message(text)
        info.set_buttons(["OK"])
        info.show(self)
