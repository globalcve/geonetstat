"""The allow/deny prompt shown when an app opens a new connection.

Shows who is connecting where, then lets you pick allow or deny, how long to
remember it (just once / while the app runs / until restart / forever) and what
the decision applies to (the whole app, this app+host, this app+port, or only
this exact connection). A plain-English line describes the resulting rule live,
and a countdown auto-applies the configured timeout action if you don't answer.
"""

from gi.repository import Gtk, GLib

from . import rules as rules_mod
from . import ports

# gtk4-layer-shell places the prompt at the Wayland OVERLAY layer so it appears
# above every other window without needing focus-steal tricks.
_LayerShell = None
try:
    import gi as _gi
    _gi.require_version("Gtk4LayerShell", "1.0")
    from gi.repository import Gtk4LayerShell as _LayerShell
except (ValueError, ImportError):
    pass


class PromptWindow(Gtk.Window):
    def __init__(self, parent, flow, config, on_choice):
        super().__init__(title="Connection Alert", transient_for=parent)
        self.set_modal(True)
        self.set_default_size(440, 0)
        self.flow = flow
        self.config = config
        self.on_choice = on_choice          # (action, scope, scope_by) or None
        self._answered = False

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        for m in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{m}")(18)
        self.set_child(box)

        proc = flow.get("process") or ""
        pid = flow.get("pid", 0)
        unknown = not proc and not pid
        proc_label = proc or ("Unknown process" if not pid else f"pid {pid}")
        dst = flow.get("dst_host") or flow.get("dst_ip") or "this host"
        head = Gtk.Label(xalign=0, wrap=True)
        head.add_css_class("prompt-dest")
        head.set_markup(
            f"<span size='large'><b>{GLib.markup_escape_text(proc_label)}</b> "
            f"wants to connect to <b>{GLib.markup_escape_text(dst)}</b></span>")
        box.append(head)

        cc = (flow.get("country") or "").upper()
        flag = (ports.flag_emoji(cc) + " ") if cc else ""
        org = flow.get("org") or ""
        dst_ip = flow.get("dst_ip") or ""
        dst_host = flow.get("dst_host") or ""
        ip_part = dst_ip if (unknown and dst_ip and dst_ip != dst_host) else ""
        meta = "  ·  ".join(
            p for p in (flow.get("proto", "").upper(),
                        f"{flag}{org}".strip(), ip_part,
                        f"port {flow.get('dst_port','?')}")
            if p)
        detail = Gtk.Label(xalign=0, wrap=True, selectable=True)
        detail.set_markup(f"<span alpha='90%'>{GLib.markup_escape_text(meta)}</span>")
        box.append(detail)

        path = Gtk.Label(xalign=0, wrap=True, selectable=True)
        path.add_css_class("prompt-path")
        proc_path = flow.get("process_path") or ""
        if unknown:
            pid_text = "Process could not be identified (kernel or very short-lived connection)"
        elif proc_path:
            pid_text = f"{proc_path}  (pid {pid})"
        elif pid:
            pid_text = f"pid {pid}"
        else:
            pid_text = ""
        path.set_markup(f"<span alpha='75%'>{GLib.markup_escape_text(pid_text)}</span>")
        box.append(path)

        self._app_name = proc or "this app"

        # "Remember this for…" — plain-English durations.
        box.append(self._sep())
        self._dur_keys = ["once", "60", "600", "3600", "process", "session", "forever"]
        dur_labels = ["Once", "For 1 minute", "For 10 minutes", "For 1 hour",
                      f"Until {self._app_name} quits", "Until restart", "Forever"]
        self.scope_combo = Gtk.DropDown.new_from_strings(dur_labels)
        cur_scope = config.get("enforce_default_scope", "forever")
        if cur_scope not in self._dur_keys:
            cur_scope = "forever"
        self.scope_combo.set_selected(self._dur_keys.index(cur_scope))
        self.scope_combo.connect("notify::selected", self._update_explain)
        box.append(self._row("Allow/Deny", self.scope_combo))

        # "Apply to…" — Little Snitch scopes. Default to any connection (app).
        self._by_keys = ["app_any", "app_host", "app_port", "exact"]
        by_labels = ["Any connection", "Connections to this host",
                     "Connections on this port", "Only this connection"]
        self.by_combo = Gtk.DropDown.new_from_strings(by_labels)
        cur_by = config.get("enforce_default_scope_by", "app_any")
        if cur_by not in self._by_keys:
            cur_by = "app_any"
        self.by_combo.set_selected(self._by_keys.index(cur_by))
        self.by_combo.connect("notify::selected", self._update_explain)
        box.append(self._row("Apply to", self.by_combo))

        # Live plain-English description of the rule the choice will create.
        self.explain = Gtk.Label(xalign=0, wrap=True)
        self.explain.add_css_class("prompt-explain")
        box.append(self.explain)
        self._update_explain()

        # buttons
        box.append(self._sep())
        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10,
                       homogeneous=True)
        deny = Gtk.Button(label="Deny")
        deny.add_css_class("prompt-deny")
        deny.connect("clicked", lambda *_: self._choose(rules_mod.DENY))
        allow = Gtk.Button(label="Allow")
        allow.add_css_class("prompt-allow")
        allow.connect("clicked", lambda *_: self._choose(rules_mod.ALLOW))
        btns.append(deny)
        btns.append(allow)
        box.append(btns)

        self.countdown = Gtk.Label(xalign=0)
        self.countdown.add_css_class("dim-label")
        box.append(self.countdown)

        self._remaining = max(15, int(config.get("enforce_prompt_timeout_s", 90)))
        self._tick_countdown()
        self._timer = GLib.timeout_add_seconds(1, self._tick_countdown)
        self.connect("close-request", self._on_close)

    # ---- helpers --------------------------------------------------------
    def _sep(self):
        return Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)

    def _row(self, label, widget):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        lbl = Gtk.Label(label=label, xalign=0, hexpand=True)
        widget.set_halign(Gtk.Align.END)
        row.append(lbl)
        row.append(widget)
        return row

    def _scope(self):
        return self._dur_keys[self.scope_combo.get_selected()]

    def _scope_by(self):
        return self._by_keys[self.by_combo.get_selected()]

    def _update_explain(self, *_):
        """Rewrite the plain-English summary whenever a choice changes."""
        app = self._app_name
        host = self.flow.get("dst_host") or self.flow.get("dst_ip") or "this host"
        port = self.flow.get("dst_port", "?")
        by = self._scope_by()
        target = {
            "app_any": f"any connection from {app}",
            "app_host": f"connections from {app} to {host}",
            "app_port": f"connections from {app} on port {port}",
        }.get(by, f"only {app} → {host}:{port}")
        when = {
            "once": "this time only",
            "60": "for 1 minute",
            "600": "for 10 minutes",
            "3600": "for 1 hour",
            "process": f"until {app} quits",
            "session": "until restart",
            "forever": "forever",
        }.get(self._scope(), "")
        self.explain.set_markup(
            "<span alpha='85%'>This rule covers <b>"
            f"{GLib.markup_escape_text(target)}</b>, "
            f"{GLib.markup_escape_text(when)}.</span>")

    def _tick_countdown(self):
        action = self.config.get("enforce_timeout_action", "deny")
        self.countdown.set_text(
            f"Auto-{action} in {self._remaining}s if no choice is made."
        )
        if self._remaining <= 0:
            self._choose(action, timed_out=True)
            return False
        self._remaining -= 1
        return True

    def _choose(self, action, timed_out=False):
        if self._answered:
            return
        self._answered = True
        if self._timer:
            GLib.source_remove(self._timer)
            self._timer = 0
        scope = self._scope()
        scope_by = self._scope_by()
        if self.on_choice:
            self.on_choice(action, scope, scope_by)
        self.close()

    def _on_close(self, *_):
        # closing the window without choosing = apply timeout action once
        if not self._answered:
            self._answered = True
            if self._timer:
                GLib.source_remove(self._timer)
            if self.on_choice:
                self.on_choice(self.config.get("enforce_timeout_action", "deny"),
                               "once", "exact")
        return False
