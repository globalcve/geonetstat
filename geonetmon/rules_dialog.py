"""Rules manager: view, enable/disable, reorder, and delete firewall rules.

Renders from a list of rule dicts (the daemon's wire format, which includes a
``summary`` field). In daemon mode it edits via the daemon socket and refreshes
when the daemon broadcasts updated rules; in in-process mode it edits a local
Rules object directly.
"""


import os

from gi.repository import Gtk, Gio

from .ui import escape_closes

_SCOPE_NOTE = {
    "forever": "",
    "session": " · until restart",
    "process": " · while app runs",
    "once": " · once",
}


class RulesWindow(Gtk.Window):
    def __init__(self, parent, rule_dicts, daemon=None, local_rules=None):
        super().__init__(title="Firewall rules", transient_for=parent)
        self.set_default_size(640, 520)
        escape_closes(self)
        self.daemon = daemon            # DaemonClient or None
        self.local_rules = local_rules  # Rules or None (in-process mode)
        self._rules = list(rule_dicts or [])

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        for m in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{m}")(14)
        self.set_child(box)

        info = Gtk.Label(xalign=0, wrap=True)
        info.add_css_class("dim-label")
        info.set_text(
            "Rules are evaluated top to bottom; the first match wins. "
            "Only 'Forever' rules persist across restarts."
        )
        box.append(info)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller.set_child(self.listbox)
        box.append(scroller)

        bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        add = Gtk.Button(label="Add rule…")
        add.add_css_class("suggested-action")
        add.connect("clicked", self._open_add_dialog)
        bottom.append(add)
        clear_session = Gtk.Button(label="Clear temporary rules")
        clear_session.set_tooltip_text(
            "Remove all non-permanent rules (once / while-running / until-restart)")
        clear_session.connect("clicked", self._clear_session)
        bottom.append(clear_session)
        bottom.append(Gtk.Box(hexpand=True))
        close = Gtk.Button(label="Close")
        close.connect("clicked", lambda *_: self.close())
        bottom.append(close)
        box.append(bottom)

        self._reload()

    # ---- external refresh (daemon pushed new rules) ---------------------
    def update(self, rule_dicts):
        self._rules = list(rule_dicts or [])
        self._reload()

    # ---- rendering ------------------------------------------------------
    def _reload(self):
        child = self.listbox.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.listbox.remove(child)
            child = nxt

        if not self._rules:
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label="No rules yet. Decisions you make on "
                                          "connection alerts appear here.",
                                    xalign=0, margin_top=10, margin_bottom=10,
                                    margin_start=8, wrap=True))
            self.listbox.append(row)
            return

        for d in self._rules:
            self.listbox.append(self._rule_row(d))

    def _rule_row(self, d):
        rid = d.get("id")
        action = (d.get("action") or "deny").lower()
        row = Gtk.ListBoxRow()
        line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        for m in ("top", "bottom", "start", "end"):
            getattr(line, f"set_margin_{m}")(6)

        sw = Gtk.Switch(active=bool(d.get("enabled", True)),
                        valign=Gtk.Align.CENTER)
        sw.connect("state-set", self._toggle, rid)
        line.append(sw)

        scope_note = _SCOPE_NOTE.get(d.get("scope"), "")
        summary = d.get("summary") or ""
        # the daemon's summary starts with the ACTION; show that as a coloured
        # chip. Colour via the theme's enc-ok/enc-bad classes (a hardcoded
        # pastel was invisible on the light themes).
        rest = summary.split("  ", 1)[-1] if "  " in summary else summary
        chip = Gtk.Label(label=action.upper(), xalign=0, valign=Gtk.Align.CENTER)
        chip.add_css_class("enc-ok" if action == "allow" else "enc-bad")
        line.append(chip)
        text = Gtk.Label(xalign=0, hexpand=True, wrap=True)
        text.set_markup(
            f"{_esc(rest)}"
            f"<span alpha='55%'>{_esc(scope_note)} · {d.get('hits', 0)} hits</span>"
        )
        line.append(text)

        up = Gtk.Button(icon_name="go-up-symbolic")
        up.connect("clicked", lambda *_: self._move(rid, -1))
        down = Gtk.Button(icon_name="go-down-symbolic")
        down.connect("clicked", lambda *_: self._move(rid, 1))
        delete = Gtk.Button(icon_name="user-trash-symbolic")
        delete.add_css_class("destructive-action")
        delete.connect("clicked", lambda *_: self._delete(rid))
        for b in (up, down, delete):
            b.set_valign(Gtk.Align.CENTER)
            line.append(b)

        row.set_child(line)
        return row

    # ---- mutations (daemon socket or local Rules) -----------------------
    def _toggle(self, _sw, state, rid):
        if self.daemon:
            self.daemon.rule_enable(rid, state)   # daemon re-broadcasts -> update()
        elif self.local_rules:
            self.local_rules.set_enabled(rid, state)
        return False

    def _move(self, rid, delta):
        if self.daemon:
            self.daemon.rule_move(rid, delta)
        elif self.local_rules:
            self.local_rules.move(rid, delta)
            self._reload_local()

    def _delete(self, rid):
        if self.daemon:
            self.daemon.rule_remove(rid)
        elif self.local_rules:
            self.local_rules.remove(rid)
            self._reload_local()

    def _clear_session(self, _btn):
        if self.daemon:
            # no bulk IPC op — remove each non-permanent rule individually
            for d in list(self._rules):
                if d.get("scope") != "forever":
                    self.daemon.rule_remove(d.get("id"))
        elif self.local_rules:
            self.local_rules.clear_session()
            self._reload_local()

    def _reload_local(self):
        self._rules = [r.to_dict() | {"summary": r.summary()}
                       for r in self.local_rules.rules]
        self._reload()

    # ---- add a rule by hand (pick a binary, allow/deny) -----------------
    def _open_add_dialog(self, _btn):
        dlg = Gtk.Window(title="Add firewall rule", transient_for=self,
                         modal=True)
        dlg.set_default_size(460, 0)
        escape_closes(dlg)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        for m in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{m}")(16)
        dlg.set_child(box)

        box.append(Gtk.Label(
            label="Create a rule for an application binary, like Little Snitch.",
            xalign=0, wrap=True))

        # binary path + Browse
        path_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        path_entry = Gtk.Entry(hexpand=True)
        path_entry.set_placeholder_text("/usr/bin/somebinary")
        browse = Gtk.Button(label="Browse…")
        browse.connect("clicked", lambda b, e=path_entry, w=dlg: self._browse_binary(b, e, w))
        path_row.append(path_entry)
        path_row.append(browse)
        box.append(self._field("Application binary", path_row))

        host_entry = Gtk.Entry()
        host_entry.set_placeholder_text("optional — leave blank for any destination")
        box.append(self._field("Host", host_entry))

        action_drop = Gtk.DropDown.new_from_strings(["Allow", "Block"])
        box.append(self._field("Action", action_drop))

        dur_labels = ["Forever", "Until restart", "Once"]
        dur_keys = ["forever", "session", "once"]
        dur_drop = Gtk.DropDown.new_from_strings(dur_labels)
        box.append(self._field("Duration", dur_drop))

        err = Gtk.Label(xalign=0, wrap=True)
        err.add_css_class("foreign")
        box.append(err)

        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10,
                       homogeneous=True)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: dlg.close())
        ok = Gtk.Button(label="Add rule")
        ok.add_css_class("suggested-action")

        def submit(*_):
            path = path_entry.get_text().strip()
            if not path:
                err.set_text("Enter or browse to an application binary.")
                return
            host = host_entry.get_text().strip()
            action = "allow" if action_drop.get_selected() == 0 else "deny"
            scope = dur_keys[dur_drop.get_selected()]
            scope_by = "app_host" if host else "app_any"
            flow = {"process": os.path.basename(path), "process_path": path,
                    "dst_host": host, "dst_ip": "", "dst_port": 0, "proto": ""}
            self._do_add(flow, action, scope, scope_by)
            dlg.close()

        ok.connect("clicked", submit)
        btns.append(cancel)
        btns.append(ok)
        box.append(btns)
        dlg.present()

    def _field(self, label, widget):
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        lbl = Gtk.Label(label=label, xalign=0)
        lbl.add_css_class("dim-label")
        col.append(lbl)
        col.append(widget)
        return col

    def _browse_binary(self, _btn, entry, parent_win=None):
        # FileChooserNative bypasses GTK's modal event-grab, which prevents
        # Gtk.FileDialog from receiving input when opened inside a modal window.
        chooser = Gtk.FileChooserNative.new(
            "Choose an application binary",
            parent_win or self,
            Gtk.FileChooserAction.OPEN,
            "_Open",
            "_Cancel",
        )

        def on_response(d, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                f = d.get_file()
                if f:
                    entry.set_text(f.get_path() or "")

        chooser.connect("response", on_response)
        chooser.show()

    def _do_add(self, flow, action, scope, scope_by):
        if self.daemon:
            self.daemon.add_rule(flow, action, scope, scope_by)
        elif self.local_rules:
            self.local_rules.build_from_choice(flow, action, scope, scope_by)
            self._reload_local()


def _esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
