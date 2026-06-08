"""Main application window: the live connection table and all controls."""

import csv
import time
from collections import deque

from gi.repository import Gtk, Gio, GLib, GObject, Pango

from . import collector
from . import firewall as fw_mod
from .models import ConnectionObject, human_rate
from .enrich import Enricher
from .alerts import AlertManager
from .history import History
from .detail_dialog import DetailWindow
from .settings_dialog import SettingsWindow
from .firewall_dialog import FirewallWindow
from .rules import Rules
from .procmap import ProcMap
from .netfilter import Engine
from .client import DaemonClient
from .rules_dialog import RulesWindow
from .prompt_dialog import PromptWindow
from .map_view import MapWindow
from .stats_dialog import StatsWindow
from .blocklist_dialog import BlocklistWindow
from . import blocklists as bl_mod
from . import ports

_CLOSING_STATES = {
    "TIME-WAIT", "CLOSE-WAIT", "FIN-WAIT-1", "FIN-WAIT-2",
    "LAST-ACK", "CLOSING", "CLOSED", "SYN-SENT", "SYN-RECV",
}


# --- per-column renderers: each returns (text, [css_classes]) -------------
def _r_ip(o):       return o.ip, ["mono"]
def _r_proto(o):    return o.proto.upper(), []
def _r_org(o):      return o.org, []
def _r_loc(o):      return o.location, (["foreign"] if o.is_foreign else [])
def _r_rdns(o):     return o.rdns, ["mono", "dim-label"]
def _r_app(o):      return o.application, ["bold"]
def _r_port(o):     return (str(o.port) if o.port else ""), ["mono"]
def _r_service(o):  return o.service, []
def _r_state(o):    return o.state, []
def _r_pid(o):      return (str(o.pid) if o.pid else ""), ["mono"]
def _r_up(o):       return human_rate(o.rate_up), ["mono", "dir-out"]
def _r_down(o):     return human_rate(o.rate_down), ["mono", "dir-in"]


def _r_risk(o):
    if o.risk < 0:
        return "", ["dim-label"]
    cls = ["enc-bad", "bold"] if o.is_risky else ["dim-label"]
    return str(o.risk), cls


def _r_dir(o):
    cls = {"INCOMING": ["dir-in"], "OUTGOING": ["dir-out"],
           "LISTEN": ["listen"]}.get(o.direction, [])
    return o.direction, cls


def _r_verdict(o):
    if o.verdict == "allow":
        return "Allowed", ["enc-ok", "bold"]
    if o.verdict == "deny":
        return "Blocked", ["enc-bad", "bold"]
    return "", ["dim-label"]


def _r_enc(o):
    if o.encryption == "Encrypted":
        return o.encryption, ["enc-ok"]
    if o.encryption.startswith("Plain"):
        return o.encryption, ["enc-bad"]
    return o.encryption, ["dim-label"]


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app, config):
        super().__init__(application=app, title="GeoNetMon")
        self.config = config
        self.set_default_size(1280, 760)

        self.objs = {}                 # key -> ConnectionObject
        self._past_objs = {}           # key -> ConnectionObject (closed connections)
        self.search_text = ""
        self.paused = bool(config["paused_on_start"])
        self._timer_id = 0
        self._initial_load_done = False
        self.privacy_mode = False      # shoulder-surfer blur
        self._quick_filter = None      # None = all; "out"/"in"/"foreign"/"enc"/"plain"/"risk"
        self._columns = {}             # title -> Gtk.ColumnViewColumn (main view only)

        self.enricher = Enricher(config, self.on_enrich)
        self.alerts = AlertManager(app, config, on_alert=self.on_alert)
        self.firewall = fw_mod.Firewall(config)
        self.history = History(config)
        self.rules = Rules(config)
        self.procmap = ProcMap()
        self.blocklists = bl_mod.Blocklists(config, self.rules)

        # Prefer the privileged daemon; fall back to an in-process engine.
        self.daemon = DaemonClient(
            on_prompt=self._on_daemon_prompt,
            on_event=self._on_daemon_event,
            on_status=self._on_daemon_status,
            on_rules=self._on_daemon_rules,
            on_disconnect=self._on_daemon_disconnect,
        )
        self.daemon_status = {}
        self._daemon_rules = []          # latest rules pushed by the daemon
        self._rules_win = None           # open RulesWindow, if any
        self._verdicts = {}              # (ip, port, proto) -> "allow"/"deny"
        self._geo_points = {}            # ip -> {lon,lat,kind,label,ts} for the map
        self._prompt_queue = []          # (flow, on_choice) awaiting display
        self._prompt_active = False      # a prompt window is currently open
        self._prompt_win = None          # the live PromptWindow instance
        self.using_daemon = self.daemon.connect()
        if not self.using_daemon:
            self.engine = Engine(
                config, self.rules, self.procmap,
                on_prompt=self._on_prompt,
                # engine emits (flow, action, auto, rule_summary); the handler
                # only needs the first three.
                on_event=lambda flow, action, auto, _summary:
                    self._on_enforce_decision(flow, action, auto))
        else:
            self.engine = None
        self._spark = deque(maxlen=120)   # recent total-connection counts
        self._spark_area = None

        self._build_headerbar()
        self._build_body()
        self._install_actions()

        self.connect("close-request", self._on_close)
        self.start_timer()
        GLib.timeout_add_seconds(6, self._prime_alerts)
        if (not self.using_daemon and self.config.get("enforce_enabled")
                and self.engine and self.engine.available()):
            ok, msg = self.engine.start()
            self._sync_shield()
            if not ok:
                self.config["enforce_enabled"] = False

    # ===================================================================
    # UI construction
    # ===================================================================
    def _build_headerbar(self):
        hb = Gtk.HeaderBar()
        self.set_titlebar(hb)

        # "Traffic light" window controls (coloured circles, styled in style.css).
        # Hide GTK's native min/max/close and draw our own on the RIGHT. Order
        # min, max, close so close sits at the far-right corner.
        hb.set_show_title_buttons(False)
        tl = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        tl.add_css_class("traffic-lights")
        tl.set_valign(Gtk.Align.CENTER)
        for cls, tip, cb in (
            ("tl-min", "Minimize", lambda *_: self.minimize()),
            ("tl-max", "Maximize", lambda *_: (self.unmaximize() if self.is_maximized() else self.maximize())),
            ("tl-close", "Close", lambda *_: self.close()),
        ):
            b = Gtk.Button()
            b.add_css_class("tl")
            b.add_css_class(cls)
            b.set_tooltip_text(tip)
            b.set_valign(Gtk.Align.CENTER)
            b.connect("clicked", cb)
            tl.append(b)
        hb.pack_end(tl)

        self.btn_pause = Gtk.ToggleButton()
        self.btn_pause.set_icon_name("media-playback-pause-symbolic")
        self.btn_pause.set_tooltip_text("Pause / resume live updates")
        self.btn_pause.set_active(self.paused)
        self.btn_pause.connect("toggled", self._on_pause_toggled)
        hb.pack_start(self.btn_pause)

        self.btn_shield = Gtk.ToggleButton()
        self.btn_shield.set_icon_name("security-medium-symbolic")
        self.btn_shield.connect("toggled", self._on_shield_toggled)
        hb.pack_start(self.btn_shield)
        self._sync_shield()

        btn_refresh = Gtk.Button(icon_name="view-refresh-symbolic")
        btn_refresh.set_tooltip_text("Refresh now")
        btn_refresh.connect("clicked", lambda *_: self.tick())
        hb.pack_start(btn_refresh)

        self.btn_privacy = Gtk.ToggleButton()
        self.btn_privacy.set_icon_name("view-conceal-symbolic")
        self.btn_privacy.set_tooltip_text("Privacy mode — blur IP addresses")
        self.btn_privacy.connect("toggled", self._on_privacy_toggled)
        hb.pack_start(self.btn_privacy)

        btn_cols = Gtk.Button(icon_name="view-column-symbolic")
        btn_cols.set_tooltip_text("Show / hide columns")
        btn_cols.connect("clicked", self._show_cols_popover)
        hb.pack_end(btn_cols)

        self.title_label = Gtk.Label(label="GeoNetMon")
        self.title_label.add_css_class("title")
        hb.set_title_widget(self.title_label)

        # primary menu
        menu = Gio.Menu()
        menu.append("Preferences", "win.preferences")
        menu.append("Connection map…", "win.map")
        menu.append("Statistics…", "win.stats")
        menu.append("Firewall rules…", "win.rules")
        menu.append("Blocklist subscriptions…", "win.blocklists")
        menu.append("Blocked IPs (firewall)…", "win.firewall")
        menu.append("Export visible to CSV…", "win.export")
        menu.append("Export rules…", "win.exportrules")
        menu.append("Import rules…", "win.importrules")
        menu.append("Clear alert log", "win.clearalerts")
        menu.append("About GeoNetMon", "win.about")
        menu.append("Quit", "app.quit")
        btn_menu = Gtk.MenuButton(icon_name="open-menu-symbolic")
        btn_menu.set_menu_model(menu)
        hb.pack_end(btn_menu)

        self.btn_alerts = Gtk.MenuButton(icon_name="dialog-warning-symbolic")
        self.btn_alerts.set_tooltip_text("Alert log")
        self.alerts_popover = Gtk.Popover()
        self.alerts_popover.set_size_request(380, 360)
        self.btn_alerts.set_popover(self.alerts_popover)
        self.btn_alerts.connect("notify::active", self._on_alerts_open)
        hb.pack_end(self.btn_alerts)

        self.btn_search = Gtk.ToggleButton(icon_name="system-search-symbolic")
        self.btn_search.set_tooltip_text("Search / filter rows")
        hb.pack_end(self.btn_search)

    def _build_body(self):
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_child(root)

        # Process-name banner — shown only when the root daemon ISN'T publishing
        # names (you never launch the GUI as root). tick() hides it the moment
        # the daemon appears.
        self._privbar = None
        if not collector.is_root():
            self._privbar = self._privilege_bar()
            root.append(self._privbar)
            self._privbar.set_visible(not collector.daemon_procs_available())

        # search bar
        self.search_bar = Gtk.SearchBar()
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text(
            "Filter by IP, org, country, host, app, service…"
        )
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", self._on_search)
        self.search_bar.set_child(self.search_entry)
        self.search_bar.connect_entry(self.search_entry)
        self.search_bar.set_key_capture_widget(self)
        self.btn_search.bind_property(
            "active", self.search_bar, "search-mode-enabled",
            GObject.BindingFlags.BIDIRECTIONAL,
        )
        root.append(self.search_bar)
        root.append(self._build_filter_bar())

        # column view
        self.store = Gio.ListStore.new(ConnectionObject)
        self.cfilter = Gtk.CustomFilter.new(lambda it, *_: self._filter(it))
        self.filter_model = Gtk.FilterListModel(model=self.store, filter=self.cfilter)
        self.sort_model = Gtk.SortListModel(model=self.filter_model)
        self.selection = Gtk.SingleSelection(model=self.sort_model)
        self.selection.set_autoselect(False)
        self.selection.set_can_unselect(True)

        self.column_view = Gtk.ColumnView(model=self.selection)
        self.column_view.set_show_column_separators(True)
        self.column_view.set_show_row_separators(True)
        self.column_view.set_reorderable(True)
        self.column_view.connect("activate", self._on_row_activate)

        self._add_columns()
        self.sort_model.set_sorter(self.column_view.get_sorter())

        key_ctrl = Gtk.EventControllerKey()
        key_ctrl.connect("key-pressed", self._on_key_pressed)
        self.column_view.add_controller(key_ctrl)

        scroller = Gtk.ScrolledWindow()
        scroller.set_child(self.column_view)
        scroller.set_vexpand(True)
        scroller.set_hexpand(True)

        self._vpaned = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        self._vpaned.set_vexpand(True)
        self._vpaned.set_hexpand(True)
        self._vpaned.set_start_child(scroller)
        self._vpaned.set_resize_start_child(True)
        self._vpaned.set_shrink_start_child(False)
        self._vpaned.set_end_child(self._build_past_section())
        self._vpaned.set_resize_end_child(True)
        self._vpaned.set_shrink_end_child(True)
        root.append(self._vpaned)

        root.append(self._status_bar())

    def _privilege_bar(self):
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        bar.add_css_class("privbar")
        bar.set_margin_top(4)
        bar.set_margin_bottom(4)
        bar.set_margin_start(8)
        bar.set_margin_end(8)
        lbl = Gtk.Label(
            label="Some process names hidden — start the GeoNetMon daemon "
                  "(geonetmond) to see every process. No need to run as root.",
            xalign=0, hexpand=True, wrap=True,
        )
        bar.append(lbl)
        return bar

    def _status_bar(self):
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        bar.add_css_class("statusbar")
        self.lbl_counts = Gtk.Label(xalign=0, hexpand=True)
        bar.append(self.lbl_counts)
        if self.config.get("show_sparkline", True):
            self._spark_area = Gtk.DrawingArea()
            self._spark_area.set_content_width(120)
            self._spark_area.set_content_height(20)
            self._spark_area.set_valign(Gtk.Align.CENTER)
            self._spark_area.set_tooltip_text("Tracked connections over time")
            self._spark_area.set_draw_func(self._draw_spark)
            bar.append(self._spark_area)
        self.lbl_throughput = Gtk.Label(xalign=1)
        self.lbl_throughput.add_css_class("mono")
        bar.append(self.lbl_throughput)
        self.lbl_updated = Gtk.Label(xalign=1)
        bar.append(self.lbl_updated)
        return bar

    def _draw_spark(self, _area, ctx, width, height, *_):
        data = list(self._spark)
        if len(data) < 2:
            return
        hi = max(data) or 1
        n = len(data)
        step = width / max(1, n - 1)
        ctx.set_line_width(1.5)
        ctx.set_source_rgba(0.36, 0.65, 0.86, 0.9)   # accent blue
        for i, v in enumerate(data):
            x = i * step
            y = height - (v / hi) * (height - 2) - 1
            if i == 0:
                ctx.move_to(x, y)
            else:
                ctx.line_to(x, y)
        ctx.stroke()

    def _add_columns(self, cv=None):
        target = cv if cv is not None else self.column_view
        cols = [
            ("IP Address", _r_ip, lambda o: o.ip, False, 150),
            ("Proto", _r_proto, lambda o: o.proto, False, 64),
            ("Organization", _r_org, lambda o: o.org.lower(), True, 200),
            ("Location", _r_loc, lambda o: o.location.lower(), False, 170),
            ("Reverse DNS", _r_rdns, lambda o: o.rdns.lower(), True, 200),
            ("Direction", _r_dir, lambda o: o.direction, False, 100),
            ("GeoNetMon", _r_verdict, lambda o: o.verdict, False, 100),
            ("Application", _r_app, lambda o: o.application.lower(), False, 150),
            ("Port", _r_port, lambda o: o.port, False, 70),
            ("Service", _r_service, lambda o: o.service, False, 130),
            ("Encryption", _r_enc, lambda o: o.encryption, False, 110),
            ("State", _r_state, lambda o: o.state, False, 110),
        ]
        if self.config.get("show_rate_columns", True):
            cols.append(("↑/s", _r_up, lambda o: o.rate_up, False, 90))
            cols.append(("↓/s", _r_down, lambda o: o.rate_down, False, 90))
        if self.config.get("show_risk_column", False):
            cols.append(("Risk", _r_risk, lambda o: o.risk, False, 70))
        if self.config["show_pid_column"]:
            cols.append(("PID", _r_pid, lambda o: o.pid, False, 80))

        for title, render, sort_key, expand, width in cols:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._cell_setup)
            factory.connect("bind", self._cell_bind, render)
            factory.connect("unbind", self._cell_unbind)
            col = Gtk.ColumnViewColumn(title=title, factory=factory)
            col.set_resizable(True)
            col.set_expand(expand)
            if width:
                col.set_fixed_width(width)
            col.set_sorter(Gtk.CustomSorter.new(self._make_sorter(sort_key)))
            target.append_column(col)
            if cv is None:
                self._columns[title] = col

    def _build_past_section(self):
        """Collapsible panel showing connections that closed this session."""
        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        section.append(Gtk.Separator())

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        header.set_margin_start(8)
        header.set_margin_end(8)
        header.set_margin_top(3)
        header.set_margin_bottom(3)

        self._past_toggle = Gtk.ToggleButton()
        self._past_toggle.set_icon_name("pan-end-symbolic")
        self._past_toggle.set_has_frame(False)
        self._past_toggle.set_tooltip_text("Show / hide past connections")
        self._past_toggle.connect("toggled", self._on_past_toggled)
        header.append(self._past_toggle)

        self._past_label = Gtk.Label(label="Past connections (0)", xalign=0,
                                     hexpand=True)
        self._past_label.add_css_class("dim-label")
        header.append(self._past_label)

        clear_btn = Gtk.Button(label="Clear")
        clear_btn.set_has_frame(False)
        clear_btn.set_tooltip_text("Clear past connection list")
        clear_btn.connect("clicked", self._clear_past)
        header.append(clear_btn)

        section.append(header)

        self._past_revealer = Gtk.Revealer()
        self._past_revealer.set_transition_type(
            Gtk.RevealerTransitionType.SLIDE_DOWN)
        self._past_revealer.set_reveal_child(False)

        self._past_store = Gio.ListStore.new(ConnectionObject)
        past_sel = Gtk.SingleSelection(model=self._past_store)
        past_sel.set_autoselect(False)
        past_sel.set_can_unselect(True)

        self._past_cv = Gtk.ColumnView(model=past_sel)
        self._past_cv.set_show_column_separators(True)
        self._past_cv.set_show_row_separators(True)
        self._past_cv.connect("activate", self._on_past_row_activate)
        self._add_columns(self._past_cv)

        past_scroller = Gtk.ScrolledWindow()
        past_scroller.set_child(self._past_cv)
        past_scroller.set_vexpand(True)
        self._past_revealer.set_child(past_scroller)
        section.append(self._past_revealer)
        return section

    def _on_past_toggled(self, btn):
        reveal = btn.get_active()
        self._past_revealer.set_reveal_child(reveal)
        btn.set_icon_name("pan-down-symbolic" if reveal else "pan-end-symbolic")

    _MAX_PAST = 200

    def _add_to_past(self, obj):
        key = obj.key
        if key in self._past_objs:
            return
        if len(self._past_objs) >= self._MAX_PAST:
            oldest_key = next(iter(self._past_objs))
            oldest = self._past_objs.pop(oldest_key)
            found, pos = self._past_store.find(oldest)
            if found:
                self._past_store.remove(pos)
        obj.set_property("is_new", False)
        self._past_objs[key] = obj
        self._past_store.insert(0, obj)
        self._past_label.set_text(f"Past connections ({len(self._past_objs)})")

    def _clear_past(self, *_):
        self._past_objs.clear()
        self._past_store.remove_all()
        self._past_label.set_text("Past connections (0)")

    def _on_past_row_activate(self, cv, position):
        obj = cv.get_model().get_item(position)
        if obj is not None:
            DetailWindow(self, obj, self.firewall, window=self).present()

    # ===================================================================
    # Quick filter bar
    # ===================================================================
    def _build_filter_bar(self):
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        bar.set_margin_start(8)
        bar.set_margin_end(8)
        bar.set_margin_top(3)
        bar.set_margin_bottom(3)

        self._qf_buttons = {}
        for label, kind in [
            ("All", None), ("Outgoing", "out"), ("Incoming", "in"),
            ("Foreign", "foreign"), ("Encrypted", "enc"), ("Plain", "plain"),
        ]:
            b = Gtk.ToggleButton(label=label)
            b.set_active(kind is None)
            b.add_css_class("pill")
            b.connect("toggled", self._on_quick_filter, kind)
            bar.append(b)
            self._qf_buttons[kind] = b
        return bar

    def _on_quick_filter(self, btn, kind):
        if not btn.get_active():
            return
        for k, b in self._qf_buttons.items():
            if b is not btn:
                b.handler_block_by_func(self._on_quick_filter)
                b.set_active(False)
                b.handler_unblock_by_func(self._on_quick_filter)
        self._quick_filter = kind
        self.refilter()

    # ===================================================================
    # Privacy mode
    # ===================================================================
    def _on_privacy_toggled(self, btn):
        self.privacy_mode = btn.get_active()
        btn.set_icon_name(
            "view-reveal-symbolic" if self.privacy_mode else "view-conceal-symbolic")
        if self.privacy_mode:
            btn.add_css_class("enforcing")
        else:
            btn.remove_css_class("enforcing")
        for obj in list(self.objs.values()) + list(self._past_objs.values()):
            obj.notify("ip")

    # ===================================================================
    # Column visibility popover
    # ===================================================================
    def _show_cols_popover(self, btn):
        popover = Gtk.Popover()
        popover.set_parent(btn)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(10)
        box.set_margin_end(10)
        hdr = Gtk.Label(label="Visible columns", xalign=0)
        hdr.add_css_class("heading")
        box.append(hdr)
        box.append(Gtk.Separator())
        for title, col in self._columns.items():
            cb = Gtk.CheckButton(label=title, active=col.get_visible())
            cb.connect("toggled", lambda b, c=col: c.set_visible(b.get_active()))
            box.append(cb)
        popover.set_child(box)
        popover.popup()

    # ===================================================================
    # Keyboard shortcuts
    # ===================================================================
    def _on_key_pressed(self, _ctrl, keyval, _keycode, state):
        from gi.repository import Gdk
        if keyval == Gdk.KEY_c and (state & Gdk.ModifierType.CONTROL_MASK):
            pos = self.selection.get_selected()
            obj = self.selection.get_item(pos)
            if obj:
                text = (f"{obj.application} → {obj.ip}:{obj.port} "
                        f"({obj.org}, {obj.location}) [{obj.verdict or '—'}]")
                self.get_clipboard().set(text)
            return True
        return False

    # ===================================================================
    # Filter to single app
    # ===================================================================
    def _filter_to_app(self, app):
        self.search_entry.set_text(app)
        self.search_text = app.lower()
        self.btn_search.set_active(True)
        self.cfilter.changed(Gtk.FilterChange.DIFFERENT)
        self.update_status()

    # ===================================================================
    # Whois popup
    # ===================================================================
    def _show_whois(self, ip):
        import subprocess, threading
        win = Gtk.Window(title=f"Whois  {ip}", transient_for=self)
        win.set_default_size(580, 500)
        buf = Gtk.TextBuffer()
        buf.set_text("Running whois…")
        tv = Gtk.TextView(buffer=buf, editable=False,
                          monospace=True, wrap_mode=Gtk.WrapMode.WORD)
        sw = Gtk.ScrolledWindow()
        sw.set_child(tv)
        win.set_child(sw)
        win.present()

        def run():
            try:
                r = subprocess.run(
                    ["whois", ip], capture_output=True, text=True, timeout=12)
                out = r.stdout or r.stderr or "(no output)"
            except FileNotFoundError:
                out = "whois not found — sudo apt install whois"
            except subprocess.TimeoutExpired:
                out = "(timed out after 12 s)"
            GLib.idle_add(buf.set_text, out)

        threading.Thread(target=run, daemon=True).start()

    # ===================================================================
    # Cell factory plumbing
    # ===================================================================
    def _cell_setup(self, _factory, list_item):
        label = Gtk.Label(xalign=0)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        label.set_margin_start(8)
        label.set_margin_end(8)
        gesture = Gtk.GestureClick()
        gesture.set_button(3)
        gesture.connect("pressed", self._on_cell_right_click, list_item)
        label.add_controller(gesture)
        list_item.set_child(label)

    # Renders whose output should be blurred in privacy mode
    _PRIVATE_RENDERS = None  # set after class body; references _r_ip, _r_rdns

    def _cell_bind(self, _factory, list_item, render):
        label = list_item.get_child()
        obj = list_item.get_item()

        if self._PRIVATE_RENDERS is None:
            MainWindow._PRIVATE_RENDERS = {_r_ip, _r_rdns}

        def update(*_):
            text, classes = render(obj)
            private = self.privacy_mode and render in self._PRIVATE_RENDERS
            if private:
                classes = list(classes) + ["privacy-blur"]
            label.set_text(text or "")
            if obj.is_new:
                classes = list(classes) + ["newconn"]
            label.set_css_classes(classes)
            tip = f"{obj.org}  ·  {obj.location}  ·  {obj.verdict or '—'}"
            label.set_tooltip_text(tip)

        list_item._handler = obj.connect("notify", update)
        list_item._obj = obj
        update()

    def _cell_unbind(self, _factory, list_item):
        obj = getattr(list_item, "_obj", None)
        handler = getattr(list_item, "_handler", None)
        if obj is not None and handler is not None:
            obj.disconnect(handler)
        list_item._handler = None
        list_item._obj = None

    @staticmethod
    def _make_sorter(key):
        def cmp(a, b, *_):
            ka, kb = key(a), key(b)
            return (ka > kb) - (ka < kb)
        return cmp

    # ===================================================================
    # Filtering / search
    # ===================================================================
    def _filter(self, obj):
        c = self.config
        if obj.proto == "tcp" and not c["show_tcp"]:
            return False
        if obj.proto == "udp" and not c["show_udp"]:
            return False
        if obj.direction == "LISTEN" and not c["show_listen"]:
            return False
        if not c["show_timewait"] and obj.state.upper() in _CLOSING_STATES:
            return False
        if c["hide_loopback"]:
            ip = obj.geo_ip or obj.local_ip
            if ip.startswith("127.") or ip == "::1":
                return False
        if self.search_text and self.search_text not in obj.search_blob():
            return False
        qf = self._quick_filter
        if qf == "out" and obj.direction != "OUTGOING":
            return False
        if qf == "in" and obj.direction != "INCOMING":
            return False
        if qf == "foreign" and not obj.is_foreign:
            return False
        if qf == "enc" and obj.encryption != "Encrypted":
            return False
        if qf == "plain" and not obj.encryption.startswith("Plain"):
            return False
        return True

    def _on_search(self, entry):
        self.search_text = entry.get_text().strip().lower()
        self.cfilter.changed(Gtk.FilterChange.DIFFERENT)
        self.update_status()

    def refilter(self):
        self.cfilter.changed(Gtk.FilterChange.DIFFERENT)
        self.update_status()

    # ===================================================================
    # Live polling
    # ===================================================================
    def start_timer(self):
        if self._timer_id:
            GLib.source_remove(self._timer_id)
        interval = max(250, int(self.config["refresh_ms"]))
        self._timer_id = GLib.timeout_add(interval, self._on_timer)

    def _on_timer(self):
        if not self.paused:
            self.tick()
        return True

    def tick(self):
        try:
            conns = collector.collect()
        except RuntimeError as exc:
            self.lbl_counts.set_text(f"Error: {exc}")
            return
        # Fill in process names the unprivileged GUI couldn't see, from the root
        # daemon's published map. No-op if the daemon isn't running.
        daemon_procs = collector.enrich_from_daemon(conns)
        if getattr(self, "_privbar", None) is not None:
            self._privbar.set_visible(not daemon_procs)
        seen = set()
        for c in conns:
            seen.add(c.key)
            obj = self.objs.get(c.key)
            if obj is None:
                obj = ConnectionObject(c)
                self.objs[c.key] = obj
                self.store.append(obj)
                self.alerts.on_appear(obj)
                self.history.log_event("appear", obj)
                if obj.geo_ip and not obj.enriched:
                    self.enricher.request(obj.geo_ip)
                if self._initial_load_done:
                    self._flash_new(obj)
            else:
                obj.apply(c)
            v = self._verdicts.get((obj.ip, obj.port, (obj.proto or "").lower()))
            if v and obj.verdict != v:
                obj.verdict = v

        self._initial_load_done = True

        for key in list(self.objs):
            if key not in seen:
                gone = self.objs.pop(key)
                self.history.log_event("vanish", gone)
                found, pos = self.store.find(gone)
                if found:
                    self.store.remove(pos)
                self._add_to_past(gone)

        cap = self.config["max_rows"]
        if cap > 0 and len(self.objs) > cap:
            extra = sorted(self.objs.values(), key=lambda o: o.last_seen)
            for gone in extra[:len(self.objs) - cap]:
                self.objs.pop(gone.key, None)
                found, pos = self.store.find(gone)
                if found:
                    self.store.remove(pos)

        self._sample_and_spark()
        self.update_status()

    def _sample_and_spark(self):
        total = len(self.objs)
        estab = sum(1 for o in self.objs.values() if o.state.upper() == "ESTAB")
        foreign = sum(1 for o in self.objs.values() if o.is_foreign)
        up = sum(o.rate_up for o in self.objs.values())
        down = sum(o.rate_down for o in self.objs.values())
        self.history.log_sample(total, estab, foreign, up, down)
        self._spark.append(total)
        if self._spark_area is not None:
            self._spark_area.queue_draw()

    def _flash_new(self, obj):
        secs = self.config["highlight_seconds"]
        if secs <= 0:
            return
        obj.set_property("is_new", True)
        GLib.timeout_add_seconds(secs, self._unflash, obj)

    @staticmethod
    def _unflash(obj):
        obj.set_property("is_new", False)
        return False

    def on_enrich(self, ip, data):
        home = self.config["home_country"]
        matched = None
        for obj in self.objs.values():
            if obj.geo_ip == ip:
                obj.apply_enrichment(data, home)
                self.alerts.on_enriched(obj)
                matched = obj
        # Remember geolocated endpoints so the map accumulates everywhere we've
        # connected this session, not just the handful live at this instant.
        if matched is not None and matched.has_geo:
            self._geo_points[ip] = {
                "lon": matched.lng, "lat": matched.lat,
                "kind": self._point_kind(matched),
                "label": matched.location, "ts": time.time(),
                "ip": ip, "org": matched.org, "app": matched.application,
                "service": matched.service, "port": matched.port,
                "direction": matched.direction, "verdict": matched.verdict or ""}
            if len(self._geo_points) > 800:
                for k in sorted(self._geo_points,
                                key=lambda k: self._geo_points[k]["ts"])[:200]:
                    del self._geo_points[k]
        return False

    @staticmethod
    def _point_kind(o):
        if o.is_risky:
            return "risk"
        if o.is_foreign:
            return "foreign"
        return "in" if o.direction == "INCOMING" else "out"

    def _prime_alerts(self):
        self.alerts.prime_done()
        return False

    # ===================================================================
    # Status / alerts UI
    # ===================================================================
    def update_status(self):
        total = len(self.objs)
        estab = sum(1 for o in self.objs.values() if o.state.upper() == "ESTAB")
        listen = sum(1 for o in self.objs.values() if o.direction == "LISTEN")
        foreign = sum(1 for o in self.objs.values() if o.is_foreign)
        visible = self.selection.get_n_items()
        self.lbl_counts.set_text(
            f"{total} tracked   ·   {visible} shown   ·   {estab} established"
            f"   ·   {listen} listening   ·   {foreign} foreign"
        )
        state = "paused" if self.paused else "live"
        up = sum(o.rate_up for o in self.objs.values())
        down = sum(o.rate_down for o in self.objs.values())
        self.lbl_throughput.set_text(
            f"↑ {human_rate(up) or '0'}   ↓ {human_rate(down) or '0'}"
        )
        self.lbl_updated.set_text(
            f"{state} · updated {time.strftime('%H:%M:%S')}"
        )
        self.title_label.set_text(
            f"GeoNetMon — {estab} active" + ("  ⏸" if self.paused else "")
        )

    def on_alert(self, _alert):
        self.btn_alerts.add_css_class("has-alerts")

    def _on_alerts_open(self, btn, _param):
        if not btn.get_active():
            return
        self.btn_alerts.remove_css_class("has-alerts")
        self._fill_alerts_popover()

    def _fill_alerts_popover(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        outer.set_margin_top(8)
        outer.set_margin_bottom(8)
        outer.set_margin_start(8)
        outer.set_margin_end(8)

        topbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title = Gtk.Label(label="Alert log", xalign=0, hexpand=True)
        title.add_css_class("heading")
        topbar.append(title)
        clear = Gtk.Button(label="Clear")
        clear.connect("clicked", self._clear_alerts_from_popover)
        topbar.append(clear)
        outer.append(topbar)
        outer.append(Gtk.Separator())

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        scroller.set_child(box)
        outer.append(scroller)

        if not self.alerts.log:
            box.append(Gtk.Label(label="No alerts yet.", xalign=0))
        for alert in self.alerts.log[:100]:
            row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            head = Gtk.Label(
                label=f"{time.strftime('%H:%M:%S', time.localtime(alert.ts))}  "
                      f"{alert.title}",
                xalign=0,
            )
            head.add_css_class("bold")
            if alert.level == "warn":
                head.add_css_class("foreign")
            body = Gtk.Label(label=alert.body, xalign=0, wrap=True)
            body.add_css_class("dim-label")
            row.append(head)
            row.append(body)
            # actionable alerts (a known app/connection) get allow/deny buttons
            if getattr(alert, "flow", None) and alert.flow.get("process"):
                acts = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                acts.set_margin_top(2)
                allow = Gtk.Button(label="Allow app")
                allow.add_css_class("prompt-allow")
                allow.connect("clicked", self._alert_decide, alert.flow, "allow")
                deny = Gtk.Button(label="Block app")
                deny.add_css_class("prompt-deny")
                deny.connect("clicked", self._alert_decide, alert.flow, "deny")
                acts.append(allow)
                acts.append(deny)
                row.append(acts)
            box.append(row)
            box.append(Gtk.Separator())
        self.alerts_popover.set_child(outer)

    def _clear_alerts_from_popover(self, _btn):
        self.alerts.clear()
        self.btn_alerts.remove_css_class("has-alerts")
        self._fill_alerts_popover()

    def _alert_decide(self, _btn, flow, action):
        """Allow/deny a whole app straight from the alert log (Forever)."""
        if self.using_daemon:
            self.daemon.add_rule(flow, action, "forever", "app_any")
        else:
            self.rules.build_from_choice(flow, action, "forever", "app_any")
        self.alerts_popover.popdown()

    # ===================================================================
    # Actions
    # ===================================================================
    def _install_actions(self):
        for name, cb in [
            ("preferences", self._act_preferences),
            ("map", self._act_map),
            ("stats", self._act_stats),
            ("rules", self._act_rules),
            ("blocklists", self._act_blocklists),
            ("firewall", self._act_firewall),
            ("export", self._act_export),
            ("exportrules", self._act_export_rules),
            ("importrules", self._act_import_rules),
            ("clearalerts", self._act_clear_alerts),
            ("about", self._act_about),
        ]:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", cb)
            self.add_action(action)

    def _act_preferences(self, *_):
        win = SettingsWindow(self, self.config, self._on_settings_changed)
        win.present()

    def _act_firewall(self, *_):
        FirewallWindow(self, self.firewall).present()

    def _act_rules(self, *_):
        if self.using_daemon:
            self.daemon.get_rules()        # refresh; reply arrives via _on_daemon_rules
            win = RulesWindow(self, self._daemon_rules, daemon=self.daemon)
        else:
            win = RulesWindow(
                self,
                [r.to_dict() | {"summary": r.summary()} for r in self.rules.rules],
                local_rules=self.rules)
        self._rules_win = win
        win.connect("close-request", self._on_rules_closed)
        win.present()

    def _on_rules_closed(self, *_):
        self._rules_win = None
        return False

    def _map_points(self):
        """Geolocated endpoints for the map: everywhere connected recently, with
        currently-live endpoints kept fresh so the map fills in over time."""
        now = time.time()
        for o in self.objs.values():
            if o.has_geo and o.geo_ip:
                self._geo_points[o.geo_ip] = {
                    "lon": o.lng, "lat": o.lat, "kind": self._point_kind(o),
                    "label": o.location, "ts": now,
                    "ip": o.geo_ip, "org": o.org, "app": o.application,
                    "service": o.service, "port": o.port,
                    "direction": o.direction, "verdict": o.verdict or ""}
        cutoff = now - 900   # show endpoints seen in the last 15 minutes
        return [dict(p) for p in self._geo_points.values() if p["ts"] >= cutoff]

    def _act_map(self, *_):
        home = ports.capital_coords(self.config.get("home_country", ""))
        dark = self.config.get("theme", "system") not in (
            "system", "catppuccin-latte")
        MapWindow(self, self._map_points, home=home, dark=dark).present()

    def _act_stats(self, *_):
        StatsWindow(self, self.history, self.objs).present()

    def _act_blocklists(self, *_):
        BlocklistWindow(self, self.blocklists).present()

    def _act_export_rules(self, *_):
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("geonetmon-rules.json")
        dialog.save(self, None, self._export_rules_done)

    def _export_rules_done(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            return
        if not gfile:
            return
        try:
            n = bl_mod.export_rules(self.rules, gfile.get_path())
            self._notice("Rules exported", f"Wrote {n} rules.")
        except OSError as exc:
            self._notice("Export failed", str(exc))

    def _act_import_rules(self, *_):
        dialog = Gtk.FileDialog()
        dialog.open(self, None, self._import_rules_done)

    def _import_rules_done(self, dialog, result):
        try:
            gfile = dialog.open_finish(result)
        except GLib.Error:
            return
        if not gfile:
            return
        try:
            n = bl_mod.import_rules(self.rules, gfile.get_path(), replace=False)
            if self.using_daemon:
                self.daemon.get_rules()
            self._notice("Rules imported", f"Merged {n} rules from file.")
        except (OSError, ValueError) as exc:
            self._notice("Import failed", str(exc))

    # ---- enforcement (interactive outbound firewall) -------------------
    def _enf_available(self):
        if self.using_daemon:
            return bool(self.daemon_status.get("available"))
        return bool(self.engine and self.engine.available())

    def _enf_running(self):
        if self.using_daemon:
            return bool(self.daemon_status.get("enforcing"))
        return bool(self.engine and self.engine.running)

    def _enf_status_text(self):
        if self.using_daemon:
            return self.daemon_status.get("engine_status", "daemon")
        return self.engine.status_text() if self.engine else "unavailable"

    def _sync_shield(self):
        btn = getattr(self, "btn_shield", None)
        if btn is None:
            return
        btn.set_sensitive(self._enf_available())
        btn.handler_block_by_func(self._on_shield_toggled)
        btn.set_active(self._enf_running())
        btn.handler_unblock_by_func(self._on_shield_toggled)
        suffix = " (via daemon)" if self.using_daemon else ""
        btn.set_tooltip_text(
            f"Interactive outbound firewall — {self._enf_status_text()}{suffix}")
        if self._enf_running():
            btn.add_css_class("enforcing")
        else:
            btn.remove_css_class("enforcing")

    def _on_shield_toggled(self, btn):
        want = btn.get_active()
        if self.using_daemon:
            self.daemon.set_enforce(want)
            return  # status update arrives async, _sync_shield runs then
        if want and self.engine and not self.engine.running:
            ok, msg = self.engine.start()
            self.config["enforce_enabled"] = ok
            if not ok:
                self._notice("Could not start enforcement", msg)
        elif not want and self.engine and self.engine.running:
            self.engine.stop()
            self.config["enforce_enabled"] = False
        self._sync_shield()

    # ---- prompt queue (one pop-up at a time, OpenSnitch-style) ----------
    def _show_or_queue_prompt(self, flow, on_choice):
        """Show one prompt at a time; queue the rest so a burst can't bury you."""
        self._prompt_queue.append((flow, on_choice))
        self._pump_prompts()

    def _pump_prompts(self):
        if self._prompt_active or not self._prompt_queue:
            return False
        flow, on_choice = self._prompt_queue.pop(0)
        self._prompt_active = True
        self._prompt_win = PromptWindow(self, flow, self.config, on_choice)
        self._prompt_win.connect("close-request", self._on_prompt_closed)
        self._prompt_win.present()
        self._send_prompt_notification(flow)
        return False

    def _send_prompt_notification(self, flow):
        """GNOME notification — click it to raise the prompt window to front."""
        if not self.config.get("enforce_notify_prompt", True):
            return
        app = self.get_application()
        if not app:
            return
        proc = flow.get("process") or "Unknown process"
        dst = flow.get("dst_host") or flow.get("dst_ip") or "?"
        port = flow.get("dst_port", "")
        dst_str = f"{dst}:{port}" if port else dst
        try:
            from gi.repository import Gio
            n = Gio.Notification.new("Connection request")
            n.set_body(f"{proc} → {dst_str}")
            n.set_priority(Gio.NotificationPriority.URGENT)
            n.set_default_action("app.show-prompt")
            app.send_notification("connection-prompt", n)
        except Exception:  # noqa: BLE001
            pass

    def _on_prompt_closed(self, *_):
        self._prompt_active = False
        self._prompt_win = None
        app = self.get_application()
        if app:
            try:
                app.withdraw_notification("connection-prompt")
            except Exception:  # noqa: BLE001
                pass
        GLib.idle_add(self._pump_prompts)
        return False

    # ---- daemon-mode callbacks -----------------------------------------
    def _on_daemon_prompt(self, prompt_id, flow):
        entry = self.enricher.cache.get(flow.get("dst_ip"))
        if entry:
            flow.setdefault("org", entry.get("org", ""))
            flow.setdefault("country", entry.get("country", ""))

        def on_choice(action, scope, scope_by):
            self.daemon.decide(prompt_id, action, scope, scope_by)
        self._show_or_queue_prompt(flow, on_choice)
        return False

    def _on_daemon_event(self, msg):
        self._on_enforce_decision(msg.get("flow", {}), msg.get("action"),
                                  msg.get("auto", True))
        return False

    def _on_daemon_status(self, msg):
        self.daemon_status = msg
        self._sync_shield()
        return False

    def _on_daemon_rules(self, rules_list):
        self._daemon_rules = rules_list
        if getattr(self, "_rules_win", None):
            self._rules_win.update(rules_list)
        self._backfill_verdicts_from_rules(rules_list)
        return False

    def _backfill_verdicts_from_rules(self, rules_list):
        """On connect/refresh, pre-populate verdicts for live connections that
        already have a matching saved rule so the Firewall column isn't blank."""
        from .rules import Rule
        parsed = []
        for d in rules_list:
            if not d.get("enabled", True):
                continue
            try:
                parsed.append(Rule.from_dict(d))
            except Exception:  # noqa: BLE001
                pass
        if not parsed:
            return
        for obj in self.objs.values():
            if not obj.ip or obj.direction == "LISTEN":
                continue
            key = (obj.ip, obj.port, (obj.proto or "").lower())
            if key in self._verdicts:
                continue
            flow = {
                "process": obj.application,
                "dst_ip": obj.ip,
                "dst_host": obj.rdns or obj.ip,
                "dst_port": obj.port,
                "proto": (obj.proto or "").lower(),
            }
            for rule in parsed:
                if rule.matches(flow):
                    self._verdicts[key] = rule.action
                    obj.verdict = rule.action
                    break

    def _on_daemon_disconnect(self):
        self.using_daemon = False
        self.daemon_status = {}
        self._notice("Daemon disconnected",
                     "The GeoNetMon daemon stopped. Enforcement is off; the "
                     "monitor keeps running. Restart the daemon and reopen to "
                     "re-enable interactive blocking.")
        self._sync_shield()
        return False

    # ---- in-process-mode callbacks -------------------------------------
    def _on_prompt(self, prompt_id, flow):
        entry = self.enricher.cache.get(flow.get("dst_ip"))
        if entry:
            flow.setdefault("org", entry.get("org", ""))
            flow.setdefault("country", entry.get("country", ""))
            if entry.get("rdns") and entry["rdns"] not in ("Unknown", ""):
                flow["dst_host"] = entry["rdns"]

        def on_choice(action, scope, scope_by):
            # resolve_prompt builds the rule and releases the whole held group.
            self.engine.resolve_prompt(prompt_id, action, scope, scope_by)
            self._on_enforce_decision(flow, action, auto=False)
        self._show_or_queue_prompt(flow, on_choice)
        return False

    def _record_verdict(self, flow, action):
        """Remember the firewall's allow/deny for a remote endpoint so the main
        list can show it (applied to rows on the next refresh)."""
        ip = flow.get("dst_ip")
        if not ip:
            return
        try:
            port = int(flow.get("dst_port") or 0)
        except (TypeError, ValueError):
            port = 0
        self._verdicts[(ip, port, (flow.get("proto") or "").lower())] = action
        if len(self._verdicts) > 4000:      # bound memory
            for k in list(self._verdicts)[:2000]:
                del self._verdicts[k]

    def _on_enforce_decision(self, flow, action, auto):
        self._record_verdict(flow, action)
        if action == "allow":
            key = "enforce_notify_allow_auto" if auto else "enforce_notify_allow"
        else:
            key = "enforce_notify_deny_auto" if auto else "enforce_notify_deny"
        if not self.config.get(key):
            return False
        proc = flow.get("process") or "unknown app"
        dst = flow.get("dst_host") or flow.get("dst_ip") or "?"
        verb = "allowed" if action == "allow" else "blocked"
        self.alerts._raise(
            "info" if action == "allow" else "warn",
            f"Connection {verb}",
            f"{proc} → {dst}:{flow.get('dst_port','?')} "
            f"({'auto' if auto else 'your choice'})",
        )
        return False

    def _notice(self, title, body):
        dlg = Gtk.AlertDialog()
        dlg.set_message(title)
        dlg.set_detail(body)
        dlg.set_buttons(["OK"])
        dlg.show(self)

    def _on_settings_changed(self):
        app = self.get_application()
        if app and hasattr(app, "apply_theme"):
            app.apply_theme()
        self.enricher.reload_geoip()
        # apply enforcement on/off changes made in Preferences (in-process only;
        # daemon mode is controlled via the shield button / daemon config)
        if not self.using_daemon and self.engine:
            want = self.config.get("enforce_enabled") and self.engine.available()
            if want and not self.engine.running:
                ok, _ = self.engine.start()
                self.config["enforce_enabled"] = ok
            elif not self.config.get("enforce_enabled") and self.engine.running:
                self.engine.stop()
        self._sync_shield()
        self.start_timer()
        self.refilter()

    def _act_clear_alerts(self, *_):
        self.alerts.clear()
        self.btn_alerts.remove_css_class("has-alerts")

    def _act_about(self, *_):
        from . import __version__
        about = Gtk.AboutDialog(transient_for=self, modal=True)
        about.set_program_name("GeoNetMon")
        about.set_version(__version__)
        about.set_logo_icon_name("geonetmon")
        about.set_comments(
            "Real-time, geo-aware network connection monitor and "
            "interactive firewall."
        )
        about.set_license_type(Gtk.License.MIT_X11)
        about.set_website("https://www.jegly.xyz")
        about.set_website_label("jegly.xyz")
        about.present()

    def _act_export(self, *_):
        dlg = Gtk.FileDialog()
        dlg.set_initial_name("connections.csv")
        dlg.save(self, None, self._export_done)

    def _export_done(self, dlg, result):
        try:
            gfile = dlg.save_finish(result)
        except GLib.Error:
            return
        path = gfile.get_path()
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow([
                    "IP", "Proto", "Organization", "Location", "ReverseDNS",
                    "Direction", "Application", "PID", "Port", "Service",
                    "Encryption", "State", "Up_Bps", "Down_Bps",
                    "TotalUp", "TotalDown", "Risk",
                ])
                for i in range(self.selection.get_n_items()):
                    o = self.selection.get_item(i)
                    writer.writerow([
                        o.ip, o.proto, o.org, o.location, o.rdns, o.direction,
                        o.application, o.pid, o.port, o.service,
                        o.encryption, o.state, int(o.rate_up), int(o.rate_down),
                        o.total_up, o.total_down,
                        (o.risk if o.risk >= 0 else ""),
                    ])
        except OSError:
            pass

    # ===================================================================
    # Misc handlers
    # ===================================================================
    def _on_pause_toggled(self, btn):
        self.paused = btn.get_active()
        btn.set_icon_name(
            "media-playback-start-symbolic" if self.paused
            else "media-playback-pause-symbolic"
        )
        self.update_status()

    def _on_row_activate(self, _cv, position):
        obj = self.selection.get_item(position)
        if obj is not None:
            DetailWindow(self, obj, self.firewall, window=self).present()

    def _on_cell_right_click(self, gesture, _n, x, y, list_item):
        obj = list_item.get_item()
        if obj is None:
            return
        gesture.set_state(Gtk.EventSequenceState.CLAIMED)
        self._show_context_menu(gesture.get_widget(), obj, x, y)

    def _show_context_menu(self, anchor, obj, x, y):
        from gi.repository import Gdk
        popover = Gtk.Popover()
        popover.set_parent(anchor)
        popover.set_pointing_to(
            Gdk.Rectangle(x=int(x), y=int(y), width=1, height=1))
        popover.set_has_arrow(True)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        box.set_margin_start(4)
        box.set_margin_end(4)
        popover.set_child(box)

        def btn(label, cb, destructive=False, suggested=False):
            b = Gtk.Button(label=label)
            b.set_has_frame(False)
            if destructive:
                b.add_css_class("destructive-action")
            if suggested:
                b.add_css_class("suggested-action")
            b.connect("clicked", lambda *_: [popover.popdown(), cb()])
            box.append(b)

        is_listen = obj.direction in ("LISTEN", "")

        if not is_listen:
            if obj.verdict == "allow":
                btn("Deny app (remove allow rule)",
                    lambda: self._quick_rule(obj, "deny"), destructive=True)
            else:
                btn("Allow app forever",
                    lambda: self._quick_rule(obj, "allow"))

        btn("Details / lsof…",
            lambda: DetailWindow(self, obj, self.firewall, window=self).present())

        if obj.application:
            btn(f"Filter to  {obj.application}",
                lambda: self._filter_to_app(obj.application))

        import ipaddress
        try:
            addr = ipaddress.ip_address(obj.ip)
            blockable = not (addr.is_loopback or addr.is_private
                             or addr.is_unspecified or addr.is_link_local)
        except ValueError:
            blockable = False

        if blockable:
            blocked = self.firewall.is_blocked(obj.ip)
            btn(f"{'Unblock' if blocked else 'Block'} IP  {obj.ip}",
                lambda: self._ctx_block_ip(obj.ip, blocked), destructive=not blocked)
            btn(f"Whois  {obj.ip}…",
                lambda: self._show_whois(obj.ip))

        if obj.pid:
            btn(f"Kill PID {obj.pid}  ({obj.application})",
                lambda: self._ctx_kill(obj), destructive=True)

        popover.popup()

    def _quick_rule(self, obj, action):
        exe = ""
        if obj.pid:
            try:
                exe = __import__("os").readlink(f"/proc/{obj.pid}/exe")
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
        if self.using_daemon:
            self.daemon.add_rule(flow, action, "forever", "app_any")
        else:
            self.rules.build_from_choice(flow, action, "forever", "app_any")
        key = (obj.ip, obj.port, (obj.proto or "").lower())
        self._verdicts[key] = action
        obj.verdict = action

    def _ctx_block_ip(self, ip, currently_blocked):
        if currently_blocked:
            self.firewall.unblock(ip, on_done=lambda ok, msg: None)
        else:
            self.firewall.block(ip, on_done=lambda ok, msg: None)

    def _ctx_kill(self, obj):
        import signal as _sig
        try:
            __import__("os").kill(obj.pid, _sig.SIGTERM)
        except OSError:
            pass

    def _show_root_cmd(self, _btn):
        cmd = ("pkexec env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY "
               "WAYLAND_DISPLAY=$WAYLAND_DISPLAY "
               "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR python3 -m geonetmon")
        dlg = Gtk.AlertDialog()
        dlg.set_message("Run with full process visibility")
        dlg.set_detail(
            "From the project directory, run:\n\n" + cmd +
            "\n\n(The command has been copied to your clipboard.)"
        )
        dlg.set_buttons(["OK"])
        self.get_clipboard().set(cmd)
        dlg.show(self)

    def _on_close(self, *_):
        # Background mode: hide the window, keep daemon/engine/monitor alive.
        if self.config.get("run_in_background"):
            self.set_visible(False)
            if not self.config.get("silent_mode"):
                self.alerts._raise(
                    "info", "GeoNetMon still running",
                    "Monitoring continues in the background. Reopen from the "
                    "app launcher or quit from its menu.")
            return True   # stop the default destroy
        self._teardown()
        return False

    def _teardown(self):
        if self.engine:
            self.engine.stop()
        if self.using_daemon:
            self.daemon.on_disconnect = None  # don't show "disconnected" dialog on intentional exit
            self.daemon.close()
        self.rules.save()
        self.blocklists.save()
        self.enricher.shutdown()
        self.alerts.save()
        self.firewall.save()
        self.history.prune(self.config.get("history_keep_days", 30))
        self.history.close()
