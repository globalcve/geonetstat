"""Preferences window. GTK4-only (no libadwaita dependency)."""

from gi.repository import Gtk

from . import applock
from . import themes
from . import ports
from .ui import escape_closes


class SettingsWindow(Gtk.Window):
    def __init__(self, parent, config, on_change):
        super().__init__(title="Preferences", transient_for=parent)
        self.set_default_size(540, 680)
        escape_closes(self)
        self.config = config
        self.on_change = on_change

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_child(scroller)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(16)
        box.set_margin_bottom(16)
        box.set_margin_start(16)
        box.set_margin_end(16)
        scroller.set_child(box)

        # ---- Polling ----
        box.append(self._heading("Polling"))
        adj = Gtk.Adjustment(
            value=config["refresh_ms"], lower=250, upper=10000,
            step_increment=250, page_increment=1000,
        )
        self.spin_refresh = Gtk.SpinButton(adjustment=adj, climb_rate=1, digits=0)
        self.spin_refresh.connect("value-changed", self._set_int, "refresh_ms")
        box.append(self._row("Refresh interval (ms)", self.spin_refresh))

        # ---- Appearance ----
        box.append(self._heading("Appearance"))
        self.drop_theme = Gtk.DropDown.new_from_strings(
            [label for _, label in themes.THEME_CHOICES]
        )
        self.drop_theme.set_selected(themes.index_of(config["theme"]))
        self.drop_theme.connect("notify::selected", self._set_theme)
        box.append(self._row("Theme", self.drop_theme))

        # Catppuccin accent colour (app-wide). "Theme default" keeps the theme's
        # own accent; any other choice overrides it everywhere.
        self.drop_accent = Gtk.DropDown.new_from_strings(themes.ACCENT_CHOICES)
        cur_accent = config.get("accent", "")
        self.drop_accent.set_selected(
            themes.ACCENT_CHOICES.index(cur_accent)
            if cur_accent in themes.ACCENT_CHOICES else 0)
        self.drop_accent.connect("notify::selected", self._set_accent)
        box.append(self._row("Accent colour", self.drop_accent))

        # ---- Security ----
        box.append(self._heading("Security"))
        lhint = Gtk.Label(
            label="Ask for a password before the window opens. This guards "
                  "casual access to the UI only — it does not encrypt the "
                  "history, cache, or config on disk.",
            xalign=0, wrap=True,
        )
        lhint.add_css_class("dim-label")
        box.append(lhint)

        self.sw_lock = Gtk.Switch(
            active=bool(config["app_lock_enabled"] and config["app_lock_hash"]))
        self.sw_lock.set_valign(Gtk.Align.CENTER)
        self.sw_lock.connect("state-set", self._on_lock_switch)
        box.append(self._row("Require password on launch", self.sw_lock))

        self.btn_change_pw = Gtk.Button(label="Change password…")
        self.btn_change_pw.set_sensitive(bool(config["app_lock_hash"]))
        self.btn_change_pw.connect("clicked", self._on_change_pw)
        box.append(self._row("Password", self.btn_change_pw))

        adj_idle = Gtk.Adjustment(
            value=config["app_lock_idle_min"], lower=0, upper=480,
            step_increment=5, page_increment=15,
        )
        self.spin_idle = Gtk.SpinButton(adjustment=adj_idle, climb_rate=1,
                                        digits=0)
        self.spin_idle.connect("value-changed", self._set_int,
                               "app_lock_idle_min")
        box.append(self._row("Auto-lock after idle (minutes, 0 = off)",
                             self.spin_idle))

        # ---- Display ----
        box.append(self._heading("Display"))
        for key, label in [
            ("show_tcp", "Show TCP"),
            ("show_udp", "Show UDP"),
            ("show_listen", "Show listening sockets"),
            ("show_timewait", "Show TIME-WAIT / closing states"),
            ("hide_loopback", "Hide loopback (127.0.0.0/8, ::1)"),
            ("show_pid_column", "Show PID column (restart to apply)"),
            ("show_rate_columns", "Show ↑/↓ throughput columns (restart to apply)"),
            ("show_risk_column", "Show risk column (restart to apply)"),
            ("show_sparkline", "Show sparkline in status bar (restart to apply)"),
        ]:
            box.append(self._switch_row(label, key))

        box.append(self._switch_row("Run in background when window closed",
                                    "run_in_background"))

        # Autostart: the XDG desktop file is the source of truth, not config.
        from . import config as cfg_mod
        self.sw_autostart = Gtk.Switch(active=cfg_mod.autostart_enabled())
        self.sw_autostart.set_valign(Gtk.Align.CENTER)
        self.sw_autostart.connect("state-set", self._on_autostart)
        box.append(self._row("Start on login (needs installed 'geonetmon' "
                             "launcher)", self.sw_autostart))

        adj_rows = Gtk.Adjustment(
            value=config["max_rows"], lower=0, upper=5000,
            step_increment=50, page_increment=200,
        )
        self.spin_rows = Gtk.SpinButton(adjustment=adj_rows, climb_rate=1, digits=0)
        self.spin_rows.connect("value-changed", self._set_int, "max_rows")
        box.append(self._row("Max rows (0 = unlimited)", self.spin_rows))

        adj_hl = Gtk.Adjustment(
            value=config["highlight_seconds"], lower=0, upper=30,
            step_increment=1, page_increment=5,
        )
        self.spin_hl = Gtk.SpinButton(adjustment=adj_hl, climb_rate=1, digits=0)
        self.spin_hl.connect("value-changed", self._set_int, "highlight_seconds")
        box.append(self._row("New-connection highlight (s)", self.spin_hl))

        # ---- Enrichment ----
        box.append(self._heading("Enrichment (network lookups)"))
        box.append(self._switch_row("Resolve geolocation (ipinfo.io)", "resolve_geo"))
        box.append(self._switch_row("Resolve reverse DNS", "resolve_rdns"))
        box.append(self._switch_row(
            "Passive DNS capture — daemon learns hostnames from DNS replies "
            "(shows real names for CDN IPs with no reverse DNS)",
            "dns_sniff"))

        self.entry_token = Gtk.Entry(text=config["ipinfo_token"])
        self.entry_token.set_placeholder_text("optional ipinfo.io token")
        self.entry_token.connect("changed", self._set_text, "ipinfo_token")
        box.append(self._row("ipinfo.io token", self.entry_token))

        # Pick Home by name (no need to know ISO codes). Only countries we can
        # place on the map are offered, so any choice yields a Home origin — and
        # the connection arcs / flowing packets that radiate from it.
        home_codes = [""] + sorted(ports.CAPITAL_COORDS, key=ports.country_name)
        home_labels = ["None (everywhere is foreign)"] + [
            ports.country_name(c) for c in home_codes[1:]]
        self.drop_home = self._labeled_drop(
            home_labels, home_codes, (config["home_country"] or "").upper(),
            "home_country")
        box.append(self._row("Home country", self.drop_home))

        adj_ttl = Gtk.Adjustment(
            value=config["cache_ttl_hours"], lower=1, upper=2160,
            step_increment=1, page_increment=24,
        )
        self.spin_ttl = Gtk.SpinButton(adjustment=adj_ttl, climb_rate=1, digits=0)
        self.spin_ttl.connect("value-changed", self._set_int, "cache_ttl_hours")
        box.append(self._row("Cache TTL (hours)", self.spin_ttl))

        # ---- Offline geolocation (GeoLite2) ----
        box.append(self._heading("Offline geolocation (GeoLite2)"))
        hint = Gtk.Label(
            label="Point these at MaxMind GeoLite2 .mmdb files for fully "
                  "offline lookups (needs the 'maxminddb' Python module). "
                  "Leave blank to use ipinfo.io.",
            xalign=0, wrap=True,
        )
        hint.add_css_class("dim-label")
        box.append(hint)

        self.entry_geodb = Gtk.Entry(text=config["geoip_db_path"])
        self.entry_geodb.set_placeholder_text("/path/to/GeoLite2-City.mmdb")
        self.entry_geodb.connect("changed", self._set_text, "geoip_db_path")
        box.append(self._row("City/Country DB", self.entry_geodb))

        self.entry_asndb = Gtk.Entry(text=config["geoip_asn_db_path"])
        self.entry_asndb.set_placeholder_text("/path/to/GeoLite2-ASN.mmdb (optional)")
        self.entry_asndb.connect("changed", self._set_text, "geoip_asn_db_path")
        box.append(self._row("ASN DB (org names)", self.entry_asndb))

        # ---- Threat intelligence ----
        box.append(self._heading("Threat intelligence"))
        self.entry_abuse = Gtk.Entry(text=config["abuseipdb_token"])
        self.entry_abuse.set_placeholder_text("optional AbuseIPDB API key")
        self.entry_abuse.connect("changed", self._set_text, "abuseipdb_token")
        box.append(self._row("AbuseIPDB token", self.entry_abuse))

        # ---- Firewall ----
        box.append(self._heading("Firewall"))
        self.drop_fw = Gtk.DropDown.new_from_strings(
            ["auto", "ufw", "nftables", "iptables"]
        )
        self.drop_fw.set_selected(
            {"auto": 0, "ufw": 1, "nftables": 2, "iptables": 3}
            .get(config["firewall_backend"], 0)
        )
        self.drop_fw.connect("notify::selected", self._set_firewall_backend)
        box.append(self._row("Backend", self.drop_fw))

        # ---- Enforcement (interactive outbound firewall) ----
        box.append(self._heading("Enforcement (interactive outbound firewall)"))
        ehint = Gtk.Label(
            label="Intercepts new connections and asks allow or deny. Needs "
                  "root, nftables, and python3-netfilterqueue. Toggle it live "
                  "with the shield button in the header.",
            xalign=0, wrap=True,
        )
        ehint.add_css_class("dim-label")
        box.append(ehint)

        box.append(self._switch_row("Enable enforcement", "enforce_enabled"))

        self.drop_dir = self._labeled_drop(
            ["Outgoing", "Incoming", "Both"],
            ["outbound", "inbound", "both"],
            config["enforce_direction"], "enforce_direction")
        box.append(self._row("Filter direction", self.drop_dir))

        self.drop_default = self._enum_drop(
            ["prompt", "allow", "deny"], config["enforce_default_action"],
            "enforce_default_action")
        box.append(self._row("Unmatched connections", self.drop_default))

        self.drop_timeout_act = self._enum_drop(
            ["deny", "allow"], config["enforce_timeout_action"],
            "enforce_timeout_action")
        box.append(self._row("On prompt timeout", self.drop_timeout_act))

        adj_to = Gtk.Adjustment(value=config["enforce_prompt_timeout_s"],
                                lower=15, upper=300, step_increment=5,
                                page_increment=15)
        self.spin_to = Gtk.SpinButton(adjustment=adj_to, climb_rate=1, digits=0)
        self.spin_to.connect("value-changed", self._set_int,
                             "enforce_prompt_timeout_s")
        box.append(self._row("Prompt timeout (s)", self.spin_to))

        self.drop_scope = self._labeled_drop(
            ["Once", "Until the app quits", "Until restart", "Forever"],
            ["once", "process", "session", "forever"],
            config["enforce_default_scope"], "enforce_default_scope")
        box.append(self._row("Default duration", self.drop_scope))

        self.drop_by = self._labeled_drop(
            ["Any connection", "Connections to this host",
             "Connections on this port", "Only this connection"],
            ["app_any", "app_host", "app_port", "exact"],
            config["enforce_default_scope_by"], "enforce_default_scope_by")
        box.append(self._row("Default scope", self.drop_by))

        shint = Gtk.Label(
            label="These pre-select the two dropdowns on each connection alert. "
                  "Duration = how long the decision lasts (Once, until the app "
                  "quits, until restart, or Forever). Scope = how widely it "
                  "applies (the whole app anywhere, just one host, just one "
                  "port, or only that exact connection). 'Forever' + 'Any "
                  "connection' means one click allows/blocks an app for good.",
            xalign=0, wrap=True)
        shint.add_css_class("dim-label")
        box.append(shint)

        box.append(self._switch_row("Filter TCP", "enforce_apply_tcp"))
        box.append(self._switch_row("Filter UDP", "enforce_apply_udp"))
        box.append(self._switch_row("Fail open (allow if engine dies)",
                                    "enforce_fail_open"))

        # ---- Notifications (toast pop-ups) ----
        box.append(self._heading("Notifications"))
        nhint = Gtk.Label(
            label="Toast pop-ups for firewall and alert events. Their position "
                  "and on-screen time are controlled by your desktop's "
                  "notification settings; below controls which events pop up.",
            xalign=0, wrap=True)
        nhint.add_css_class("dim-label")
        box.append(nhint)
        box.append(self._switch_row("Enable desktop pop-up notifications",
                                    "desktop_notifications"))
        box.append(self._switch_row("Silent mode — suppress ALL pop-ups",
                                    "silent_mode"))

        nhint2 = Gtk.Label(
            label="Firewall decision pop-ups:",
            xalign=0, wrap=True)
        nhint2.add_css_class("dim-label")
        box.append(nhint2)
        box.append(self._switch_row(
            "GNOME notification when allow/deny prompt appears (visible even when minimised)",
            "enforce_notify_prompt"))
        box.append(self._switch_row(
            "Notify when you manually allow a connection (your choice)",
            "enforce_notify_allow"))
        box.append(self._switch_row(
            "Notify on auto-allowed connections (already-allowed apps repeating)",
            "enforce_notify_allow_auto"))
        box.append(self._switch_row(
            "Notify when you manually block a connection (your choice)",
            "enforce_notify_deny"))
        box.append(self._switch_row(
            "Notify on auto-blocked connections (existing deny rule matched — off by default to avoid spam)",
            "enforce_notify_deny_auto"))

        nhint3 = Gtk.Label(label="Monitor event pop-ups:", xalign=0, wrap=True)
        nhint3.add_css_class("dim-label")
        box.append(nhint3)
        box.append(self._switch_row("New application first seen", "alert_new_app"))
        box.append(self._switch_row("New remote host / IP address", "alert_new_ip"))
        box.append(self._switch_row("Connection to a new country",
                                    "alert_new_country"))
        box.append(self._switch_row("Incoming connection accepted", "alert_incoming"))
        box.append(self._switch_row("Unencrypted foreign traffic",
                                    "alert_unencrypted_foreign"))
        box.append(self._switch_row("High-risk host (AbuseIPDB ≥ 50)",
                                    "alert_high_risk"))

        self.btn_reset_seen = Gtk.Button(label="Reset now")
        self.btn_reset_seen.connect("clicked", self._on_reset_seen)
        box.append(self._row("Forget seen apps/countries/IPs "
                             "(re-primes 'new X' alerts)", self.btn_reset_seen))

        # ---- History ----
        box.append(self._heading("History"))
        box.append(self._switch_row("Log connection history (SQLite)",
                                    "log_history"))
        adj_keep = Gtk.Adjustment(
            value=config["history_keep_days"], lower=1, upper=365,
            step_increment=1, page_increment=7,
        )
        self.spin_keep = Gtk.SpinButton(adjustment=adj_keep, climb_rate=1, digits=0)
        self.spin_keep.connect("value-changed", self._set_int, "history_keep_days")
        box.append(self._row("Keep history (days)", self.spin_keep))

        # ---- About ----
        box.append(self._heading("About"))
        box.append(self._about_section())

    # ---- About ----------------------------------------------------------
    def _about_section(self):
        from . import __version__
        wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        wrap.set_halign(Gtk.Align.CENTER)
        wrap.set_margin_top(6)

        logo = Gtk.Image.new_from_icon_name("geonetmon")
        logo.set_pixel_size(128)
        logo.set_halign(Gtk.Align.CENTER)
        wrap.append(logo)

        name = Gtk.Label(label="GeoNetMon", halign=Gtk.Align.CENTER)
        name.add_css_class("heading")
        wrap.append(name)

        ver = Gtk.Label(label=f"Version {__version__}", halign=Gtk.Align.CENTER)
        ver.add_css_class("dim-label")
        wrap.append(ver)

        links = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12,
                        halign=Gtk.Align.CENTER)
        links.append(Gtk.LinkButton(uri="https://www.jegly.xyz", label="jegly.xyz"))
        links.append(Gtk.LinkButton(uri="https://www.github.com/jegly",
                                     label="github.com/jegly"))
        wrap.append(links)
        return wrap

    # ---- builders -------------------------------------------------------
    def _heading(self, text):
        lbl = Gtk.Label(label=text, xalign=0)
        lbl.add_css_class("heading")
        lbl.set_margin_top(8)
        return lbl

    def _row(self, label, widget):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        lbl = Gtk.Label(label=label, xalign=0, hexpand=True)
        widget.set_halign(Gtk.Align.END)
        row.append(lbl)
        row.append(widget)
        return row

    def _switch_row(self, label, key):
        sw = Gtk.Switch(active=bool(self.config[key]))
        sw.set_valign(Gtk.Align.CENTER)
        sw.connect("state-set", self._set_switch, key)
        return self._row(label, sw)

    # ---- handlers -------------------------------------------------------
    def _commit(self):
        self.config.save()
        if self.on_change:
            self.on_change()

    def _set_switch(self, _sw, state, key):
        self.config[key] = bool(state)
        self._commit()
        return False

    def _set_int(self, spin, key):
        self.config[key] = int(spin.get_value())
        self._commit()

    def _set_text(self, entry, key):
        self.config[key] = entry.get_text().strip()
        self._commit()

    def _on_lock_switch(self, sw, state):
        """Enabling with no password set first asks for one; cancelling the
        dialog leaves the lock off."""
        if state and not self.config["app_lock_hash"]:
            def done(phc):
                if phc:
                    self.config["app_lock_hash"] = phc
                    self.config["app_lock_enabled"] = True
                    self._commit()
                    self.btn_change_pw.set_sensitive(True)
                    sw.set_state(True)
                else:
                    sw.set_active(False)
            applock.SetPasswordDialog(self, done).present()
            return True   # hold the switch until the dialog answers
        self.config["app_lock_enabled"] = bool(state)
        self._commit()
        return False

    def _on_change_pw(self, _btn):
        def done(phc):
            if phc:
                self.config["app_lock_hash"] = phc
                self._commit()
        applock.SetPasswordDialog(self, done).present()

    def _on_autostart(self, sw, state):
        from . import config as cfg_mod
        if not cfg_mod.set_autostart(bool(state)):
            sw.set_active(cfg_mod.autostart_enabled())  # write failed — revert
        return False

    def _on_reset_seen(self, btn):
        win = self.get_transient_for()
        alerts = getattr(win, "alerts", None)
        if alerts is not None:
            alerts.reset_seen()
            btn.set_label("Done ✓")
            btn.set_sensitive(False)

    def _set_theme(self, drop, _param):
        self.config["theme"] = themes.id_at(drop.get_selected())
        self._commit()

    def _set_accent(self, drop, _param):
        choice = themes.ACCENT_CHOICES[drop.get_selected()]
        self.config["accent"] = "" if choice == "Theme default" else choice
        self._commit()

    def _set_firewall_backend(self, drop, _param):
        self.config["firewall_backend"] = \
            ["auto", "ufw", "nftables", "iptables"][drop.get_selected()]
        self._commit()

    def _enum_drop(self, values, current, key):
        """A DropDown bound to a config key holding one of `values`."""
        return self._labeled_drop(values, values, current, key)

    def _labeled_drop(self, labels, values, current, key):
        """A DropDown showing human `labels` but storing `values[i]` for key."""
        drop = Gtk.DropDown.new_from_strings(labels)
        if current in values:
            drop.set_selected(values.index(current))
        drop._gnm_values = values
        drop._gnm_key = key
        drop.connect("notify::selected", self._set_enum)
        return drop

    def _set_enum(self, drop, _param):
        self.config[drop._gnm_key] = drop._gnm_values[drop.get_selected()]
        self._commit()
