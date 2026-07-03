"""Native system-tray icon: StatusNotifierItem + DBusMenu over Gio D-Bus.

GTK4 removed Gtk.Menu, and the AppIndicator libraries are GTK3-based, so an
in-process appindicator *menu* is impossible in a GTK4 app (tray.py kept as a
last-resort fallback). This module speaks the underlying wire protocols
directly — org.kde.StatusNotifierItem for the icon/clicks and
com.canonical.dbusmenu for the right-click menu — using nothing but Gio, so
it works wherever a StatusNotifier host exists (KDE, GNOME with the
AppIndicator extension, XFCE, budgie, …) with zero extra dependencies.

Menu state (pause / enforcement checkmarks, lock visibility) is pulled fresh
from the app via ``get_state()`` every time the host opens the menu
(AboutToShow), so it never goes stale.
"""

import os

from gi.repository import Gio, GLib

ITEM_PATH = "/StatusNotifierItem"
MENU_PATH = "/geonetmon/Menu"
_WATCHER = "org.kde.StatusNotifierWatcher"

_SNI_XML = """<node>
 <interface name="org.kde.StatusNotifierItem">
  <property name="Category" type="s" access="read"/>
  <property name="Id" type="s" access="read"/>
  <property name="Title" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="WindowId" type="u" access="read"/>
  <property name="IconName" type="s" access="read"/>
  <property name="IconThemePath" type="s" access="read"/>
  <property name="OverlayIconName" type="s" access="read"/>
  <property name="AttentionIconName" type="s" access="read"/>
  <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
  <property name="Menu" type="o" access="read"/>
  <property name="ItemIsMenu" type="b" access="read"/>
  <method name="ContextMenu"><arg type="i"/><arg type="i"/></method>
  <method name="Activate"><arg type="i"/><arg type="i"/></method>
  <method name="SecondaryActivate"><arg type="i"/><arg type="i"/></method>
  <method name="Scroll"><arg type="i"/><arg type="s"/></method>
  <signal name="NewIcon"/>
  <signal name="NewTitle"/>
  <signal name="NewToolTip"/>
  <signal name="NewStatus"><arg type="s"/></signal>
 </interface>
</node>"""

_MENU_XML = """<node>
 <interface name="com.canonical.dbusmenu">
  <property name="Version" type="u" access="read"/>
  <property name="TextDirection" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconThemePath" type="as" access="read"/>
  <method name="GetLayout">
   <arg type="i" direction="in"/><arg type="i" direction="in"/>
   <arg type="as" direction="in"/>
   <arg type="u" direction="out"/><arg type="(ia{sv}av)" direction="out"/>
  </method>
  <method name="GetGroupProperties">
   <arg type="ai" direction="in"/><arg type="as" direction="in"/>
   <arg type="a(ia{sv})" direction="out"/>
  </method>
  <method name="GetProperty">
   <arg type="i" direction="in"/><arg type="s" direction="in"/>
   <arg type="v" direction="out"/>
  </method>
  <method name="Event">
   <arg type="i" direction="in"/><arg type="s" direction="in"/>
   <arg type="v" direction="in"/><arg type="u" direction="in"/>
  </method>
  <method name="EventGroup">
   <arg type="a(isvu)" direction="in"/><arg type="ai" direction="out"/>
  </method>
  <method name="AboutToShow">
   <arg type="i" direction="in"/><arg type="b" direction="out"/>
  </method>
  <method name="AboutToShowGroup">
   <arg type="ai" direction="in"/>
   <arg type="ai" direction="out"/><arg type="ai" direction="out"/>
  </method>
  <signal name="ItemsPropertiesUpdated">
   <arg type="a(ia{sv})"/><arg type="a(ias)"/>
  </signal>
  <signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
  <signal name="ItemActivationRequested"><arg type="i"/><arg type="u"/></signal>
 </interface>
</node>"""

# menu item ids
_SHOW, _PAUSE, _ENFORCE, _LOCK, _SEP, _QUIT = 1, 2, 3, 4, 5, 6


def available():
    """True when the session bus is reachable (the watcher may appear later —
    we re-register automatically when it does)."""
    try:
        return Gio.bus_get_sync(Gio.BusType.SESSION, None) is not None
    except GLib.Error:
        return False


def _vprop(key, val):
    if key == "toggle-state":
        return GLib.Variant("i", int(val))
    if key in ("enabled", "visible"):
        return GLib.Variant("b", bool(val))
    return GLib.Variant("s", str(val))


class SNITray:
    """Tray icon + right-click menu. All callbacks fire on the GLib main loop.

    get_state() -> {"paused": bool, "enforcing": bool, "lock": bool}
    """

    def __init__(self, app_id, on_show, on_toggle_pause, on_toggle_enforce,
                 on_lock, on_quit, get_state):
        self.app_id = app_id
        self.on_show = on_show
        self.on_toggle_pause = on_toggle_pause
        self.on_toggle_enforce = on_toggle_enforce
        self.on_lock = on_lock
        self.on_quit = on_quit
        self.get_state = get_state

        self._revision = 1
        self._enforcing = False
        # Monochrome symbolic icon: the shell recolors *-symbolic names to
        # match the top bar, so it reads white like the other panel icons.
        # The HOST resolves the name against the system theme, so fall back
        # to a stock symbolic for source-tree runs without the icon installed.
        self._icon = ("geonetmon-symbolic" if os.path.exists(
            "/usr/share/icons/hicolor/symbolic/apps/geonetmon-symbolic.svg")
            else "security-medium-symbolic")

        self._conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self._sni_node = Gio.DBusNodeInfo.new_for_xml(_SNI_XML)
        self._menu_node = Gio.DBusNodeInfo.new_for_xml(_MENU_XML)
        self._reg_ids = [
            self._conn.register_object(
                ITEM_PATH, self._sni_node.interfaces[0],
                self._sni_call, self._sni_get, None),
            self._conn.register_object(
                MENU_PATH, self._menu_node.interfaces[0],
                self._menu_call, self._menu_get, None),
        ]
        self._bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        self._own_id = Gio.bus_own_name_on_connection(
            self._conn, self._bus_name, Gio.BusNameOwnerFlags.NONE,
            None, None)
        # Register now, and re-register whenever the watcher (re)appears —
        # e.g. a GNOME shell reload or the tray extension being enabled later.
        self._watch_id = Gio.bus_watch_name_on_connection(
            self._conn, _WATCHER, Gio.BusNameWatcherFlags.NONE,
            lambda *_a: self._register(), None)
        self._register()

    # ---- watcher registration -------------------------------------------
    def _register(self):
        try:
            self._conn.call_sync(
                _WATCHER, "/StatusNotifierWatcher", _WATCHER,
                "RegisterStatusNotifierItem",
                GLib.Variant("(s)", (self._bus_name,)),
                None, Gio.DBusCallFlags.NONE, 2000, None)
            return True
        except GLib.Error:
            return False        # no host right now; the name-watch retries

    # ---- StatusNotifierItem ----------------------------------------------
    def _sni_get(self, _conn, _sender, _path, _iface, name):
        tip_body = ("Enforcement active — interactive firewall on"
                    if self._enforcing else "Network monitor running")
        vals = {
            "Category": GLib.Variant("s", "ApplicationStatus"),
            "Id": GLib.Variant("s", self.app_id),
            "Title": GLib.Variant("s", "GeoNetMon"),
            "Status": GLib.Variant("s", "Active"),
            "WindowId": GLib.Variant("u", 0),
            "IconName": GLib.Variant("s", self._icon),
            "IconThemePath": GLib.Variant("s", ""),
            "OverlayIconName": GLib.Variant(
                "s", "security-high-symbolic" if self._enforcing else ""),
            "AttentionIconName": GLib.Variant("s", ""),
            "ToolTip": GLib.Variant("(sa(iiay)ss)",
                                    ("", [], "GeoNetMon", tip_body)),
            "Menu": GLib.Variant("o", MENU_PATH),
            "ItemIsMenu": GLib.Variant("b", False),
        }
        return vals.get(name)

    def _sni_call(self, _conn, _sender, _path, _iface, method, _params,
                  invocation):
        if method in ("Activate", "SecondaryActivate"):
            self.on_show()
        # ContextMenu/Scroll: the host renders our dbusmenu itself
        invocation.return_value(None)

    # ---- menu model -------------------------------------------------------
    def _items(self):
        try:
            st = self.get_state() or {}
        except Exception:  # noqa: BLE001 — a state bug must not kill the menu
            st = {}
        items = [
            (_SHOW, {"label": "Show GeoNetMon"}),
            (_PAUSE, {"label": "Pause monitoring",
                      "toggle-type": "checkmark",
                      "toggle-state": 1 if st.get("paused") else 0}),
            (_ENFORCE, {"label": "Enforcement (interactive firewall)",
                        "toggle-type": "checkmark",
                        "toggle-state": 1 if st.get("enforcing") else 0}),
        ]
        if st.get("lock"):
            items.append((_LOCK, {"label": "Lock now"}))
        items.append((_SEP, {"type": "separator"}))
        items.append((_QUIT, {"label": "Quit GeoNetMon"}))
        return items

    def _child_variants(self):
        out = []
        for iid, props in self._items():
            pv = {k: _vprop(k, v) for k, v in props.items()}
            out.append(GLib.Variant("(ia{sv}av)", (iid, pv, [])))
        return out

    def refresh(self):
        """Bump the layout revision so the host refetches the menu."""
        self._revision += 1
        try:
            self._conn.emit_signal(
                None, MENU_PATH, "com.canonical.dbusmenu", "LayoutUpdated",
                GLib.Variant("(ui)", (self._revision, 0)))
        except GLib.Error:
            pass

    def set_enforcing(self, on):
        """Reflect shield state in overlay icon + tooltip + menu checkmark."""
        on = bool(on)
        if on == self._enforcing:
            return
        self._enforcing = on
        for sig in ("NewIcon", "NewToolTip"):
            try:
                self._conn.emit_signal(
                    None, ITEM_PATH, "org.kde.StatusNotifierItem", sig, None)
            except GLib.Error:
                pass
        self.refresh()

    # ---- com.canonical.dbusmenu ------------------------------------------
    def _menu_get(self, _conn, _sender, _path, _iface, name):
        vals = {
            "Version": GLib.Variant("u", 3),
            "TextDirection": GLib.Variant("s", "ltr"),
            "Status": GLib.Variant("s", "normal"),
            "IconThemePath": GLib.Variant("as", []),
        }
        return vals.get(name)

    def _menu_call(self, _conn, _sender, _path, _iface, method, params,
                   invocation):
        if method == "GetLayout":
            root = (0, {"children-display": GLib.Variant("s", "submenu")},
                    self._child_variants())
            invocation.return_value(GLib.Variant(
                "(u(ia{sv}av))", (self._revision, root)))
        elif method == "GetGroupProperties":
            wanted = set(params[0])
            rows = [(iid, {k: _vprop(k, v) for k, v in props.items()})
                    for iid, props in self._items()
                    if not wanted or iid in wanted]
            invocation.return_value(GLib.Variant("(a(ia{sv}))", (rows,)))
        elif method == "GetProperty":
            iid, pname = params
            for i, props in self._items():
                if i == iid and pname in props:
                    invocation.return_value(GLib.Variant(
                        "(v)", (_vprop(pname, props[pname]),)))
                    return
            invocation.return_value(GLib.Variant(
                "(v)", (GLib.Variant("s", ""),)))
        elif method == "Event":
            iid, event = params[0], params[1]
            if event == "clicked":
                self._clicked(iid)
            invocation.return_value(None)
        elif method == "EventGroup":
            for iid, event, _data, _ts in params[0]:
                if event == "clicked":
                    self._clicked(iid)
            invocation.return_value(GLib.Variant("(ai)", ([],)))
        elif method == "AboutToShow":
            # State may have changed since last open — republish the layout.
            self.refresh()
            invocation.return_value(GLib.Variant("(b)", (False,)))
        elif method == "AboutToShowGroup":
            invocation.return_value(GLib.Variant("(aiai)", ([], [])))
        else:
            invocation.return_value(None)

    def _clicked(self, iid):
        try:
            st = self.get_state() or {}
        except Exception:  # noqa: BLE001
            st = {}
        if iid == _SHOW:
            self.on_show()
        elif iid == _PAUSE:
            self.on_toggle_pause(not st.get("paused"))
        elif iid == _ENFORCE:
            self.on_toggle_enforce(not st.get("enforcing"))
        elif iid == _LOCK:
            self.on_lock()
        elif iid == _QUIT:
            self.on_quit()
            return
        self.refresh()          # checkmarks reflect the new state

    # ---- teardown ---------------------------------------------------------
    def close(self):
        if self._watch_id:
            Gio.bus_unwatch_name(self._watch_id)
            self._watch_id = 0
        if self._own_id:
            Gio.bus_unown_name(self._own_id)
            self._own_id = 0
        for rid in self._reg_ids:
            try:
                self._conn.unregister_object(rid)
            except Exception:  # noqa: BLE001
                pass
        self._reg_ids = []
