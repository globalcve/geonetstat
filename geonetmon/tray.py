"""Optional system-tray icon via AyatanaAppIndicator3 / AppIndicator3.

GTK4 has no built-in tray. Where a StatusNotifier host exists (most desktops,
including GNOME with an extension, KDE, and many others) we expose a menu with
Show / Enforcement toggle / Quit. When the indicator library or a tray host is
unavailable we degrade silently — background mode still works, the user just
reopens from the app launcher.

Wayland note: some compositors don't implement the tray protocol; if the icon
never appears, that's the environment, not GeoNetMon.
"""

import gi

_HAVE_INDICATOR = False
_AppIndicator = None
for _lib, _ver in (("AyatanaAppIndicator3", "0.1"), ("AppIndicator3", "0.1")):
    try:
        gi.require_version(_lib, _ver)
        if _lib == "AyatanaAppIndicator3":
            from gi.repository import AyatanaAppIndicator3 as _AppIndicator
        else:
            from gi.repository import AppIndicator3 as _AppIndicator
        _HAVE_INDICATOR = True
        break
    except (ValueError, ImportError):
        continue

from gi.repository import Gtk  # noqa: E402


def available():
    return _HAVE_INDICATOR


class Tray:
    """Wraps an AppIndicator with a small menu. No-op if unavailable."""

    def __init__(self, app_id, on_show, on_toggle_enforce, on_quit):
        self.on_show = on_show
        self.on_toggle_enforce = on_toggle_enforce
        self.on_quit = on_quit
        self.indicator = None
        self._enforce_item = None
        if not _HAVE_INDICATOR:
            return
        self.indicator = _AppIndicator.Indicator.new(
            app_id, "security-medium-symbolic",
            _AppIndicator.IndicatorCategory.APPLICATION_STATUS)
        self.indicator.set_status(_AppIndicator.IndicatorStatus.ACTIVE)
        self.indicator.set_title("GeoNetMon")
        self.indicator.set_menu(self._build_menu())

    def _build_menu(self):
        menu = Gtk.Menu() if hasattr(Gtk, "Menu") else None
        if menu is None:
            # GTK4 has no Gtk.Menu; AppIndicator needs a Gtk3 menu. If we get
            # here the indicator lib is GTK3-based; build with Gtk.Menu from
            # that namespace is not available, so fall back to no menu.
            return None
        show = Gtk.MenuItem(label="Show GeoNetMon")
        show.connect("activate", lambda *_: self.on_show())
        menu.append(show)
        self._enforce_item = Gtk.CheckMenuItem(label="Enforcement")
        self._enforce_handler = self._enforce_item.connect(
            "toggled", lambda it: self.on_toggle_enforce(it.get_active()))
        menu.append(self._enforce_item)
        sep = Gtk.SeparatorMenuItem()
        menu.append(sep)
        quit_item = Gtk.MenuItem(label="Quit")
        quit_item.connect("activate", lambda *_: self.on_quit())
        menu.append(quit_item)
        menu.show_all()
        return menu

    def set_enforcing(self, on):
        if self._enforce_item is not None:
            self._enforce_item.handler_block(self._enforce_handler)
            self._enforce_item.set_active(bool(on))
            self._enforce_item.handler_unblock(self._enforce_handler)
        if self.indicator and _HAVE_INDICATOR:
            icon = "security-high-symbolic" if on else "security-medium-symbolic"
            self.indicator.set_icon_full(icon, "GeoNetMon")
