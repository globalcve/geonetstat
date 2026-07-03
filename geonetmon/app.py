"""Gtk.Application: wires up the window, CSS, and global actions."""

import sys
import time

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Gio, Gdk, GLib  # noqa: E402

from . import __app_id__
from . import themes
from .config import Config
from .window import MainWindow
from . import tray as tray_mod


class GeoNetMonApp(Gtk.Application):
    def __init__(self):
        super().__init__(
            application_id=__app_id__,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.config = Config()
        self.win = None
        self._css_provider = None
        self._tray = None
        self._held = False
        # Start locked only when the launch-lock is on; "Lock now" can re-lock
        # any session that has a password set, even with the launch-lock off.
        self._unlocked = not (self.config.get("app_lock_enabled")
                              and self.config.get("app_lock_hash"))
        self._lock_win = None
        self._last_activity = time.time()

    def do_startup(self):
        Gtk.Application.do_startup(self)
        self._load_css()
        GLib.timeout_add_seconds(30, self._idle_lock_check)
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self._real_quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Primary>q"])
        self.set_accels_for_action("win.preferences", ["<Primary>comma"])
        show_prompt = Gio.SimpleAction.new("show-prompt", None)
        show_prompt.connect("activate", self._on_show_prompt)
        self.add_action(show_prompt)
        self._maybe_tray()

    def _on_show_prompt(self, *_):
        """Notification click — raise only the prompt window, not the full app."""
        if self.win and self.win._prompt_win:
            self.win._prompt_win.present()

    def _maybe_tray(self):
        # Prefer the native SNI tray (works in a GTK4 process and carries the
        # right-click menu); fall back to the appindicator wrapper.
        try:
            from . import tray_sni
            if tray_sni.available():
                self._tray = tray_sni.SNITray(
                    __app_id__,
                    on_show=self._present_window,
                    on_toggle_pause=self._tray_toggle_pause,
                    on_toggle_enforce=self._tray_toggle_enforce,
                    on_lock=self.lock_now,
                    on_quit=self._real_quit,
                    get_state=self._tray_state,
                )
                return
        except Exception:  # noqa: BLE001 — tray is best-effort
            self._tray = None
        if not tray_mod.available():
            return
        try:
            self._tray = tray_mod.Tray(
                __app_id__,
                on_show=self._present_window,
                on_toggle_enforce=self._tray_toggle_enforce,
                on_quit=self._real_quit,
            )
        except Exception:  # noqa: BLE001 — tray is best-effort
            self._tray = None

    def _tray_state(self):
        """Fresh state for the tray menu (pulled on every menu open)."""
        win = self.win
        return {
            "paused": bool(win and win.paused),
            "enforcing": bool(win and win.btn_shield.get_active()),
            "lock": bool(self.config.get("app_lock_hash")),
        }

    def _tray_toggle_pause(self, on):
        if self.win:
            self.win.btn_pause.set_active(bool(on))

    def _present_window(self):
        if self._locked():
            self._present_lock()
            return
        if not self.win:
            self.win = MainWindow(self, self.config)
        self.win.present()

    # ---- app-lock (optional password gate, see applock.py) --------------
    def _locked(self):
        return bool(self.config.get("app_lock_hash") and not self._unlocked)

    def _present_lock(self):
        if self._lock_win is None:
            from .applock import LockWindow
            self._lock_win = LockWindow(
                self, self.config["app_lock_hash"], self._on_unlocked)
        self._lock_win.present()

    def _on_unlocked(self):
        self._unlocked = True
        self._lock_win = None
        self.activate()

    def lock_now(self):
        """Menu action: hide the main window behind the lock screen again."""
        if not self.config.get("app_lock_hash"):
            return
        self._unlocked = False
        if self.win:
            self.win.set_visible(False)
        self._present_lock()

    def touch_activity(self):
        """Called by the main window on any input — resets the idle clock."""
        self._last_activity = time.time()

    def _idle_lock_check(self):
        mins = int(self.config.get("app_lock_idle_min") or 0)
        if (not mins or not self.config.get("app_lock_hash")
                or self._locked()):
            return True
        if time.time() - self._last_activity < mins * 60:
            return True
        # Idle limit hit: re-lock. If the window is hidden (background mode),
        # lock silently — the gate appears on the next Show instead of popping
        # a lock screen out of nowhere.
        self._unlocked = False
        if self.win and self.win.get_visible():
            self.win.set_visible(False)
            self._present_lock()
        return True

    def _tray_toggle_enforce(self, on):
        if self.win:
            self.win.btn_shield.set_active(on)

    def _real_quit(self):
        if self._tray is not None and hasattr(self._tray, "close"):
            try:
                self._tray.close()
            except Exception:  # noqa: BLE001 — never let the tray block quit
                pass
            self._tray = None
        if self._held:
            self.release()
            self._held = False
        self.quit()

    def do_activate(self):
        if self._locked():
            self._present_lock()
            return
        if not self.win:
            self.win = MainWindow(self, self.config)
        self.win.present()
        # In background mode, hold the app so it survives window close.
        if self.config.get("run_in_background") and not self._held:
            self.hold()
            self._held = True

    def _load_css(self):
        provider = Gtk.CssProvider()
        display = Gdk.Display.get_default()
        if not display:
            return
        # USER priority (not APPLICATION): GTK's default theme styles the
        # headerbar/window-controls strongly, and APPLICATION priority loses to
        # it for some nodes (the "white header bar" bug). USER overrides the
        # theme reliably.
        Gtk.StyleContext.add_provider_for_display(
            display, provider,
            Gtk.STYLE_PROVIDER_PRIORITY_USER,
        )
        self._css_provider = provider
        self.apply_theme()

    def apply_theme(self):
        """(Re)build CSS for the configured theme and apply it live."""
        if not self._css_provider:
            return
        theme = self.config.get("theme", "system")
        # Make GTK fall back to its DARK variant for any widget our CSS doesn't
        # explicitly style (plain buttons, menus, etc.) so they don't render
        # white on a dark theme. 'system' follows the desktop; Latte is light.
        settings = Gtk.Settings.get_default()
        if settings is not None and theme != "system":
            settings.set_property("gtk-application-prefer-dark-theme",
                                  themes.is_dark(theme))
        css = themes.build_css(theme, self.config.get("accent", ""))
        try:
            self._css_provider.load_from_string(css)
        except AttributeError:
            # Older GTK4 without load_from_string
            self._css_provider.load_from_data(css.encode("utf-8"))
        except GLib.Error:
            pass

    def do_shutdown(self):
        if self.win:
            if self.win.engine:
                self.win.engine.stop()
            if getattr(self.win, "using_daemon", False):
                # Quitting disarms the daemon firewall (full stop). No-ops if the
                # window's own teardown already closed the socket.
                self.win.daemon.on_disconnect = None
                self.win.daemon.set_enforce(False)
                self.win.daemon.close()
            self.win.rules.save()
            self.win.enricher.shutdown()
            self.win.alerts.save()
            self.win.firewall.save()
            self.win.history.close()
        self.config.save()
        Gtk.Application.do_shutdown(self)


def main():
    app = GeoNetMonApp()
    return app.run(sys.argv)
