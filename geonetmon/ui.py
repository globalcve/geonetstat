"""Small shared GTK helpers."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gtk  # noqa: E402


def escape_closes(win):
    """Close `win` when Escape is pressed.

    Plain Gtk.Window subclasses (all our secondary dialogs) don't respond to
    Escape by default — only Gtk.Dialog does, and we don't use it. Every
    dialog's close-request path already handles cleanup, so closing is always
    safe (the connection prompt, for instance, applies its timeout action).
    """
    ctrl = Gtk.EventControllerKey()

    def on_key(_ctrl, keyval, _keycode, _state):
        if keyval == Gdk.KEY_Escape:
            win.close()
            return True
        return False

    ctrl.connect("key-pressed", on_key)
    win.add_controller(ctrl)
