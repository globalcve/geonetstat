"""Optional app-lock: a password gate on the GUI window itself.

Ported from Tesseract's app-lock. It protects casual access to the running
app; it is NOT encryption — the monitor's data and config stay readable on
disk. We store a salted PBKDF2-HMAC-SHA256 hash (stdlib; Tesseract uses
Argon2id, which has no stdlib equivalent) of the chosen password in the
config and verify against it. The lock screen carries no padlock
iconography — just the app icon, a title, and a password field.
"""

import hashlib
import hmac
import os

from gi.repository import Gtk

from .ui import escape_closes

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 600_000


def hash_password(password):
    """PHC-style hash string for a new app-lock password."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                             _ITERATIONS)
    return f"{_ALGO}${_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    """Check a password against a stored hash string."""
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != _ALGO:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk, bytes.fromhex(hash_hex))
    except (ValueError, TypeError, AttributeError):
        return False


class SetPasswordDialog(Gtk.Window):
    """Choose + confirm a password. Calls on_done(hash) or on_done(None)."""

    def __init__(self, parent, on_done):
        super().__init__(title="Set GeoNetMon password", transient_for=parent,
                         modal=True)
        self.set_default_size(360, -1)
        escape_closes(self)   # cancelling: close-request answers on_done(None)
        self.on_done = on_done
        self._replied = False

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(16)
        box.set_margin_bottom(16)
        box.set_margin_start(16)
        box.set_margin_end(16)
        self.set_child(box)

        self.entry = Gtk.PasswordEntry(show_peek_icon=True)
        self.entry.set_property("placeholder-text", "Password")
        box.append(self.entry)

        self.confirm = Gtk.PasswordEntry(show_peek_icon=True)
        self.confirm.set_property("placeholder-text", "Confirm password")
        self.confirm.connect("activate", self._on_set)
        box.append(self.confirm)

        self.error = Gtk.Label(label="", xalign=0)
        self.error.add_css_class("enc-bad")
        box.append(self.error)

        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btns.set_halign(Gtk.Align.END)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        btns.append(cancel)
        ok = Gtk.Button(label="Set password")
        ok.add_css_class("suggested-action")
        ok.connect("clicked", self._on_set)
        btns.append(ok)
        box.append(btns)

        self.connect("close-request", self._on_close)

    def _on_set(self, *_):
        pw = self.entry.get_text()
        if not pw:
            self.error.set_label("Password cannot be empty")
            return
        if pw != self.confirm.get_text():
            self.error.set_label("Passwords do not match")
            return
        self._replied = True
        cb = self.on_done
        self.close()
        cb(hash_password(pw))

    def _on_close(self, *_):
        if not self._replied:
            self._replied = True
            self.on_done(None)
        return False


class LockWindow(Gtk.ApplicationWindow):
    """App gate shown instead of the main window until the password matches."""

    def __init__(self, app, stored_hash, on_unlock):
        super().__init__(application=app, title="GeoNetMon")
        self.set_default_size(420, 320)
        self.set_resizable(False)
        self._hash = stored_hash
        self._on_unlock = on_unlock

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_valign(Gtk.Align.CENTER)
        box.set_halign(Gtk.Align.CENTER)
        self.set_child(box)

        logo = Gtk.Image.new_from_icon_name("geonetmon")
        logo.set_pixel_size(96)
        box.append(logo)

        title = Gtk.Label(label="GeoNetMon")
        title.add_css_class("heading")
        box.append(title)

        sub = Gtk.Label(label="Enter your password to unlock")
        sub.add_css_class("dim-label")
        box.append(sub)

        self.entry = Gtk.PasswordEntry(show_peek_icon=True)
        self.entry.set_size_request(240, -1)
        self.entry.connect("activate", self._try)
        box.append(self.entry)

        self.error = Gtk.Label(label="")
        self.error.add_css_class("enc-bad")
        box.append(self.error)

        btn = Gtk.Button(label="Unlock")
        btn.add_css_class("suggested-action")
        btn.set_halign(Gtk.Align.CENTER)
        btn.connect("clicked", self._try)
        box.append(btn)

        self.entry.grab_focus()

    def _try(self, *_):
        if verify_password(self.entry.get_text(), self._hash):
            cb = self._on_unlock
            self.destroy()
            cb()
        else:
            self.error.set_label("Wrong password")
            self.entry.set_text("")
            self.entry.grab_focus()
