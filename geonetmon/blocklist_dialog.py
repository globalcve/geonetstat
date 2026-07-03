"""Blocklist subscriptions manager + rule import/export UI."""

import threading
import time

from gi.repository import Gtk, GLib

from .ui import escape_closes


SUGGESTED = [
    # Ads & tracking
    ("StevenBlack (ads + malware)",
     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    ("StevenBlack (ads + malware + social + porn)",
     "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts"),
    ("AdGuard DNS filter",
     "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"),
    ("OISD basic (ads + trackers)",
     "https://hosts.oisd.nl/basic"),
    ("OISD big (comprehensive)",
     "https://big.oisd.nl/"),
    ("Hagezi Pro (ads + malware + tracking)",
     "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt"),
    ("Hagezi Ultimate (strictest)",
     "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt"),
    ("Peter Lowe's ad servers",
     "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
    ("Disconnect.me trackers",
     "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"),
    # Malware & phishing
    ("URLhaus (malware distribution)",
     "https://urlhaus.abuse.ch/downloads/hostfile/"),
    ("Phishing Army",
     "https://phishing.army/download/phishing_army_blocklist.txt"),
    ("Hagezi Threat Intelligence Feeds",
     "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/tif.txt"),
    # Privacy
    ("EasyPrivacy (trackers)",
     "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt"),
    ("Fanboy's Annoyances",
     "https://adguardteam.github.io/HostlistsRegistry/assets/filter_122.txt"),
]


class BlocklistWindow(Gtk.Window):
    def __init__(self, parent, blocklist_mgr):
        super().__init__(title="Blocklist subscriptions", transient_for=parent)
        self.set_default_size(620, 540)
        escape_closes(self)
        self.mgr = blocklist_mgr

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        for m in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{m}")(14)
        self.set_child(box)

        info = Gtk.Label(xalign=0, wrap=True)
        info.add_css_class("dim-label")
        info.set_text("Subscribed lists become deny rules matched by domain. "
                      "Your own allow rules still win. Lists are fetched on "
                      "demand; large lists may take a moment.")
        box.append(info)

        add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.entry = Gtk.Entry(hexpand=True)
        self.entry.set_placeholder_text("Blocklist URL (hosts or domain format)")
        add_row.append(self.entry)
        add_btn = Gtk.Button(label="Add & fetch")
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._on_add)
        add_row.append(add_btn)
        box.append(add_row)

        # suggestions
        sug_hdr = Gtk.Label(label="Suggested lists (click to add):", xalign=0)
        sug_hdr.add_css_class("dim-label")
        box.append(sug_hdr)
        flow = Gtk.FlowBox()
        flow.set_selection_mode(Gtk.SelectionMode.NONE)
        flow.set_column_spacing(4)
        flow.set_row_spacing(4)
        flow.set_max_children_per_line(4)
        flow.set_homogeneous(False)
        for name, url in SUGGESTED:
            b = Gtk.Button(label=name)
            b.set_tooltip_text(url)
            b.connect("clicked", lambda _b, u=url: self._fetch(u))
            flow.append(b)
        box.append(flow)

        self.status = Gtk.Label(xalign=0)
        self.status.add_css_class("dim-label")
        box.append(self.status)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller.set_child(self.listbox)
        box.append(scroller)

        bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        refresh_all = Gtk.Button(label="Refresh all")
        refresh_all.connect("clicked", lambda *_: self._refresh_all())
        bottom.append(refresh_all)
        bottom.append(Gtk.Box(hexpand=True))
        close = Gtk.Button(label="Close")
        close.connect("clicked", lambda *_: self.close())
        bottom.append(close)
        box.append(bottom)

        self._reload()

    def _reload(self):
        child = self.listbox.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.listbox.remove(child)
            child = nxt
        if not self.mgr.subs:
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label="No subscriptions yet.", xalign=0,
                                    margin_top=10, margin_bottom=10,
                                    margin_start=8))
            self.listbox.append(row)
            return
        for url, meta in self.mgr.subs.items():
            row = Gtk.ListBoxRow()
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            for m in ("top", "bottom", "start", "end"):
                getattr(line, f"set_margin_{m}")(6)
            when = time.strftime("%Y-%m-%d %H:%M",
                                 time.localtime(meta.get("updated", 0)))
            lbl = Gtk.Label(xalign=0, hexpand=True, wrap=True)
            lbl.set_markup(f"<tt>{_esc(url)}</tt>\n<span alpha='60%'>"
                           f"{meta.get('count', 0)} domains · {when}</span>")
            line.append(lbl)
            ref = Gtk.Button(label="Refresh")
            ref.connect("clicked", lambda _b, u=url: self._fetch(u))
            line.append(ref)
            rm = Gtk.Button(label="Remove")
            rm.add_css_class("destructive-action")
            rm.connect("clicked", lambda _b, u=url: self._remove(u))
            line.append(rm)
            row.set_child(line)
            self.listbox.append(row)

    def _on_add(self, _btn):
        url = self.entry.get_text().strip()
        if url:
            self.entry.set_text("")
            self._fetch(url)

    def _fetch(self, url):
        self.status.set_text(f"Fetching {url} …")

        def worker():
            ok, msg = self.mgr.refresh(url)
            GLib.idle_add(self._after, ok, msg)
        threading.Thread(target=worker, daemon=True).start()

    def _refresh_all(self):
        self.status.set_text("Refreshing all subscriptions …")

        def worker():
            self.mgr.refresh_all()
            GLib.idle_add(self._after, True, "refreshed all")
        threading.Thread(target=worker, daemon=True).start()

    def _remove(self, url):
        self.mgr.remove(url)
        self._reload()

    def _after(self, ok, msg):
        self.status.set_text(("✓ " if ok else "✗ ") + msg)
        self._reload()
        return False


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
