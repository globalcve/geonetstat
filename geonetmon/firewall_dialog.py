"""Firewall manager: list blocked IPs, unblock them, or block a new one."""

import time

from gi.repository import Gtk



class FirewallWindow(Gtk.Window):
    def __init__(self, parent, firewall):
        super().__init__(title="Firewall — blocked IPs", transient_for=parent)
        self.set_default_size(560, 480)
        self.fw = firewall

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        for m in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{m}")(14)
        self.set_child(box)

        backend = self.fw.resolve_backend() or "none found"
        info = Gtk.Label(xalign=0, wrap=True)
        info.set_markup(
            f"Backend: <b>{backend}</b>. Rules are applied with pkexec "
            "(one prompt). iptables/nftables rules are not persistent across "
            "reboot on their own; ufw rules are."
        )
        info.add_css_class("dim-label")
        box.append(info)

        # add a manual block
        add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.entry_ip = Gtk.Entry(hexpand=True)
        self.entry_ip.set_placeholder_text("IP address to block (e.g. 203.0.113.9)")
        add_row.append(self.entry_ip)
        btn_add = Gtk.Button(label="Block")
        btn_add.add_css_class("destructive-action")
        btn_add.connect("clicked", self._on_add)
        add_row.append(btn_add)
        box.append(add_row)

        self.status = Gtk.Label(xalign=0)
        self.status.add_css_class("dim-label")
        box.append(self.status)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller.set_child(self.listbox)
        box.append(scroller)

        self._reload()

    def _reload(self):
        child = self.listbox.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.listbox.remove(child)
            child = nxt

        blocked = self.fw.list_blocked()
        if not blocked:
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label="Nothing blocked.", xalign=0,
                                    margin_top=8, margin_bottom=8,
                                    margin_start=8))
            self.listbox.append(row)
            return

        for ip, meta in blocked:
            row = Gtk.ListBoxRow()
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            for m in ("top", "bottom", "start", "end"):
                getattr(line, f"set_margin_{m}")(6)
            when = time.strftime("%Y-%m-%d %H:%M",
                                 time.localtime(meta.get("ts", 0)))
            lbl = Gtk.Label(xalign=0, hexpand=True)
            lbl.set_markup(f"<tt>{ip}</tt>  "
                           f"<span alpha='60%'>{meta.get('backend','')} · {when}</span>")
            line.append(lbl)
            btn = Gtk.Button(label="Unblock")
            btn.connect("clicked", self._on_unblock, ip)
            line.append(btn)
            row.set_child(line)
            self.listbox.append(row)

    def _on_add(self, _btn):
        ip = self.entry_ip.get_text().strip()
        if not ip:
            return
        self.status.set_text(f"Blocking {ip}…")
        self.fw.block(ip, on_done=self._after)
        self.entry_ip.set_text("")

    def _on_unblock(self, _btn, ip):
        self.status.set_text(f"Unblocking {ip}…")
        self.fw.unblock(ip, on_done=self._after)

    def _after(self, ok, msg):
        self.status.set_text(("✓ " if ok else "✗ ") + msg)
        self._reload()
        return False
