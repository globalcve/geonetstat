"""World connection map — equirectangular projection with arc rendering.

Layout:
  ┌─────────────────────────────┬──────────────────────────┐
  │   WorldMap (Cairo canvas)   │  Connection list sidebar  │
  │                             │  (scrolled, click to pick)│
  ├─────────────────────────────┴──────────────────────────┤
  │   Selected-endpoint detail panel                        │
  └─────────────────────────────────────────────────────────┘
"""

import math

from gi.repository import Gtk, Gdk, GLib, Pango

from .world_outline import COASTLINE


# ── projection helpers ────────────────────────────────────────────────────────

def project(lon, lat, width, height):
    x = (lon + 180.0) / 360.0 * width
    y = (90.0 - lat) / 180.0 * height
    return x, y


def great_circle_points(lon1, lat1, lon2, lat2, segments=48):
    p1 = _to_xyz(lon1, lat1)
    p2 = _to_xyz(lon2, lat2)
    dot = max(-1.0, min(1.0, sum(a * b for a, b in zip(p1, p2))))
    omega = math.acos(dot)
    if omega < 1e-6:
        yield (lon1, lat1)
        yield (lon2, lat2)
        return
    sin_omega = math.sin(omega)
    for i in range(segments + 1):
        t = i / segments
        a = math.sin((1 - t) * omega) / sin_omega
        b = math.sin(t * omega) / sin_omega
        x, y, z = (a * p1[k] + b * p2[k] for k in range(3))
        yield _to_lonlat(x, y, z)


def _to_xyz(lon, lat):
    rlon, rlat = math.radians(lon), math.radians(lat)
    return (math.cos(rlat) * math.cos(rlon),
            math.cos(rlat) * math.sin(rlon),
            math.sin(rlat))


def _to_lonlat(x, y, z):
    lat = math.degrees(math.asin(max(-1.0, min(1.0, z))))
    lon = math.degrees(math.atan2(y, x))
    return lon, lat


def _split_antimeridian(pts, width):
    runs, cur, prev_x = [], [], None
    for (lon, lat) in pts:
        if prev_x is not None and abs(lon - prev_x) > 180:
            runs.append(cur)
            cur = []
        cur.append((lon, lat))
        prev_x = lon
    if cur:
        runs.append(cur)
    return runs


# ── WorldMap drawing area ──────────────────────────────────────────────────────

# Packet-flow animation: how fast a "packet" traverses an arc (fraction of the
# path per second) and which direction it travels. Outbound flows Home→peer;
# inbound flows peer→Home; risky traffic moves faster to draw the eye.
_FLOW_SPEED = {"out": 0.30, "in": 0.30, "foreign": 0.34, "risk": 0.55}
_FLOW_REVERSE = {"in"}            # endpoint → Home
_FLOW_PACKETS = 3                 # evenly spaced packets per arc
_FLOW_TRAIL = 4                   # comet-trail dots behind each packet


class WorldMap(Gtk.DrawingArea):
    def __init__(self):
        super().__init__()
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_content_height(320)
        self._home = None
        self._points = []
        self._theme = "dark"
        self._hot = []
        self._selected = None
        self._on_pick = None
        self._on_right_pick = None
        self._now = 0.0              # wall-clock seconds, advanced by the frame clock
        self.set_draw_func(self._draw)
        self.add_tick_callback(self._on_tick)
        click = Gtk.GestureClick()
        click.connect("pressed", self._on_click)
        self.add_controller(click)
        rclick = Gtk.GestureClick()
        rclick.set_button(3)
        rclick.connect("pressed", self._on_right_click)
        self.add_controller(rclick)

    def set_on_pick(self, cb):
        self._on_pick = cb

    def set_on_right_pick(self, cb):
        self._on_right_pick = cb

    def select_point(self, p):
        self._selected = p
        self.queue_draw()

    def _nearest_point(self, x, y):
        best, bestd = None, 18.0 ** 2
        for hx, hy, p in self._hot:
            d = (hx - x) ** 2 + (hy - y) ** 2
            if d <= bestd:
                best, bestd = p, d
        return best

    def _on_click(self, _gesture, _n, x, y):
        best = self._nearest_point(x, y)
        self._selected = best
        self.queue_draw()
        if self._on_pick:
            self._on_pick(best)

    def _on_right_click(self, gesture, _n, x, y):
        best = self._nearest_point(x, y)
        if best and self._on_right_pick:
            gesture.set_state(Gtk.EventSequenceState.CLAIMED)
            self._on_right_pick(best, x, y, self)

    def set_home(self, lon, lat):
        self._home = (lon, lat)
        self.queue_draw()

    def set_points(self, points):
        self._points = list(points)
        self.queue_draw()

    def set_theme_dark(self, dark):
        self._theme = "dark" if dark else "light"
        self.queue_draw()

    def _on_tick(self, _widget, clock):
        # Drive the packet animation off the monotonic frame clock so motion is
        # wall-clock paced regardless of frame rate. Only redraw when there is
        # something to animate (arcs need a Home + endpoints) so an idle map
        # doesn't burn CPU repainting every frame.
        self._now = clock.get_frame_time() / 1_000_000.0
        if self._home and self._points:
            self.queue_draw()
        return GLib.SOURCE_CONTINUE

    def _colors(self):
        if self._theme == "dark":
            return {
                "bg":        (0.08, 0.09, 0.13),
                "land":      (0.18, 0.21, 0.28),
                "land_line": (0.30, 0.34, 0.42),
                "home":      (0.36, 0.78, 0.95),
                "out":       (0.36, 0.65, 0.86),
                "in":        (0.91, 0.67, 0.30),
                "foreign":   (1.0,  0.55, 0.30),
                "risk":      (0.90, 0.30, 0.30),
            }
        return {
            "bg":        (0.96, 0.97, 0.99),
            "land":      (0.86, 0.89, 0.93),
            "land_line": (0.70, 0.74, 0.80),
            "home":      (0.12, 0.45, 0.80),
            "out":       (0.20, 0.45, 0.75),
            "in":        (0.80, 0.50, 0.10),
            "foreign":   (0.90, 0.40, 0.10),
            "risk":      (0.80, 0.15, 0.15),
        }

    def _draw(self, _area, ctx, width, height, *_):
        col = self._colors()
        ctx.set_source_rgb(*col["bg"])
        ctx.rectangle(0, 0, width, height)
        ctx.fill()

        ctx.set_line_width(0.8)
        for shape in COASTLINE:
            ctx.new_path()
            started = False
            for (lon, lat) in shape:
                x, y = project(lon, lat, width, height)
                if not started:
                    ctx.move_to(x, y)
                    started = True
                else:
                    ctx.line_to(x, y)
            ctx.set_source_rgb(*col["land"])
            ctx.fill_preserve()
            ctx.set_source_rgb(*col["land_line"])
            ctx.stroke()

        self._hot = []

        if self._home:
            hlon, hlat = self._home
            hx, hy = project(hlon, hlat, width, height)
            for p in self._points:
                c = col.get(p.get("kind", "out"), col["out"])
                pts = list(great_circle_points(hlon, hlat, p["lon"], p["lat"]))
                selected = (p is self._selected)
                ctx.set_line_width(1.8 if selected else 1.0)
                ctx.set_source_rgba(*c, 0.75 if selected else 0.40)
                for run in _split_antimeridian(pts, width):
                    started = False
                    for (lon, lat) in run:
                        x, y = project(lon, lat, width, height)
                        if not started:
                            ctx.move_to(x, y)
                            started = True
                        else:
                            ctx.line_to(x, y)
                    ctx.stroke()
                self._draw_flow(ctx, pts, width, height, c, p.get("kind", "out"))
                self._dot(ctx, p, width, height, col)

            ctx.set_source_rgb(*col["home"])
            ctx.arc(hx, hy, 5.0, 0, 2 * math.pi)
            ctx.fill()
            ctx.set_source_rgba(*col["home"], 0.35)
            ctx.arc(hx, hy, 9.0, 0, 2 * math.pi)
            ctx.stroke()
        else:
            for p in self._points:
                self._dot(ctx, p, width, height, col)

    def _draw_flow(self, ctx, pts, width, height, color, kind):
        """Animate glowing packets travelling along one arc's polyline.

        ``pts`` runs Home→endpoint; outbound packets ride it forward, inbound
        ones backward. Each packet trails a few fading dots (a comet). Segments
        that wrap the antimeridian (a big horizontal jump) are skipped so a
        packet never streaks across the whole map."""
        n = len(pts)
        if n < 2:
            return
        sp = [project(lon, lat, width, height) for (lon, lat) in pts]
        speed = _FLOW_SPEED.get(kind, 0.30)
        reverse = kind in _FLOW_REVERSE
        base = self._now * speed
        for i in range(_FLOW_PACKETS):
            head = (base + i / _FLOW_PACKETS) % 1.0
            for t_off in range(_FLOW_TRAIL):
                t = head - t_off * 0.018
                if t < 0.0:
                    continue
                tt = (1.0 - t) if reverse else t
                pos = tt * (n - 1)
                seg = min(int(pos), n - 2)
                (x0, y0), (x1, y1) = sp[seg], sp[seg + 1]
                frac = pos - seg
                # Antimeridian: the great circle leaves one edge and re-enters
                # the other. Unwrap the segment so the packet keeps moving the
                # short way across the seam, then fold the result back onto the
                # map — the packet flows visibly OVER the edge instead of
                # popping out of existence.
                dx = x1 - x0
                if dx > width * 0.5:
                    x1 -= width
                elif dx < -width * 0.5:
                    x1 += width
                x = (x0 + (x1 - x0) * frac) % width
                y = y0 + (y1 - y0) * frac
                alpha = 0.9 * (1.0 - t_off / _FLOW_TRAIL)
                r = 2.6 if t_off == 0 else max(1.0, 2.6 - t_off * 0.5)
                ctx.set_source_rgba(*color, alpha)
                ctx.arc(x, y, r, 0, 2 * math.pi)
                ctx.fill()

    def _dot(self, ctx, p, width, height, col):
        c = col.get(p.get("kind", "out"), col["out"])
        ex, ey = project(p["lon"], p["lat"], width, height)
        self._hot.append((ex, ey, p))
        selected = (p is self._selected)
        if selected:
            ctx.set_source_rgba(1, 1, 1, 0.9)
            ctx.arc(ex, ey, 7.0, 0, 2 * math.pi)
            ctx.fill()
        ctx.set_source_rgba(*c, 0.95)
        ctx.arc(ex, ey, 4.5 if selected else 3.0, 0, 2 * math.pi)
        ctx.fill()


# ── MapWindow ─────────────────────────────────────────────────────────────────

_KIND_LABEL = {
    "out":     "OUTGOING",
    "in":      "INCOMING",
    "foreign": "FOREIGN",
    "risk":    "HIGH RISK",
}
_KIND_COLOR = {
    "out":     "#5ba6dc",
    "in":      "#e8ab4d",
    "foreign": "#ff8c4d",
    "risk":    "#e64d4d",
}


class MapWindow(Gtk.Window):
    def __init__(self, parent, get_points, home=None, dark=True):
        super().__init__(title="Connection map", transient_for=parent)
        self.set_default_size(1100, 560)
        self._parent_win = parent   # MainWindow ref for firewall actions
        self._get_points = get_points
        self._dark = dark
        self._rows = {}           # ip -> Gtk.ListBoxRow for the sidebar
        self._filter_kind = None  # None = show all

        # ── root layout ──────────────────────────────────────────────────────
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_child(vbox)

        # toolbar
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        toolbar.set_margin_start(10)
        toolbar.set_margin_end(10)
        toolbar.set_margin_top(6)
        toolbar.set_margin_bottom(4)
        vbox.append(toolbar)

        self._count_label = Gtk.Label(xalign=0, hexpand=True)
        self._count_label.add_css_class("dim-label")
        toolbar.append(self._count_label)

        for label, kind in [("All", None), ("Outgoing", "out"),
                             ("Incoming", "in"), ("Foreign", "foreign")]:
            b = Gtk.ToggleButton(label=label)
            b.set_active(kind is None)
            b.connect("toggled", self._on_filter, kind)
            toolbar.append(b)
        self._filter_btns = toolbar

        # main horizontal split: map | sidebar
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_vexpand(True)
        vbox.append(paned)

        # ── left: map ────────────────────────────────────────────────────────
        map_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.map = WorldMap()
        self.map.set_theme_dark(dark)
        if home:
            self.map.set_home(*home)
        self.map.set_on_pick(self._on_map_pick)
        self.map.set_on_right_pick(self._on_map_right_click)
        map_box.append(self.map)

        paned.set_start_child(map_box)
        paned.set_resize_start_child(True)
        paned.set_shrink_start_child(False)

        # ── right: sidebar ───────────────────────────────────────────────────
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar.set_size_request(280, -1)

        hdr = Gtk.Label(label="Active endpoints", xalign=0)
        hdr.add_css_class("heading")
        hdr.set_margin_start(8)
        hdr.set_margin_top(6)
        hdr.set_margin_bottom(4)
        sidebar.append(hdr)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self._listbox = Gtk.ListBox()
        self._listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._listbox.connect("row-activated", self._on_list_pick)
        scroll.set_child(self._listbox)
        sidebar.append(scroll)
        paned.set_end_child(sidebar)
        paned.set_resize_end_child(False)
        paned.set_shrink_end_child(False)

        # ── bottom: detail panel ─────────────────────────────────────────────
        self._detail = _DetailPanel()
        self._detail.set_visible(False)
        vbox.append(self._detail)

        self.refresh()
        self._timer = GLib.timeout_add_seconds(3, self._tick)
        self.connect("close-request", self._on_close)

    # ── data refresh ─────────────────────────────────────────────────────────

    def refresh(self):
        points = self._get_points()

        kind_filter = self._filter_kind
        shown = [p for p in points
                 if kind_filter is None or p.get("kind") == kind_filter]

        self.map.set_points(shown)
        self._rebuild_list(shown)

        counts = {}
        for p in points:
            counts[p.get("kind", "out")] = counts.get(p.get("kind", "out"), 0) + 1
        parts = [f"{v} {_KIND_LABEL.get(k, k).lower()}"
                 for k, v in sorted(counts.items())]
        self._count_label.set_text(f"{len(points)} endpoints — " + ", ".join(parts)
                                   if parts else "No geolocated endpoints yet")

    def _rebuild_list(self, points):
        # remove rows no longer present
        current_ips = {p["ip"] for p in points if "ip" in p}
        for ip in list(self._rows):
            if ip not in current_ips:
                row = self._rows.pop(ip)
                self._listbox.remove(row)

        # add or update
        for p in points:
            ip = p.get("ip", "")
            if ip in self._rows:
                # update the label in the existing row
                row = self._rows[ip]
                row._point = p
                row.get_child().update(p)
            else:
                cell = _SidebarCell(p)
                row = Gtk.ListBoxRow()
                row._point = p
                row.set_child(cell)
                rc = Gtk.GestureClick()
                rc.set_button(3)
                rc.connect("pressed", self._on_row_right_click, row)
                row.add_controller(rc)
                self._listbox.append(row)
                self._rows[ip] = row

    # ── interactions ─────────────────────────────────────────────────────────

    def _on_map_pick(self, p):
        if p is None:
            self._detail.set_visible(False)
            self._listbox.unselect_all()
            return
        self._detail.set_visible(True)
        self._detail.show_point(p)
        ip = p.get("ip", "")
        row = self._rows.get(ip)
        if row:
            self._listbox.select_row(row)
            row.grab_focus()

    def _on_list_pick(self, _lb, row):
        p = getattr(row, "_point", None)
        if p is None:
            return
        self._detail.set_visible(True)
        self._detail.show_point(p)
        self.map.select_point(p)

    def _on_filter(self, btn, kind):
        if not btn.get_active():
            return
        # deactivate other filter buttons
        child = self._filter_btns.get_first_child()
        while child:
            if isinstance(child, Gtk.ToggleButton) and child is not btn:
                child.handler_block_by_func(self._on_filter)
                child.set_active(False)
                child.handler_unblock_by_func(self._on_filter)
            child = child.get_next_sibling()
        self._filter_kind = kind
        self.refresh()

    def _on_map_right_click(self, p, x, y, widget):
        self._show_point_menu(p, widget, x, y)

    def _on_row_right_click(self, gesture, _n, x, y, row):
        p = getattr(row, "_point", None)
        if p:
            gesture.set_state(Gtk.EventSequenceState.CLAIMED)
            self._show_point_menu(p, row, x, y)

    def _show_point_menu(self, p, anchor, x, y):
        from gi.repository import Gdk
        popover = Gtk.Popover()
        popover.set_parent(anchor)
        popover.set_pointing_to(Gdk.Rectangle(x=int(x), y=int(y), width=1, height=1))
        popover.set_has_arrow(True)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        box.set_margin_start(4)
        box.set_margin_end(4)
        popover.set_child(box)

        def add_btn(label, cb, destructive=False, suggested=False):
            b = Gtk.Button(label=label)
            b.set_has_frame(False)
            if destructive:
                b.add_css_class("destructive-action")
            if suggested:
                b.add_css_class("suggested-action")
            b.connect("clicked", lambda *_: [popover.popdown(), cb()])
            box.append(b)

        verdict = p.get("verdict", "")
        app = p.get("app", "")
        ip = p.get("ip", "")

        if verdict == "allow":
            add_btn(f"Deny app  ({app})",
                    lambda: self._map_rule(p, "deny"), destructive=True)
        else:
            add_btn(f"Allow app  ({app})",
                    lambda: self._map_rule(p, "allow"), suggested=True)

        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            blockable = not (addr.is_loopback or addr.is_private
                             or addr.is_unspecified or addr.is_link_local)
        except ValueError:
            blockable = False

        if blockable:
            win = self._parent_win
            blocked = win.firewall.is_blocked(ip) if win else False
            add_btn(f"{'Unblock' if blocked else 'Block'} IP  {ip}",
                    lambda: self._map_block_ip(ip, blocked),
                    destructive=not blocked)

        if not box.get_first_child():
            add_btn("No actions available", lambda: None)

        popover.popup()

    def _map_rule(self, p, action):
        win = self._parent_win
        if win is None:
            return
        flow = {
            "process": p.get("app", ""),
            "process_path": "",
            "dst_host": p.get("ip", ""),
            "dst_ip": p.get("ip", ""),
            "dst_port": p.get("port") or 0,
            "proto": "tcp",
        }
        if win.using_daemon:
            win.daemon.add_rule(flow, action, "forever", "app_any")
        else:
            win.rules.build_from_choice(flow, action, "forever", "app_any")
        p["verdict"] = action

    def _map_block_ip(self, ip, currently_blocked):
        win = self._parent_win
        if win is None:
            return
        if currently_blocked:
            win.firewall.unblock(ip, on_done=lambda ok, msg: None)
        else:
            win.firewall.block(ip, on_done=lambda ok, msg: None)

    def _tick(self):
        self.refresh()
        return True

    def _on_close(self, *_):
        if self._timer:
            GLib.source_remove(self._timer)
            self._timer = 0
        return False


# ── sidebar cell ──────────────────────────────────────────────────────────────

class _SidebarCell(Gtk.Box):
    def __init__(self, p):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        self.set_margin_top(5)
        self.set_margin_bottom(5)
        self.set_margin_start(8)
        self.set_margin_end(8)

        self._top = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self._top.add_css_class("bold")
        self.append(self._top)

        self._sub = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        self._sub.add_css_class("dim-label")
        self._sub.set_use_markup(True)
        self.append(self._sub)

        self.update(p)

    def update(self, p):
        kind = p.get("kind", "out")
        app = p.get("app") or "Unknown"
        direction = _KIND_LABEL.get(kind, kind)
        verdict = p.get("verdict", "")
        verdict_str = f"  [{verdict}]" if verdict else ""

        self._top.set_text(f"{app}{verdict_str}")

        org = p.get("org") or ""
        loc = p.get("label") or ""
        ip = p.get("ip") or ""
        geo = ", ".join(x for x in [loc, org] if x) or ip
        color = _KIND_COLOR.get(kind, "#888888")
        self._sub.set_markup(
            f"<span foreground='{color}'>{direction}</span>"
            f"  <small>{geo}</small>"
        )


# ── detail panel ─────────────────────────────────────────────────────────────

class _DetailPanel(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        self.set_margin_start(12)
        self.set_margin_end(12)
        self.set_margin_top(6)
        self.set_margin_bottom(8)

        self._fields = {}
        grid = Gtk.Grid(column_spacing=12, row_spacing=4)
        self.append(grid)

        cols = [
            ("Application", "app"),
            ("Direction",   "direction"),
            ("IP",          "ip"),
            ("Organization","org"),
            ("Location",    "label"),
            ("Service",     "service"),
            ("Port",        "port"),
            ("Verdict",     "verdict"),
        ]
        for i, (title, key) in enumerate(cols):
            col = i % 4
            row = i // 4
            lbl = Gtk.Label(label=title, xalign=0)
            lbl.add_css_class("dim-label")
            val = Gtk.Label(label="—", xalign=0, selectable=True)
            val.add_css_class("bold")
            grid.attach(lbl, col * 2,     row, 1, 1)
            grid.attach(val, col * 2 + 1, row, 1, 1)
            self._fields[key] = val

        self.clear()

    def clear(self):
        for val in self._fields.values():
            val.set_text("—")

    def show_point(self, p):
        direction = _KIND_LABEL.get(p.get("kind", "out"), "—")
        port = str(p.get("port", "")) if p.get("port") else "—"
        verdict = p.get("verdict", "") or "—"
        mapping = {
            "app":       p.get("app") or "—",
            "direction": direction,
            "ip":        p.get("ip") or "—",
            "org":       p.get("org") or "—",
            "label":     p.get("label") or "—",
            "service":   p.get("service") or "—",
            "port":      port,
            "verdict":   verdict,
        }
        for key, val in mapping.items():
            self._fields[key].set_text(val)
