"""Statistics dashboard — top apps / hosts / countries and an activity graph,
drawn from the SQLite history plus the live model.
"""


from gi.repository import Gtk

from . import ports
from .ui import escape_closes


_WINDOWS = [("Last hour", 3600), ("Last 24h", 86400),
            ("Last 7 days", 604800), ("Last 30 days", 2592000)]


class _BarList(Gtk.Box):
    """A titled horizontal-bar chart for (label, count) rows."""

    def __init__(self, title):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.set_hexpand(True)
        head = Gtk.Label(xalign=0, label=title)
        head.add_css_class("heading")
        self.append(head)
        self._rows_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.append(self._rows_box)

    def set_rows(self, rows, fmt_label=str):
        child = self._rows_box.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self._rows_box.remove(child)
            child = nxt
        if not rows:
            empty = Gtk.Label(xalign=0, label="No data yet.")
            empty.add_css_class("dim-label")
            self._rows_box.append(empty)
            return
        top = max((c for _l, c in rows), default=1) or 1
        for label, count in rows:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            name = Gtk.Label(xalign=0, label=fmt_label(label))
            name.set_size_request(150, -1)
            name.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
            row.append(name)
            bar = Gtk.ProgressBar()
            bar.set_fraction(count / top)
            bar.set_hexpand(True)
            bar.set_valign(Gtk.Align.CENTER)
            row.append(bar)
            cnt = Gtk.Label(xalign=1, label=str(count))
            cnt.set_size_request(48, -1)
            cnt.add_css_class("mono")
            row.append(cnt)
            self._rows_box.append(row)


class _Activity(Gtk.DrawingArea):
    """Line graph of recent connection-count samples."""

    def __init__(self):
        super().__init__()
        self.set_content_height(120)
        self.set_hexpand(True)
        self._series = []     # list of total counts
        self.set_draw_func(self._draw)

    def set_series(self, series):
        self._series = list(series)
        self.queue_draw()

    def _draw(self, _a, ctx, width, height, *_):
        ctx.set_source_rgba(0.5, 0.5, 0.5, 0.12)
        ctx.rectangle(0, 0, width, height)
        ctx.fill()
        data = self._series
        if len(data) < 2:
            return
        hi = max(data) or 1
        n = len(data)
        step = width / max(1, n - 1)
        ctx.set_line_width(1.6)
        ctx.set_source_rgba(0.36, 0.65, 0.86, 0.95)
        for i, v in enumerate(data):
            x = i * step
            y = height - (v / hi) * (height - 8) - 4
            if i == 0:
                ctx.move_to(x, y)
            else:
                ctx.line_to(x, y)
        ctx.stroke()
        # baseline fill
        ctx.line_to((n - 1) * step, height)
        ctx.line_to(0, height)
        ctx.close_path()
        ctx.set_source_rgba(0.36, 0.65, 0.86, 0.12)
        ctx.fill()


class StatsWindow(Gtk.Window):
    def __init__(self, parent, history, live_objs):
        super().__init__(title="Statistics", transient_for=parent)
        self.set_default_size(720, 640)
        escape_closes(self)
        self.history = history
        self.live_objs = live_objs
        self._window_secs = 86400

        scroller = Gtk.ScrolledWindow()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        for m in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{m}")(16)
        scroller.set_child(box)
        self.set_child(scroller)

        # time-window selector
        sel = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        sel.append(Gtk.Label(label="Window:", xalign=0))
        self.drop = Gtk.DropDown.new_from_strings([w[0] for w in _WINDOWS])
        self.drop.set_selected(1)
        self.drop.connect("notify::selected", self._on_window)
        sel.append(self.drop)
        self.summary = Gtk.Label(xalign=1, hexpand=True)
        self.summary.add_css_class("dim-label")
        sel.append(self.summary)
        box.append(sel)

        act_head = Gtk.Label(xalign=0, label="Tracked connections over time")
        act_head.add_css_class("heading")
        box.append(act_head)
        self.activity = _Activity()
        box.append(self.activity)

        self.apps = _BarList("Top applications")
        self.hosts = _BarList("Top remote hosts")
        self.countries = _BarList("Top countries")
        box.append(self.apps)
        box.append(self.hosts)
        box.append(self.countries)

        note = Gtk.Label(xalign=0, wrap=True)
        note.add_css_class("dim-label")
        if history.enabled():
            note.set_text("Counts are connection-appearance events logged since "
                          "GeoNetMon started. Data accumulates as connections "
                          "are seen; older sessions are kept for the history "
                          "retention period set in Preferences.")
        else:
            note.set_text("History logging is disabled — enable it in "
                          "Preferences → History to start accumulating data.")
        box.append(note)

        self.refresh()

    def _on_window(self, *_):
        self._window_secs = _WINDOWS[self.drop.get_selected()][1]
        self.refresh()

    def refresh(self):
        h = self.history
        secs = self._window_secs
        self.apps.set_rows(h.top_apps(secs, 10),
                           fmt_label=lambda s: s or "unknown")
        self.hosts.set_rows(h.top_hosts(secs, 10),
                            fmt_label=lambda s: s or "—")
        self.countries.set_rows(
            h.top_countries(secs, 10),
            fmt_label=lambda cc: f"{ports.flag_emoji((cc or '').upper())} "
                                 f"{ports.country_name((cc or '').upper())}")
        samples = [row[1] for row in h.recent_samples(180)]  # total column
        self.activity.set_series(samples)
        live = len(self.live_objs)
        total_events = h.event_count(secs)
        self.summary.set_text(f"{live} live · {total_events} events in window")
