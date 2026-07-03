"""Colour themes for GeoNetMon.

Each palette defines the semantic ``gnm_*`` tokens that style.css references.
Themes other than ``system`` also recolour the main window chrome (window,
headerbar, column view, status bar, entries, popovers) so the app reads as a
cohesive themed surface (Dracula, Catppuccin, and the palettes ported from
Tesseract) without depending on libadwaita.

``system`` supplies only the accent tokens and leaves window chrome to the
user's existing GTK theme (respecting their light/dark preference).
"""

import os

# Ordered for the preferences drop-down. (id, human label)
# The block after Catppuccin is ported from Tesseract's theme set
# (vintage / cyberpunk / Gogh-derived terminal palettes).
THEME_CHOICES = [
    ("system", "System (follow desktop)"),
    ("dracula", "Dracula"),
    ("catppuccin-latte", "Catppuccin Latte"),
    ("catppuccin-frappe", "Catppuccin Frapp\u00e9"),
    ("catppuccin-macchiato", "Catppuccin Macchiato"),
    ("catppuccin-mocha", "Catppuccin Mocha"),
    ("adventure-time", "Adventure Time"),
    ("borland", "Borland"),
    ("c64", "Commodore 64"),
    ("fairy-floss-dark", "Fairy Floss Dark"),
    ("flat", "Flat"),
    ("gogh", "Gogh \u2014 Starry Night"),
    ("grass", "Grass"),
    ("gruvbox-material", "Gruvbox Material"),
    ("homebrew", "Homebrew"),
    ("kokuban", "Kokuban"),
    ("mono-cyan", "Mono Cyan"),
    ("neon-tessera", "Neon Tessera"),
    ("ocean", "Ocean"),
    ("vintage-light", "Vintage Light"),
]

_THEME_IDS = [tid for tid, _ in THEME_CHOICES]

# Semantic accent tokens for every theme.
#   new      new-connection flash
#   foreign  out-of-home-country host (also reused for the alert pulse)
#   dir_in / dir_out / listen   direction colours
#   enc_ok / enc_bad            encryption status
#   warn     privilege banner
_ACCENTS = {
    "system": {
        "new": "#ffd200", "foreign": "#e25822",
        "dir_in": "#c9821a", "dir_out": "#3a78c2", "listen": "#8a4fbd",
        "enc_ok": "#2e9d4f", "enc_bad": "#d04a3b", "warn": "#e6a700",
        "accent": "#3a78c2",
    },
    "dracula": {
        "new": "#f1fa8c", "foreign": "#ffb86c",
        "dir_in": "#ffb86c", "dir_out": "#8be9fd", "listen": "#bd93f9",
        "enc_ok": "#50fa7b", "enc_bad": "#ff5555", "warn": "#f1fa8c",
        "accent": "#8be9fd",
    },
    "catppuccin-latte": {
        "new": "#df8e1d", "foreign": "#fe640b",
        "dir_in": "#fe640b", "dir_out": "#1e66f5", "listen": "#8839ef",
        "enc_ok": "#40a02b", "enc_bad": "#d20f39", "warn": "#df8e1d",
        "accent": "#1e66f5",
    },
    "catppuccin-frappe": {
        "new": "#e5c890", "foreign": "#ef9f76",
        "dir_in": "#ef9f76", "dir_out": "#8caaee", "listen": "#ca9ee6",
        "enc_ok": "#a6d189", "enc_bad": "#e78284", "warn": "#e5c890",
        "accent": "#ca9ee6",
    },
    "catppuccin-macchiato": {
        "new": "#eed49f", "foreign": "#f5a97f",
        "dir_in": "#f5a97f", "dir_out": "#8aadf4", "listen": "#c6a0f6",
        "enc_ok": "#a6da95", "enc_bad": "#ed8796", "warn": "#eed49f",
        "accent": "#8bd5ca",
    },
    "catppuccin-mocha": {
        "new": "#f9e2af", "foreign": "#fab387",
        "dir_in": "#fab387", "dir_out": "#89b4fa", "listen": "#cba6f7",
        "enc_ok": "#a6e3a1", "enc_bad": "#f38ba8", "warn": "#f9e2af",
        "accent": "#89dceb",
    },
    # --- ported from Tesseract (accents derived from each palette's
    #     ok/warn/err/accent/accent2 roles; a few tones lightened where the
    #     source colour was unreadable on the window background) ---
    "adventure-time": {
        "new": "#e7b000", "foreign": "#e7741e",
        "dir_in": "#e7741e", "dir_out": "#5cf9ff", "listen": "#a39ac4",
        "enc_ok": "#4ab118", "enc_bad": "#ff4b58", "warn": "#e7b000",
        "accent": "#e7741e",
    },
    "borland": {
        "new": "#ffff4e", "foreign": "#ff5959",
        "dir_in": "#ffff4e", "dir_out": "#4fe9fc", "listen": "#b6b6e6",
        "enc_ok": "#4efa78", "enc_bad": "#ff5959", "warn": "#ffff4e",
        "accent": "#ffff4e",
    },
    "c64": {
        "new": "#bfce72", "foreign": "#e09952",
        "dir_in": "#e09952", "dir_out": "#67b6bd", "listen": "#9385c9",
        "enc_ok": "#6fca63", "enc_bad": "#c05a4e", "warn": "#bfce72",
        "accent": "#bfce72",
    },
    "fairy-floss-dark": {
        "new": "#ffea00", "foreign": "#ff857f",
        "dir_in": "#ffea00", "dir_out": "#c5a3ff", "listen": "#ffb8d1",
        "enc_ok": "#c2ffdf", "enc_bad": "#ff857f", "warn": "#ffea00",
        "accent": "#ffb8d1",
    },
    "flat": {
        "new": "#f1c40f", "foreign": "#e67e22",
        "dir_in": "#e67e22", "dir_out": "#3498db", "listen": "#9b59b6",
        "enc_ok": "#2ecc71", "enc_bad": "#e74c3c", "warn": "#f1c40f",
        "accent": "#3498db",
    },
    "gogh": {
        "new": "#f4cd3a", "foreign": "#d9603b",
        "dir_in": "#d9603b", "dir_out": "#5b8dd9", "listen": "#94a8cc",
        "enc_ok": "#6bbf59", "enc_bad": "#d9603b", "warn": "#f4cd3a",
        "accent": "#f4cd3a",
    },
    "grass": {
        "new": "#e7b000", "foreign": "#e05545",
        "dir_in": "#e7b000", "dir_out": "#7fd9b0", "listen": "#bcd6a0",
        "enc_ok": "#9bea6a", "enc_bad": "#e05545", "warn": "#e7b000",
        "accent": "#e7b000",
    },
    "gruvbox-material": {
        "new": "#d8a657", "foreign": "#e78a4e",
        "dir_in": "#e78a4e", "dir_out": "#7daea3", "listen": "#d3869b",
        "enc_ok": "#a9b665", "enc_bad": "#ea6962", "warn": "#d8a657",
        "accent": "#d8a657",
    },
    "homebrew": {
        "new": "#d0d000", "foreign": "#e0a000",
        "dir_in": "#e0a000", "dir_out": "#00d8b2", "listen": "#1f8a1f",
        "enc_ok": "#00c800", "enc_bad": "#ff4040", "warn": "#d0d000",
        "accent": "#00ff00",
    },
    "kokuban": {
        "new": "#f0e68c", "foreign": "#f2b4b4",
        "dir_in": "#f0e68c", "dir_out": "#a9c2af", "listen": "#d8c8f0",
        "enc_ok": "#a8d8a0", "enc_bad": "#f2a0a0", "warn": "#f0e68c",
        "accent": "#f2e9c8",
    },
    "mono-cyan": {
        "new": "#80e0e0", "foreign": "#e08585",
        "dir_in": "#80e0e0", "dir_out": "#5ce0e0", "listen": "#5c9a9a",
        "enc_ok": "#00d0a0", "enc_bad": "#e08585", "warn": "#80e0e0",
        "accent": "#00d0d0",
    },
    "neon-tessera": {
        "new": "#ffc400", "foreign": "#ff2ec4",
        "dir_in": "#ffc400", "dir_out": "#00e5ff", "listen": "#ff2ec4",
        "enc_ok": "#00ff9c", "enc_bad": "#ff3860", "warn": "#ffc400",
        "accent": "#00e5ff",
    },
    "ocean": {
        "new": "#ebcb8b", "foreign": "#d08770",
        "dir_in": "#d08770", "dir_out": "#8fa1b3", "listen": "#b48ead",
        "enc_ok": "#a3be8c", "enc_bad": "#bf616a", "warn": "#ebcb8b",
        "accent": "#8fa1b3",
    },
    "vintage-light": {
        "new": "#b07d3a", "foreign": "#a14d3a",
        "dir_in": "#b07d3a", "dir_out": "#4f7c74", "listen": "#7a6a55",
        "enc_ok": "#5f7d4f", "enc_bad": "#a14d3a", "warn": "#b07d3a",
        "accent": "#b07d3a",
    },
}

# Window-chrome palettes for the non-system themes.
#   bg base, fg text, bg_alt raised surface, sel selection, border lines
_CHROME = {
    "dracula": {
        "bg": "#282a36", "fg": "#f8f8f2", "bg_alt": "#21222c",
        "sel": "#44475a", "border": "#191a21",
    },
    "catppuccin-latte": {
        "bg": "#eff1f5", "fg": "#4c4f69", "bg_alt": "#e6e9ef",
        "sel": "#ccd0da", "border": "#bcc0cc",
    },
    "catppuccin-frappe": {
        "bg": "#303446", "fg": "#c6d0f5", "bg_alt": "#292c3c",
        "sel": "#414559", "border": "#232634",
    },
    "catppuccin-macchiato": {
        "bg": "#24273a", "fg": "#cad3f5", "bg_alt": "#1e2030",
        "sel": "#363a4f", "border": "#181926",
    },
    "catppuccin-mocha": {
        "bg": "#1e1e2e", "fg": "#cdd6f4", "bg_alt": "#181825",
        "sel": "#313244", "border": "#11111b",
    },
    # --- ported from Tesseract (bg=window, bg_alt=headerbar, sel=raised) ---
    "adventure-time": {
        "bg": "#1f1d45", "fg": "#f8dcc0", "bg_alt": "#17152f",
        "sel": "#34306a", "border": "#3a356f",
    },
    "borland": {
        "bg": "#0000a4", "fg": "#ffff80", "bg_alt": "#000084",
        "sel": "#1730c0", "border": "#2a40c4",
    },
    "c64": {
        "bg": "#40318d", "fg": "#cabdf2", "bg_alt": "#352978",
        "sel": "#5a4bb0", "border": "#5648a8",
    },
    "fairy-floss-dark": {
        "bg": "#3b364c", "fg": "#f8f8f2", "bg_alt": "#332f42",
        "sel": "#56506f", "border": "#564f6f",
    },
    "flat": {
        "bg": "#2c3e50", "fg": "#ecf0f1", "bg_alt": "#243342",
        "sel": "#3e5870", "border": "#3e5066",
    },
    "gogh": {
        "bg": "#0d1b34", "fg": "#e8eeff", "bg_alt": "#0a1628",
        "sel": "#1b3260", "border": "#21345f",
    },
    "grass": {
        "bg": "#13773d", "fg": "#fff0a5", "bg_alt": "#0f6234",
        "sel": "#239a55", "border": "#2a9a5e",
    },
    "gruvbox-material": {
        "bg": "#282828", "fg": "#d4be98", "bg_alt": "#1f1f1f",
        "sel": "#3c3836", "border": "#45403d",
    },
    "homebrew": {
        "bg": "#000000", "fg": "#00d000", "bg_alt": "#050505",
        "sel": "#122012", "border": "#103810",
    },
    "kokuban": {
        "bg": "#1f3526", "fg": "#f0f0e8", "bg_alt": "#192c1f",
        "sel": "#2f4c39", "border": "#315040",
    },
    "mono-cyan": {
        "bg": "#081414", "fg": "#c8f0f0", "bg_alt": "#040e0e",
        "sel": "#143030", "border": "#163838",
    },
    "neon-tessera": {
        "bg": "#0a0e14", "fg": "#d8e6f2", "bg_alt": "#070a10",
        "sel": "#161d29", "border": "#1d2735",
    },
    "ocean": {
        "bg": "#2b303b", "fg": "#c0c5ce", "bg_alt": "#232831",
        "sel": "#3e4855", "border": "#3e4855",
    },
    "vintage-light": {
        "bg": "#f6efe1", "fg": "#46392b", "bg_alt": "#efe5d0",
        "sel": "#e7dabf", "border": "#d8c8a8",
    },
}

_STRUCTURAL_PATH = os.path.join(os.path.dirname(__file__), "style.css")


def normalize(theme):
    """Return a known theme id, defaulting to 'system'."""
    return theme if theme in _THEME_IDS else "system"


def index_of(theme):
    """Drop-down index for a theme id."""
    theme = normalize(theme)
    return _THEME_IDS.index(theme)


def id_at(index):
    """Theme id for a drop-down index."""
    if 0 <= index < len(_THEME_IDS):
        return _THEME_IDS[index]
    return "system"


def _structural_css():
    try:
        with open(_STRUCTURAL_PATH, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _palette_block(theme):
    lines = []
    for name, value in _ACCENTS[theme].items():
        lines.append(f"@define-color gnm_{name} {value};")
    chrome = _CHROME.get(theme)
    if chrome:
        for name, value in chrome.items():
            lines.append(f"@define-color gnm_{name} {value};")
    return "\n".join(lines) + "\n"


def _chrome_css(theme):
    if theme not in _CHROME:
        return ""   # system theme: leave window chrome to the desktop
    return """
/* --- themed window chrome (%s) --- */
window { background-color: @gnm_bg; color: @gnm_fg; }
window > box, window > grid, scrolledwindow, .view { background-color: @gnm_bg; }

/* Header bar: GTK's default theme paints it with its own background/gradient,
   so explicitly clear background-image and recolour every node (headerbar, its
   windowhandle, and the legacy .titlebar) or it stays white. */
headerbar, headerbar > windowhandle, .titlebar {
    background-color: @gnm_bg_alt; background-image: none;
    color: @gnm_fg; box-shadow: none; border-bottom: 1px solid @gnm_border;
}
/* Toolbar buttons: flat + themed text + subtle hover — not default white chips. */
headerbar button, .titlebar button {
    background-color: transparent; background-image: none;
    color: @gnm_fg; border: none; box-shadow: none; text-shadow: none;
}
headerbar button:hover, .titlebar button:hover { background-color: @gnm_sel; }
headerbar button:checked, headerbar button:active,
.titlebar button:checked, .titlebar button:active { background-color: @gnm_sel; }
headerbar .title, headerbar label { color: @gnm_fg; }
/* Native min/max/close glyphs. */
windowcontrols button { background-color: transparent; color: @gnm_fg; }
windowcontrols button:hover { background-color: @gnm_sel; }

columnview { background-color: @gnm_bg; color: @gnm_fg; }
columnview > header { background-color: @gnm_bg_alt; }
columnview > header button {
    background-color: @gnm_bg_alt; color: @gnm_fg; border-color: @gnm_border;
}
columnview > listview > row { color: @gnm_fg; }
columnview > listview > row:selected { background-color: @gnm_sel; }
.statusbar { background-color: @gnm_bg_alt; color: @gnm_fg; }

/* Gtk.ListBox (Firewall rules, alert log, etc.) renders as `list`/`row`, NOT
   `listview` — without this it stays stock-white on a themed window. */
list, list > row, list > row > box { background-color: @gnm_bg; color: @gnm_fg; }
list > row:selected { background-color: @gnm_sel; }
list > row:hover { background-color: alpha(@gnm_sel, 0.5); }

/* Entries / search field — recolour the inner text node too. */
entry, entry > text, .search entry {
    background-color: @gnm_bg_alt; color: @gnm_fg; border-color: @gnm_border;
}
entry > text { background-color: transparent; }

/* Spin buttons (e.g. Refresh interval) + drop-downs/combos — these stayed
   white. Recolour the widget, its inner text/box, and its buttons + popup. */
spinbutton, spinbutton > text {
    background-color: @gnm_bg_alt; color: @gnm_fg; border-color: @gnm_border;
}
spinbutton > button { background-color: @gnm_bg_alt; color: @gnm_fg; border-color: @gnm_border; }
spinbutton > button:hover { background-color: @gnm_sel; }
dropdown, dropdown > button, combobox, combobox button, combobox box.linked > button {
    background-color: @gnm_bg_alt; color: @gnm_fg; border-color: @gnm_border;
    background-image: none;
}
dropdown > button:hover, combobox button:hover { background-color: @gnm_sel; }
dropdown popover > contents, dropdown listview,
dropdown listview row { background-color: @gnm_bg_alt; color: @gnm_fg; }
dropdown listview row:selected { background-color: @gnm_sel; }
scrolledwindow, viewport, .view, treeview, listview { background-color: @gnm_bg; }

/* Plain buttons (dialog Close/Clear/Add, etc.) — give them a themed surface so
   they don't fall back to the light desktop theme and render white. More
   specific rules (.suggested-action, .prompt-allow, headerbar button, .tl) win.
   Pin the radius like `switch` below: without it the desktop theme's radius
   clips our painted background and its light default bleeds through at the
   corners. */
button {
    background-color: @gnm_bg_alt; background-image: none;
    color: @gnm_fg; border: 1px solid @gnm_border;
    border-radius: 6px; box-shadow: none;
}
button:hover { background-color: @gnm_sel; }
/* Toggle buttons: the desktop theme paints :checked with its own
   background-image/gradient which bled through our flat colours — clear it
   explicitly and give checked toggles the accent everywhere (body toggles
   previously had NO checked style at all and stayed stock-white). */
button:checked, button.toggle:checked {
    background-color: @gnm_accent; background-image: none;
    color: @gnm_bg; border-color: transparent;
    border-radius: 6px; box-shadow: none;
}
button:checked:hover, button.toggle:checked:hover {
    background-color: alpha(@gnm_accent, 0.85);
}
button:disabled { color: alpha(@gnm_fg, 0.4); }

/* Popover menus (the hamburger menu / context menus) and their items. */
popover.menu > contents, popover.menu { background-color: @gnm_bg_alt; color: @gnm_fg; }
popover.menu modelbutton, modelbutton { background-color: transparent; color: @gnm_fg; }
popover.menu modelbutton:hover, modelbutton:hover { background-color: @gnm_sel; }
menu, menu > arrow, menu menuitem { background-color: @gnm_bg_alt; color: @gnm_fg; }
menu menuitem:hover { background-color: @gnm_sel; }

/* Accent — replace GTK's default blue on primary/active controls so every theme
   (especially light Latte) gets its own accent instead of stock blue. */
button.suggested-action, button.default {
    background-color: @gnm_accent; background-image: none;
    color: @gnm_bg; border: none; box-shadow: none;
}
button.suggested-action:hover, button.default:hover { background-color: alpha(@gnm_accent, 0.85); }
headerbar button:checked, headerbar togglebutton:checked,
.titlebar button:checked {
    background-color: @gnm_accent; background-image: none;
    color: @gnm_bg; border-radius: 6px; box-shadow: none; }
/* Shield active: colour the icon only — no filled box.
   Alert button unread: same — just recolour the icon, no background. */
headerbar button.toggle.enforcing {
    background-color: transparent; background-image: none;
    color: @gnm_warn; border: none; box-shadow: none; }
headerbar button.toggle.enforcing:hover {
    background-color: @gnm_sel; color: @gnm_warn; }
headerbar button.has-alerts {
    background-color: transparent; color: @gnm_warn; }
/* GtkSwitch: explicit background-image:none on every node so the GTK theme
   gradient cannot override our colours. OFF trough uses @gnm_sel (a visible
   raised surface) so the slider (@gnm_fg) always contrasts against it. */
switch {
    background-color: @gnm_sel;
    background-image: none;
    border: none;
    box-shadow: none;
    /* Pin the pill shape ourselves: without an explicit radius the trough
       inherits the desktop theme's, and the square bounding-box corners of our
       painted background reveal the light default underneath (the white
       "bleed" at the corners of the coloured pill). */
    border-radius: 9999px;
    min-width: 46px; min-height: 24px;
}
switch:checked {
    background-color: @gnm_accent;
    background-image: none;
    border-radius: 9999px;
}
switch slider {
    background-color: @gnm_fg;
    background-image: none;
    border-radius: 9999px;
    box-shadow: none;
    min-width: 18px; min-height: 18px;
    margin: 3px;
}
switch:checked slider {
    background-color: @gnm_bg;
    background-image: none;
}
/* Privacy-blur mode: keep text in DOM but make it unreadable visually. */
label.privacy-blur {
    color: transparent;
    text-shadow: 0 0 7px alpha(@gnm_fg, 0.90);
}
check:checked, radio:checked { background-color: @gnm_accent; color: @gnm_bg; border-color: @gnm_accent; }
*:link, button.link { color: @gnm_accent; }
entry:focus-within, entry:focus { border-color: @gnm_accent; }

/* Dialogs / pop-ups: GTK's theme sets label colours per its own light/dark
   guess, so on Latte (light) the text stayed white-on-white. Force readable
   text + a themed surface on every window, dialog, popover and label. The
   semantic colour classes (.foreign, .dir-out, …) out-specify plain `label`,
   so they keep their colours. */
label { color: @gnm_fg; }
window, dialog, messagedialog, .background, .csd {
    background-color: @gnm_bg; color: @gnm_fg;
}
popover > contents { background-color: @gnm_bg_alt; color: @gnm_fg; }
popover > arrow { background-color: @gnm_bg_alt; }
popover label, popover { color: @gnm_fg; }
""" % theme


# Catppuccin accent palette (Mocha hexes — vivid on every dark flavour).
ACCENT_PALETTE = {
    "Rosewater": "#f5e0dc", "Flamingo": "#f2cdcd", "Pink": "#f5c2e7",
    "Mauve": "#cba6f7", "Red": "#f38ba8", "Maroon": "#eba0ac",
    "Peach": "#fab387", "Yellow": "#f9e2af", "Green": "#a6e3a1",
    "Teal": "#94e2d5", "Sky": "#89dceb", "Sapphire": "#74c7ec",
    "Blue": "#89b4fa", "Lavender": "#b4befe",
}
ACCENT_CHOICES = ["Theme default"] + list(ACCENT_PALETTE)

# Every themed palette is dark except these; 'system' follows the desktop.
_LIGHT_THEMES = ("catppuccin-latte", "vintage-light")


def is_dark(theme):
    """True if the theme is a dark one (so GTK should prefer its dark variant)."""
    theme = normalize(theme)
    return theme in _CHROME and theme not in _LIGHT_THEMES


def build_css(theme, accent=""):
    """Full CSS string for the given theme: palette + structure + chrome.

    `accent` optionally overrides @gnm_accent with a Catppuccin accent colour
    (see ACCENT_PALETTE). The override is emitted right after the palette block
    so it wins for every later use.
    """
    theme = normalize(theme)
    palette = _palette_block(theme)
    hexv = ACCENT_PALETTE.get(accent)
    if hexv:
        palette += f"@define-color gnm_accent {hexv};\n"
    return palette + _structural_css() + _chrome_css(theme)
