"""Colour themes for GeoNetMon.

Each palette defines the semantic ``gnm_*`` tokens that style.css references.
Themes other than ``system`` also recolour the main window chrome (window,
headerbar, column view, status bar, entries, popovers) so the app reads as a
cohesive Dracula / Catppuccin surface without depending on libadwaita.

``system`` supplies only the accent tokens and leaves window chrome to the
user's existing GTK theme (respecting their light/dark preference).
"""

import os

# Ordered for the preferences drop-down. (id, human label)
THEME_CHOICES = [
    ("system", "System (follow desktop)"),
    ("dracula", "Dracula"),
    ("catppuccin-latte", "Catppuccin Latte"),
    ("catppuccin-frappe", "Catppuccin Frapp\u00e9"),
    ("catppuccin-macchiato", "Catppuccin Macchiato"),
    ("catppuccin-mocha", "Catppuccin Mocha"),
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
   specific rules (.suggested-action, .prompt-allow, headerbar button, .tl) win. */
button {
    background-color: @gnm_bg_alt; background-image: none;
    color: @gnm_fg; border: 1px solid @gnm_border;
}
button:hover { background-color: @gnm_sel; }
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
.titlebar button:checked { background-color: @gnm_accent; color: @gnm_bg; }
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
    min-width: 46px; min-height: 24px;
}
switch:checked {
    background-color: @gnm_accent;
    background-image: none;
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

_DARK_THEMES = ("dracula", "catppuccin-frappe", "catppuccin-macchiato",
                "catppuccin-mocha")


def is_dark(theme):
    """True if the theme is a dark one (so GTK should prefer its dark variant)."""
    return normalize(theme) in _DARK_THEMES


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
