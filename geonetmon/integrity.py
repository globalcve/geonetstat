"""Binary-integrity pinning — the Linux analog of Little Snitch's code-signature
checks.

When you allow an app, we can record a SHA-256 of its executable. On later
connections we re-hash and, if the binary changed, flag it ("this isn't the
firefox you trusted") so a swapped or trojaned binary doesn't silently inherit
an allow rule. Hashes are cached by (path, mtime, size) so we don't re-read a
big ELF on every packet.
"""

import hashlib
import json
import os

from . import config as cfg


def hash_file(path, chunk=1 << 20, max_bytes=512 << 20):
    """SHA-256 of a file, or "" on error / oversized."""
    if not path or not os.path.isfile(path):
        return ""
    try:
        if os.path.getsize(path) > max_bytes:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                b = fh.read(chunk)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except OSError:
        return ""


class Integrity:
    def __init__(self):
        self._cache = {}       # path -> (mtime, size, sha)
        self._pins = {}        # path -> sha   (trusted-at-allow-time)
        self._path = os.path.join(cfg.config_dir(), "pins.json")
        self._load()

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._pins = {k: v for k, v in data.items()
                              if isinstance(v, str)}
        except (OSError, ValueError):
            self._pins = {}

    def save(self):
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._pins, fh, indent=2)
            os.replace(tmp, self._path)
        except OSError:
            pass

    def current_hash(self, path):
        """Cached SHA-256 keyed on (mtime, size) so edits invalidate it."""
        if not path or not os.path.isfile(path):
            return ""
        try:
            st = os.stat(path)
        except OSError:
            return ""
        key = (st.st_mtime, st.st_size)
        cached = self._cache.get(path)
        if cached and cached[0] == key:
            return cached[1]
        sha = hash_file(path)
        self._cache[path] = (key, sha)
        return sha

    def pin(self, path):
        """Record the current hash as trusted."""
        sha = self.current_hash(path)
        if sha:
            self._pins[path] = sha
            self.save()
        return sha

    def is_pinned(self, path):
        return path in self._pins

    def verify(self, path):
        """Return one of: 'ok', 'changed', 'unpinned', 'missing'."""
        if not path:
            return "unpinned"
        if not os.path.isfile(path):
            return "missing"
        pinned = self._pins.get(path)
        if not pinned:
            return "unpinned"
        return "ok" if self.current_hash(path) == pinned else "changed"

    def forget(self, path):
        if self._pins.pop(path, None) is not None:
            self.save()
