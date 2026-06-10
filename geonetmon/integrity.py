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
import threading

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
        self._cache = {}       # path -> ((mtime, size), sha)
        self._pins = {}        # path -> sha   (trusted-at-allow-time)
        self._inflight = set()  # paths being hashed off-thread
        self._lock = threading.Lock()
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

    # ---- non-blocking path (for the NFQUEUE callback) -------------------
    def _cached_hash(self, path):
        """Cached SHA if it still matches the file's (mtime,size); else None.
        Never hashes — safe to call from the single packet-processing thread."""
        try:
            st = os.stat(path)
        except OSError:
            return None
        cached = self._cache.get(path)
        if cached and cached[0] == (st.st_mtime, st.st_size):
            return cached[1]
        return None

    def _hash_async(self, path):
        with self._lock:
            if path in self._inflight:
                return
            self._inflight.add(path)

        def worker():
            try:
                self.current_hash(path)      # populates self._cache
            finally:
                with self._lock:
                    self._inflight.discard(path)
        threading.Thread(target=worker, daemon=True).start()

    def verify_async(self, path):
        """Like verify(), but never hashes inline. On a cache miss it returns
        'pending' and computes the hash off-thread so later packets get the
        real verdict — keeping the packet path from stalling on a 100s-of-MB
        ELF read. Returns 'ok' | 'changed' | 'unpinned' | 'missing' | 'pending'."""
        if not path:
            return "unpinned"
        if not os.path.isfile(path):
            return "missing"
        pinned = self._pins.get(path)
        if not pinned:
            return "unpinned"
        cached = self._cached_hash(path)
        if cached is None:
            self._hash_async(path)
            return "pending"
        return "ok" if cached == pinned else "changed"
