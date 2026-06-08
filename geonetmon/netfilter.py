"""Interactive outbound-firewall engine (OpenSnitch-style), daemon-side.

Diverts *new* connections to an NFQUEUE, attributes each to a process, resolves
the destination hostname from captured DNS, checks binary integrity, consults
the rule engine, and applies a verdict. Unknown flows are **held** — the packet
is retained in the queue and the connection genuinely blocks — while the daemon
asks the GUI; the verdict is applied when the user answers or the timeout fires.

This module is GTK-free; it runs inside the root daemon. Callbacks are plain
calls (the daemon marshals to its clients). The packet parser and nft script
are unit-tested; the live NFQUEUE binding needs a privileged host to exercise.

Requires root, nftables, and the ``netfilterqueue`` Python module; otherwise
``available()`` is False and starting is a safe no-op.
"""

import ipaddress
import os
import select
import shutil
import socket
import struct
import subprocess
import threading
import uuid

from . import rules as rules_mod

try:
    from netfilterqueue import NetfilterQueue
    _HAVE_NFQ = True
except ImportError:
    NetfilterQueue = None
    _HAVE_NFQ = False

NFT_TABLE = "geonetmon_enforce"
_TCP, _UDP = 6, 17


def parse_packet(payload):
    """Extract a flow from a raw IPv4/IPv6 packet, or None."""
    if not payload:
        return None
    ver = payload[0] >> 4
    try:
        if ver == 4:
            ihl = (payload[0] & 0x0F) * 4
            proto = payload[9]
            src = socket.inet_ntop(socket.AF_INET, payload[12:16])
            dst = socket.inet_ntop(socket.AF_INET, payload[16:20])
            l4 = payload[ihl:]
        elif ver == 6:
            proto = payload[6]
            src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
            l4 = payload[40:]
        else:
            return None
    except (OSError, IndexError):
        return None
    if proto == _TCP:
        p = "tcp"
    elif proto == _UDP:
        p = "udp"
    else:
        return None
    if len(l4) < 4:
        return None
    sport, dport = struct.unpack("!HH", l4[:4])
    return {"proto": p, "src_ip": src, "src_port": sport,
            "dst_ip": dst, "dst_port": dport}


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def nft_available():
    return shutil.which("nft") is not None


def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


class Engine:
    def __init__(self, config, rules, procmap, dnscache=None, integrity=None,
                 on_prompt=None, on_event=None):
        self.config = config
        self.rules = rules
        self.procmap = procmap
        self.dns = dnscache
        self.integrity = integrity
        self.on_prompt = on_prompt      # (prompt_id, flow) -> None
        self.on_event = on_event        # (flow, action, auto, rule_summary) -> None
        self.running = False
        self._nfq = None
        self._thread = None
        self._stop_r = self._stop_w = None
        # Held connections awaiting a decision, grouped by app so one dialog
        # covers a whole burst (Little-Snitch style):
        #   _pending[prompt_id] = {key, flow, pkts:[...], dests:[...], timer}
        #   _group_by_key[key]  = prompt_id
        self._pending = {}
        self._group_by_key = {}
        self._lock = threading.Lock()

    # ---- capability -----------------------------------------------------
    def available(self):
        return _HAVE_NFQ and nft_available() and is_root()

    def status_text(self):
        if not _HAVE_NFQ:
            return "unavailable — install python3-netfilterqueue"
        if not nft_available():
            return "unavailable — nftables (nft) not found"
        if not is_root():
            return "unavailable — daemon must run as root"
        return "enforcing" if self.running else "ready"

    # ---- nft plumbing ---------------------------------------------------
    def _nft_script(self):
        qnum = int(self.config.get("enforce_nfqueue_num", 0))
        bypass = "bypass" if self.config.get("enforce_fail_open", True) else ""
        lines = [f"add table inet {NFT_TABLE}"]
        direction = self.config.get("enforce_direction", "outbound")
        hooks = []
        if direction in ("outbound", "both"):
            hooks.append("output")
        if direction in ("inbound", "both"):
            hooks.append("input")
        if not hooks:                       # unknown value — default to outbound
            hooks = ["output"]
        for hook in hooks:
            lines.append(
                f"add chain inet {NFT_TABLE} {hook} "
                f"{{ type filter hook {hook} priority -100 ; policy accept ; }}")
            lines.append(
                f"add rule inet {NFT_TABLE} {hook} "
                f"ct state new queue num {qnum} {bypass}".strip())
        # DNS capture: sniff inbound DNS responses (we always accept these)
        if self.config.get("enforce_dns_capture", True) and self.dns is not None:
            if "input" not in hooks:
                lines.append(
                    f"add chain inet {NFT_TABLE} input "
                    f"{{ type filter hook input priority -100 ; policy accept ; }}")
            lines.append(
                f"add rule inet {NFT_TABLE} input udp sport 53 "
                f"queue num {qnum} {bypass}".strip())
        return "\n".join(lines)

    def _nft_apply(self):
        self._nft_teardown()
        return subprocess.run(["nft", "-f", "-"], input=self._nft_script(),
                              text=True, capture_output=True, check=False)

    def _nft_teardown(self):
        subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE],
                       capture_output=True, text=True, check=False)

    # ---- lifecycle ------------------------------------------------------
    def start(self):
        if self.running or not self.available():
            return False, self.status_text()
        res = self._nft_apply()
        if res.returncode != 0:
            return False, (res.stderr or "nft setup failed").strip()
        self._nfq = NetfilterQueue()
        try:
            self._nfq.bind(int(self.config.get("enforce_nfqueue_num", 0)),
                           self._on_packet)
        except OSError as exc:
            self._nft_teardown()
            return False, f"queue bind failed: {exc}"
        self._stop_r, self._stop_w = socket.socketpair()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True, "enforcing"

    def stop(self):
        if not self.running:
            return
        self.running = False
        try:
            self._stop_w.send(b"x")
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=2)
        # release any held packets (fail per configured default)
        with self._lock:
            pend = list(self._pending.values())
            self._pending.clear()
            self._group_by_key.clear()
        fail_open = self.config.get("enforce_fail_open", True)
        for item in pend:
            self._verdict_group(item, accept=fail_open)
            if item.get("timer"):
                item["timer"].cancel()
        if self._nfq:
            try:
                self._nfq.unbind()
            except Exception:  # noqa: BLE001
                pass
        self._nft_teardown()
        for s in (self._stop_r, self._stop_w):
            try:
                s.close()
            except (OSError, AttributeError):
                pass

    def _loop(self):
        nfq_sock = socket.fromfd(self._nfq.get_fd(), socket.AF_UNIX,
                                 socket.SOCK_STREAM)
        while self.running:
            try:
                r, _, _ = select.select([nfq_sock, self._stop_r], [], [], 1.0)
            except (OSError, ValueError):
                break
            if self._stop_r in r:
                break
            if nfq_sock in r:
                try:
                    self._nfq.run(block=False)
                except OSError:
                    break

    # ---- per-packet -----------------------------------------------------
    def _on_packet(self, pkt):
        payload = pkt.get_payload()
        flow = parse_packet(payload)
        if not flow:
            pkt.accept()
            return
        # DNS response sniffing — learn hostnames, then let it through.
        if flow["proto"] == "udp" and flow["src_port"] == 53 and self.dns:
            try:
                self.dns.ingest(payload[self._l4_off(payload):])
            except Exception:  # noqa: BLE001
                pass
            pkt.accept()
            return
        # Never prompt on DNS queries — we depend on them to resolve the very
        # hostnames we show, and they'd otherwise flood the prompt queue.
        if self.config.get("enforce_skip_dns", True) and flow["dst_port"] == 53:
            pkt.accept()
            return
        # Never enforce loopback (local resolvers, IPC, X/Wayland, etc.). An
        # outbound app-firewall has no business blocking 127.0.0.0/8 or ::1.
        if self.config.get("enforce_skip_loopback", True) and _is_loopback(
                flow["dst_ip"]):
            pkt.accept()
            return
        if flow["proto"] == "tcp" and not self.config.get("enforce_apply_tcp", True):
            pkt.accept()
            return
        if flow["proto"] == "udp" and not self.config.get("enforce_apply_udp", True):
            pkt.accept()
            return

        # Attribute to the local socket and decide direction: the local end is
        # the source for outbound traffic, the destination for inbound. Resolve
        # the source first (preserves the common outbound path); fall back to
        # the destination, which means the packet is inbound.
        proc = self.procmap.resolve(flow["proto"], flow["src_ip"],
                                    flow["src_port"])
        if proc.get("pid") or proc.get("process"):
            flow["direction"] = "OUTGOING"
        else:
            proc_in = self.procmap.resolve(flow["proto"], flow["dst_ip"],
                                           flow["dst_port"])
            if proc_in.get("pid") or proc_in.get("process"):
                flow["direction"] = "INCOMING"
                proc = proc_in
            else:
                flow["direction"] = "OUTGOING"
        flow.update(proc)
        if self.dns:
            flow["dst_host"] = self.dns.hostname(flow["dst_ip"]) or ""
        flow.setdefault("dst_host", "")
        if self.integrity and flow.get("process_path"):
            flow["integrity"] = self.integrity.verify(flow["process_path"])

        action, rule = self.rules.decide(flow)
        if action == rules_mod.ALLOW:
            pkt.accept()
            self._event(flow, "allow", True, rule)
            return
        if action == rules_mod.DENY:
            pkt.drop()
            self._event(flow, "deny", True, rule)
            return

        default = self.config.get("enforce_default_action", "prompt")
        if default == "allow":
            pkt.accept()
            self._event(flow, "allow", True, None)
            return
        if default == "deny":
            pkt.drop()
            self._event(flow, "deny", True, None)
            return

        # prompt: HOLD the packet until the user (or timeout) decides. Group by
        # app so a burst of connections from one program rides on ONE dialog
        # instead of spawning dozens (which both floods you and can crash the
        # GUI). New connections from an app with an open prompt attach to that
        # prompt; your single answer is applied to the whole held group.
        groups_cap = int(self.config.get("enforce_max_pending", 30))
        per_group_cap = int(self.config.get("enforce_max_per_group", 200))
        key = self._group_key(flow)
        new_prompt = None
        with self._lock:
            existing = self._group_by_key.get(key)
            grp = self._pending.get(existing) if existing else None
            if grp is not None:
                # Attach to the app's open group (no new dialog).
                if len(grp["pkts"]) >= per_group_cap:
                    self._safe_verdict(pkt, accept=self.config.get(
                        "enforce_fail_open", True))
                    return
                if not self._retain(pkt):
                    return
                grp["pkts"].append(pkt)
                grp["dests"].append((flow.get("dst_host") or flow.get("dst_ip"),
                                     flow.get("dst_port")))
                return
            if len(self._pending) >= groups_cap:
                # too many distinct apps already waiting — fail per policy
                fail = self.config.get("enforce_timeout_action", "deny")
                self._safe_verdict(pkt, accept=(fail == "allow"))
                self._event(flow, fail, True, None)
                return
            if not self._retain(pkt):
                return
            pid = uuid.uuid4().hex[:12]
            timeout = max(15, int(self.config.get("enforce_prompt_timeout_s", 90)))
            timer = threading.Timer(timeout, self._timeout, args=(pid,))
            timer.daemon = True
            self._pending[pid] = {
                "key": key, "flow": flow, "pkts": [pkt],
                "dests": [(flow.get("dst_host") or flow.get("dst_ip"),
                           flow.get("dst_port"))],
                "timer": timer}
            self._group_by_key[key] = pid
            timer.start()
            new_prompt = (pid, flow)
        if new_prompt and self.on_prompt:
            self.on_prompt(*new_prompt)

    @staticmethod
    def _group_key(flow):
        """Identity used to coalesce a burst into one prompt: the program."""
        return (flow.get("process_path") or flow.get("process")
                or f"pid:{flow.get('pid')}" or flow.get("src_ip"))

    def _retain(self, pkt):
        """Hold a packet in the queue; return True on success."""
        try:
            pkt.retain()
            return True
        except Exception:  # noqa: BLE001 — older lib without retain(): drop it
            pkt.drop()
            return False

    def _verdict_group(self, item, accept):
        """Apply one verdict to every held packet of a group."""
        for pkt in item.get("pkts", ()):
            self._safe_verdict(pkt, accept=accept)

    @staticmethod
    def _l4_off(payload):
        ver = payload[0] >> 4
        if ver == 4:
            return (payload[0] & 0x0F) * 4 + 8     # IP header + UDP header
        return 40 + 8                              # IPv6 + UDP header

    def resolve_prompt(self, prompt_id, action, scope, scope_by):
        """Called when the GUI answers a prompt — applies to the whole group."""
        with self._lock:
            item = self._pending.pop(prompt_id, None)
            if item:
                self._group_by_key.pop(item.get("key"), None)
        if not item:
            return False
        if item.get("timer"):
            item["timer"].cancel()
        flow = item["flow"]
        if action == rules_mod.ALLOW and self.integrity and flow.get("process_path"):
            self.integrity.pin(flow["process_path"])
        rule = None
        if scope and scope != "no_rule":
            rule = self.rules.build_from_choice(flow, action, scope, scope_by)
        self._verdict_group(item, accept=(action == rules_mod.ALLOW))
        self._event(flow, action, False, rule)
        return True

    def _timeout(self, prompt_id):
        with self._lock:
            item = self._pending.pop(prompt_id, None)
            if item:
                self._group_by_key.pop(item.get("key"), None)
        if not item:
            return
        action = self.config.get("enforce_timeout_action", "deny")
        self._verdict_group(item, accept=(action == "allow"))
        self._event(item["flow"], action, True, None)

    def _safe_verdict(self, pkt, accept):
        try:
            if accept:
                pkt.accept()
            else:
                pkt.drop()
        except Exception:  # noqa: BLE001
            pass

    def _event(self, flow, action, auto, rule):
        if self.on_event:
            self.on_event(flow, action, auto,
                          rule.summary() if rule else "")

    def pending_count(self):
        with self._lock:
            return len(self._pending)
