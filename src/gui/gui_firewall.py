import re
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime

from src.firewall.firewall_engine import Firewall, MODEL_PATH  # noqa: F401 (re-exported)
from src.gui.event_bus import GUIEventBus


def get_tshark_interfaces() -> list[tuple[str, str]]:
    """Return list of (name, display_label) from tshark -D.
    e.g. [('en0', '3. en0 (Wi-Fi)'), ...]
    Falls back to [('en0', 'en0')] if tshark is unavailable.
    """
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True, text=True, timeout=5,
        )
        interfaces = []
        for line in result.stdout.splitlines():
            line = line.strip()
            m = re.match(r"^\d+\.\s+(\S+)", line)
            if m:
                interfaces.append((m.group(1), line))
        return interfaces if interfaces else [("en0", "en0")]
    except Exception:
        return [("en0", "en0")]


class GUIFirewall(Firewall):
    """Firewall subclass that forwards events to the GUI via GUIEventBus."""

    def __init__(self, bus: GUIEventBus, **kwargs):
        self._bus = bus
        self._gui_allowed  = 0
        self._gui_warnings = 0
        self._gui_blocked  = 0
        super().__init__(**kwargs)

    # ── print interception ────────────────────────────────────────────────────

    @contextmanager
    def _intercept_print(self):
        import builtins
        real_print = builtins.print
        builtins.print = self._tap
        try:
            yield
        finally:
            builtins.print = real_print

    def _tap(self, *args, **kwargs):
        msg = " ".join(str(a) for a in args)
        if "[ALLOW]" in msg or "[BLOCK]" in msg or "Normal traffic from" in msg:
            return
        level = "info"
        if "[WARNING]" in msg or "⚠" in msg:
            level = "warn"
        if "Attack" in msg or "DROP" in msg:
            level = "danger"
        if "Loaded" in msg or "complete" in msg:
            level = "success"
        if "error" in msg.lower() or "fatal" in msg.lower():
            level = "danger"
        self._bus.post_log(msg, level)

    # ── prediction hook ───────────────────────────────────────────────────────

    def handle_prediction(self, label: str, source_ip: str):
        blocked_before = len(self.blocked_ips)
        with self._intercept_print():
            super().handle_prediction(label, source_ip)
        blocked_after = len(self.blocked_ips)

        is_attack = label not in {"Normal", "BENIGN"}
        action = "WARNING" if is_attack else "ALLOW"

        if is_attack:
            self._gui_warnings += 1
            if blocked_after > blocked_before:
                self._gui_blocked += 1
        else:
            self._gui_allowed += 1

        ts = datetime.now().strftime("%H:%M:%S")
        self._bus.post_row(ts, action, source_ip or "unknown", label)

        total = self.stats.get("total", 0)
        self._bus.post_stat(self._gui_allowed, self._gui_warnings, total)

        elapsed = time.time() - self.start_time
        pps = total / elapsed if elapsed > 0 else 0.0
        self._bus.post_stats_panel(elapsed, total, pps, dict(self.stats), list(self.label_names))
        self._bus.post_blocked_ips(self.blocked_ips)

    def run(self):
        with self._intercept_print():
            super().run()