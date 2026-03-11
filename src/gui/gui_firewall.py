import re
import builtins
import subprocess
import time
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
        self.bus = bus
        self.gui_allowed = 0
        self.gui_warnings = 0
        self.gui_blocked = 0
        self.real_print = None
        super().__init__(**kwargs)

    def tap_print(self, *args, **kwargs):
        """Intercepts print calls and routes them to the event bus."""
        msg = " ".join(str(a) for a in args)
        if "[ALLOW]" in msg or "[BLOCK]" in msg or "Normal traffic from" in msg:
            return
        if "[WARNING]" in msg or "⚠" in msg:
            return
        level = "info"
        if "Attack" in msg or "DROP" in msg:
            level = "danger"
        if "Loaded" in msg or "complete" in msg:
            level = "success"
        if "error" in msg.lower() or "fatal" in msg.lower():
            level = "danger"
        self.bus.post_log(msg, level)

    def intercept_print_start(self):
        self.real_print = builtins.print
        builtins.print = self.tap_print

    def intercept_print_stop(self):
        if self.real_print is not None:
            builtins.print = self.real_print
            self.real_print = None

    def handle_prediction(self, label: str, source_ip: str):
        blocked_before = len(self.blocked_ips)
        self.intercept_print_start()
        try:
            super().handle_prediction(label, source_ip)
        finally:
            self.intercept_print_stop()
        blocked_after = len(self.blocked_ips)

        is_attack = label not in {"Normal", "BENIGN"}
        action = "WARNING" if is_attack else "ALLOW"

        if is_attack:
            self.gui_warnings += 1
            if blocked_after > blocked_before:
                self.gui_blocked += 1
                self.bus.post_log(
                    f"[Firewall] Blocked {source_ip or 'unknown'} — {label}", "danger"
                )
        else:
            self.gui_allowed += 1

        ts = datetime.now().strftime("%H:%M:%S")
        self.bus.post_row(ts, action, source_ip or "unknown", label)

        total = self.stats.get("total", 0)
        self.bus.post_stat(self.gui_allowed, self.gui_warnings, total)

        elapsed = time.time() - self.start_time
        pps = total / elapsed if elapsed > 0 else 0.0
        self.bus.post_stats_panel(elapsed, total, pps, dict(self.stats), list(self.label_names))
        self.bus.post_blocked_ips(self.blocked_ips)

    def run(self):
        self.intercept_print_start()
        try:
            super().run()
        finally:
            self.intercept_print_stop()
