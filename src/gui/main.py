"""
Blackwall Firewall GUI — Cyberpunk 2077 Breach Protocol Edition
Requires: flet >= 0.80
"""

import flet as ft
import threading
import time
import queue
from datetime import datetime
from contextlib import contextmanager

import subprocess
import re

def get_tshark_interfaces() -> list[tuple[str, str]]:
    """List available capture interfaces via tshark -D.
    Returns list of (name, label) tuples e.g. ('en0', '2. en0 (Wi-Fi)')"""
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True, text=True, timeout=5
        )
        interfaces = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # Lines look like: "1. en0 (Wi-Fi)"  or  "2. lo0 (Loopback)"
            m = re.match(r"^\d+\.\s+(\S+)", line)
            if m:
                name = m.group(1)
                interfaces.append((name, line))  # (value, display label)
        return interfaces if interfaces else [("en0", "en0")]
    except Exception:
        return [("en0", "en0")]


from src.firewall.firewall_engine import Firewall, MODEL_PATH

# ══════════════════════════════════════════════════════════════════════════════
#  Palette
# ══════════════════════════════════════════════════════════════════════════════
BG = "#040305"
PANEL = "#0a0b10"
PANEL2 = "#0d0e14"
BORDER = "#c8e55b"
ACCENT = "#c8e55b"
DANGER = "#ff2a6d"  # ONLY in System Log + Traffic Matrix
SUCCESS = "#c8e55b"
TEXT = "#c8e55b"
TEXT_DIM = "#6b7a2a"
TEXT_MUTED = "#3a4015"
CELL_BG = "#040305"
HEADER_BG = "#c8e55b"
HEADER_FG = "#040305"
MONO = "neomax"
SZ = 12


# ══════════════════════════════════════════════════════════════════════════════
#  Event bus
# ══════════════════════════════════════════════════════════════════════════════
class GUIEventBus:
    LOG = "log"
    ROW = "row"
    STAT = "stat"
    STATS = "stats_panel"
    BLOCK = "blocked_ips"

    def __init__(self):
        self._q: queue.Queue = queue.Queue()

    def post(self, payload: dict):
        self._q.put_nowait(payload)

    def post_log(self, msg: str, level: str = "info"):
        self.post({"type": self.LOG, "msg": msg, "level": level})

    def post_row(self, ts: str, action: str, ip: str, label: str):
        self.post({"type": self.ROW, "ts": ts, "action": action, "ip": ip, "label": label})

    def post_stat(self, allowed: int, blocked: int, total: int):
        self.post({"type": self.STAT, "allowed": allowed, "blocked": blocked, "total": total})

    def post_stats_panel(self, elapsed: float, total: int, pps: float,
                         label_counts: dict, label_names: list):
        self.post({
            "type": self.STATS,
            "elapsed": elapsed, "total": total, "pps": pps,
            "label_counts": label_counts,
            "label_names": label_names,
        })

    def post_blocked_ips(self, ips: set):
        self.post({"type": self.BLOCK, "ips": set(ips)})

    def drain(self) -> list:
        items = []
        try:
            while True:
                items.append(self._q.get_nowait())
        except queue.Empty:
            pass
        return items


# ══════════════════════════════════════════════════════════════════════════════
#  Instrumented Firewall
# ══════════════════════════════════════════════════════════════════════════════
class GUIFirewall(Firewall):
    def __init__(self, bus: GUIEventBus, **kwargs):
        self._bus = bus
        self._gui_allowed = 0
        self._gui_blocked = 0
        super().__init__(**kwargs)

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

        # Filter out noisy traffic prints
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

    def handle_prediction(self, label: str, source_ip: str):
        with self._intercept_print():
            super().handle_prediction(label, source_ip)

        is_attack = label not in {"Normal", "BENIGN"}
        action = "WARNING" if is_attack else "ALLOW"

        if is_attack:
            self._gui_blocked += 1
        else:
            self._gui_allowed += 1

        ts = datetime.now().strftime("%H:%M:%S")
        self._bus.post_row(ts, action, source_ip or "unknown", label)

        total = self.stats.get("total", 0)
        self._bus.post_stat(self._gui_allowed, self._gui_blocked, total)

        elapsed = time.time() - self.start_time
        pps = total / elapsed if elapsed > 0 else 0.0
        self._bus.post_stats_panel(elapsed, total, pps, dict(self.stats), list(self.label_names))
        self._bus.post_blocked_ips(self.blocked_ips)

    def run(self):
        with self._intercept_print():
            super().run()


# ══════════════════════════════════════════════════════════════════════════════
#  UI
# ══════════════════════════════════════════════════════════════════════════════
def main(page: ft.Page):
    page.title = "NETWATCH — BLACKWALL — INTRUSION FIREWALL"
    page.bgcolor = BG
    page.padding = 0
    page.window.width = 1400
    page.window.height = 860
    page.window.min_width = 1100
    page.window.min_height = 700
    page.fonts = {"neomax": "./fonts/neomax.otf"}

    bus_ref: list = [None]
    fw_ref: list = [None]
    fw_thread: list = [None]
    poll_alive = {"v": False}

    def mono(text, color=TEXT, size=SZ, weight=None):
        return ft.Text(text, font_family=MONO, color=color, size=size, weight=weight)

    def label_text(text, color=TEXT_DIM, size=SZ - 1):
        return ft.Text(
            text.upper(),
            font_family=MONO,
            color=color,
            size=size,
            weight=ft.FontWeight.BOLD,
        )

    def panel_header(title: str, icon: str = "▓▓", trailing=None):
        row_items = [
            ft.Container(
                content=ft.Text(icon, color=HEADER_BG, size=9, font_family=MONO),
                bgcolor=HEADER_FG,
                width=22,
                height=22,
            ),
            ft.Text(
                title.upper(),
                font_family=MONO,
                color=HEADER_FG,
                size=SZ,
                weight=ft.FontWeight.BOLD,
            ),
            ft.Container(expand=True, height=1, bgcolor=HEADER_FG + "55"),
        ]
        if trailing is not None:
            row_items.append(trailing)

        return ft.Container(
            content=ft.Row(
                row_items,
                spacing=6,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=HEADER_BG,
            padding=ft.Padding.symmetric(horizontal=8, vertical=5),
        )

    def ydiv():
        return ft.Container(height=1, bgcolor=BORDER + "88")

    def panel(title: str, body, expand: int, icon: str = "▓▓", trailing=None):
        return ft.Container(
            expand=expand,
            bgcolor=CELL_BG,
            border=ft.Border.all(1, BORDER),
            border_radius=0,
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
            content=ft.Column(
                [
                    panel_header(title, icon, trailing=trailing),
                    ft.Container(content=body, expand=True),  # ✅ fill remaining height
                ],
                spacing=0,
                expand=True,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
        )

    def vscroll(content, pad=0):
        # Always fills panel body; scrolls vertically when needed
        return ft.ListView(
            controls=[ft.Container(content=content, padding=pad)],
            expand=True,
            spacing=0,
            padding=0,
            auto_scroll=False,
        )

    # ── SYSTEM LOG ────────────────────────────────────────────────────────────
    # (no scroll here; the panel wrapper will scroll)
    log_col = ft.Column(spacing=1)

    def push_log(msg: str, level: str = "info"):
        color = DANGER if level == "danger" else TEXT
        icon = ">>"

        log_col.controls.append(
            ft.Row(
                spacing=5,
                controls=[
                    mono(datetime.now().strftime("%H:%M:%S"), TEXT_MUTED, SZ - 3),
                    ft.Container(
                        content=mono(icon, color, SZ - 3, ft.FontWeight.BOLD),
                        bgcolor=BG,
                        padding=ft.Padding.symmetric(horizontal=3, vertical=1),
                    ),
                    # ✅ constrain long text inside panel
                    ft.Container(
                        expand=True,
                        content=ft.Text(
                            msg.strip(),
                            font_family=MONO,
                            size=SZ - 3,
                            color=color,
                            no_wrap=True,
                            overflow=ft.TextOverflow.ELLIPSIS,
                            max_lines=1,
                        ),
                    ),
                ],
            )
        )

        if len(log_col.controls) > 400:
            log_col.controls.pop(0)

    # ── LIVE TRAFFIC MATRIX ───────────────────────────────────────────────────
    def hdr(lbl):
        return ft.DataColumn(
            ft.Text(
                lbl,
                color=ACCENT,
                size=SZ,
                font_family=MONO,
                weight=ft.FontWeight.BOLD,
            )
        )

    traffic_table = ft.DataTable(
        columns=[hdr("TIME"), hdr("ACTION"), hdr("IP ADDRESS"), hdr("LABEL")],
        rows=[],
        border=ft.Border.all(1, BORDER + "55"),
        heading_row_color={"": "#0d1a09"},
        heading_row_height=26,
        data_row_min_height=22,
        data_row_max_height=22,
        divider_thickness=0,
        column_spacing=10,
    )

    def push_row(ts, action, ip, label):
        is_attack = (action == "WARNING")
        ac = DANGER if is_attack else SUCCESS
        lc = DANGER if is_attack else TEXT
        traffic_table.rows.insert(
            0,
            ft.DataRow(
                cells=[
                    ft.DataCell(mono(ts, TEXT_DIM, SZ)),
                    ft.DataCell(mono(action, ac, SZ, ft.FontWeight.BOLD)),
                    ft.DataCell(mono(ip, TEXT, SZ)),
                    ft.DataCell(mono(label, lc, SZ)),
                ]
            ),
        )
        if len(traffic_table.rows) > 200:
            traffic_table.rows.pop()

    # ── CLASSIFICATION STATS ──────────────────────────────────────────────────
    _smeta0 = mono("--", TEXT_DIM, SZ)
    _smeta1 = mono("--", TEXT_DIM, SZ)
    _smeta2 = mono("--", TEXT_DIM, SZ)

    _smeta0.width = 70
    _smeta1.width = 70
    _smeta2.width = 70

    stats_meta_row = ft.Row(controls=[_smeta0, _smeta1, _smeta2], spacing=16)

    # (no scroll here; the panel wrapper will scroll)
    stats_rows_col = ft.Column(spacing=3)

    def update_stats_panel(elapsed, total, pps, label_counts, label_names):
        NAME_W = 170  # px
        COUNT_W = 55  # px
        PCT_W = 70    # px

        _smeta0.value = f"PKT {total}"
        _smeta1.value = f"pkt/s {pps:.1f}"
        _smeta2.value = f"UP {elapsed:.0f} s"
        stats_rows_col.controls.clear()

        names = list(label_names)
        normal = [n for n in names if n.lower() == "normal"]
        others = [n for n in names if n.lower() != "normal"]
        others.sort(key=lambda n: label_counts.get(n, 0), reverse=True)
        ordered = normal + others

        for name in ordered:
            count = label_counts.get(name, 0)
            pct = 100 * count / total if total else 0.0
            bar_w = max(1, int(pct * 1.2))

            stats_rows_col.controls.append(
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Container(width=NAME_W, content=mono(name, TEXT, SZ)),
                                ft.Container(
                                    width=COUNT_W,
                                    alignment=ft.Alignment.CENTER_RIGHT,
                                    content=mono(str(count), TEXT, SZ, ft.FontWeight.BOLD),
                                ),
                                ft.Container(
                                    width=PCT_W,
                                    alignment=ft.Alignment.CENTER_RIGHT,
                                    content=mono(f"{pct:0.1f}%", TEXT_DIM, SZ),
                                ),
                            ],
                            spacing=10,
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Container(
                            content=ft.Container(width=bar_w, height=2, bgcolor=ACCENT),
                            bgcolor=TEXT_MUTED,
                            height=2,
                            expand=True,
                        ),
                    ],
                    spacing=1,
                )
            )

    # ── BLOCKED IPs ──────────────────────────────────────────────────────────
    blocked_badge = ft.Container(
        content=ft.Text(
            "0",
            font_family=MONO,
            color=HEADER_FG,
            size=SZ,
            weight=ft.FontWeight.BOLD,
        ),
        bgcolor=HEADER_FG + "22",
        border=ft.Border.all(1, HEADER_FG),
        padding=ft.Padding.symmetric(horizontal=6, vertical=2),
        margin=ft.Margin(right=4, left=0, top=0, bottom=0),
    )

    # (no scroll here; the panel wrapper will scroll)
    blocked_col = ft.Column(spacing=4)

    def update_blocked_ips(ips: set):
        blocked_badge.content.value = str(len(ips))
        blocked_col.controls.clear()
        if not ips:
            blocked_col.controls.append(
                ft.Row(
                    [
                        ft.Container(width=4, height=4, bgcolor=TEXT_MUTED),
                        mono("none", TEXT_MUTED, SZ),
                    ],
                    spacing=8,
                )
            )
        else:
            for ip in sorted(ips):
                blocked_col.controls.append(
                    ft.Row(
                        [
                            ft.Container(width=6, height=6, bgcolor=ACCENT),
                            mono(ip, ACCENT, SZ),
                        ],
                        spacing=8,
                    )
                )

    update_blocked_ips(set())

    # ── status widgets ────────────────────────────────────────────────────────
    dot = ft.Container(width=7, height=7, bgcolor=TEXT_MUTED)
    lbl_status = mono("OFFLINE", TEXT_MUTED, SZ, ft.FontWeight.BOLD)
    lbl_allowed = mono("0", SUCCESS, 18, ft.FontWeight.BOLD)
    lbl_blocked = mono("0", ACCENT, 18, ft.FontWeight.BOLD)
    lbl_total = mono("0", TEXT, 18, ft.FontWeight.BOLD)

    def update_counters(allowed, blocked, total):
        lbl_allowed.value = str(allowed)
        lbl_blocked.value = str(blocked)
        lbl_total.value = str(total)

    # ── poll loop ─────────────────────────────────────────────────────────────
    def poll_loop():
        while poll_alive["v"]:
            bus = bus_ref[0]
            if bus:
                for ev in bus.drain():
                    t = ev["type"]
                    if t == GUIEventBus.LOG:
                        push_log(ev["msg"], ev["level"])
                    elif t == GUIEventBus.ROW:
                        push_row(ev["ts"], ev["action"], ev["ip"], ev["label"])
                    elif t == GUIEventBus.STAT:
                        update_counters(ev["allowed"], ev["blocked"], ev["total"])
                    elif t == GUIEventBus.STATS:
                        update_stats_panel(
                            ev["elapsed"],
                            ev["total"],
                            ev["pps"],
                            ev["label_counts"],
                            ev["label_names"],
                        )
                    elif t == GUIEventBus.BLOCK:
                        update_blocked_ips(ev["ips"])
                page.update()
            time.sleep(0.15)

    # ── firewall thread ───────────────────────────────────────────────────────
    def on_start(_):
        if fw_ref[0] is not None:
            return

        log_col.controls.clear()
        traffic_table.rows.clear()
        stats_rows_col.controls.clear()
        update_blocked_ips(set())
        update_counters(0, 0, 0)

        raw = iface_dropdown.value or _ifaces[0][1]
        # Label looks like "3. en0 (Wi-Fi)" — extract just the interface name
        m = re.match(r"^\d+\.\s+(\S+)", raw)
        iface = m.group(1) if m else raw
        set_online(True)
        push_log("[Firewall] Loading model...", "info")
        push_log(f"[Firewall] Interface: {iface}", "info")
        page.update()

        bus = GUIEventBus()
        bus_ref[0] = bus

        def _run():
            try:
                fw = GUIFirewall(
                    bus=bus,
                    model_path=MODEL_PATH,
                    interface=iface,
                    bpf_filter=None,
                    block=False,
                    warmup_packets=100,
                    batch_size=1,
                )
                fw_ref[0] = fw
                fw.run()
            except Exception as e:
                bus.post_log(f"[Firewall] Fatal: {e}", "danger")
            finally:
                fw_ref[0] = None
                fw_thread[0] = None

        t = threading.Thread(target=_run, daemon=True)
        fw_thread[0] = t
        t.start()

    def on_stop(_):
        fw = fw_ref[0]
        if fw:
            try:
                fw.capture.stop_event.set()
                fw.capture.stop()
            except Exception:
                pass
        fw_ref[0] = fw_thread[0] = bus_ref[0] = None
        set_online(False)
        push_log("[Firewall] Firewall stopped.", "danger")
        page.update()

    # ── buttons ───────────────────────────────────────────────────────────────
    def cp_btn(label, bg, fg, hover_bg, on_click):
        return ft.Button(
            label,
            disabled=False,
            style=ft.ButtonStyle(
                bgcolor={
                    ft.ControlState.DEFAULT: bg,
                    ft.ControlState.HOVERED: hover_bg,
                    ft.ControlState.DISABLED: "#0b0b0b",
                },
                color={
                    ft.ControlState.DEFAULT: fg,
                    ft.ControlState.DISABLED: TEXT_MUTED,
                },
                shape=ft.RoundedRectangleBorder(radius=0),
                side=ft.BorderSide(1, fg),
                padding=ft.Padding.symmetric(horizontal=18, vertical=10),
                text_style=ft.TextStyle(
                    font_family=MONO,
                    size=SZ,
                    weight=ft.FontWeight.BOLD,
                    letter_spacing=2,
                ),
            ),
            on_click=on_click,
        )

    start_btn = cp_btn("▶  INITIATE", "#071408", SUCCESS, "#0f2810", on_start)
    stop_btn = cp_btn("■  TERMINATE", "#180508", DANGER, "#2a0810", on_stop)

    # ✅ ONE set_online (no duplicates) + button locking
    def set_online(on: bool):
        dot.bgcolor = SUCCESS if on else TEXT_MUTED
        lbl_status.color = SUCCESS if on else TEXT_MUTED
        lbl_status.value = "ONLINE" if on else "OFFLINE"

        start_btn.disabled = on
        stop_btn.disabled = not on
        iface_dropdown.disabled = on

    def stat_card(title, widget, accent):
        return ft.Container(
            content=ft.Column(
                [label_text(title), widget],
                spacing=1,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=PANEL2,
            border=ft.Border.all(1, accent),
            padding=ft.Padding.symmetric(horizontal=14, vertical=6),
        )

    # ── INTERFACE SELECTOR ────────────────────────────────────────────────────
    _ifaces = get_tshark_interfaces()  # list of (name, label)
    selected_iface: list[str] = [_ifaces[0][0]]

    iface_dropdown = ft.Dropdown(
        value=_ifaces[0][1],
        options=[ft.dropdown.Option(label) for name, label in _ifaces],
        width=220,
        bgcolor=PANEL2,
        border_color=BORDER,
        focused_border_color=ACCENT,
        color=TEXT,
        text_style=ft.TextStyle(font_family=MONO, size=SZ, color=TEXT),
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
        border_radius=0,
    )
    iface_dropdown.on_change = lambda e: None  # value read directly on start

    iface_card = ft.Container(
        content=ft.Row(
            [
                ft.Column(
                    [
                        label_text("INTERFACE"),
                        iface_dropdown,
                    ],
                    spacing=2,
                    horizontal_alignment=ft.CrossAxisAlignment.START,
                ),
            ],
            spacing=0,
        ),
        bgcolor=PANEL2,
        border=ft.Border.all(1, BORDER),
        padding=ft.Padding.symmetric(horizontal=10, vertical=5),
    )

    set_online(False)

    # ── HEADER ────────────────────────────────────────────────────────────────
    top_strip = ft.Container(
        content=ft.Row(
            [
                ft.Row(
                    [
                        ft.Container(
                            content=ft.Text("⊕", color=HEADER_BG, size=9, font_family=MONO),
                            bgcolor=HEADER_FG,
                            width=18,
                            height=18,
                        ),
                        ft.Text(
                            "══ NETWATCH ══",
                            color=HEADER_FG,
                            font_family=MONO,
                            size=12,
                            weight=ft.FontWeight.BOLD,
                        ),
                    ],
                    spacing=6,
                ),
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Container(expand=True, height=1, bgcolor=HEADER_FG + "55"),
                            ft.Container(
                                width=90,
                                height=10,
                                bgcolor=HEADER_FG + "22",
                                border=ft.Border.all(1, HEADER_FG + "88"),
                            ),
                            ft.Container(expand=True, height=1, bgcolor=HEADER_FG + "55"),
                        ],
                        spacing=4,
                    ),
                    expand=True,
                    padding=ft.Padding.symmetric(horizontal=20),
                ),
                ft.Text(
                    f"BREACH PROTOCOL INTERFACE      "
                    f"BKJMER 62UZ-FFLH-B6LT-E3E7  "
                    f"{datetime.now().strftime('%H%M/%S')}",
                    color=HEADER_FG,
                    font_family=MONO,
                    size=7,
                ),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=HEADER_BG,
        border=ft.Border.only(bottom=ft.BorderSide(1, BORDER)),
        padding=ft.Padding.symmetric(horizontal=14, vertical=5),
    )

    controls_strip = ft.Container(
        content=ft.Row(
            [
                ft.Container(
                    content=ft.Row([dot, lbl_status], spacing=5),
                    bgcolor=PANEL2,
                    border=ft.Border.all(1, BORDER),
                    padding=ft.Padding.symmetric(horizontal=12, vertical=7),
                ),
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Container(width=2, height=24, bgcolor=ACCENT),
                            ft.Column(
                                [
                                    label_text("BREACH MONITORING INTERFACE"),
                                    mono("ACTIVE MONITORING", ACCENT, SZ),
                                ],
                                spacing=0,
                            ),
                        ],
                        spacing=8,
                    ),
                    bgcolor=PANEL2,
                    border=ft.Border.all(1, BORDER),
                    padding=ft.Padding.symmetric(horizontal=12, vertical=5),
                ),
                stat_card("ALLOWED", lbl_allowed, SUCCESS),
                stat_card("BLOCKED", lbl_blocked, ACCENT),
                stat_card("TOTAL", lbl_total, ACCENT),
                ft.Container(expand=True),
                iface_card,
                start_btn,
                stop_btn,
            ],
            spacing=6,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        bgcolor=PANEL,
        border=ft.Border.only(bottom=ft.BorderSide(2, BORDER)),
        padding=ft.Padding.symmetric(horizontal=14, vertical=8),
    )

    header = ft.Column([top_strip, controls_strip], spacing=0)

    # ── BODY (ALL SCROLLABLE) ─────────────────────────────────────────────────
    # Panels (keep your expand weights for large screens)
    log_panel = panel("SYSTEM LOG", vscroll(log_col, pad=8), expand=3, icon="▓▓")
    traffic_table_wrap = ft.Container(
        content=traffic_table,
        expand=True,
        clip_behavior=ft.ClipBehavior.HARD_EDGE,
    )
    traffic_panel = panel("LIVE TRAFFIC MATRIX", vscroll(traffic_table_wrap, pad=8), expand=5, icon="▓▓")

    stats_body = ft.Column(
        [stats_meta_row, ydiv(), stats_rows_col],
        spacing=4,
        horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
    )
    stats_panel_col = panel("CLASSIFICATION STATS", vscroll(stats_body, pad=8), expand=3, icon="◈◈")

    blocked_panel = panel("BLOCKED IPs", vscroll(blocked_col, pad=8), expand=2, icon="██", trailing=blocked_badge)

    # Responsive layout — Row with expand weights so all panels fill exactly 100% width
    body = ft.Row(
        controls=[
            log_panel,           # expand=3 → ~21%
            traffic_panel,       # expand=5 → ~36%
            stats_panel_col,     # expand=3 → ~21%
            blocked_panel,       # expand=2 → ~14% — was being squeezed out
        ],
        spacing=6,
        expand=True,
        vertical_alignment=ft.CrossAxisAlignment.STRETCH,
    )
    # ── FOOTER ────────────────────────────────────────────────────────────────
    footer = ft.Container(
        content=ft.Row(
            [
                mono("CUSTOM GLITCHES ON UI MAY APPEAR, BASED ON THIS ANALYSIS.", TEXT_MUTED, SZ - 1),
                ft.Container(expand=True),
                mono("DOCUMENTS//BLACKWALL//SUBSYSTEM//NETWORK//INTRUSTION//FIREWALL", TEXT_MUTED, SZ - 1),
            ]
        ),
        bgcolor=PANEL,
        border=ft.Border.only(top=ft.BorderSide(1, BORDER)),
        padding=ft.Padding.symmetric(horizontal=14, vertical=4),
    )

    page.add(
        ft.Column(
            [
                header,
                ft.Container(
                    content=body,
                    padding=ft.Padding.only(left=6, right=6, top=4, bottom=2),
                    expand=True,
                ),
                footer,
            ],
            spacing=0,
            expand=True,
        )
    )

    poll_alive["v"] = True
    threading.Thread(target=poll_loop, daemon=True).start()
    page.on_disconnect = lambda _: poll_alive.update({"v": False})


ft.run(main)