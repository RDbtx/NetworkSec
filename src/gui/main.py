"""
Blackwall Firewall GUI — Cyberpunk 2077 Breach Protocol Edition
────────────────────────────────────────────────────────────────
Requires: flet >= 0.80
"""

import threading
import time
import queue
from datetime import datetime

import flet as ft

from src.firewall.firewall_engine import Firewall, MODEL_PATH
from src.firewall.data_extraction import LiveCapture  # noqa

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
WARN = "#f5a623"
TEXT = "#c8e55b"
TEXT_DIM = "#6b7a2a"
TEXT_MUTED = "#3a4015"
CELL_BG = "#040305"
HEADER_BG = "#c8e55b"
HEADER_FG = "#040305"
MONO = "neomax"
SZ = 10


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

    def post_log(self, msg: str, level: str = "info"):
        self._q.put_nowait({"type": self.LOG, "msg": msg, "level": level})

    def post_row(self, ts: str, action: str, ip: str, label: str):
        self._q.put_nowait({"type": self.ROW,
                            "ts": ts, "action": action, "ip": ip, "label": label})

    def post_stat(self, allowed: int, blocked: int, total: int):
        self._q.put_nowait({"type": self.STAT,
                            "allowed": allowed, "blocked": blocked, "total": total})

    def post_stats_panel(self, elapsed: float, total: int, pps: float,
                         label_counts: dict, label_names: list):
        self._q.put_nowait({"type": self.STATS,
                            "elapsed": elapsed, "total": total, "pps": pps,
                            "label_counts": label_counts,
                            "label_names": label_names})

    def post_blocked_ips(self, ips: set):
        self._q.put_nowait({"type": self.BLOCK, "ips": set(ips)})

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
        import builtins
        self._real_print = builtins.print
        builtins.print = self._tap
        try:
            super().__init__(**kwargs)
        finally:
            builtins.print = self._real_print

    def _tap(self, *args, **kwargs):
        msg = " ".join(str(a) for a in args)
        if "[ALLOW]" in msg or "[BLOCK]" in msg or "Normal traffic from" in msg:
            return
        level = "info"
        if "[WARNING]" in msg or "⚠" in msg:   level = "warn"
        if "Attack" in msg or "DROP" in msg:    level = "danger"
        if "Loaded" in msg or "complete" in msg: level = "success"
        if "error" in msg.lower() or "Fatal" in msg: level = "danger"
        self._bus.post_log(msg, level)

    def handle_prediction(self, label: str, source_ip: str):
        import builtins
        builtins.print = self._tap
        try:
            super().handle_prediction(label, source_ip)
        finally:
            builtins.print = self._real_print

        is_attack = label not in {"Normal", "BENIGN"}
        action = "WARNING" if is_attack else "ALLOW"
        if is_attack:
            self._gui_blocked += 1
        else:
            self._gui_allowed += 1

        ts = datetime.now().strftime("%H:%M:%S")
        self._bus.post_row(ts, action, source_ip or "unknown", label)
        self._bus.post_stat(self._gui_allowed, self._gui_blocked,
                            self.stats.get("total", 0))

        elapsed = time.time() - self.start_time
        total = self.stats.get("total", 0)
        pps = total / elapsed if elapsed > 0 else 0.0
        self._bus.post_stats_panel(elapsed, total, pps,
                                   dict(self.stats), list(self.label_names))
        self._bus.post_blocked_ips(self.blocked_ips)

    def run(self):
        import builtins
        builtins.print = self._tap
        try:
            super().run()
        finally:
            builtins.print = self._real_print


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

    # ── helpers ───────────────────────────────────────────────────────────────
    def mono(text, color=TEXT, size=SZ, weight=None):
        return ft.Text(text, font_family=MONO, color=color, size=size, weight=weight)

    def label_text(text, color=TEXT_DIM, size=SZ - 1):
        return ft.Text(text.upper(), font_family=MONO, color=color, size=size,
                       weight=ft.FontWeight.BOLD)

    # ── panel_header: optional trailing widget injected into the yellow banner ─
    def panel_header(title: str, icon: str = "▓▓", trailing=None):
        row_items = [
            ft.Container(
                content=ft.Text(icon, color=HEADER_BG, size=9, font_family=MONO),
                bgcolor=HEADER_FG, border_radius=0, width=22, height=22,
            ),
            ft.Text(title.upper(), font_family=MONO, color=HEADER_FG,
                    size=SZ, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True, height=1, bgcolor=HEADER_FG + "55"),
        ]
        if trailing is not None:
            row_items.append(trailing)
        return ft.Container(
            content=ft.Row(row_items, spacing=6,
                           vertical_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor=HEADER_BG, border_radius=0,
            padding=ft.Padding.symmetric(horizontal=8, vertical=5),
        )

    def bordered(content, expand=True, padding=8):
        return ft.Container(
            content=content, bgcolor=CELL_BG,
            border=ft.Border.all(1, BORDER),
            border_radius=0, padding=padding, expand=expand,
        )

    def ydiv():
        """Thin yellow-green horizontal divider, no Flet theming."""
        return ft.Container(height=1, bgcolor=BORDER)

    # ══════════════════════════════════════════════════════════════════════════
    #  SYSTEM LOG  (red allowed)
    # ══════════════════════════════════════════════════════════════════════════
    LEVEL_COLOR = {"info": TEXT, "success": SUCCESS, "warn": WARN, "danger": DANGER}
    LEVEL_ICON = {"info": ">>", "success": "OK", "warn": "!!", "danger": "XX"}

    log_col = ft.Column(scroll=ft.ScrollMode.AUTO, spacing=1, expand=True)
    log_content = bordered(log_col)

    def push_log(msg: str, level: str = "info"):
        color = LEVEL_COLOR.get(level, TEXT)
        icon = LEVEL_ICON.get(level, ">>")
        log_col.controls.append(
            ft.Row(spacing=5, controls=[
                mono(datetime.now().strftime("%H:%M:%S"), TEXT_MUTED, SZ),
                ft.Container(
                    content=mono(icon, color, SZ, ft.FontWeight.BOLD),
                    bgcolor=color + "18", border_radius=0,
                    padding=ft.Padding.symmetric(horizontal=3, vertical=1),
                ),
                mono(msg.strip()[:110], color, SZ),
            ])
        )
        if len(log_col.controls) > 400:
            log_col.controls.pop(0)

    # ══════════════════════════════════════════════════════════════════════════
    #  LIVE TRAFFIC MATRIX  (red allowed for WARNING)
    # ══════════════════════════════════════════════════════════════════════════
    def hdr(lbl):
        return ft.DataColumn(
            ft.Text(lbl, color=ACCENT, size=SZ, font_family=MONO,
                    weight=ft.FontWeight.BOLD)
        )

    traffic_table = ft.DataTable(
        columns=[hdr("TIME"), hdr("ACTION"), hdr("IP ADDRESS"), hdr("LABEL")],
        rows=[],
        border=ft.Border.all(1, BORDER),
        border_radius=0,
        heading_row_color={"": "#0d1a09"},
        heading_row_height=26,
        data_row_min_height=22,
        data_row_max_height=22,
        divider_thickness=0,
        column_spacing=16,
        expand=True,
    )
    traffic_content = bordered(
        ft.Column([traffic_table], scroll=ft.ScrollMode.AUTO, expand=True)
    )

    def push_row(ts, action, ip, label):
        is_attack = (action == "WARNING")
        ac = DANGER if is_attack else SUCCESS
        lc = DANGER if is_attack else TEXT
        traffic_table.rows.insert(0, ft.DataRow(cells=[
            ft.DataCell(mono(ts, TEXT_DIM, SZ)),
            ft.DataCell(mono(action, ac, SZ, ft.FontWeight.BOLD)),
            ft.DataCell(mono(ip, TEXT, SZ)),
            ft.DataCell(mono(label, lc, SZ)),
        ]))
        if len(traffic_table.rows) > 200:
            traffic_table.rows.pop()

    # ══════════════════════════════════════════════════════════════════════════
    #  CLASSIFICATION STATS  (yellow only)
    # ══════════════════════════════════════════════════════════════════════════
    _smeta0 = mono("--", TEXT_DIM, SZ)
    _smeta1 = mono("--", TEXT_DIM, SZ)
    _smeta2 = mono("--", TEXT_DIM, SZ)
    stats_meta_row = ft.Row(
        controls=[_smeta0, _smeta1, _smeta2],
        spacing=16, wrap=False,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )
    stats_rows_col = ft.Column(spacing=3, scroll=ft.ScrollMode.AUTO, expand=True)
    stats_content = bordered(
        ft.Column([stats_meta_row, ydiv(), stats_rows_col], spacing=4, expand=True)
    )

    def update_stats_panel(elapsed, total, pps, label_counts, label_names):
        _smeta0.value = f"UP  {elapsed:.0f}s"
        _smeta1.value = f"PKT {total}"
        _smeta2.value = f"{pps:.1f} pkt/s"
        stats_rows_col.controls.clear()
        for name in label_names:
            count = label_counts.get(name, 0)
            pct = 100 * count / total if total else 0
            bar_w = max(1, int(pct * 1.2))
            stats_rows_col.controls.append(
                ft.Column([
                    ft.Row([
                        mono(f"{name:<22}", TEXT, SZ),
                        mono(f"{count:>5}", TEXT, SZ, ft.FontWeight.BOLD),
                        mono(f"  {pct:>5.1f}%", TEXT_DIM, SZ),
                    ], spacing=0),
                    ft.Container(
                        content=ft.Container(width=bar_w, height=2,
                                             bgcolor=ACCENT, border_radius=0),
                        bgcolor=TEXT_MUTED, height=2,
                        border_radius=0, expand=True,
                    ),
                ], spacing=1)
            )

    # ══════════════════════════════════════════════════════════════════════════
    #  BLOCKED IPs  (yellow only)
    #  • count lives in the yellow banner via panel_header(trailing=...)
    #  • body shows the actual IP list
    # ══════════════════════════════════════════════════════════════════════════

    # The count badge that goes into the banner
    blocked_badge = ft.Container(
        content=ft.Text("0", font_family=MONO, color=HEADER_FG,
                        size=SZ, weight=ft.FontWeight.BOLD),
        bgcolor=HEADER_FG + "22",
        border=ft.Border.all(1, HEADER_FG),
        border_radius=0,
        padding=ft.Padding.symmetric(horizontal=6, vertical=2),
        margin=ft.Margin(right=4, left=0, top=0, bottom=0),
    )

    blocked_col = ft.Column(spacing=4, scroll=ft.ScrollMode.AUTO, expand=True)
    blocked_content = bordered(blocked_col)

    def update_blocked_ips(ips: set):
        # Update badge in banner
        blocked_badge.content.value = str(len(ips))
        # Rebuild the IP list
        blocked_col.controls.clear()
        if not ips:
            blocked_col.controls.append(
                ft.Row([
                    ft.Container(width=4, height=4, bgcolor=TEXT_MUTED, border_radius=0),
                    mono("none", TEXT_MUTED, SZ),
                ], spacing=8)
            )
        else:
            for ip in sorted(ips):
                blocked_col.controls.append(
                    ft.Row([
                        ft.Container(width=6, height=6, bgcolor=ACCENT, border_radius=0),
                        mono(ip, ACCENT, SZ),
                    ], spacing=8)
                )

    # Pre-populate with "none"
    update_blocked_ips(set())

    # ── status widgets ────────────────────────────────────────────────────────
    dot = ft.Container(width=7, height=7, border_radius=0, bgcolor=TEXT_MUTED)
    lbl_status = mono("OFFLINE", TEXT_MUTED, SZ, ft.FontWeight.BOLD)
    lbl_allowed = mono("0", SUCCESS, 18, ft.FontWeight.BOLD)
    lbl_blocked = mono("0", ACCENT, 18, ft.FontWeight.BOLD)
    lbl_total = mono("0", TEXT, 18, ft.FontWeight.BOLD)

    def set_online(on: bool):
        dot.bgcolor = SUCCESS if on else TEXT_MUTED
        lbl_status.color = SUCCESS if on else TEXT_MUTED
        lbl_status.value = "ONLINE" if on else "OFFLINE"

    def update_counters(allowed, blocked, total):
        lbl_allowed.value = str(allowed)
        lbl_blocked.value = str(blocked)
        lbl_total.value = str(total)

    # ── poll loop ─────────────────────────────────────────────────────────────
    def poll_loop():
        while poll_alive["v"]:
            bus = bus_ref[0]
            if bus:
                events = bus.drain()
                if events:
                    for ev in events:
                        t = ev["type"]
                        if t == GUIEventBus.LOG:
                            push_log(ev["msg"], ev["level"])
                        elif t == GUIEventBus.ROW:
                            push_row(ev["ts"], ev["action"], ev["ip"], ev["label"])
                        elif t == GUIEventBus.STAT:
                            update_counters(ev["allowed"], ev["blocked"], ev["total"])
                        elif t == GUIEventBus.STATS:
                            update_stats_panel(ev["elapsed"], ev["total"], ev["pps"],
                                               ev["label_counts"], ev["label_names"])
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
        set_online(True)
        push_log("[Firewall] Loading model...", "info")
        page.update()

        bus = GUIEventBus()
        bus_ref[0] = bus

        def _run():
            try:
                fw = GUIFirewall(
                    bus=bus,
                    model_path=MODEL_PATH,
                    interface="en0",
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
            style=ft.ButtonStyle(
                bgcolor={ft.ControlState.DEFAULT: bg, ft.ControlState.HOVERED: hover_bg},
                color=fg,
                shape=ft.RoundedRectangleBorder(radius=0),
                side=ft.BorderSide(1, fg),
                padding=ft.Padding.symmetric(horizontal=18, vertical=10),
                text_style=ft.TextStyle(font_family=MONO, size=SZ,
                                        weight=ft.FontWeight.BOLD, letter_spacing=2),
            ),
            on_click=on_click,
        )

    start_btn = cp_btn("▶  INITIATE", "#071408", SUCCESS, "#0f2810", on_start)
    stop_btn = cp_btn("■  TERMINATE", "#180508", DANGER, "#2a0810", on_stop)

    def stat_card(title, widget, accent):
        return ft.Container(
            content=ft.Column([label_text(title, TEXT_DIM, SZ - 1), widget],
                              spacing=1,
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor=PANEL2, border=ft.Border.all(1, accent), border_radius=0,
            padding=ft.Padding.symmetric(horizontal=14, vertical=6),
        )

    # ══════════════════════════════════════════════════════════════════════════
    #  HEADER
    # ══════════════════════════════════════════════════════════════════════════
    top_strip = ft.Container(
        content=ft.Row([
            ft.Row([
                ft.Container(
                    content=ft.Text("⊕", color=HEADER_BG, size=9, font_family=MONO),
                    bgcolor=HEADER_FG, border_radius=0, width=18, height=18,
                ),
                ft.Text("══ NETWATCH ══", color=HEADER_FG, font_family=MONO,
                        size=12, weight=ft.FontWeight.BOLD),
            ], spacing=6),
            ft.Container(
                content=ft.Row([
                    ft.Container(expand=True, height=1, bgcolor=HEADER_FG + "55"),
                    ft.Container(width=90, height=10, bgcolor=HEADER_FG + "22",
                                 border=ft.Border.all(1, HEADER_FG + "88")),
                    ft.Container(expand=True, height=1, bgcolor=HEADER_FG + "55"),
                ], spacing=4),
                expand=True,
                padding=ft.Padding.symmetric(horizontal=20),
            ),
            ft.Text(
                f"BREACH PROTOCOL INTERFACE      "
                f"BKJMER 62UZ-FFLH-B6LT-E3E7  "
                f"{datetime.now().strftime('%H%M/%S')}",
                color=HEADER_FG, font_family=MONO, size=7,
            ),
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor=HEADER_BG,
        border=ft.Border.only(bottom=ft.BorderSide(1, BORDER)),
        padding=ft.Padding.symmetric(horizontal=14, vertical=5),
    )

    controls_strip = ft.Container(
        content=ft.Row([
            ft.Container(
                content=ft.Row([dot, lbl_status], spacing=5),
                bgcolor=PANEL2, border=ft.Border.all(1, BORDER), border_radius=0,
                padding=ft.Padding.symmetric(horizontal=12, vertical=7),
            ),
            ft.Container(
                content=ft.Row([
                    ft.Container(width=2, height=24, bgcolor=ACCENT, border_radius=0),
                    ft.Column([
                        label_text("BREACH MONITORING INTERFACE", TEXT_DIM, SZ - 1),
                        mono("ACTIVE MONITORING", ACCENT, SZ),
                    ], spacing=0),
                ], spacing=8),
                bgcolor=PANEL2, border=ft.Border.all(1, BORDER), border_radius=0,
                padding=ft.Padding.symmetric(horizontal=12, vertical=5),
            ),
            stat_card("ALLOWED", lbl_allowed, SUCCESS),
            stat_card("BLOCKED", lbl_blocked, ACCENT),
            stat_card("TOTAL", lbl_total, ACCENT),
            ft.Container(expand=True),
            start_btn,
            stop_btn,
        ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor=PANEL,
        border=ft.Border.only(bottom=ft.BorderSide(2, BORDER)),
        padding=ft.Padding.symmetric(horizontal=14, vertical=8),
    )

    header = ft.Column([top_strip, controls_strip], spacing=0)

    # ══════════════════════════════════════════════════════════════════════════
    #  BODY — 4 columns
    #  blocked_badge is injected as trailing widget in the BLOCKED IPs banner
    # ══════════════════════════════════════════════════════════════════════════
    log_panel = ft.Column([
        panel_header("SYSTEM LOG"),
        log_content,
    ], expand=2, spacing=0)

    traffic_panel = ft.Column([
        panel_header("LIVE TRAFFIC MATRIX"),
        traffic_content,
    ], expand=3, spacing=0)

    stats_panel_col = ft.Column([
        panel_header("CLASSIFICATION STATS", "◈◈"),
        stats_content,
    ], expand=2, spacing=0)

    blocked_panel = ft.Column([
        panel_header("BLOCKED IPs", "██", trailing=blocked_badge),  # ← count in banner
        blocked_content,  # ← IPs in body
    ], expand=1, spacing=0)

    body = ft.Row([log_panel, traffic_panel, stats_panel_col, blocked_panel],
                  spacing=6, expand=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  FOOTER
    # ══════════════════════════════════════════════════════════════════════════
    footer = ft.Container(
        content=ft.Row([
            mono("\tNETWACH CORPORATE SECURITY **// VOS VIDEMUS //**",
                 TEXT_MUTED, SZ - 1),
            ft.Container(expand=True),
            mono("DOCUMENTS//BLACKWALL//SUBSYSTEM//NETWORK//INTRUSTION//FIREWALL",
                 TEXT_MUTED, SZ - 1),
        ]),
        bgcolor=PANEL,
        border=ft.Border.only(top=ft.BorderSide(1, BORDER)),
        padding=ft.Padding.symmetric(horizontal=14, vertical=4),
    )

    page.add(ft.Column([
        header,
        ft.Container(content=body,
                     padding=ft.Padding.only(left=6, right=6, top=4, bottom=2),
                     expand=True),
        footer,
    ], spacing=0, expand=True))

    poll_alive["v"] = True
    threading.Thread(target=poll_loop, daemon=True).start()
    page.on_disconnect = lambda _: poll_alive.update({"v": False})


ft.run(main)
