import re
import threading
import time
from datetime import datetime
import sys
import os
import flet as ft

from src.firewall.firewall_engine import MODEL_PATH
from src.gui.boot_screen import show_boot_screen
from src.gui.event_bus import GUIEventBus
from src.gui.gui_firewall import GUIFirewall, get_tshark_interfaces
from src.gui.panels import (
    build_blocked_panel,
    build_log_panel,
    build_stats_panel,
    build_traffic_panel,
    label_text,
    panel_header,
    stat_card,
    text_ui,
)
from src.gui.theme import (
    ACCENT, BG, BORDER, DANGER, FONT,
    HEADER_BG, HEADER_FG, PANEL, PANEL2,
    SUCCESS, SZ, TEXT, TEXT_DIM, TEXT_MUTED,
)


def resource_path(relative_path: str) -> str:
    """
    Resolve a resource path that works in three situations:
      1. PyInstaller .app / exe  → sys._MEIPASS
      2. Dev: running main.py directly → same directory as main.py
    """
    if hasattr(sys, '_MEIPASS'):
        # Inside PyInstaller bundle — _MEIPASS is the _internal/ folder
        base = sys._MEIPASS
    else:
        # Dev mode — anchor to the folder containing main.py
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)


def _build_app(page: ft.Page):
    # shared state
    bus_ref: list = [None]
    fw_ref: list = [None]
    fw_thread: list = [None]
    poll_alive = {"v": False}

    # ── panels ────────────────────────────────────────────────────────────────
    log_panel, push_log = build_log_panel()
    traffic_panel, push_row, clear_traffic = build_traffic_panel()
    stats_panel, update_stats, clear_stats = build_stats_panel()

    blocked_panel, update_blocked = build_blocked_panel(
        fw_ref, bus_ref, push_log, page
    )

    # ── status widgets ────────────────────────────────────────────────────────
    dot = ft.Container(width=7, height=7, bgcolor=TEXT_MUTED)
    lbl_status = text_ui("OFFLINE", TEXT_MUTED, SZ, ft.FontWeight.BOLD)
    lbl_allowed = text_ui("0", SUCCESS, 18, ft.FontWeight.BOLD)
    lbl_warnings = text_ui("0", ACCENT, 18, ft.FontWeight.BOLD)
    lbl_total = text_ui("0", TEXT, 18, ft.FontWeight.BOLD)

    def update_counters(allowed, warnings, total):
        lbl_allowed.value = str(allowed)
        lbl_warnings.value = str(warnings)
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
                        update_stats(ev["elapsed"], ev["total"], ev["pps"],
                                     ev["label_counts"], ev["label_names"])
                    elif t == GUIEventBus.BLOCK:
                        update_blocked(ev["ips"])
                page.update()
            time.sleep(0.15)

    # ── firewall start / stop ─────────────────────────────────────────────────
    def on_start(_):
        if fw_ref[0] is not None:
            return

        clear_traffic()
        clear_stats()
        update_blocked(set())
        update_counters(0, 0, 0)

        raw = iface_dropdown.value or _ifaces[0][1]
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
                    block=True,
                    warmup_packets=1,
                    keylog_file=None,
                    batch_size=8,
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
                    font_family=FONT, size=SZ,
                    weight=ft.FontWeight.BOLD, letter_spacing=2,
                ),
            ),
            on_click=on_click,
        )

    start_btn = cp_btn("▶  INITIATE", "#071408", SUCCESS, "#0f2810", on_start)
    stop_btn = cp_btn("■  TERMINATE", "#180508", DANGER, "#2a0810", on_stop)

    # ── online / offline state ────────────────────────────────────────────────
    def set_online(on: bool):
        dot.bgcolor = SUCCESS if on else TEXT_MUTED
        lbl_status.color = SUCCESS if on else TEXT_MUTED
        lbl_status.value = "ONLINE" if on else "OFFLINE"
        start_btn.disabled = on
        stop_btn.disabled = not on
        iface_dropdown.disabled = on

    # ── interface selector ────────────────────────────────────────────────────
    _ifaces = get_tshark_interfaces()

    iface_dropdown = ft.Dropdown(
        value=_ifaces[0][1],
        options=[ft.dropdown.Option(label) for _, label in _ifaces],
        width=220,
        bgcolor=PANEL2,
        border_color=BORDER,
        focused_border_color=ACCENT,
        color=TEXT,
        text_style=ft.TextStyle(font_family=FONT, size=SZ, color=TEXT),
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
        border_radius=0,
    )

    iface_card = ft.Container(
        content=ft.Column(
            [label_text("INTERFACE"), iface_dropdown],
            spacing=2,
            horizontal_alignment=ft.CrossAxisAlignment.START,
        ),
        bgcolor=PANEL2,
        border=ft.Border.all(1, BORDER),
        padding=ft.Padding.symmetric(horizontal=10, vertical=5),
    )

    set_online(False)

    # ── header ────────────────────────────────────────────────────────────────
    top_strip = ft.Container(
        content=ft.Row(
            [
                ft.Row([
                    ft.Container(
                        content=ft.Text("⊕", color=HEADER_BG, size=9, font_family=FONT),
                        bgcolor=HEADER_FG, width=18, height=18,
                    ),
                    ft.Text("══ NETWATCH ══", color=HEADER_FG, font_family=FONT,
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
                    color=HEADER_FG, font_family=FONT, size=7,
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
                    bgcolor=PANEL2, border=ft.Border.all(1, BORDER),
                    padding=ft.Padding.symmetric(horizontal=12, vertical=7),
                ),
                ft.Container(
                    content=ft.Row([
                        ft.Container(width=2, height=24, bgcolor=ACCENT),
                        ft.Column([
                            label_text("BREACH MONITORING INTERFACE"),
                            text_ui("ACTIVE MONITORING", ACCENT, SZ),
                        ], spacing=0),
                    ], spacing=8),
                    bgcolor=PANEL2, border=ft.Border.all(1, BORDER),
                    padding=ft.Padding.symmetric(horizontal=12, vertical=5),
                ),
                stat_card("ALLOWED", lbl_allowed, SUCCESS),
                stat_card("WARNINGS", lbl_warnings, ACCENT),
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

    # ── body ──────────────────────────────────────────────────────────────────
    body = ft.Row(
        controls=[log_panel, traffic_panel, stats_panel, blocked_panel],
        spacing=6,
        expand=True,
        vertical_alignment=ft.CrossAxisAlignment.STRETCH,
    )

    # ── footer ────────────────────────────────────────────────────────────────
    footer = ft.Container(
        content=ft.Row([
            text_ui("CUSTOM GLITCHES ON UI MAY APPEAR, BASED ON THIS ANALYSIS.",
                    TEXT_MUTED, SZ - 1),
            ft.Container(expand=True),
            text_ui("DOCUMENTS//BLACKWALL//SUBSYSTEM//NETWORK//INTRUSTION//FIREWALL",
                    TEXT_MUTED, SZ - 1),
        ]),
        bgcolor=PANEL,
        border=ft.Border.only(top=ft.BorderSide(1, BORDER)),
        padding=ft.Padding.symmetric(horizontal=14, vertical=4),
    )

    # ── assemble ──────────────────────────────────────────────────────────────
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


def main(page: ft.Page):
    page.title = "NETWATCH — BLACKWALL — INTRUSION FIREWALL"
    page.bgcolor = BG
    page.padding = 0
    page.window.width = 1400
    page.window.height = 860
    page.window.min_width = 1100
    page.window.min_height = 700
    page.fonts = {}

    def launch_app():
        page.clean()
        _build_app(page)

    show_boot_screen(
        resource_path("src/gui/assets/netwatch_logo.png"),
        page,
        on_complete=launch_app,
    )


ft.run(main)
