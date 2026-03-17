import re
import threading
import time
from datetime import datetime
import sys
import os
import flet as ft

from src.firewall.firewall_engine import MODEL_PATH, SCALER_PATH
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

LOGO_PATH = "assets/netwatch_logo.png"


def resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def make_cp_button(label: str, bg: str, fg: str, hover_bg: str,
                   on_click) -> ft.Button:
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


class AppController:
    """
    Owns all shared state and event handlers for the main application view.
    """

    def __init__(self, page: ft.Page):
        self.page = page
        self.bus_ref = [None]
        self.fw_ref = [None]
        self.fw_thread = [None]
        self.poll_alive = False
        self.needs_update = False

        # ── panels ────────────────────────────────────────────────────────────
        self.log_panel, self.push_log_inner, self.clear_log = build_log_panel()
        self.traffic_panel, self.push_row, self.clear_traffic = build_traffic_panel()
        self.stats_panel, self.update_stats, self.clear_stats = build_stats_panel()
        self.blocked_panel, self.update_blocked = build_blocked_panel(
            self.fw_ref, self.bus_ref, self.push_log, page
        )

        # ── status widgets ────────────────────────────────────────────────────
        self.dot = ft.Container(width=7, height=7, bgcolor=TEXT_MUTED)
        self.lbl_status = text_ui("OFFLINE", TEXT_MUTED, SZ, ft.FontWeight.BOLD)
        self.lbl_allowed = text_ui("0", SUCCESS, 18, ft.FontWeight.BOLD)
        self.lbl_warnings = text_ui("0", ACCENT, 18, ft.FontWeight.BOLD)
        self.lbl_total = text_ui("0", TEXT, 18, ft.FontWeight.BOLD)

        # ── interface list ────────────────────────────────────────────────────
        self.ifaces = get_tshark_interfaces()
        self.iface_dropdown = ft.Dropdown(
            value=self.ifaces[0][1],
            options=[ft.dropdown.Option(label) for _, label in self.ifaces],
            width=220,
            bgcolor=PANEL2,
            border_color=BORDER,
            focused_border_color=ACCENT,
            color=TEXT,
            text_style=ft.TextStyle(font_family=FONT, size=SZ, color=TEXT),
            content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
            border_radius=0,
        )

        # ── control buttons ───────────────────────────────────────────────────
        self.start_btn = make_cp_button(
            "▶  INITIATE", "#071408", SUCCESS, "#0f2810", self.on_start)
        self.stop_btn = make_cp_button(
            "■  TERMINATE", "#180508", DANGER, "#2a0810", self.on_stop)

        self.set_online(False)

    # ── log wrapper ───────────────────────────────────────────────────────────

    def push_log(self, msg: str, level: str = "info"):
        self.push_log_inner(msg, level)
        self.needs_update = True

    # ── counter + online state ────────────────────────────────────────────────

    def update_counters(self, allowed: int, warnings: int, total: int):
        self.lbl_allowed.value = str(allowed)
        self.lbl_warnings.value = str(warnings)
        self.lbl_total.value = str(total)

    def set_online(self, on: bool):
        self.dot.bgcolor = SUCCESS if on else TEXT_MUTED
        self.lbl_status.color = SUCCESS if on else TEXT_MUTED
        self.lbl_status.value = "ONLINE" if on else "OFFLINE"
        self.start_btn.disabled = on
        self.stop_btn.disabled = not on
        self.iface_dropdown.disabled = on
        self.needs_update = True

    # ── firewall thread target ────────────────────────────────────────────────

    # main.py

    def run_firewall(self, bus: GUIEventBus, iface: str):
        try:
            fw = GUIFirewall(
                bus=bus,
                model_path=resource_path(MODEL_PATH),
                interface=iface,
                bpf_filter=None,
                block=False,
                batch_size=8,
                keylog_file="/Users/riccardo/Desktop/NetworkSec/src/model/dataset/ssl keys/all.txt",
            )
            self.fw_ref[0] = fw
            fw.run()
        except Exception as e:
            bus.post_log(f"[Firewall] Fatal: {e}", "danger")
        finally:
            self.fw_ref[0] = None
            self.fw_thread[0] = None

    # ── button handlers ───────────────────────────────────────────────────────

    def on_start(self, _):
        if self.fw_ref[0] is not None:
            return

        self.clear_log()
        self.clear_traffic()
        self.clear_stats()
        self.update_blocked(set())
        self.update_counters(0, 0, 0)

        raw = self.iface_dropdown.value or self.ifaces[0][1]
        m = re.match(r"^\d+\.\s+(\S+)", raw)
        iface = m.group(1) if m else raw

        self.set_online(True)
        self.push_log("[Firewall] Loading model...", "info")
        self.push_log(f"[Firewall] Interface: {iface}", "info")

        bus = GUIEventBus()
        self.bus_ref[0] = bus

        t = threading.Thread(target=self.run_firewall, args=(bus, iface), daemon=True)
        self.fw_thread[0] = t
        t.start()

    def on_stop(self, _):
        fw = self.fw_ref[0]
        if fw:
            try:
                fw.capture.stop_event.set()
                fw.capture.stop()
            except Exception:
                pass
        self.fw_ref[0] = self.fw_thread[0] = self.bus_ref[0] = None
        self.set_online(False)
        self.push_log("[Firewall] Firewall stopped.", "danger")

    # ── poll loop ─────────────────────────────────────────────────────────────

    def poll_loop(self):
        while self.poll_alive:
            bus = self.bus_ref[0]
            if bus:
                for ev in bus.drain():
                    t = ev["type"]
                    if t == GUIEventBus.LOG:
                        self.push_log(ev["msg"], ev["level"])
                    elif t == GUIEventBus.ROW:
                        self.push_row(ev["ts"], ev["action"], ev["ip"], ev["label"])
                        self.needs_update = True
                    elif t == GUIEventBus.STAT:
                        self.update_counters(ev["allowed"], ev["blocked"], ev["total"])
                        self.needs_update = True
                    elif t == GUIEventBus.STATS:
                        self.update_stats(ev["elapsed"], ev["total"], ev["pps"],
                                          ev["label_counts"], ev["label_names"])
                        self.needs_update = True
                    elif t == GUIEventBus.BLOCK:
                        self.update_blocked(ev["ips"])
                        self.needs_update = True
            if self.needs_update:
                self.needs_update = False
                self.page.update()
            time.sleep(0.15)

    def stop_poll(self, _):
        self.poll_alive = False

    # ── layout builders ───────────────────────────────────────────────────────

    def build_top_strip(self) -> ft.Container:
        return ft.Container(
            content=ft.Row(
                [
                    ft.Row([
                        ft.Container(
                            content=ft.Text("⊕", color=HEADER_BG, size=9,
                                            font_family=FONT),
                            bgcolor=HEADER_FG, width=18, height=18,
                        ),
                        ft.Text("══ NETWATCH ══", color=HEADER_FG,
                                font_family=FONT, size=12,
                                weight=ft.FontWeight.BOLD),
                    ], spacing=6),
                    ft.Container(
                        content=ft.Row([
                            ft.Container(expand=True, height=1,
                                         bgcolor=HEADER_FG + "55"),
                            ft.Container(width=90, height=10,
                                         bgcolor=HEADER_FG + "22",
                                         border=ft.Border.all(1, HEADER_FG + "88")),
                            ft.Container(expand=True, height=1,
                                         bgcolor=HEADER_FG + "55"),
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

    def build_controls_strip(self) -> ft.Container:
        iface_card = ft.Container(
            content=ft.Column(
                [label_text("INTERFACE"), self.iface_dropdown],
                spacing=2,
                horizontal_alignment=ft.CrossAxisAlignment.START,
            ),
            bgcolor=PANEL2,
            border=ft.Border.all(1, BORDER),
            padding=ft.Padding.symmetric(horizontal=10, vertical=5),
        )
        return ft.Container(
            content=ft.Row(
                [
                    ft.Container(
                        content=ft.Row([self.dot, self.lbl_status], spacing=5),
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
                    stat_card("ALLOWED", self.lbl_allowed, SUCCESS),
                    stat_card("WARNINGS", self.lbl_warnings, ACCENT),
                    stat_card("TOTAL", self.lbl_total, ACCENT),
                    ft.Container(expand=True),
                    iface_card,
                    self.start_btn,
                    self.stop_btn,
                ],
                spacing=6,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            bgcolor=PANEL,
            border=ft.Border.only(bottom=ft.BorderSide(2, BORDER)),
            padding=ft.Padding.symmetric(horizontal=14, vertical=8),
        )

    def build_footer(self) -> ft.Container:
        return ft.Container(
            content=ft.Row([
                text_ui("CUSTOM GLITCHES ON UI MAY APPEAR, BASED ON THIS ANALYSIS.",
                        TEXT_MUTED, SZ - 1),
                ft.Container(expand=True),
                text_ui(
                    "DOCUMENTS//BLACKWALL//SUBSYSTEM//NETWORK//INTRUSTION//FIREWALL",
                    TEXT_MUTED, SZ - 1),
            ]),
            bgcolor=PANEL,
            border=ft.Border.only(top=ft.BorderSide(1, BORDER)),
            padding=ft.Padding.symmetric(horizontal=14, vertical=4),
        )

    def mount(self):
        """Assemble the full layout, add it to the page, and start the poll loop."""
        header = ft.Column(
            [self.build_top_strip(), self.build_controls_strip()],
            spacing=0,
        )
        body = ft.Row(
            controls=[
                self.log_panel, self.traffic_panel,
                self.stats_panel, self.blocked_panel,
            ],
            spacing=6,
            expand=True,
            vertical_alignment=ft.CrossAxisAlignment.STRETCH,
        )
        self.page.add(
            ft.Column(
                [
                    header,
                    ft.Container(
                        content=body,
                        padding=ft.Padding.only(left=6, right=6, top=4, bottom=2),
                        expand=True,
                    ),
                    self.build_footer(),
                ],
                spacing=0,
                expand=True,
            )
        )
        self.poll_alive = True
        threading.Thread(target=self.poll_loop, daemon=True).start()
        self.page.on_disconnect = self.stop_poll


def build_app(page: ft.Page):
    AppController(page).mount()


def main(page: ft.Page):
    """Entry point — shows boot screen then hands off to the main app."""
    page.title = "NETWATCH — BLACKWALL — INTRUSION FIREWALL"
    page.bgcolor = BG
    page.padding = 0
    page.window.width = 1400
    page.window.height = 860
    page.window.min_width = 1100
    page.window.min_height = 700
    page.fonts = {}

    """show_boot_screen(
        resource_path(LOGO_PATH),
        page,
        on_complete=lambda: (page.clean(), build_app(page)),
    )"""

    build_app(page)

ft.run(main)