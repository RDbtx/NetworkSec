"""
boot_screen.py — Animated boot sequence for Blackwall GUI.
"""

import asyncio
import flet as ft

from src.gui.theme import ACCENT, BG, FONT, SZ, TEXT_DIM, TEXT_MUTED

_BOOT_MESSAGES = [
    "INITIALISING BLACKWALL SUBSYSTEM...",
    "LOADING NETWATCH BREACH PROTOCOL v4.7.1...",
    "ESTABLISHING SECURE CHANNEL...",
    "VERIFYING NEURAL UPLINK INTEGRITY...",
    "SCANNING FOR ROGUE AI SIGNATURES...",
    "LOADING CLASSIFICATION ENGINE...",
    "MOUNTING TRAFFIC INTERCEPTION MODULE...",
    "CALIBRATING THREAT DETECTION MATRIX...",
    "SYNCHRONISING BLACKWALL FIREWALL RULES...",
    "NETWATCH PROTOCOL ONLINE. VOS VIDEMUS.",
]


def show_boot_screen(page: ft.Page, on_complete):
    page.clean()
    page.bgcolor = BG

    # ─────────────────────────────────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────────────────────────────────
    logo = ft.Image(
        src="/Users/riccardo/Desktop/NetworkSec/src/gui/assets/netwatch_logo.png",
        width=200, height=200, fit="contain",
    )
    logo.opacity = 0.0

    title = ft.Text(
        "NETWATCH", font_family=FONT, color=ACCENT,
        size=32, weight=ft.FontWeight.BOLD
    )
    title.letter_spacing = 8
    title.opacity = 0.0

    subtitle = ft.Text(
        "VOS VIDEMUS", font_family=FONT, color=TEXT_DIM,
        size=11, weight=ft.FontWeight.BOLD
    )
    subtitle.letter_spacing = 6
    subtitle.opacity = 0.0

    progress_fill  = ft.Container(width=0,   height=3, bgcolor=ACCENT)
    progress_track = ft.Container(width=400, height=3, bgcolor=TEXT_MUTED)
    progress_bar   = ft.Container(
        content=ft.Stack([progress_track, progress_fill]),
        width=400, height=3
    )
    progress_bar.opacity = 0.0

    progress_pct = ft.Text("0%", font_family=FONT, color=TEXT_DIM, size=SZ - 2)
    progress_pct.opacity = 0.0

    msg_rows: list[ft.Row] = []
    for msg in _BOOT_MESSAGES:
        row = ft.Row(
            [
                ft.Text(">>", font_family=FONT, color=ACCENT,
                        size=SZ - 3, weight=ft.FontWeight.BOLD),
                ft.Text(msg, font_family=FONT, color=TEXT_DIM,
                        size=SZ - 3, no_wrap=True),
            ],
            spacing=6,
            visible=False,
        )
        msg_rows.append(row)

    boot_log = ft.Column(
        controls=msg_rows,
        spacing=4,
        horizontal_alignment=ft.CrossAxisAlignment.START,
    )
    boot_log_container = ft.Container(content=boot_log, width=400, height=170)
    boot_log_container.opacity = 0.0

    stamp = ft.Text(
        "MCMXCI  ·  BREACH PROTOCOL INTERFACE  ·  BLACKWALL DIVISION",
        font_family=FONT, color=TEXT_MUTED, size=SZ - 3,
    )
    stamp.letter_spacing = 2
    stamp.opacity = 0.0

    enter_btn = ft.Container(
        content=ft.Text(
            "[ ENTER SYSTEM ]",
            font_family=FONT,
            color=ACCENT,
            size=SZ + 1,
            weight=ft.FontWeight.BOLD,
        ),
        bgcolor=BG,
        border=ft.Border.all(1, ACCENT),
        padding=ft.Padding.symmetric(horizontal=32, vertical=12),
        on_click=lambda _: on_complete(),
        ink=True,
        visible=False,
    )
    enter_btn.opacity = 0.0

    page.add(
        ft.Container(
            expand=True,
            bgcolor=BG,
            content=ft.Column(
                [
                    ft.Container(expand=True),
                    ft.Column(
                        [
                            logo,
                            ft.Container(height=24),
                            title,
                            ft.Container(height=4),
                            subtitle,
                            ft.Container(height=40),
                            progress_bar,
                            ft.Container(height=6),
                            progress_pct,
                            ft.Container(height=16),
                            boot_log_container,
                            ft.Container(height=28),
                            enter_btn,
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=0,
                    ),
                    ft.Container(expand=True),
                    ft.Container(
                        content=stamp,
                        padding=ft.Padding.only(bottom=20),
                        alignment=ft.Alignment.BOTTOM_CENTER,
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                expand=True,
            ),
        )
    )
    page.update()

    # ─────────────────────────────────────────────────────────────────────────
    # Animation (async, runs on UI loop)
    # ─────────────────────────────────────────────────────────────────────────
    async def _animate():
        # 1) Fade in logo
        for step in range(11):
            logo.opacity = step / 10
            page.update()
            await asyncio.sleep(0.05)

        await asyncio.sleep(0.15)

        # 2) Fade in title + subtitle
        for step in range(11):
            v = step / 10
            title.opacity = v
            subtitle.opacity = v
            page.update()
            await asyncio.sleep(0.05)

        await asyncio.sleep(0.2)

        # 3) Fade in bar + log + stamp
        for step in range(11):
            v = step / 10
            progress_bar.opacity = v
            progress_pct.opacity = v
            boot_log_container.opacity = v
            stamp.opacity = v
            page.update()
            await asyncio.sleep(0.05)

        await asyncio.sleep(0.15)

        # 4) Messages one by one + progress (no more 0→100 jump)
        n = len(msg_rows)
        for i in range(n):
            pct = int((i + 1) / n * 100)
            progress_fill.width = int(400 * pct / 100)
            progress_pct.value = f"{pct}%"
            msg_rows[i].visible = True
            page.update()
            await asyncio.sleep(0.45)

        await asyncio.sleep(0.3)

        # 5) Flash last line
        for _ in range(3):
            msg_rows[-1].controls[1].color = TEXT_MUTED
            page.update()
            await asyncio.sleep(0.25)
            msg_rows[-1].controls[1].color = ACCENT
            page.update()
            await asyncio.sleep(0.25)

        await asyncio.sleep(0.2)

        # 6) Fade in enter button
        enter_btn.visible = True
        for step in range(11):
            enter_btn.opacity = step / 10
            page.update()
            await asyncio.sleep(0.05)

        # 7) Pulse button border
        for _ in range(4):
            enter_btn.border = ft.Border.all(1, TEXT_DIM)
            page.update()
            await asyncio.sleep(0.5)
            enter_btn.border = ft.Border.all(1, ACCENT)
            page.update()
            await asyncio.sleep(0.5)

    # Start animation
    page.run_task(_animate)