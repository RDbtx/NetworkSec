"""
boot_screen.py — Animated boot sequence for Blackwall GUI.
"""

import asyncio
import flet as ft

from src.gui.theme import ACCENT, BG, FONT, SZ, TEXT_DIM, TEXT_MUTED

BOOT_MESSAGES = [
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


class BootAnimator:
    """Owns all boot-screen widgets and runs the async animation sequence."""

    def __init__(self, asset_path: str, page: ft.Page, on_complete):
        self.page = page
        self.on_complete = on_complete

        self.logo = ft.Image(src=asset_path, width=200, height=200, fit="contain")
        self.logo.opacity = 0.0

        self.title = ft.Text(
            "NETWATCH", font_family=FONT, color=ACCENT,
            size=32, weight=ft.FontWeight.BOLD,
             opacity=0.0,
        )

        self.subtitle = ft.Text(
            "VOS VIDEMUS", font_family=FONT, color=TEXT_DIM,
            size=11, weight=ft.FontWeight.BOLD,
            opacity=0.0,
        )

        self.progress_fill = ft.Container(width=0, height=3, bgcolor=ACCENT)
        self.progress_bar = ft.Container(
            content=ft.Stack([
                ft.Container(width=400, height=3, bgcolor=TEXT_MUTED),
                self.progress_fill,
            ]),
            width=400, height=3, opacity=0.0,
        )

        self.progress_pct = ft.Text(
            "0%", font_family=FONT, color=TEXT_DIM,
            size=SZ - 2, opacity=0.0,
        )

        self.msg_rows: list[ft.Row] = []
        for msg in BOOT_MESSAGES:
            self.msg_rows.append(ft.Row(
                controls=[
                    ft.Text(">>", font_family=FONT, color=ACCENT,
                            size=SZ - 3, weight=ft.FontWeight.BOLD),
                    ft.Text(msg, font_family=FONT, color=TEXT_DIM,
                            size=SZ - 3, no_wrap=True),
                ],
                spacing=6,
                visible=False,
            ))

        self.boot_log_container = ft.Container(
            content=ft.Column(
                controls=self.msg_rows,
                spacing=4,
                horizontal_alignment=ft.CrossAxisAlignment.START,
            ),
            width=400, height=170, opacity=0.0,
        )

        self.stamp = ft.Text(
            "MCMXCI  ·  BREACH PROTOCOL INTERFACE  ·  BLACKWALL DIVISION",
            font_family=FONT, color=TEXT_MUTED, size=SZ - 3,
            opacity=0.0,
        )

        self.enter_btn = ft.Container(
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
            on_click=self.handle_enter,
            ink=True,
            visible=False,
            opacity=0.0,
        )

    def handle_enter(self, _):
        self.on_complete()

    def build_layout(self) -> ft.Container:
        return ft.Container(
            expand=True,
            bgcolor=BG,
            content=ft.Column(
                [
                    ft.Container(expand=True),
                    ft.Column(
                        [
                            self.logo,
                            ft.Container(height=24),
                            self.title,
                            ft.Container(height=4),
                            self.subtitle,
                            ft.Container(height=40),
                            self.progress_bar,
                            ft.Container(height=6),
                            self.progress_pct,
                            ft.Container(height=16),
                            self.boot_log_container,
                            ft.Container(height=28),
                            self.enter_btn,
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=0,
                    ),
                    ft.Container(expand=True),
                    ft.Container(
                        content=self.stamp,
                        padding=ft.Padding.only(bottom=20),
                        alignment=ft.Alignment.BOTTOM_CENTER,
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                expand=True,
            ),
        )

    async def fade_in(self, *controls, steps: int = 11, delay: float = 0.05):
        for step in range(steps):
            v = step / (steps - 1)
            for ctrl in controls:
                ctrl.opacity = v
            self.page.update()
            await asyncio.sleep(delay)

    async def run_animation(self):
        await self.fade_in(self.logo)
        await asyncio.sleep(0.15)

        await self.fade_in(self.title, self.subtitle)
        await asyncio.sleep(0.2)

        await self.fade_in(
            self.progress_bar, self.progress_pct,
            self.boot_log_container, self.stamp,
        )
        await asyncio.sleep(0.15)

        n = len(self.msg_rows)
        for i, row in enumerate(self.msg_rows):
            pct = int((i + 1) / n * 100)
            self.progress_fill.width = int(400 * pct / 100)
            self.progress_pct.value = f"{pct}%"
            row.visible = True
            self.page.update()
            await asyncio.sleep(0.45)

        await asyncio.sleep(0.3)

        last_text = self.msg_rows[-1].controls[1]
        for _ in range(3):
            last_text.color = TEXT_MUTED
            self.page.update()
            await asyncio.sleep(0.25)
            last_text.color = ACCENT
            self.page.update()
            await asyncio.sleep(0.25)

        await asyncio.sleep(0.2)

        self.enter_btn.visible = True
        await self.fade_in(self.enter_btn)

        for _ in range(4):
            self.enter_btn.border = ft.Border.all(1, TEXT_MUTED)
            self.page.update()
            await asyncio.sleep(0.5)
            self.enter_btn.border = ft.Border.all(1, ACCENT)
            self.page.update()
            await asyncio.sleep(0.5)


def show_boot_screen(asset_path: str, page: ft.Page, on_complete):
    page.clean()
    page.bgcolor = BG

    animator = BootAnimator(asset_path, page, on_complete)
    page.add(animator.build_layout())
    page.update()

    page.run_task(animator.run_animation)