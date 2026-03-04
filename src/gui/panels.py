"""
panels.py — widget factories for every panel in the Blackwall GUI.

Each builder returns a Flet control (or a tuple of control + updater callable)
so that main.py only needs to wire them together, not build them.
"""

from datetime import datetime
import flet as ft

from src.gui.theme import (
    ACCENT, BG, BORDER, CELL_BG, DANGER, FONT,
    HEADER_BG, HEADER_FG, PANEL2, SUCCESS, SZ,
    TEXT, TEXT_DIM, TEXT_MUTED,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def text_ui(text, color=TEXT, size=SZ, weight=None) -> ft.Text:
    kwargs = dict(color=color, size=size, weight=weight)
    if FONT:
        kwargs["font_family"] = FONT
    return ft.Text(text, **kwargs)


def label_text(text, color=TEXT_DIM, size=SZ - 1) -> ft.Text:
    return ft.Text(
        text.upper(),
        font_family=FONT,
        color=color,
        size=size,
        weight=ft.FontWeight.BOLD,
    )


def panel_header(title: str, icon: str = "▓▓", trailing=None) -> ft.Container:
    row_items = [
        ft.Container(
            content=ft.Text(icon, color=HEADER_BG, size=9, font_family=FONT),
            bgcolor=HEADER_FG,
            width=22,
            height=22,
        ),
        ft.Text(
            title.upper(),
            font_family=FONT,
            color=HEADER_FG,
            size=SZ,
            weight=ft.FontWeight.BOLD,
        ),
        ft.Container(expand=True, height=1, bgcolor=HEADER_FG + "55"),
    ]
    if trailing is not None:
        row_items.append(trailing)
    return ft.Container(
        content=ft.Row(row_items, spacing=6,
                       vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor=HEADER_BG,
        padding=ft.Padding.symmetric(horizontal=8, vertical=5),
    )


def panel(title: str, body, expand: int,
          icon: str = "▓▓", trailing=None) -> ft.Container:
    return ft.Container(
        expand=expand,
        bgcolor=CELL_BG,
        border=ft.Border.all(1, BORDER),
        border_radius=0,
        clip_behavior=ft.ClipBehavior.HARD_EDGE,
        content=ft.Column(
            [
                panel_header(title, icon, trailing=trailing),
                ft.Container(content=body, expand=True),
            ],
            spacing=0,
            expand=True,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        ),
    )


def ydiv() -> ft.Container:
    return ft.Container(height=1, bgcolor=BORDER + "88")


def vscroll(content, pad=0) -> ft.ListView:
    return ft.ListView(
        controls=[ft.Container(content=content, padding=pad)],
        expand=True, spacing=0, padding=0, auto_scroll=False,
    )


def hvscroll(content, pad=0) -> ft.Column:
    """Vertical + horizontal scroll — used for logs and blocked IPs."""
    return ft.Column(
        controls=[
            ft.Row(
                controls=[ft.Container(content=content, padding=pad)],
                scroll=ft.ScrollMode.AUTO,
                expand=True,
            )
        ],
        expand=True,
        spacing=0,
        scroll=ft.ScrollMode.AUTO,
    )


def stat_card(title, widget, accent) -> ft.Container:
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


# ── System Log ────────────────────────────────────────────────────────────────

def build_log_panel():
    """Returns (panel_control, push_log_fn)."""
    log_col = ft.Column(spacing=1)

    def push_log(msg: str, level: str = "info"):
        color = DANGER if level == "danger" else TEXT
        log_col.controls.append(
            ft.Row(
                spacing=5,
                controls=[
                    text_ui(datetime.now().strftime("%H:%M:%S"), TEXT_DIM, SZ - 3),
                    ft.Container(
                        content=text_ui(">>", color, SZ - 3, ft.FontWeight.BOLD),
                        bgcolor=BG,
                        padding=ft.Padding.symmetric(horizontal=3, vertical=1),
                    ),
                    ft.Text(msg.strip(), font_family=FONT,
                            size=SZ - 3, color=color, no_wrap=True),
                ],
            )
        )
        if len(log_col.controls) > 400:
            log_col.controls.pop(0)

    log_panel = panel("SYSTEM LOG", hvscroll(log_col, pad=8), expand=3, icon="▓▓")
    return log_panel, push_log


# ── Live Traffic Matrix ───────────────────────────────────────────────────────

def build_traffic_panel():
    """Returns (panel_control, push_row_fn, clear_fn)."""

    def hdr(lbl):
        return ft.DataColumn(
            ft.Text(lbl, color=ACCENT, size=SZ,
                    font_family=FONT, weight=ft.FontWeight.BOLD)
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
        is_attack = action == "WARNING"
        ac = DANGER if is_attack else SUCCESS
        lc = DANGER if is_attack else TEXT
        traffic_table.rows.insert(
            0,
            ft.DataRow(cells=[
                ft.DataCell(text_ui(ts,     TEXT_DIM, SZ)),
                ft.DataCell(text_ui(action, ac,       SZ, ft.FontWeight.BOLD)),
                ft.DataCell(text_ui(ip,     TEXT,     SZ)),
                ft.DataCell(text_ui(label,  lc,       SZ)),
            ]),
        )
        if len(traffic_table.rows) > 200:
            traffic_table.rows.pop()

    def clear():
        traffic_table.rows.clear()

    wrap = ft.Container(content=traffic_table, expand=True,
                        clip_behavior=ft.ClipBehavior.HARD_EDGE)
    traffic_panel = panel("LIVE TRAFFIC MATRIX", vscroll(wrap, pad=8),
                          expand=5, icon="▓▓")
    return traffic_panel, push_row, clear


# ── Classification Stats ──────────────────────────────────────────────────────

def build_stats_panel():
    """Returns (panel_control, update_stats_fn, clear_fn)."""
    _m0 = text_ui("--", TEXT_DIM, SZ); _m0.width = 70
    _m1 = text_ui("--", TEXT_DIM, SZ); _m1.width = 70
    _m2 = text_ui("--", TEXT_DIM, SZ); _m2.width = 70
    meta_row   = ft.Row(controls=[_m0, _m1, _m2], spacing=16)
    rows_col   = ft.Column(spacing=3)

    def update_stats(elapsed, total, pps, label_counts, label_names):
        NAME_W, COUNT_W, PCT_W = 170, 55, 70
        _m0.value = f"PKT {total}"
        _m1.value = f"pkt/s {pps:.1f}"
        _m2.value = f"UP {elapsed:.0f} s"
        rows_col.controls.clear()

        names  = list(label_names)
        normal = [n for n in names if n.lower() == "normal"]
        others = sorted([n for n in names if n.lower() != "normal"],
                        key=lambda n: label_counts.get(n, 0), reverse=True)
        for name in normal + others:
            count  = label_counts.get(name, 0)
            pct    = 100 * count / total if total else 0.0
            bar_w  = max(1, int(pct * 1.2))
            rows_col.controls.append(
                ft.Column([
                    ft.Row([
                        ft.Container(width=NAME_W,  content=text_ui(name,          TEXT,     SZ)),
                        ft.Container(width=COUNT_W, alignment=ft.Alignment.CENTER_RIGHT,
                                     content=text_ui(str(count), TEXT, SZ, ft.FontWeight.BOLD)),
                        ft.Container(width=PCT_W,   alignment=ft.Alignment.CENTER_RIGHT,
                                     content=text_ui(f"{pct:.1f}%", TEXT_DIM, SZ)),
                    ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    ft.Container(
                        content=ft.Container(width=bar_w, height=2, bgcolor=ACCENT),
                        bgcolor=TEXT_MUTED, height=2, expand=True,
                    ),
                ], spacing=1)
            )

    def clear():
        rows_col.controls.clear()

    body = ft.Column([meta_row, ydiv(), rows_col], spacing=4,
                     horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
    stats_panel = panel("CLASSIFICATION STATS", vscroll(body, pad=8),
                        expand=3, icon="◈◈")
    return stats_panel, update_stats, clear


# ── Blocked IPs ───────────────────────────────────────────────────────────────

def build_blocked_panel(fw_ref, bus_ref, push_log, page):
    """Returns (panel_control, update_blocked_fn)."""

    blocked_badge = ft.Container(
        content=ft.Text("0", font_family=FONT, color=HEADER_FG,
                        size=SZ, weight=ft.FontWeight.BOLD),
        bgcolor=HEADER_FG + "22",
        border=ft.Border.all(1, HEADER_FG),
        padding=ft.Padding.symmetric(horizontal=6, vertical=2),
        margin=ft.Margin(right=4, left=0, top=0, bottom=0),
    )

    blocked_col = ft.Column(spacing=4)

    def update_blocked(ips: set):
        blocked_badge.content.value = str(len(ips))
        blocked_col.controls.clear()
        if not ips:
            blocked_col.controls.append(
                ft.Row([
                    ft.Container(width=4, height=4, bgcolor=TEXT_MUTED),
                    text_ui("none", TEXT_MUTED, SZ),
                ], spacing=8)
            )
        else:
            for ip in sorted(ips):
                def make_unblock(target_ip):
                    def _unblock(_):
                        fw = fw_ref[0]
                        if fw:
                            fw.unblock_ip(target_ip)
                            push_log(f"[Firewall] Unblocked {target_ip}", "info")
                            bus = bus_ref[0]
                            if bus:
                                bus.post_blocked_ips(fw.blocked_ips)
                            page.update()
                    return _unblock

                blocked_col.controls.append(
                    ft.Row([
                        ft.Container(width=6, height=6, bgcolor=DANGER),
                        text_ui(ip, DANGER, SZ),
                        ft.Container(expand=True),
                        ft.TextButton(
                            "✕",
                            on_click=make_unblock(ip),
                            style=ft.ButtonStyle(
                                color={ft.ControlState.DEFAULT: TEXT_MUTED,
                                       ft.ControlState.HOVERED: DANGER},
                                padding=ft.Padding.all(0),
                            ),
                        ),
                    ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER)
                )

    # ── manual unblock input ──────────────────────────────────────────────────
    unblock_input = ft.TextField(
        hint_text="IP address...",
        hint_style=ft.TextStyle(font_family=FONT, color=TEXT_MUTED, size=SZ),
        text_style=ft.TextStyle(font_family=FONT, color=TEXT,       size=SZ),
        bgcolor=BG,
        border_color=BORDER,
        focused_border_color=BORDER,
        border_radius=0,
        content_padding=ft.Padding.symmetric(horizontal=8, vertical=6),
        expand=True,
        height=32,
    )

    def do_unblock(_):
        ip = (unblock_input.value or "").strip()
        if not ip:
            return
        fw = fw_ref[0]
        if fw:
            if ip not in fw.blocked_ips:
                push_log(f"[Firewall] {ip} is not in the blocked list", "warn")
            else:
                fw.unblock_ip(ip)
                push_log(f"[Firewall] Unblocked {ip}", "info")
                bus = bus_ref[0]
                if bus:
                    bus.post_blocked_ips(fw.blocked_ips)
        else:
            push_log(f"[Firewall] No active session to unblock {ip}", "warn")
        unblock_input.value = ""
        page.update()

    unblock_btn = ft.IconButton(
        icon=ft.Icons.REMOVE_CIRCLE_OUTLINE,
        icon_color=DANGER,
        icon_size=16,
        on_click=do_unblock,
        tooltip="Unblock IP",
        style=ft.ButtonStyle(
            bgcolor={ft.ControlState.DEFAULT: BG,
                     ft.ControlState.HOVERED: "#2a0810"},
            shape=ft.RoundedRectangleBorder(radius=0),
            side=ft.BorderSide(1, DANGER),
            padding=ft.Padding.all(4),
        ),
    )

    unblock_section = ft.Container(
        content=ft.Column([
            ft.Container(height=1, bgcolor=BORDER),
            ft.Container(
                content=ft.Column([
                    label_text("MANUAL UNBLOCK"),
                    ft.Row([unblock_input, unblock_btn], spacing=4),
                ], spacing=4),
                padding=ft.Padding.symmetric(horizontal=8, vertical=6),
            ),
        ], spacing=0),
        bgcolor=PANEL2,
    )

    blocked_panel = ft.Container(
        expand=2,
        bgcolor=CELL_BG,
        border=ft.Border.all(1, BORDER),
        border_radius=0,
        clip_behavior=ft.ClipBehavior.HARD_EDGE,
        content=ft.Column(
            [
                panel_header("BLOCKED IPs", "██", trailing=blocked_badge),
                ft.Container(content=hvscroll(blocked_col, pad=8), expand=True),
                unblock_section,
            ],
            spacing=0, expand=True,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        ),
    )

    update_blocked(set())
    return blocked_panel, update_blocked