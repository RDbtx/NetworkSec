import queue


class GUIEventBus:
    LOG   = "log"
    ROW   = "row"
    STAT  = "stat"
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

    def post_stat(self, allowed: int, warnings: int, total: int):
        self.post({"type": self.STAT, "allowed": allowed, "blocked": warnings, "total": total})

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