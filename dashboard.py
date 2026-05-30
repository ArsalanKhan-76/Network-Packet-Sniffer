from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.columns import Columns
from rich import box
import threading


console = Console()

# ── Protocol colors ───────────────────────────────────────────
PROTO_COLORS = {
    "TCP":   "cyan",
    "UDP":   "blue",
    "ICMP":  "yellow",
    "ARP":   "magenta",
    "DNS":   "green",
    "HTTP":  "bright_green",
    "OTHER": "dim white",
}

# ── Severity colors ───────────────────────────────────────────
SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "dim yellow",
}


class Dashboard:
    """
    Real-time terminal dashboard using Rich.
    Shows live packet stream, protocol stats,
    and threat alerts side by side.
    """

    def __init__(self, sniffer, detector):
        self.sniffer  = sniffer
        self.detector = detector
        self.console  = Console()
        self._lock    = threading.Lock()
        self.recent_packets = []   # Last 20 packets for display
        self.max_display    = 20

    # ── Header ────────────────────────────────────────────────
    def _make_header(self):
        return Panel(
            Text(
                "🔍  Network Packet Sniffer & Analyzer  |  "
                "by Arsalan Khan Pathan  |  "
                "Press CTRL+C to stop",
                justify="center",
                style="bold cyan"
            ),
            style="cyan",
            box=box.HEAVY,
        )

    # ── Stats panel ───────────────────────────────────────────
    def _make_stats(self, stats):
        table = Table(
            box=box.SIMPLE,
            show_header=False,
            padding=(0, 2)
        )
        table.add_column("Protocol", style="dim")
        table.add_column("Count",    justify="right")
        table.add_column("Bar",      width=20)

        total = max(stats["total"], 1)

        for proto in ["tcp", "udp", "icmp", "arp", "dns", "http", "other"]:
            count  = stats[proto]
            pct    = count / total
            bar_len = int(pct * 18)
            color  = PROTO_COLORS.get(proto.upper(), "white")
            bar    = f"[{color}]{'█' * bar_len}{'░' * (18 - bar_len)}[/{color}]"

            table.add_row(
                f"[{color}]{proto.upper()}[/{color}]",
                f"[bold]{count}[/bold]",
                bar
            )

        return Panel(
            table,
            title=f"[bold cyan]Protocol Stats  "
                  f"[dim]({stats['total']} total)[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
        )

    # ── Packet table ──────────────────────────────────────────
    def _make_packet_table(self):
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )

        table.add_column("Time",     width=12, style="dim")
        table.add_column("Proto",    width=6)
        table.add_column("Source",   width=22)
        table.add_column("Destination", width=22)
        table.add_column("Info",     no_wrap=False)

        with self._lock:
            packets = list(self.recent_packets[-self.max_display:])

        for p in reversed(packets):
            proto = p.get("protocol", "OTHER")
            color = PROTO_COLORS.get(proto, "white")

            src = p.get("src_ip") or "—"
            dst = p.get("dst_ip") or "—"

            if p.get("src_port"):
                src += f":{p['src_port']}"
            if p.get("dst_port"):
                dst += f":{p['dst_port']}"

            table.add_row(
                p.get("timestamp", ""),
                f"[{color}]{proto}[/{color}]",
                src,
                dst,
                p.get("info", "")[:60],
            )

        return Panel(
            table,
            title="[bold cyan]Live Packet Stream",
            border_style="cyan",
            box=box.ROUNDED,
        )

    # ── Alerts panel ──────────────────────────────────────────
    def _make_alerts_panel(self, alerts):
        if not alerts:
            return Panel(
                Text(
                    "✅  No threats detected",
                    style="green",
                    justify="center"
                ),
                title="[bold red]🚨 Threat Alerts",
                border_style="red",
                box=box.ROUNDED,
            )

        table = Table(
            box=box.SIMPLE,
            show_header=False,
            padding=(0, 1),
        )
        table.add_column("Severity", width=10)
        table.add_column("Type",     width=16)
        table.add_column("Detail")
        table.add_column("Time",     width=10, style="dim")

        for alert in reversed(alerts[-10:]):
            sev   = alert["severity"]
            color = SEV_COLORS.get(sev, "white")
            table.add_row(
                f"[{color}]{sev}[/{color}]",
                f"[bold]{alert['type']}[/bold]",
                alert["detail"][:50],
                alert["time"],
            )

        return Panel(
            table,
            title=f"[bold red]🚨 Threat Alerts  "
                  f"[dim]({len(alerts)} total)[/dim]",
            border_style="red",
            box=box.ROUNDED,
        )

    # ── Full layout ───────────────────────────────────────────
    def _build_layout(self):
        stats   = self.sniffer.get_stats()
        alerts  = self.detector.get_alerts()

        layout = Layout()
        layout.split_column(
            Layout(self._make_header(),        size=3),
            Layout(name="middle"),
            Layout(self._make_alerts_panel(alerts), size=14),
        )
        layout["middle"].split_row(
            Layout(self._make_stats(stats),    ratio=1),
            Layout(self._make_packet_table(),  ratio=3),
        )
        return layout

    # ── Add packet to display ─────────────────────────────────
    def on_packet(self, packet_summary):
        with self._lock:
            self.recent_packets.append(packet_summary)
            if len(self.recent_packets) > 200:
                self.recent_packets = self.recent_packets[-200:]

    # ── Run live dashboard ────────────────────────────────────
    def run(self):
        with Live(
            self._build_layout(),
            console=self.console,
            refresh_per_second=2,
            screen=True,
        ) as live:
            while self.sniffer.is_running:
                live.update(self._build_layout())

    # ── Simple print mode (no live UI) ───────────────────────
    def print_packet(self, packet_summary, alerts=None):
        proto = packet_summary.get("protocol", "OTHER")
        color = PROTO_COLORS.get(proto, "white")

        src = packet_summary.get("src_ip") or "—"
        dst = packet_summary.get("dst_ip") or "—"
        if packet_summary.get("src_port"):
            src += f":{packet_summary['src_port']}"
        if packet_summary.get("dst_port"):
            dst += f":{packet_summary['dst_port']}"

        console.print(
            f"[dim]{packet_summary.get('timestamp', '')}[/dim]  "
            f"[{color}]{proto:<6}[/{color}]  "
            f"{src:<25} → {dst:<25}  "
            f"{packet_summary.get('info', '')[:50]}"
        )

        if alerts:
            for alert in alerts:
                sev   = alert["severity"]
                color = SEV_COLORS.get(sev, "white")
                console.print(
                    f"  [bold {color}]⚠  {sev} | "
                    f"{alert['type']} | "
                    f"{alert['detail']}[/bold {color}]"
                )