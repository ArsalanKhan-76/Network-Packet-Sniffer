import click
import threading
import time
import sys
from sniffer import PacketSniffer
from detector import ThreatDetector
from dashboard import Dashboard, console
from report_generator import generate_report
from rich.panel import Panel
from rich.text import Text
from rich import box


@click.command()
@click.option("--interface", "-i",
              default=None,
              help="Network interface to sniff on (default: auto)")
@click.option("--count", "-c",
              default=0,
              help="Number of packets to capture (0 = unlimited)")
@click.option("--filter", "-f", "bpf_filter",
              default=None,
              help="BPF filter e.g. 'tcp port 80' or 'udp'")
@click.option("--timeout", "-t",
              default=0,
              help="Stop after N seconds (0 = run until CTRL+C)")
@click.option("--report", "-r",
              is_flag=True,
              default=False,
              help="Generate HTML report after capture ends")
@click.option("--list-interfaces", "-l",
              is_flag=True,
              default=False,
              help="List all available network interfaces and exit")
@click.option("--no-dashboard",
              is_flag=True,
              default=False,
              help="Disable live dashboard, print packets instead")
def main(interface, count, bpf_filter, timeout,
         report, list_interfaces, no_dashboard):
    """
    \b
    ╔══════════════════════════════════════════════╗
    ║   Network Packet Sniffer & Analyzer          ║
    ║   by Arsalan Khan Pathan                     ║
    ║   github.com/ArsalanKhan-76                  ║
    ╚══════════════════════════════════════════════╝

    Capture and analyze live network traffic.
    Detects port scans, brute force, ARP spoofing,
    DNS tunneling and suspicious ports automatically.

    \b
    Examples:
      python main.py
      python main.py --interface Wi-Fi
      python main.py --filter "tcp port 80"
      python main.py --count 100 --report
      python main.py --timeout 30 --report
      python main.py --list-interfaces
    """

    sniffer  = PacketSniffer()
    detector = ThreatDetector()

    # ── List interfaces and exit ──────────────────────────────
    if list_interfaces:
        console.print(Panel(
            "\n".join(
                f"  [cyan]{i+1}.[/cyan] {iface}"
                for i, iface in enumerate(sniffer.list_interfaces())
            ),
            title="[bold cyan]Available Network Interfaces",
            border_style="cyan",
            box=box.ROUNDED,
        ))
        return

    # ── Resolve interface ─────────────────────────────────────
    if not interface:
        interface = str(sniffer.get_default_interface())

    # ── Print startup banner ──────────────────────────────────
    console.print(Panel(
        Text.from_markup(
            f"[bold cyan]Interface :[/bold cyan]  {interface}\n"
            f"[bold cyan]Filter    :[/bold cyan]  {bpf_filter or 'None'}\n"
            f"[bold cyan]Count     :[/bold cyan]  "
            f"{'Unlimited' if count == 0 else count}\n"
            f"[bold cyan]Timeout   :[/bold cyan]  "
            f"{'None' if timeout == 0 else f'{timeout}s'}\n"
            f"[bold cyan]Report    :[/bold cyan]  "
            f"{'Yes' if report else 'No'}\n\n"
            f"[dim]Run as Administrator for full packet capture.[/dim]\n"
            f"[dim]Press CTRL+C to stop.[/dim]"
        ),
        title="[bold cyan]🔍 Network Packet Sniffer",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    time.sleep(1)

    # ── Setup dashboard ───────────────────────────────────────
    dashboard = Dashboard(sniffer, detector)

    # ── Packet callback ───────────────────────────────────────
    def on_packet(packet_summary):
        # Run threat detection
        alerts = detector.analyze(packet_summary)

        if no_dashboard:
            dashboard.print_packet(packet_summary, alerts)
        else:
            dashboard.on_packet(packet_summary)

    # ── Start capture in background thread ────────────────────
    start_time = time.time()

    capture_thread = threading.Thread(
        target=sniffer.start,
        kwargs={
            "interface":    interface,
            "packet_count": count,
            "filter_str":   bpf_filter,
            "callback":     on_packet,
        },
        daemon=True
    )
    capture_thread.start()

    # ── Timeout thread ────────────────────────────────────────
    if timeout > 0:
        def stop_after_timeout():
            time.sleep(timeout)
            sniffer.stop()
        threading.Thread(
            target=stop_after_timeout,
            daemon=True
        ).start()

    # ── Run UI ────────────────────────────────────────────────
    try:
        if no_dashboard:
            # Simple mode — just wait
            while sniffer.is_running:
                time.sleep(0.1)
        else:
            dashboard.run()

    except KeyboardInterrupt:
        sniffer.stop()
        console.print("\n[yellow]Capture stopped by user.[/yellow]")

    # ── Wait for capture to finish ────────────────────────────
    capture_thread.join(timeout=2)
    duration = round(time.time() - start_time, 1)

    # ── Final summary ─────────────────────────────────────────
    stats  = sniffer.get_stats()
    alerts = detector.get_alerts()

    console.print(Panel(
        Text.from_markup(
            f"[bold]Duration   :[/bold]  {duration}s\n"
            f"[bold]Total Pkts :[/bold]  {stats['total']}\n"
            f"[bold]TCP        :[/bold]  {stats['tcp']}\n"
            f"[bold]UDP        :[/bold]  {stats['udp']}\n"
            f"[bold]DNS        :[/bold]  {stats['dns']}\n"
            f"[bold]HTTP       :[/bold]  {stats['http']}\n"
            f"[bold]ARP        :[/bold]  {stats['arp']}\n"
            f"[bold]ICMP       :[/bold]  {stats['icmp']}\n"
            f"[bold red]Alerts     :[/bold red]  {len(alerts)}"
        ),
        title="[bold cyan]📊 Capture Summary",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    # ── Generate report ───────────────────────────────────────
    if report and stats["total"] > 0:
        console.print("\n[cyan]Generating report...[/cyan]")
        report_path = generate_report(
            sniffer, detector, interface, duration
        )
        console.print(
            f"[bold green]✅ Report saved → {report_path}[/bold green]"
        )
    elif report and stats["total"] == 0:
        console.print(
            "[yellow]No packets captured — report not generated.[/yellow]"
        )


if __name__ == "__main__":
    main()