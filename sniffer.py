from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP, Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import datetime
import threading


class PacketSniffer:
    """
    Core packet capture engine.
    Captures live packets and extracts useful information
    from each one based on its protocol.
    """

    def __init__(self):
        self.packets = []           # All captured packets
        self.stats = {
            "total":    0,
            "tcp":      0,
            "udp":      0,
            "icmp":     0,
            "arp":      0,
            "dns":      0,
            "http":     0,
            "other":    0,
        }
        self.is_running   = False
        self.callback     = None    # UI update function
        self._lock        = threading.Lock()

    # ── Interface helpers ─────────────────────────────────────
    def list_interfaces(self):
        """Return all available network interfaces."""
        return get_if_list()

    def get_default_interface(self):
        """Return system default interface."""
        return conf.iface

    # ── Packet processing ─────────────────────────────────────
    def process_packet(self, packet):
        """
        Called for every captured packet.
        Extracts key fields and stores a clean summary dict.
        """
        summary = {
            "timestamp":  datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "protocol":   "OTHER",
            "src_ip":     None,
            "dst_ip":     None,
            "src_port":   None,
            "dst_port":   None,
            "length":     len(packet),
            "info":       "",
            "raw":        packet,
            "flags":      None,
        }

        # ── ARP ───────────────────────────────────────────────
        if packet.haslayer(ARP):
            arp = packet[ARP]
            summary["protocol"] = "ARP"
            summary["src_ip"]   = arp.psrc
            summary["dst_ip"]   = arp.pdst
            summary["info"]     = (
                f"Who has {arp.pdst}? Tell {arp.psrc}"
                if arp.op == 1
                else f"{arp.psrc} is at {arp.hwsrc}"
            )
            with self._lock:
                self.stats["arp"] += 1

        # ── IP based packets ──────────────────────────────────
        elif packet.haslayer(IP):
            ip = packet[IP]
            summary["src_ip"] = ip.src
            summary["dst_ip"] = ip.dst

            # ── DNS ───────────────────────────────────────────
            if packet.haslayer(DNS):
                summary["protocol"] = "DNS"
                try:
                    if packet.haslayer(DNSQR):
                        query = packet[DNSQR].qname.decode(errors="ignore")
                        summary["info"] = f"Query: {query}"
                    else:
                        summary["info"] = "DNS Response"
                except Exception:
                    summary["info"] = "DNS"
                with self._lock:
                    self.stats["dns"] += 1

            # ── HTTP ──────────────────────────────────────────
            elif packet.haslayer(HTTPRequest):
                summary["protocol"] = "HTTP"
                try:
                    http  = packet[HTTPRequest]
                    host  = http.Host.decode(errors="ignore") \
                            if http.Host else ""
                    path  = http.Path.decode(errors="ignore") \
                            if http.Path else "/"
                    method = http.Method.decode(errors="ignore") \
                            if http.Method else "GET"
                    summary["info"] = f"{method} {host}{path}"
                except Exception:
                    summary["info"] = "HTTP Request"
                with self._lock:
                    self.stats["http"] += 1

            elif packet.haslayer(HTTPResponse):
                summary["protocol"] = "HTTP"
                summary["info"]     = "HTTP Response"
                with self._lock:
                    self.stats["http"] += 1

            # ── TCP ───────────────────────────────────────────
            elif packet.haslayer(TCP):
                tcp = packet[TCP]
                summary["protocol"] = "TCP"
                summary["src_port"] = tcp.sport
                summary["dst_port"] = tcp.dport
                summary["flags"]    = str(tcp.flags)

                # Decode flags to readable form
                flag_map = {
                    "S":  "SYN",
                    "A":  "ACK",
                    "F":  "FIN",
                    "R":  "RST",
                    "P":  "PSH",
                    "SA": "SYN-ACK",
                    "FA": "FIN-ACK",
                    "PA": "PSH-ACK",
                    "RA": "RST-ACK",
                }
                flag_str = flag_map.get(
                    summary["flags"], summary["flags"]
                )
                summary["info"] = (
                    f"{tcp.sport} → {tcp.dport} [{flag_str}]"
                )
                with self._lock:
                    self.stats["tcp"] += 1

            # ── UDP ───────────────────────────────────────────
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                summary["protocol"] = "UDP"
                summary["src_port"] = udp.sport
                summary["dst_port"] = udp.dport
                summary["info"]     = f"{udp.sport} → {udp.dport}"
                with self._lock:
                    self.stats["udp"] += 1

            # ── ICMP ──────────────────────────────────────────
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                summary["protocol"] = "ICMP"
                type_map = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    8: "Echo Request (Ping)",
                    11: "Time Exceeded",
                }
                summary["info"] = type_map.get(
                    icmp.type, f"Type {icmp.type}"
                )
                with self._lock:
                    self.stats["icmp"] += 1

            else:
                with self._lock:
                    self.stats["other"] += 1

        else:
            with self._lock:
                self.stats["other"] += 1

        # ── Store and notify ──────────────────────────────────
        with self._lock:
            self.stats["total"] += 1
            self.packets.append(summary)

        if self.callback:
            self.callback(summary)

    # ── Capture control ───────────────────────────────────────
    def start(self, interface=None, packet_count=0,
              filter_str=None, callback=None):
        """
        Start capturing packets.

        interface    → network interface (None = default)
        packet_count → 0 = capture forever
        filter_str   → BPF filter e.g. "tcp port 80"
        callback     → function called for each packet
        """
        self.callback   = callback
        self.is_running = True

        sniff(
            iface   = interface,
            prn     = self.process_packet,
            count   = packet_count,
            filter  = filter_str,
            store   = False,        # Don't store raw in Scapy
            stop_filter = lambda _: not self.is_running
        )

    def stop(self):
        """Stop the capture."""
        self.is_running = False

    def get_packets(self):
        """Return all captured packet summaries."""
        with self._lock:
            return list(self.packets)

    def get_stats(self):
        """Return current protocol statistics."""
        with self._lock:
            return dict(self.stats)

    def clear(self):
        """Reset everything."""
        with self._lock:
            self.packets = []
            for key in self.stats:
                self.stats[key] = 0