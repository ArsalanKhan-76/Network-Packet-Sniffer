from collections import defaultdict
from datetime import datetime


class ThreatDetector:
    """
    Analyzes captured packets in real time and
    detects suspicious patterns automatically.
    """

    def __init__(self):
        # Port scan tracking
        self.port_scan_tracker  = defaultdict(set)

        # Brute force tracking
        self.syn_tracker        = defaultdict(list)

        # ARP spoofing tracking
        self.arp_table          = {}

        # DNS tracking
        self.dns_queries        = defaultdict(list)

        # All detected alerts
        self.alerts             = []

        # Thresholds
        self.PORT_SCAN_THRESHOLD    = 10   # ports in 5 sec = port scan
        self.BRUTE_FORCE_THRESHOLD  = 20   # SYNs in 3 sec = brute force

    # ── Main analysis function ────────────────────────────────
    def analyze(self, packet_summary):
        """
        Run all detection checks on every packet.
        Returns a list of new alerts triggered by this packet.
        """
        new_alerts = []

        proto = packet_summary.get("protocol")
        src   = packet_summary.get("src_ip")
        dst   = packet_summary.get("dst_ip")
        dport = packet_summary.get("dst_port")
        flags = packet_summary.get("flags")
        now   = datetime.now()

        # Run each detector
        alert = self._check_port_scan(src, dst, dport, now)
        if alert:
            new_alerts.append(alert)
            self.alerts.append(alert)

        alert = self._check_brute_force(src, dst, dport, flags, now)
        if alert:
            new_alerts.append(alert)
            self.alerts.append(alert)

        alert = self._check_arp_spoof(packet_summary)
        if alert:
            new_alerts.append(alert)
            self.alerts.append(alert)

        alert = self._check_dns_tunneling(packet_summary, now)
        if alert:
            new_alerts.append(alert)
            self.alerts.append(alert)

        alert = self._check_suspicious_ports(src, dst, dport)
        if alert:
            new_alerts.append(alert)
            self.alerts.append(alert)

        return new_alerts

    # ── Port scan detection ───────────────────────────────────
    def _check_port_scan(self, src, dst, dport, now):
        """
        Detect port scanning — one source hitting
        many different ports in a short time.
        """
        if not all([src, dst, dport]):
            return None

        key = f"{src}→{dst}"
        self.port_scan_tracker[key].add(dport)

        if len(self.port_scan_tracker[key]) >= self.PORT_SCAN_THRESHOLD:
            ports = len(self.port_scan_tracker[key])
            # Reset to avoid repeated alerts
            self.port_scan_tracker[key] = set()
            return self._make_alert(
                severity = "HIGH",
                type     = "PORT SCAN",
                src      = src,
                dst      = dst,
                detail   = f"{src} scanned {ports} ports on {dst}",
                time     = now
            )
        return None

    # ── Brute force detection ─────────────────────────────────
    def _check_brute_force(self, src, dst, dport, flags, now):
        """
        Detect brute force — many SYN packets to
        same port in short time (e.g. SSH brute force).
        """
        if not all([src, dst, dport, flags]):
            return None

        if "S" not in str(flags) or "A" in str(flags):
            return None  # Only count pure SYNs

        key = f"{src}→{dst}:{dport}"
        self.syn_tracker[key].append(now)

        # Keep only last 3 seconds
        self.syn_tracker[key] = [
            t for t in self.syn_tracker[key]
            if (now - t).seconds < 3
        ]

        if len(self.syn_tracker[key]) >= self.BRUTE_FORCE_THRESHOLD:
            self.syn_tracker[key] = []
            service = self._port_to_service(dport)
            return self._make_alert(
                severity = "CRITICAL",
                type     = "BRUTE FORCE",
                src      = src,
                dst      = dst,
                detail   = f"Brute force on {service} (port {dport}) from {src}",
                time     = now
            )
        return None

    # ── ARP spoofing detection ────────────────────────────────
    def _check_arp_spoof(self, packet_summary):
        """
        Detect ARP spoofing — same IP claimed by
        two different MAC addresses.
        """
        if packet_summary.get("protocol") != "ARP":
            return None

        info = packet_summary.get("info", "")
        src  = packet_summary.get("src_ip")

        if not src:
            return None

        # Extract MAC from info if available
        raw = packet_summary.get("raw")
        if not raw:
            return None

        try:
            from scapy.layers.l2 import ARP as ScapyARP
            if raw.haslayer(ScapyARP):
                arp = raw[ScapyARP]
                ip  = arp.psrc
                mac = arp.hwsrc

                if ip in self.arp_table:
                    if self.arp_table[ip] != mac:
                        old_mac = self.arp_table[ip]
                        self.arp_table[ip] = mac
                        return self._make_alert(
                            severity = "CRITICAL",
                            type     = "ARP SPOOFING",
                            src      = ip,
                            dst      = "Network",
                            detail   = f"IP {ip} changed MAC: "
                                       f"{old_mac} → {mac}",
                            time     = datetime.now()
                        )
                else:
                    self.arp_table[ip] = mac
        except Exception:
            pass

        return None

    # ── DNS tunneling detection ───────────────────────────────
    def _check_dns_tunneling(self, packet_summary, now):
        """
        Detect DNS tunneling — unusually long DNS queries
        used to exfiltrate data through DNS.
        """
        if packet_summary.get("protocol") != "DNS":
            return None

        info = packet_summary.get("info", "")
        src  = packet_summary.get("src_ip")

        if "Query:" in info:
            query = info.replace("Query:", "").strip()

            # Long subdomain = possible tunneling
            if len(query) > 50:
                return self._make_alert(
                    severity = "MEDIUM",
                    type     = "DNS TUNNELING",
                    src      = src,
                    dst      = "DNS Server",
                    detail   = f"Unusually long DNS query ({len(query)} chars): "
                               f"{query[:60]}...",
                    time     = now
                )

            # Track query frequency
            self.dns_queries[src].append(now)
            self.dns_queries[src] = [
                t for t in self.dns_queries[src]
                if (now - t).seconds < 10
            ]

            if len(self.dns_queries[src]) > 30:
                self.dns_queries[src] = []
                return self._make_alert(
                    severity = "MEDIUM",
                    type     = "DNS FLOOD",
                    src      = src,
                    dst      = "DNS Server",
                    detail   = f"{src} sent 30+ DNS queries in 10 seconds",
                    time     = now
                )

        return None

    # ── Suspicious ports detection ────────────────────────────
    def _check_suspicious_ports(self, src, dst, dport):
        """
        Flag connections to known dangerous or
        unusual ports.
        """
        if not dport:
            return None

        suspicious = {
            4444:  "Metasploit default shell port",
            1337:  "Common backdoor port",
            31337: "Elite hacker port / backdoor",
            6667:  "IRC — often used by botnets",
            6666:  "IRC / malware C2 channel",
            9001:  "Tor relay port",
            9050:  "Tor SOCKS proxy",
            23:    "Telnet — unencrypted remote access",
            512:   "Rexec — remote execution",
            513:   "Rlogin — remote login",
            514:   "Rsh — remote shell",
        }

        if dport in suspicious:
            return self._make_alert(
                severity = "HIGH",
                type     = "SUSPICIOUS PORT",
                src      = src,
                dst      = dst,
                detail   = f"Connection to port {dport}: "
                           f"{suspicious[dport]}",
                time     = datetime.now()
            )
        return None

    # ── Helpers ───────────────────────────────────────────────
    def _make_alert(self, severity, type, src, dst, detail, time):
        return {
            "severity":  severity,
            "type":      type,
            "src":       src,
            "dst":       dst,
            "detail":    detail,
            "time":      time.strftime("%H:%M:%S"),
        }

    def _port_to_service(self, port):
        services = {
            22:   "SSH",
            21:   "FTP",
            23:   "Telnet",
            25:   "SMTP",
            80:   "HTTP",
            443:  "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            3389: "RDP",
        }
        return services.get(port, f"Port {port}")

    def get_alerts(self):
        return list(self.alerts)

    def clear_alerts(self):
        self.alerts = []