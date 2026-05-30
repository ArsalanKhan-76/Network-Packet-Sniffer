from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.l2 import ARP


def decode_dns(packet):
    """
    Deep decode DNS packets.
    Extracts full query names and all answer records.
    """
    result = {
        "type":    "query",
        "queries": [],
        "answers": []
    }

    try:
        dns = packet[DNS]

        # ── Queries ───────────────────────────────────────────
        if packet.haslayer(DNSQR):
            qr = packet[DNSQR]
            while qr:
                try:
                    name = qr.qname.decode(errors="ignore").rstrip(".")
                    result["queries"].append(name)
                    qr = qr.payload if qr.payload else None
                    if not hasattr(qr, "qname"):
                        break
                except Exception:
                    break

        # ── Answers ───────────────────────────────────────────
        if dns.ancount > 0 and packet.haslayer(DNSRR):
            result["type"] = "response"
            rr = packet[DNSRR]
            while rr:
                try:
                    name = rr.rrname.decode(errors="ignore").rstrip(".")
                    rdata = str(rr.rdata)
                    result["answers"].append({
                        "name":  name,
                        "value": rdata
                    })
                    rr = rr.payload if rr.payload else None
                    if not hasattr(rr, "rrname"):
                        break
                except Exception:
                    break

    except Exception:
        pass

    return result


def decode_http(packet):
    """
    Deep decode HTTP packets.
    Extracts method, host, path, headers and
    looks for credentials in POST bodies.
    """
    result = {
        "type":        "request",
        "method":      None,
        "host":        None,
        "path":        None,
        "user_agent":  None,
        "body":        None,
        "credentials": None,
    }

    try:
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]

            result["method"] = http.Method.decode(errors="ignore") \
                               if http.Method else None
            result["host"]   = http.Host.decode(errors="ignore") \
                               if http.Host else None
            result["path"]   = http.Path.decode(errors="ignore") \
                               if http.Path else "/"
            result["user_agent"] = http.User_Agent.decode(errors="ignore") \
                               if hasattr(http, "User_Agent") \
                               and http.User_Agent else None

            # ── Check POST body for credentials ───────────────
            if result["method"] == "POST":
                try:
                    raw = bytes(packet[TCP].payload)
                    body = raw.decode(errors="ignore")
                    result["body"] = body[:500]  # cap at 500 chars

                    # Look for common credential field names
                    cred_keywords = [
                        "password", "passwd", "pass", "pwd",
                        "username", "user", "email", "login",
                        "token", "secret", "key", "auth"
                    ]
                    lower_body = body.lower()
                    if any(kw in lower_body for kw in cred_keywords):
                        result["credentials"] = body[:300]

                except Exception:
                    pass

        elif packet.haslayer(HTTPResponse):
            result["type"] = "response"

    except Exception:
        pass

    return result


def decode_tcp_flags(flags_str):
    """
    Convert Scapy TCP flags to human readable format.
    """
    flag_meanings = {
        "F": "FIN — Connection termination",
        "S": "SYN — Connection request",
        "R": "RST — Connection reset",
        "P": "PSH — Push data immediately",
        "A": "ACK — Acknowledgement",
        "U": "URG — Urgent data",
        "E": "ECE — ECN Echo",
        "C": "CWR — Congestion Window Reduced",
    }
    result = []
    for flag, meaning in flag_meanings.items():
        if flag in str(flags_str):
            result.append(meaning)
    return result


def decode_arp(packet):
    """
    Decode ARP packet details.
    """
    try:
        arp = packet[ARP]
        return {
            "operation":  "request" if arp.op == 1 else "reply",
            "sender_ip":  arp.psrc,
            "sender_mac": arp.hwsrc,
            "target_ip":  arp.pdst,
            "target_mac": arp.hwdst,
        }
    except Exception:
        return {}


def get_payload_preview(packet, max_bytes=100):
    """
    Extract a readable preview of packet payload.
    Useful for seeing what data is being transferred.
    """
    try:
        if packet.haslayer(TCP):
            raw = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            raw = bytes(packet[UDP].payload)
        else:
            return None

        if not raw:
            return None

        # Try to decode as text first
        try:
            text = raw[:max_bytes].decode("utf-8", errors="strict")
            return text.strip()
        except UnicodeDecodeError:
            # Return hex representation for binary data
            return raw[:max_bytes].hex()

    except Exception:
        return None