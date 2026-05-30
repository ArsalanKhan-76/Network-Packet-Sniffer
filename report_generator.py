from jinja2 import Template
from datetime import datetime
import os


def generate_report(sniffer, detector, interface, duration):
    """
    Generate a clean HTML forensics report
    from a completed capture session.
    """

    stats   = sniffer.get_stats()
    packets = sniffer.get_packets()
    alerts  = detector.get_alerts()

    # ── Risk score ────────────────────────────────────────────
    score = 0
    for alert in alerts:
        if alert["severity"] == "CRITICAL":
            score += 30
        elif alert["severity"] == "HIGH":
            score += 20
        elif alert["severity"] == "MEDIUM":
            score += 10
        elif alert["severity"] == "LOW":
            score += 5

    score = min(score, 100)

    if score >= 70:
        risk_level = "CRITICAL"
        risk_color = "#ff5555"
    elif score >= 40:
        risk_level = "HIGH"
        risk_color = "#ff9800"
    elif score >= 20:
        risk_level = "MEDIUM"
        risk_color = "#ffaa33"
    else:
        risk_level = "LOW"
        risk_color = "#3ddc84"

    # ── Unique IPs ────────────────────────────────────────────
    src_ips = set(p["src_ip"] for p in packets if p.get("src_ip"))
    dst_ips = set(p["dst_ip"] for p in packets if p.get("dst_ip"))

    template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Capture Report</title>
    <style>
        :root {
            --bg:      #0a0a0f;
            --card:    #16161f;
            --border:  #222233;
            --accent:  #6c63ff;
            --green:   #3ddc84;
            --red:     #ff5555;
            --orange:  #ffaa33;
            --text:    #e8e8f0;
            --dim:     #8888aa;
            --mono:    'Consolas', monospace;
        }

        * { margin:0; padding:0; box-sizing:border-box; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Segoe UI', sans-serif;
            padding: 40px 20px;
        }

        .container { max-width: 1000px; margin: 0 auto; }

        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-left: 4px solid var(--accent);
            padding-left: 16px;
            margin-bottom: 32px;
        }

        .topbar h1 { font-size: 22px; color: var(--accent); }
        .topbar p  { font-size: 12px; color: var(--dim); margin-top: 4px; }

        .risk-badge {
            padding: 10px 24px;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 700;
            font-family: var(--mono);
            color: {{ risk_color }};
            background: {{ risk_color }}22;
            border: 1px solid {{ risk_color }};
        }

        .grid-4 {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }

        .stat-card .num {
            font-size: 32px;
            font-weight: 700;
            color: var(--accent);
            font-family: var(--mono);
        }

        .stat-card .label {
            font-size: 11px;
            color: var(--dim);
            margin-top: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .card h2 {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--dim);
            margin-bottom: 16px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            font-family: var(--mono);
        }

        th {
            text-align: left;
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
            color: var(--dim);
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
        }

        td {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
            color: var(--text);
        }

        tr:hover { background: #1c1c28; }

        .badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
        }

        .badge-critical { background:#ff555522; color:#ff5555; }
        .badge-high     { background:#ff980022; color:#ff9800; }
        .badge-medium   { background:#ffaa3322; color:#ffaa33; }
        .badge-low      { background:#3ddc8422; color:#3ddc84; }

        .proto-tcp   { color: #00bcd4; }
        .proto-udp   { color: #3f51b5; }
        .proto-dns   { color: #4caf50; }
        .proto-http  { color: #8bc34a; }
        .proto-icmp  { color: #ffeb3b; }
        .proto-arp   { color: #e91e63; }
        .proto-other { color: #888; }

        .footer {
            text-align: center;
            color: var(--dim);
            font-size: 11px;
            margin-top: 40px;
        }
    </style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="topbar">
        <div>
            <h1>🔍 Network Capture Report</h1>
            <p>
                Interface: {{ interface }}  |
                Duration: {{ duration }}s  |
                Generated: {{ report_time }}
            </p>
        </div>
        <div class="risk-badge">
            {{ risk_score }}/100 — {{ risk_level }}
        </div>
    </div>

    <!-- Summary stats -->
    <div class="grid-4">
        <div class="stat-card">
            <div class="num">{{ stats.total }}</div>
            <div class="label">Total Packets</div>
        </div>
        <div class="stat-card">
            <div class="num" style="color:#ff5555">{{ alerts|length }}</div>
            <div class="label">Threats Detected</div>
        </div>
        <div class="stat-card">
            <div class="num" style="color:#3ddc84">{{ unique_src }}</div>
            <div class="label">Unique Sources</div>
        </div>
        <div class="stat-card">
            <div class="num" style="color:#ffaa33">{{ unique_dst }}</div>
            <div class="label">Unique Destinations</div>
        </div>
    </div>

    <!-- Protocol breakdown -->
    <div class="card">
        <h2>Protocol Breakdown</h2>
        <table>
            <tr>
                <th>Protocol</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            {% for proto, count in proto_rows %}
            <tr>
                <td class="proto-{{ proto.lower() }}">
                    {{ proto }}
                </td>
                <td>{{ count }}</td>
                <td>
                    {{ "%.1f"|format(count / [stats.total, 1]|max * 100) }}%
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <!-- Alerts -->
    {% if alerts %}
    <div class="card">
        <h2>🚨 Threat Alerts ({{ alerts|length }})</h2>
        <table>
            <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Source</th>
                <th>Detail</th>
            </tr>
            {% for alert in alerts %}
            <tr>
                <td>{{ alert.time }}</td>
                <td>
                    <span class="badge badge-{{ alert.severity.lower() }}">
                        {{ alert.severity }}
                    </span>
                </td>
                <td>{{ alert.type }}</td>
                <td>{{ alert.src }}</td>
                <td>{{ alert.detail }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    <!-- Packet log -->
    <div class="card">
        <h2>Packet Log (last 100)</h2>
        <table>
            <tr>
                <th>Time</th>
                <th>Protocol</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Length</th>
                <th>Info</th>
            </tr>
            {% for p in packets[-100:] %}
            <tr>
                <td>{{ p.timestamp }}</td>
                <td class="proto-{{ p.protocol.lower() }}">
                    {{ p.protocol }}
                </td>
                <td>
                    {{ p.src_ip or "—" }}
                    {% if p.src_port %}:{{ p.src_port }}{% endif %}
                </td>
                <td>
                    {{ p.dst_ip or "—" }}
                    {% if p.dst_port %}:{{ p.dst_port }}{% endif %}
                </td>
                <td>{{ p.length }} B</td>
                <td>{{ p.info[:60] }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="footer">
        Network Capture Report &nbsp;|&nbsp;
        Built by Arsalan Khan Pathan &nbsp;|&nbsp;
        github.com/ArsalanKhan-76
    </div>

</div>
</body>
</html>
    """

    proto_rows = [
        ("TCP",   stats["tcp"]),
        ("UDP",   stats["udp"]),
        ("DNS",   stats["dns"]),
        ("HTTP",  stats["http"]),
        ("ICMP",  stats["icmp"]),
        ("ARP",   stats["arp"]),
        ("OTHER", stats["other"]),
    ]

    template = Template(template_str)
    html = template.render(
        interface   = interface,
        duration    = duration,
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        stats       = stats,
        alerts      = alerts,
        packets     = packets,
        proto_rows  = proto_rows,
        risk_score  = score,
        risk_level  = risk_level,
        risk_color  = risk_color,
        unique_src  = len(src_ips),
        unique_dst  = len(dst_ips),
    )

    os.makedirs("reports", exist_ok=True)
    filename    = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join("reports", filename)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    return report_path