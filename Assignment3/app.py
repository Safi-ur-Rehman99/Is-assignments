from __future__ import annotations

import ipaddress
import socket
from typing import Any

from flask import Flask, jsonify, render_template, request

try:
    import nmap  # type: ignore
except ImportError:  # pragma: no cover - depends on local environment
    nmap = None

app = Flask(__name__)

SCAN_TYPES = {
    "tcp_syn": "-sS",
    "udp": "-sU",
    "full_connect": "-sT",
}

RISKY_PORT_HINTS = {
    21: "FTP is often insecure when configured without TLS.",
    23: "Telnet transmits credentials in plaintext.",
    135: "RPC endpoint exposure can increase attack surface.",
    139: "NetBIOS service exposure can leak system information.",
    445: "SMB exposure is commonly targeted by malware.",
    3306: "MySQL should not be publicly exposed without strict controls.",
    3389: "RDP exposure can be targeted by brute-force attacks.",
    5432: "PostgreSQL should be restricted to trusted hosts.",
    6379: "Redis is risky if exposed without authentication.",
    9200: "Elasticsearch exposure can leak sensitive data.",
}


def sanitize_target(target: str) -> str:
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target IP or hostname is required.")
    if " " in cleaned:
        raise ValueError("Target must not contain spaces.")
    return cleaned


def sanitize_ports(ports: str) -> str:
    cleaned = ports.strip()
    if not cleaned:
        return "1-1024"

    valid_chars = set("0123456789,-")
    if any(ch not in valid_chars for ch in cleaned):
        raise ValueError("Ports must use digits, commas, and hyphens only.")

    if "--" in cleaned or ",," in cleaned:
        raise ValueError("Invalid port format.")

    tokens = [token.strip() for token in cleaned.split(",") if token.strip()]
    if not tokens:
        raise ValueError("Invalid port format.")

    for token in tokens:
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                raise ValueError("Invalid port range format.")
            start_port = int(parts[0])
            end_port = int(parts[1])
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Port ranges must be between 1 and 65535.")
        else:
            if not token.isdigit():
                raise ValueError("Invalid port value.")
            value = int(token)
            if value < 1 or value > 65535:
                raise ValueError("Ports must be between 1 and 65535.")

    return cleaned


def parse_ports_for_fallback(ports: str) -> list[int]:
    expanded: list[int] = []
    for token in ports.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start_port = int(start_text)
            end_port = int(end_text)
            expanded.extend(list(range(start_port, end_port + 1)))
        else:
            expanded.append(int(token))

    unique_ports = sorted(set(expanded))
    if len(unique_ports) > 512:
        raise ValueError(
            "Fallback scan supports up to 512 ports per request. Install Nmap for larger scans."
        )
    return unique_ports


def get_service_name(port: int, protocol: str, declared_name: str | None = None) -> str:
    if declared_name:
        return declared_name
    try:
        return socket.getservbyport(port, protocol.lower())
    except OSError:
        return "unknown"


def scan_with_nmap(target: str, scan_type: str, ports: str) -> list[dict[str, Any]]:
    if nmap is None:
        raise RuntimeError("python-nmap is not installed.")

    scanner = nmap.PortScanner()
    scan_args = f"{SCAN_TYPES[scan_type]} -Pn"
    scanner.scan(hosts=target, ports=ports, arguments=scan_args)

    rows: list[dict[str, Any]] = []
    for host in scanner.all_hosts():
        host_record = scanner[host]
        protocols = host_record.all_protocols()
        for protocol in protocols:
            protocol_data = host_record[protocol]
            for port in sorted(protocol_data.keys()):
                details = protocol_data[port]
                rows.append(
                    {
                        "ip": host,
                        "port": int(port),
                        "protocol": protocol.upper(),
                        "service": get_service_name(
                            int(port), protocol, details.get("name") or None
                        ),
                        "status": details.get("state", "unknown"),
                    }
                )

    rows.sort(key=lambda item: (item["ip"], item["protocol"], item["port"]))
    return rows


def scan_with_socket_fallback(target: str, ports: str) -> list[dict[str, Any]]:
    host_ip = socket.gethostbyname(target)
    rows: list[dict[str, Any]] = []

    for port in parse_ports_for_fallback(ports):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(0.35)
        try:
            status_code = connection.connect_ex((host_ip, port))
            state = "open" if status_code == 0 else "closed"
            rows.append(
                {
                    "ip": host_ip,
                    "port": port,
                    "protocol": "TCP",
                    "service": get_service_name(port, "tcp"),
                    "status": state,
                }
            )
        finally:
            connection.close()

    return rows


def detect_possible_vulnerabilities(scan_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    for row in scan_rows:
        if row.get("status") != "open":
            continue
        port = int(row.get("port", 0))
        ip = str(row.get("ip", ""))
        hint = RISKY_PORT_HINTS.get(port)
        if not hint:
            continue

        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            {
                "ip": ip,
                "port": port,
                "service": row.get("service", "unknown"),
                "risk": hint,
            }
        )

    return findings


def ip_rule_matches(rule_ip: str, traffic_ip: str) -> bool:
    if rule_ip == "any":
        return True

    try:
        network = ipaddress.ip_network(rule_ip, strict=False)
        return ipaddress.ip_address(traffic_ip) in network
    except ValueError:
        return rule_ip.lower() == traffic_ip.lower()


def port_rule_matches(rule_port: str, traffic_port: int) -> bool:
    if rule_port == "any":
        return True

    if "-" in rule_port:
        start_text, end_text = rule_port.split("-", 1)
        start_port = int(start_text)
        end_port = int(end_text)
        return start_port <= traffic_port <= end_port

    return int(rule_port) == traffic_port


def evaluate_traffic(rules: list[dict[str, Any]], traffic: dict[str, Any]) -> dict[str, Any]:
    traffic_ip = str(traffic.get("ip", "")).strip()
    traffic_port = int(traffic.get("port", 0))
    traffic_protocol = str(traffic.get("protocol", "ANY")).upper()

    ordered_rules = sorted(rules, key=lambda item: item["priority"])

    for rule in ordered_rules:
        protocol_match = (
            rule["protocol"] == "ANY" or rule["protocol"] == traffic_protocol
        )
        if not protocol_match:
            continue

        if not ip_rule_matches(rule["ip"], traffic_ip):
            continue

        if not port_rule_matches(rule["port"], traffic_port):
            continue

        return {
            "ip": traffic_ip,
            "port": traffic_port,
            "protocol": traffic_protocol,
            "decision": rule["action"],
            "matchedRule": rule,
        }

    return {
        "ip": traffic_ip,
        "port": traffic_port,
        "protocol": traffic_protocol,
        "decision": "ALLOW",
        "matchedRule": None,
    }


def normalize_rule(raw_rule: dict[str, Any], index: int) -> dict[str, Any]:
    action = str(raw_rule.get("action", "")).strip().upper()
    ip_value = str(raw_rule.get("ip", "any")).strip().lower() or "any"
    port_value = str(raw_rule.get("port", "any")).strip().lower() or "any"
    protocol_value = str(raw_rule.get("protocol", "ANY")).strip().upper() or "ANY"

    if action not in {"ALLOW", "DENY"}:
        raise ValueError("Rule action must be ALLOW or DENY.")
    if protocol_value not in {"ANY", "TCP", "UDP"}:
        raise ValueError("Rule protocol must be ANY, TCP, or UDP.")

    if port_value != "any":
        if "-" in port_value:
            start_text, end_text = port_value.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError("Rule port range is invalid.")
            start_port = int(start_text)
            end_port = int(end_text)
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Rule port range must be between 1 and 65535.")
        else:
            if not port_value.isdigit():
                raise ValueError("Rule port must be a number, range, or any.")
            int_port = int(port_value)
            if int_port < 1 or int_port > 65535:
                raise ValueError("Rule port must be between 1 and 65535.")

    priority = int(raw_rule.get("priority", index + 1))

    return {
        "id": index + 1,
        "action": action,
        "ip": ip_value,
        "port": port_value,
        "protocol": protocol_value,
        "priority": priority,
    }


@app.get("/")
def home() -> str:
    return render_template("index.html")


@app.post("/api/scan")
def api_scan() -> Any:
    payload = request.get_json(silent=True) or {}

    try:
        target = sanitize_target(str(payload.get("target", "")))
        scan_type = str(payload.get("scanType", "")).strip()
        ports = sanitize_ports(str(payload.get("ports", "1-1024")))

        if scan_type not in SCAN_TYPES:
            return jsonify({"error": "Unsupported scan type selected."}), 400

        if nmap is not None:
            rows = scan_with_nmap(target, scan_type, ports)
        elif scan_type == "full_connect":
            rows = scan_with_socket_fallback(target, ports)
        else:
            return (
                jsonify(
                    {
                        "error": (
                            "Nmap is not available. Install Nmap + python-nmap "
                            "or use Full Connect for fallback scanning."
                        )
                    }
                ),
                500,
            )

        findings = detect_possible_vulnerabilities(rows)

        return jsonify(
            {
                "target": target,
                "scanType": scan_type,
                "ports": ports,
                "results": rows,
                "vulnerabilities": findings,
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except socket.gaierror:
        return jsonify({"error": "Hostname could not be resolved."}), 400
    except nmap.PortScannerError as exc:  # type: ignore[attr-defined]
        return jsonify({"error": f"Nmap scan error: {exc}"}), 500
    except Exception as exc:  # pragma: no cover - safety catch
        return jsonify({"error": f"Scan failed: {exc}"}), 500


@app.post("/api/firewall/evaluate")
def api_firewall_evaluate() -> Any:
    payload = request.get_json(silent=True) or {}
    raw_rules = payload.get("rules", [])
    traffic_items = payload.get("traffic", [])

    if not isinstance(raw_rules, list) or not isinstance(traffic_items, list):
        return jsonify({"error": "Rules and traffic must be arrays."}), 400

    try:
        normalized_rules = [normalize_rule(rule, idx) for idx, rule in enumerate(raw_rules)]
        normalized_rules.sort(key=lambda item: item["priority"])

        decisions = [evaluate_traffic(normalized_rules, item) for item in traffic_items]
        blocked_count = sum(1 for item in decisions if item["decision"] == "DENY")
        allowed_count = len(decisions) - blocked_count

        return jsonify(
            {
                "rules": normalized_rules,
                "decisions": decisions,
                "summary": {
                    "total": len(decisions),
                    "allowed": allowed_count,
                    "blocked": blocked_count,
                },
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - safety catch
        return jsonify({"error": f"Firewall evaluation failed: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
