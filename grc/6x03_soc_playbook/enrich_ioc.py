#!/usr/bin/env python3
"""Local-feed IOC enrichment. BLOCK is a label, never a network action."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import socket
from urllib.parse import urlsplit

DOCUMENTATION = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
PRIVATE = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_ioc(value: str) -> str:
    """Return an IP or DNS hostname; never fetch a URL or resolve its A record."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("IOC must be a nonempty string")
    raw = value.strip()
    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError("Expected an HTTP(S) URL with a hostname")
        if any(char.isspace() for char in raw):
            raise ValueError("Whitespace in URL")
        # Accessing port also rejects nonnumeric and out-of-range values.
        _ = parsed.port
        raw = parsed.hostname
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    domain = raw.rstrip(".").encode("idna").decode("ascii").lower()
    labels = domain.split(".")
    if (len(domain) > 253 or len(labels) < 2
            or not all(DOMAIN_LABEL.fullmatch(label) for label in labels)
            or labels[-1].isdigit()):
        raise ValueError("Malformed IP address or domain")
    return domain


def detect_ioc_type(value: str) -> str:
    host = normalize_ioc(value)
    if "://" in value.strip():
        return "url"
    try:
        return "ipv4" if ipaddress.ip_address(host).version == 4 else "ipv6"
    except ValueError:
        return "domain"


def classify_ip(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if any(address.version == net.version and address in net for net in DOCUMENTATION):
        return "documentation"
    if address.is_multicast:
        return "multicast"
    if any(address.version == net.version and address in net for net in PRIVATE):
        return "private"
    # The task has no separate reserved/special category. Do not grant those
    # addresses the private-network ALLOW exemption merely via is_private.
    return "public"


def reverse_dns(ip: str) -> str:
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.timeout:
        return "TIMEOUT"
    except socket.herror:
        return "NXDOMAIN"
    except OSError:
        # Offline resolver failure must not break local-feed scoring.
        return "NXDOMAIN"
    finally:
        socket.setdefaulttimeout(previous)


def check_feed(value: str, feed: dict) -> dict:
    host = normalize_ioc(value)
    result = {"in_malicious_feed": False, "in_benign_list": False}
    for name in ("malicious_ips", "malicious_domains"):
        entries = feed.get(name, {})
        if not isinstance(entries, dict):
            raise ValueError("Malformed malicious feed collection")
        if host in entries:
            entry = entries[host]
            if not isinstance(entry, dict):
                raise ValueError("Malformed feed entry")
            result.update(entry)
            result["in_malicious_feed"] = True
    for name in ("benign_ips", "benign_domains"):
        entries = feed.get(name, [])
        if not isinstance(entries, (list, dict)):
            raise ValueError("Malformed benign feed collection")
        if host in entries:
            result["in_benign_list"] = True
    return result


def score_ioc(feed_result: dict, ip_class: str) -> tuple[int, str]:
    if ip_class in ("private", "loopback") or feed_result.get("in_benign_list"):
        return 0, "ALLOW"
    if feed_result.get("in_malicious_feed"):
        confidence = feed_result.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("Feed confidence must be numeric")
        if not 0 <= confidence <= 100:
            raise ValueError("Feed confidence must be between 0 and 100")
        return confidence, "BLOCK" if confidence >= 80 else "INVESTIGATE"
    return 30, "INVESTIGATE"


def enrich_ioc(value: str, feed_path: str = "ioc_feed.json") -> dict:
    result = {"ioc": value, "type": "domain", "ip_class": "N/A",
              "reverse_dns": "N/A",
              "feed_result": {"in_malicious_feed": False, "in_benign_list": False},
              "score": 30, "verdict": "INVESTIGATE", "enriched_at": utc_now()}
    try:
        host = normalize_ioc(value)
        result["type"] = detect_ioc_type(value)
    except (ValueError, UnicodeError) as exc:
        result["note"] = "Malformed IOC; analyst review required: " + str(exc)
        result["error"] = "malformed_ioc"
        return result
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        result["ip_class"] = classify_ip(host)
        result["reverse_dns"] = reverse_dns(host)
    try:
        feed = json.loads(Path(feed_path).read_text(encoding="utf-8-sig"))
        required = {"malicious_ips", "malicious_domains", "benign_ips", "benign_domains"}
        if not isinstance(feed, dict) or not required.issubset(feed):
            raise ValueError("Missing feed collections")
        result["feed_result"] = check_feed(host, feed)
        result["score"], result["verdict"] = score_ioc(result["feed_result"], result["ip_class"])
    except (OSError, ValueError, TypeError) as exc:
        result["note"] = "Feed unavailable or invalid; analyst review required: " + str(exc)
        result["error"] = "feed_error"
        return result
    if result["ip_class"] == "private":
        result["note"] = "Private address range; internal network traffic"
    elif result["ip_class"] == "loopback":
        result["note"] = "Loopback address; local host traffic"
    if result["feed_result"].get("in_malicious_feed") and result["feed_result"].get("in_benign_list"):
        result["note"] = "Conflicting feed entries; task scoring gives benign-list precedence; review feed governance"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ioc", nargs="?")
    parser.add_argument("--feed", default="ioc_feed.json")
    parser.add_argument("--batch")
    parser.add_argument("--output")
    args = parser.parse_args()
    if bool(args.ioc) == bool(args.batch):
        parser.error("Choose one IOC or --batch")
    if args.output and not args.batch:
        parser.error("--output requires --batch")
    try:
        if args.batch:
            values = [line.strip() for line in Path(args.batch).read_text().splitlines() if line.strip()]
            results = [enrich_ioc(value, args.feed) for value in values]
            destination = Path(args.output or "results.json")
            if destination.exists():
                raise ValueError("Refusing to overwrite existing batch evidence")
            destination.write_text(json.dumps(results, indent=2) + "\n")
            counts = {v: sum(r["verdict"] == v for r in results) for v in ("BLOCK", "INVESTIGATE", "ALLOW")}
            print("Processed: {} | BLOCK: {} | INVESTIGATE: {} | ALLOW: {}".format(
                len(results), counts["BLOCK"], counts["INVESTIGATE"], counts["ALLOW"]))
        else:
            print(json.dumps(enrich_ioc(args.ioc, args.feed), indent=2))
        return 0
    except (OSError, ValueError) as exc:
        logging_error = {"error": str(exc)}
        print(json.dumps(logging_error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
