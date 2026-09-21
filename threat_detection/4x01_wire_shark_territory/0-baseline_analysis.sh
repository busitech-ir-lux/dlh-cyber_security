#!/usr/bin/env python3
"""
Network PCAP Baseline Analyzer

Clean, maintainable approach to network traffic analysis.
Uses pyshark (Python wrapper around tshark) for easier data handling.
"""

import json
import sys
import subprocess
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple

# Configuration
PORT_SERVICES = {
    443: "HTTPS",
    80: "HTTP",
    88: "Kerberos",
    389: "LDAP",
    636: "LDAP",
    445: "SMB",
    9100: "Printing",
    53: "DNS",
    123: "NTP",
}

@dataclass
class CaptureMetrics:
    """Core capture statistics"""
    filename: str
    start_epoch: float
    end_epoch: float
    total_packets: int
    duration_seconds: float
    duration_minutes: float

@dataclass
class ProtocolStats:
    """Protocol breakdown"""
    tcp_count: int
    udp_count: int
    icmp_count: int
    other_count: int
    
    @property
    def total(self) -> int:
        return self.tcp_count + self.udp_count + self.icmp_count + self.other_count
    
    def percentages(self) -> Dict[str, float]:
        t = self.total
        if t == 0:
            return {}
        return {
            "tcp": (self.tcp_count / t) * 100,
            "udp": (self.udp_count / t) * 100,
            "icmp": (self.icmp_count / t) * 100,
            "other": (self.other_count / t) * 100,
        }

class PcapAnalyzer:
    """Main analyzer class"""
    
    def __init__(self, pcap_path: str, output_json: str = "baseline_clinical.json"):
        self.pcap = Path(pcap_path)
        self.output = output_json
        self._validate()
    
    def _validate(self):
        """Check prerequisites"""
        if not self.pcap.exists():
            raise FileNotFoundError(f"PCAP not found: {self.pcap}")
        
        if subprocess.run(["which", "tshark"], capture_output=True).returncode != 0:
            raise RuntimeError("tshark not installed")
    
    def run_tshark(self, *args, filter_expr: str = None) -> str:
        """Execute tshark and return output"""
        cmd = ["tshark", "-r", str(self.pcap), "-T", "fields"]
        
        if filter_expr:
            cmd.extend(["-Y", filter_expr])
        
        cmd.extend(args)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    
    def analyze(self) -> Dict:
        """Run all analyses"""
        print(f"Analyzing: {self.pcap.name}")
        print("=" * 60)
        
        metrics = self._extract_basics()
        protocols = self._analyze_protocols()
        apps = self._analyze_applications()
        talkers = self._analyze_talkers(top_n=10)
        dns = self._analyze_dns()
        tls = self._analyze_tls()
        temporal = self._analyze_temporal()
        
        # Print summaries
        self._print_metrics(metrics, protocols, apps, talkers, dns, tls, temporal)
        
        # Build JSON
        baseline = {
            "capture": {
                "filename": str(self.pcap),
                "start_epoch": metrics.start_epoch,
                "end_epoch": metrics.end_epoch,
                "duration_seconds": metrics.duration_seconds,
                "duration_minutes": metrics.duration_minutes,
                "total_packets": metrics.total_packets,
            },
            "protocols": {
                "tcp": protocols.tcp_count,
                "udp": protocols.udp_count,
                "icmp": protocols.icmp_count,
                "other": protocols.other_count,
                "percentages": protocols.percentages(),
            },
            "applications": apps,
            "talkers": talkers,
            "dns": dns,
            "tls": tls,
            "temporal": temporal,
        }
        
        self._save_json(baseline)
        return baseline
    
    def _extract_basics(self) -> CaptureMetrics:
        """Extract capture envelope"""
        epochs = self.run_tshark("-e", "frame.time_epoch").strip().split("\n")
        
        if not epochs or not epochs[0]:
            raise ValueError("No packets in PCAP")
        
        start = float(epochs[0])
        end = float(epochs[-1])
        duration = end - start
        
        return CaptureMetrics(
            filename=str(self.pcap),
            start_epoch=start,
            end_epoch=end,
            total_packets=len(epochs),
            duration_seconds=duration,
            duration_minutes=duration / 60,
        )
    
    def _analyze_protocols(self) -> ProtocolStats:
        """Count protocol types"""
        output = self.run_tshark("-e", "ip.proto")
        
        tcp = udp = icmp = other = 0
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                proto = int(line)
                if proto == 6:
                    tcp += 1
                elif proto == 17:
                    udp += 1
                elif proto == 1:
                    icmp += 1
                else:
                    other += 1
            except ValueError:
                continue
        
        return ProtocolStats(
            tcp_count=tcp,
            udp_count=udp,
            icmp_count=icmp,
            other_count=other,
        )
    
    def _analyze_applications(self) -> Dict[str, int]:
        """Classify traffic by port"""
        output = self.run_tshark(
            "-e", "ip.proto",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            filter_expr="ip"
        )
        
        services = Counter()
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            
            try:
                proto = int(parts[0])
                port = int(parts[1] if proto == 6 else parts[2])
                
                if port in PORT_SERVICES:
                    service = PORT_SERVICES[port]
                else:
                    service = "Other"
                
                services[service] += 1
            except (ValueError, IndexError):
                continue
        
        return dict(services.most_common(10))
    
    def _analyze_talkers(self, top_n: int = 10) -> List[Dict]:
        """Top source IPs by bytes"""
        output = self.run_tshark(
            "-e", "frame.len",
            "-e", "ip.src"
        )
        
        talkers = defaultdict(int)
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1]:
                try:
                    talkers[parts[1]] += int(parts[0])
                except ValueError:
                    continue
        
        return [
            {"ip": ip, "bytes": bytes_sent, "mb": bytes_sent / 1048576}
            for ip, bytes_sent in sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:top_n]
        ]
    
    def _analyze_dns(self) -> Dict:
        """DNS query analysis"""
        output = self.run_tshark(
            "-e", "dns.qry.name",
            "-e", "dns.qry.type",
            filter_expr="dns.flags.response == 0"
        )
        
        if not output.strip():
            return {"total_queries": 0, "domains": []}
        
        domains = Counter()
        query_types = Counter()
        
        for line in output.strip().split("\n"):
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                domains[parts[0]] += 1
                try:
                    query_types[int(parts[1])] += 1
                except ValueError:
                    pass
        
        return {
            "total_queries": sum(domains.values()),
            "top_domains": [
                {"domain": d, "count": c} 
                for d, c in domains.most_common(20)
            ],
            "query_types": {
                "A": query_types.get(1, 0),
                "AAAA": query_types.get(28, 0),
                "MX": query_types.get(15, 0),
                "TXT": query_types.get(16, 0),
                "Other": sum(v for k, v in query_types.items() if k not in [1, 28, 15, 16]),
            }
        }
    
    def _analyze_tls(self) -> Dict:
        """TLS/HTTPS analysis"""
        # SNI values
        sni_output = self.run_tshark(
            "-e", "tls.handshake.extensions_server_name",
            filter_expr="tls.handshake.extensions_server_name"
        )
        
        snis = Counter()
        for line in sni_output.strip().split("\n"):
            if line:
                for sni in line.split(","):
                    sni = sni.strip()
                    if sni:
                        snis[sni] += 1
        
        # TLS versions
        tls_output = self.run_tshark(
            "-e", "tls.handshake.negotiated_version",
            filter_expr="tls.handshake.type == 2"
        )
        
        versions = Counter()
        for line in tls_output.strip().split("\n"):
            if line:
                versions[line.strip()] += 1
        
        return {
            "sni_values": [{"sni": s, "count": c} for s, c in snis.most_common(10)],
            "versions": [{"version": v, "count": c} for v, c in versions.most_common()],
        }
    
    def _analyze_temporal(self) -> List[Dict]:
        """Per-minute traffic bins"""
        output = self.run_tshark(
            "-e", "frame.time_epoch",
            "-e", "frame.len"
        )
        
        if not output.strip():
            return []
        
        epochs = [line.split("\t") for line in output.strip().split("\n") if line]
        if not epochs:
            return []
        
        start = float(epochs[0][0])
        bins = defaultdict(lambda: {"packets": 0, "bytes": 0})
        
        for epoch_str, length_str in epochs:
            try:
                epoch = float(epoch_str)
                minute = int((epoch - start) / 60)
                bins[minute]["packets"] += 1
                bins[minute]["bytes"] += int(length_str)
            except ValueError:
                continue
        
        return [
            {
                "minute_offset": m,
                "packets": data["packets"],
                "bytes": data["bytes"],
                "kb": data["bytes"] / 1024,
            }
            for m, data in sorted(bins.items())
        ]
    
    def _save_json(self, baseline: Dict):
        """Save baseline to JSON"""
        with open(self.output, "w") as f:
            json.dump(baseline, f, indent=2)
            f.write("\n")
        
        print(f"\n✓ Baseline saved: {self.output}")
    
    def _print_metrics(self, metrics, protocols, apps, talkers, dns, tls, temporal):
        """Pretty-print analysis results"""
        print(f"\nCapture Duration: {metrics.duration_minutes:.2f} min ({metrics.duration_seconds:.0f}s)")
        print(f"Total Packets: {metrics.total_packets}")
        
        print(f"\n--- Protocols ---")
        for proto, pct in protocols.percentages().items():
            print(f"  {proto.upper():6} {pct:6.1f}%")
        
        print(f"\n--- Top Applications ---")
        for app, count in sorted(apps.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {app:20} {count:6} packets")
        
        print(f"\n--- Top Talkers (by bytes) ---")
        for t in talkers[:5]:
            print(f"  {t['ip']:16} {t['mb']:8.2f} MB")
        
        if dns.get("total_queries", 0) > 0:
            print(f"\n--- DNS ---")
            print(f"  Total queries: {dns['total_queries']}")
            for domain, count in dns.get("top_domains", [])[:5]:
                print(f"    {domain}: {count}")
        
        print(f"\n--- Traffic Over Time ---")
        for tbin in temporal[:5]:
            print(f"  +{tbin['minute_offset']:02d}min: {tbin['packets']:6d} packets  {tbin['kb']:9.1f} KB")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap-file> [output.json]", file=sys.stderr)
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "baseline_clinical.json"
    
    try:
        analyzer = PcapAnalyzer(pcap_path, output)
        analyzer.analyze()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
