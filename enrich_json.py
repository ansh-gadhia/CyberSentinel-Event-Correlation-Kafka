#!/usr/bin/env python3
"""
Enhanced Log Enrichment Pipeline with Network Intelligence
Adds ASN, cloud provider detection, IP reputation, Tor detection, and QUIC detection.

All enrichment uses FREE, OFFLINE data sources only - no external APIs.

Requirements:
    pip install geoip2 --break-system-packages

Databases needed:
    - GeoLite2-City.mmdb (for GeoIP)
    - GeoLite2-ASN.mmdb (for ASN lookup)
    - tor-exit-nodes.txt (Tor exit node list)
    - malicious-ips.txt (IP reputation data)

Usage:
    python3 enrich_logs_network.py --input normalized.jsonl --output enriched.jsonl
"""

import argparse
import hashlib
import ipaddress
import json
import sys
import math
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Set

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


# Internal network CIDRs — IPs in these ranges are classified as "private"
# and used for is_internal_traffic / is_external_outbound / is_external_inbound.
# Covers RFC1918 by default; add site-specific ranges as needed.
INTERNAL_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _ip_is_internal(ip_obj) -> bool:
    """Check if an ip_address object falls in any INTERNAL_CIDRS."""
    for net in INTERNAL_CIDRS:
        if ip_obj in net:
            return True
    return False


class NetworkIntelligence:
    """Offline network intelligence using local databases."""
    
    # Cloud provider ASN mapping (major providers only)
    CLOUD_PROVIDERS = {
        # Google Cloud / Google
        15169: "google", 16550: "google", 36040: "google", 36384: "google", 36385: "google",
        43515: "google", 139190: "google", 36492: "google", 19527: "google", 395973: "google",
        
        # AWS
        16509: "aws", 14618: "aws", 8987: "aws", 10124: "aws", 17493: "aws",
        38895: "aws", 58588: "aws", 62785: "aws", 133788: "aws", 135971: "aws",
        
        # Microsoft Azure
        8075: "azure", 12076: "azure", 8068: "azure", 3598: "azure", 6584: "azure",
        
        # Cloudflare
        13335: "cloudflare", 209242: "cloudflare",
        
        # DigitalOcean
        14061: "digitalocean", 393406: "digitalocean",
        
        # OVH
        16276: "ovh",
        
        # Linode/Akamai
        63949: "linode", 20473: "linode",
        
        # Vultr
        20473: "vultr", 64515: "vultr",
        
        # Hetzner
        24940: "hetzner", 213230: "hetzner",
    }
    
    def __init__(self, 
                 asn_db_path: Optional[str] = None,
                 tor_list_path: Optional[str] = None,
                 reputation_db_path: Optional[str] = None):
        
        # ASN database
        self.asn_reader = None
        if asn_db_path and GEOIP_AVAILABLE:
            try:
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                print(f"✓ ASN database loaded: {asn_db_path}", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not load ASN database: {e}", file=sys.stderr)
        
        # Tor exit nodes
        self.tor_exits: Set[str] = set()
        if tor_list_path and os.path.exists(tor_list_path):
            try:
                with open(tor_list_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.tor_exits.add(line)
                print(f"✓ Tor exit nodes loaded: {len(self.tor_exits)} nodes", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not load Tor list: {e}", file=sys.stderr)
        
        # IP reputation database
        self.malicious_ips: Dict[str, float] = {}  # ip -> confidence
        if reputation_db_path and os.path.exists(reputation_db_path):
            try:
                with open(reputation_db_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(',')
                            if len(parts) >= 2:
                                ip = parts[0].strip()
                                confidence = float(parts[1].strip())
                                self.malicious_ips[ip] = confidence
                            elif len(parts) == 1:
                                # Default confidence if not specified
                                self.malicious_ips[parts[0].strip()] = 0.8
                print(f"✓ IP reputation loaded: {len(self.malicious_ips)} malicious IPs", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not load reputation database: {e}", file=sys.stderr)
    
    def lookup_asn(self, ip: str, ip_type: str) -> Optional[Dict[str, Any]]:
        """Lookup ASN information for an IP."""
        if not self.asn_reader or not ip or ip_type != "public":
            return None
        
        try:
            response = self.asn_reader.asn(ip)
            return {
                "number": response.autonomous_system_number,
                "org": response.autonomous_system_organization
            }
        except (geoip2.errors.AddressNotFoundError, AttributeError):
            return None
        except Exception as e:
            return None
    
    def get_provider(self, asn_number: Optional[int]) -> Optional[str]:
        """Get cloud provider from ASN."""
        if asn_number is None:
            return None
        return self.CLOUD_PROVIDERS.get(asn_number)
    
    def check_tor_exit(self, ip: str) -> bool:
        """Check if IP is a Tor exit node."""
        return ip in self.tor_exits
    
    def check_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation."""
        if ip in self.malicious_ips:
            return {
                "status": "malicious",
                "confidence": self.malicious_ips[ip]
            }
        return None
    
    def detect_quic(self, protocol: Optional[str], port: Optional[int], asn_number: Optional[int]) -> Optional[Dict[str, Any]]:
        """Detect QUIC protocol based on UDP + port 443."""
        if not protocol or not port:
            return None
        
        # QUIC detection: UDP + port 443
        if protocol.upper() in ["UDP", "17"] and port == 443:
            quic_data = {
                "is_quic": True,
                "quic_hint": "likely_http3"
            }
            
            # Google QUIC specific detection
            if asn_number == 15169:  # Google ASN
                quic_data["quic_provider"] = "google"
            
            return quic_data
        
        return None
    
    def close(self):
        """Close database readers."""
        if self.asn_reader:
            self.asn_reader.close()


class RollingCounter:
    """Bounded rolling counter with time-based eviction."""
    
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.events = defaultdict(deque)
    
    def increment(self, key: str, timestamp: datetime) -> int:
        if key not in self.events:
            self.events[key] = deque()
        
        self.events[key].append(timestamp)
        
        cutoff = timestamp - timedelta(seconds=self.window_seconds)
        while self.events[key] and self.events[key][0] < cutoff:
            self.events[key].popleft()
        
        count = len(self.events[key])
        if count == 0:
            del self.events[key]
        
        return count


class GeoTracker:
    """Track geographic patterns for impossible travel detection."""
    
    def __init__(self):
        self.last_location = {}
    
    def update_location(self, key: str, country: str, city: str, lat: float, lon: float,
                        timestamp: datetime, source_ip: str = None) -> Optional[Dict]:
        if key in self.last_location:
            last = self.last_location[key]
            time_diff = (timestamp - last["time"]).total_seconds() / 3600
            distance_km = self._calculate_distance(last["lat"], last["lon"], lat, lon)

            if time_diff > 0 and distance_km > 0:
                max_speed_kmh = distance_km / time_diff
                # Require >= 5 min gap: shorter gaps are almost always
                # VPN/proxy IP reassignment, not real travel.
                is_impossible = max_speed_kmh > 1000 and time_diff >= (5.0 / 60)

                result = {
                    "is_impossible_travel": is_impossible,
                    "previous_login": {
                        "source_ip": last.get("source_ip"),
                        "location": f"{last['city']}, {last['country']}",
                        "timestamp": last["time"].isoformat() + ("Z" if last["time"].tzinfo is None else ""),
                    },
                    "current_login": {
                        "source_ip": source_ip,
                        "location": f"{city}, {country}",
                        "timestamp": timestamp.isoformat() + ("Z" if timestamp.tzinfo is None else ""),
                    },
                    "distance_km": round(distance_km, 2),
                    "time_diff_hours": round(time_diff, 2),
                    "required_speed_kmh": round(max_speed_kmh, 2) if time_diff > 0 else 0
                }
            else:
                result = None
        else:
            result = None

        self.last_location[key] = {
            "country": country, "city": city,
            "lat": lat, "lon": lon, "time": timestamp,
            "source_ip": source_ip,
        }
        
        cutoff = timestamp - timedelta(hours=24)
        to_remove = [k for k, v in self.last_location.items() if v["time"] < cutoff]
        for k in to_remove:
            del self.last_location[k]
        
        return result
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371.0
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return R * c


class BehaviorTracker:
    """Track behavioral patterns with proper time-windowed rolling counts.

    Every observation is stored as a (timestamp, value) pair in a deque.
    On each query the deque is pruned to the window boundary, then unique
    values are counted.  Per-entity cap prevents unbounded memory growth.
    """

    MAX_ENTRIES_PER_ENTITY = 5000   # hard cap per deque

    def __init__(self, window_seconds: int = 3600, failure_window: int = 300):
        self.window_seconds = window_seconds
        self.failure_window = failure_window
        # deque of (datetime, dest_ip)
        self._dest_ips: Dict[str, deque] = defaultdict(deque)
        # deque of (datetime, dest_port)
        self._dest_ports: Dict[str, deque] = defaultdict(deque)
        # deque of datetime (one per failure)
        self._failures: Dict[str, deque] = defaultdict(deque)

    def _evict(self, dq: deque, cutoff: datetime, cap: int) -> None:
        """Remove entries older than *cutoff* and trim to *cap*."""
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        while len(dq) > cap:
            dq.popleft()

    def _evict_ts(self, dq: deque, cutoff: datetime, cap: int) -> None:
        """Same as _evict but entries are bare timestamps (no tuple)."""
        while dq and dq[0] < cutoff:
            dq.popleft()
        while len(dq) > cap:
            dq.popleft()

    def update_destination_diversity(
        self, src_ip: str, dest_ip: str, dest_port: int,
        timestamp: datetime,
    ) -> Dict[str, int]:
        if not src_ip:
            return {"unique_dest_ips": 0, "unique_dest_ports": 0}

        cutoff = timestamp - timedelta(seconds=self.window_seconds)

        # Record destination IP
        if dest_ip:
            self._dest_ips[src_ip].append((timestamp, dest_ip))
        self._evict(self._dest_ips[src_ip], cutoff, self.MAX_ENTRIES_PER_ENTITY)

        # Record destination port
        if dest_port is not None:
            self._dest_ports[src_ip].append((timestamp, dest_port))
        self._evict(self._dest_ports[src_ip], cutoff, self.MAX_ENTRIES_PER_ENTITY)

        unique_ips = len({v for _, v in self._dest_ips[src_ip]})
        unique_ports = len({v for _, v in self._dest_ports[src_ip]})

        # Evict stale entity keys periodically (every 1000 events approx)
        if len(self._dest_ips) > 10000:
            stale = [k for k, dq in self._dest_ips.items() if not dq]
            for k in stale:
                del self._dest_ips[k]
                self._dest_ports.pop(k, None)

        return {"unique_dest_ips": unique_ips, "unique_dest_ports": unique_ports}

    def track_failure(self, entity_key: str, timestamp: datetime) -> int:
        cutoff = timestamp - timedelta(seconds=self.failure_window)
        self._failures[entity_key].append(timestamp)
        self._evict_ts(self._failures[entity_key], cutoff, self.MAX_ENTRIES_PER_ENTITY)

        # Periodic stale-key cleanup for _failures
        if len(self._failures) > 10000:
            stale = [k for k, dq in self._failures.items() if not dq]
            for k in stale:
                del self._failures[k]

        return len(self._failures[entity_key])


class LogEnricher:
    """Enhanced log enrichment engine with network intelligence."""

    # Anomaly detection thresholds
    ANOMALY_HIGH_FREQUENCY_THRESHOLD = 50
    ANOMALY_PORT_SCAN_THRESHOLD = 15
    ANOMALY_LATERAL_MOVEMENT_THRESHOLD = 20
    ANOMALY_BRUTE_FORCE_USER_THRESHOLD = 15
    ANOMALY_DATA_EXFIL_EVENT_THRESHOLD = 100
    ANOMALY_DATA_EXFIL_MAX_TARGETS = 3

    # Business hours
    BUSINESS_HOURS_START = 9
    BUSINESS_HOURS_END = 17

    # Risk score bonuses/penalties
    RISK_SEVERITY_MULTIPLIER = 10
    RISK_SEVERITY_MAX_BASE = 50
    RISK_FAILURE_HIGH_THRESHOLD = 10
    RISK_FAILURE_HIGH_BONUS = 20
    RISK_FAILURE_MEDIUM_THRESHOLD = 5
    RISK_FAILURE_MEDIUM_BONUS = 10
    RISK_PUBLIC_SRC_BONUS = 15
    RISK_PUBLIC_DEST_BONUS = 10
    RISK_PORT_SCAN_BONUS = 20
    RISK_LATERAL_MOVEMENT_BONUS = 20
    RISK_HIGH_FREQUENCY_BONUS = 15
    RISK_BRUTE_FORCE_BONUS = 25
    RISK_DATA_EXFIL_BONUS = 20
    RISK_AFTER_HOURS_BONUS = 10
    RISK_CROSS_BORDER_BONUS = 10
    RISK_LONG_DISTANCE_BONUS = 5
    RISK_LONG_DISTANCE_THRESHOLD_KM = 5000
    RISK_IMPOSSIBLE_TRAVEL_BONUS = 25
    RISK_TOR_BONUS = 15
    RISK_THREAT_CONFIDENCE_MULTIPLIER = 30
    RISK_BLOCKED_PENALTY = 30
    RISK_SCORE_MAX = 100

    # Geographic thresholds
    GEO_CROSS_CONTINENT_THRESHOLD_KM = 3000

    def __init__(self,
                 counter_window_seconds: int = 300, 
                 overwrite: bool = False,
                 geoip_db_path: Optional[str] = None,
                 asn_db_path: Optional[str] = None,
                 tor_list_path: Optional[str] = None,
                 reputation_db_path: Optional[str] = None):
        
        self.overwrite = overwrite
        self.counter_window = counter_window_seconds
        
        # Rolling counters
        self.src_ip_counter = RollingCounter(counter_window_seconds)
        self.user_counter = RollingCounter(counter_window_seconds)
        self.host_counter = RollingCounter(counter_window_seconds)
        self.signature_counter = RollingCounter(counter_window_seconds)
        self.dest_ip_counter = RollingCounter(counter_window_seconds)
        self.dest_port_counter = RollingCounter(counter_window_seconds)
        
        # Behavioral tracking
        self.behavior_tracker = BehaviorTracker(window_seconds=3600)
        self.geo_tracker = GeoTracker()
        
        # GeoIP database
        self.geoip_reader = None
        self.geo_cache = {}
        
        if geoip_db_path and GEOIP_AVAILABLE:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
                print(f"✓ GeoIP database loaded: {geoip_db_path}", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not load GeoIP database: {e}", file=sys.stderr)
        
        # Network intelligence
        self.network_intel = NetworkIntelligence(
            asn_db_path=asn_db_path,
            tor_list_path=tor_list_path,
            reputation_db_path=reputation_db_path
        )
    
    def lookup_geo(self, ip: str, ip_type: str) -> Optional[Dict[str, Any]]:
        if not self.geoip_reader or not ip or ip_type != "public":
            return None
        
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        try:
            response = self.geoip_reader.city(ip)
            
            geo_data = {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name if response.city.name else "Unknown",
                "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
                "is_in_eu": response.country.is_in_european_union,
            }
            
            self.geo_cache[ip] = geo_data
            
            if len(self.geo_cache) > 10000:
                for _ in range(1000):
                    self.geo_cache.pop(next(iter(self.geo_cache)))
            
            return geo_data
            
        except (geoip2.errors.AddressNotFoundError, AttributeError):
            return None
        except Exception:
            return None
    
    def classify_ip(self, ip_str: Optional[str]) -> str:
        """Classify IP type.

        Returns one of: private, public, loopback, link_local, multicast, unknown.
        Uses INTERNAL_CIDRS for the private/internal check so site-specific
        ranges (e.g. 10.200.0.0/16) are handled correctly.
        """
        if not ip_str:
            return "unknown"

        try:
            ip = ipaddress.ip_address(ip_str)

            if ip.is_loopback:
                return "loopback"
            elif ip.is_link_local:
                return "link_local"
            elif ip.is_multicast:
                return "multicast"
            elif _ip_is_internal(ip) or ip.is_private:
                return "private"
            elif not ip.is_reserved:
                return "public"
            else:
                return "unknown"
        except (ValueError, AttributeError):
            return "unknown"
    
    def extract_temporal_context(self, timestamp: datetime) -> Dict[str, Any]:
        return {
            "hour_of_day": timestamp.hour,
            "day_of_week": timestamp.strftime("%A"),
            "day_of_month": timestamp.day,
            "is_business_hours": self.BUSINESS_HOURS_START <= timestamp.hour < self.BUSINESS_HOURS_END and timestamp.weekday() < 5,
            "is_weekend": timestamp.weekday() >= 5,
            "is_night": timestamp.hour < 6 or timestamp.hour >= 22,
        }
    
    def normalize_protocol(self, protocol: Optional[str]) -> str:
        """Return uppercase protocol enum: TCP, UDP, ICMP, QUIC, UNKNOWN."""
        if not protocol or protocol.upper() in ("UNKNOWN", "NONE", ""):
            return "UNKNOWN"

        up = protocol.upper()
        proto_map = {
            "TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP", "QUIC": "QUIC",
            "HTTP": "TCP", "HTTPS": "TCP", "DNS": "UDP",
            "SSH": "TCP", "FTP": "TCP", "SMTP": "TCP",
            "6": "TCP", "17": "UDP", "1": "ICMP",
        }
        return proto_map.get(up, up)
    
    def normalize_action(self, event: Dict[str, Any]) -> str:
        outcome = event.get("event_outcome", "").lower()
        action = event.get("event_action", "").lower()
        raw_action = event.get("context", {}).get("raw_event", {}).get("data", {}).get("action", "").lower()
        
        if outcome == "success" or raw_action in ["pass", "allow", "accept", "permit"]:
            return "allowed"
        elif outcome == "failure" or raw_action in ["deny", "drop", "reject"]:
            return "denied"
        elif "block" in action or "block" in raw_action:
            return "blocked"
        else:
            return "unknown"
    
    def infer_host_role(self, event: Dict[str, Any]) -> Optional[str]:
        host = event.get("host", {})
        existing_type = host.get("type", "")
        os_family = host.get("os", {}).get("family", "")
        
        known_types = ["firewall", "router", "switch", "server", "workstation", "endpoint", "domain_controller"]
        if existing_type and any(kt in existing_type.lower() for kt in known_types):
            return None
        
        event_category = event.get("event_category", "")
        subject = event.get("subject", {})
        
        if os_family == "network_os" and event_category == "network":
            if not existing_type or existing_type == "unknown":
                return "network_device"
        
        if event_category == "auth" and subject.get("name"):
            if not existing_type or existing_type == "unknown":
                return "endpoint"
        
        return None
    
    def compute_fingerprint(self, event: Dict[str, Any]) -> str:
        subject = event.get("subject", {})
        obj = event.get("object", {})
        host = event.get("host", {})
        security = event.get("security", {})
        
        components = [
            event.get("event_category", ""),
            event.get("event_action", ""),
            event.get("event_outcome", ""),
            subject.get("name", ""),
            subject.get("ip", ""),
            obj.get("name", ""),
            obj.get("ip", ""),
            host.get("id", ""),
            security.get("signature_id", ""),
        ]
        
        fingerprint_input = "|".join(str(c) for c in components)
        return hashlib.sha1(fingerprint_input.encode("utf-8")).hexdigest()
    
    def detect_anomalies(
        self,
        counters: Dict[str, int],
        diversity: Dict[str, int],
        normalized_action: str,
        src_ip_type: str,
        dest_ip_type: str,
        temporal: Dict[str, Any],
        geo_data: Optional[Dict[str, Any]] = None,
        impossible_travel: Optional[Dict[str, Any]] = None,
        network_intel: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        # Fixed schema — all anomaly keys always present
        anomalies: Dict[str, Any] = {
            "is_high_frequency": counters.get("src_ip_5m", 0) > self.ANOMALY_HIGH_FREQUENCY_THRESHOLD,
            "is_port_scan": diversity.get("unique_dest_ports", 0) > self.ANOMALY_PORT_SCAN_THRESHOLD,
            "is_lateral_movement": diversity.get("unique_dest_ips", 0) > self.ANOMALY_LATERAL_MOVEMENT_THRESHOLD,
            "is_brute_force": (
                counters.get("user_5m", 0) > self.ANOMALY_BRUTE_FORCE_USER_THRESHOLD
                and normalized_action in ("denied", "blocked")
            ),
            "is_data_exfil": (
                src_ip_type == "private" and dest_ip_type == "public"
                and normalized_action not in ("blocked", "denied")
                and counters.get("src_ip_5m", 0) > self.ANOMALY_DATA_EXFIL_EVENT_THRESHOLD
                and diversity.get("unique_dest_ips", 0) <= self.ANOMALY_DATA_EXFIL_MAX_TARGETS
            ),
            "is_after_hours": not temporal.get("is_business_hours", True),
            "cross_continent": bool(geo_data and geo_data.get("cross_continent")),
            "cross_border": bool(geo_data and geo_data.get("cross_border")),
            "is_impossible_travel": bool(
                impossible_travel and impossible_travel.get("is_impossible_travel")
            ),
            "is_tor_traffic": bool(network_intel and network_intel.get("tor_detected")),
            "is_malicious_ip": bool(network_intel and network_intel.get("threat_detected")),
        }
        anomalies["anomaly_count"] = sum(1 for k, v in anomalies.items() if v is True)

        return anomalies
    
    def compute_risk_score(
        self,
        event: Dict[str, Any],
        src_ip_type: str,
        dest_ip_type: str,
        counters: Dict[str, int],
        normalized_action: str,
        diversity: Dict[str, int],
        anomalies: Dict[str, Any],
        failure_count: int,
        geo_data: Optional[Dict[str, Any]] = None,
        network_intel: Optional[Dict[str, Any]] = None
    ) -> int:
        security = event.get("security", {})
        severity = security.get("severity")
        
        score = 0
        if severity is not None:
            try:
                score = min(int(severity) * self.RISK_SEVERITY_MULTIPLIER, self.RISK_SEVERITY_MAX_BASE)
            except (ValueError, TypeError):
                score = 0

        if failure_count > self.RISK_FAILURE_HIGH_THRESHOLD:
            score += self.RISK_FAILURE_HIGH_BONUS
        elif failure_count > self.RISK_FAILURE_MEDIUM_THRESHOLD:
            score += self.RISK_FAILURE_MEDIUM_BONUS

        if src_ip_type == "public":
            score += self.RISK_PUBLIC_SRC_BONUS
        if dest_ip_type == "public" and src_ip_type == "private":
            score += self.RISK_PUBLIC_DEST_BONUS

        if anomalies.get("is_port_scan"):
            score += self.RISK_PORT_SCAN_BONUS
        if anomalies.get("is_lateral_movement"):
            score += self.RISK_LATERAL_MOVEMENT_BONUS
        if anomalies.get("is_high_frequency"):
            score += self.RISK_HIGH_FREQUENCY_BONUS
        if anomalies.get("is_brute_force"):
            score += self.RISK_BRUTE_FORCE_BONUS
        if anomalies.get("is_data_exfil"):
            score += self.RISK_DATA_EXFIL_BONUS
        if anomalies.get("is_after_hours") and anomalies.get("anomaly_count", 0) > 1:
            score += self.RISK_AFTER_HOURS_BONUS

        if geo_data:
            if geo_data.get("cross_border"):
                score += self.RISK_CROSS_BORDER_BONUS
            if geo_data.get("distance_km", 0) > self.RISK_LONG_DISTANCE_THRESHOLD_KM:
                score += self.RISK_LONG_DISTANCE_BONUS

        if anomalies.get("is_impossible_travel"):
            score += self.RISK_IMPOSSIBLE_TRAVEL_BONUS

        # Network intelligence scoring
        if network_intel:
            if network_intel.get("tor_detected"):
                score += self.RISK_TOR_BONUS
            if network_intel.get("threat_detected"):
                threat_confidence = network_intel.get("threat_confidence", 0.0)
                score += int(self.RISK_THREAT_CONFIDENCE_MULTIPLIER * threat_confidence)

        # Blocked/denied traffic: the firewall handled it — reduce risk
        if normalized_action in ("blocked", "denied"):
            score = max(score - self.RISK_BLOCKED_PENALTY, 0)

        return min(score, self.RISK_SCORE_MAX)
    
    def parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
    
    def update_counters(self, event: Dict[str, Any], timestamp: datetime) -> Dict[str, int]:
        subject = event.get("subject", {})
        obj = event.get("object", {})
        host = event.get("host", {})
        security = event.get("security", {})
        
        counters = {}
        
        src_ip = subject.get("ip")
        if src_ip:
            counters["src_ip_5m"] = self.src_ip_counter.increment(src_ip, timestamp)
        
        dest_ip = obj.get("ip")
        if dest_ip:
            counters["dest_ip_5m"] = self.dest_ip_counter.increment(dest_ip, timestamp)
        
        dest_port = obj.get("port")
        if dest_port:
            counters["dest_port_5m"] = self.dest_port_counter.increment(str(dest_port), timestamp)
        
        user = subject.get("name")
        if user:
            counters["user_5m"] = self.user_counter.increment(user, timestamp)
        
        host_id = host.get("id")
        if host_id:
            counters["host_5m"] = self.host_counter.increment(host_id, timestamp)
        
        sig_id = security.get("signature_id")
        if sig_id:
            counters["signature_5m"] = self.signature_counter.increment(str(sig_id), timestamp)
        
        return counters
    
    def build_enrichment_section(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event_time_str = event.get("event_time", "")
        event_time = self.parse_timestamp(event_time_str)
        if not event_time:
            event_time = datetime.now(timezone.utc)
        
        subject = event.get("subject", {})
        obj = event.get("object", {})
        security = event.get("security", {})
        network = event.get("network", {})
        event_category = event.get("event_category", "")
        
        src_ip = subject.get("ip")
        dest_ip = obj.get("ip")
        dest_port = obj.get("port")
        is_network_event = event_category in ("network", "vpn")

        # For non-network events (process, file, auth, etc.) protocol and
        # direction are meaningless — keep them null so downstream stages
        # don't treat process-create events as network traffic.
        protocol = None
        direction = None

        if is_network_event:
            protocol = network.get("protocol")
            direction = network.get("direction")

            # --- Fallback: extract protocol/direction from raw_event when the
            #     normalizer missed them (Sysmon EventID=3, FortiGate, etc.)
            raw = event.get("context", {}).get("raw_event", {})
            raw_data = raw.get("data", {}) if isinstance(raw, dict) else {}

            if not protocol:
                win_ed = raw_data.get("win", {})
                if isinstance(win_ed, dict):
                    win_ed = win_ed.get("eventdata", {})
                if isinstance(win_ed, dict):
                    protocol = win_ed.get("protocol") or win_ed.get("Protocol")
                if not protocol:
                    for key in ("proto", "protocol", "transport", "Protocol"):
                        v = raw_data.get(key)
                        if v:
                            protocol = str(v)
                            break

            _PROTO_NUM = {"6": "TCP", "17": "UDP", "1": "ICMP"}
            if protocol:
                protocol = _PROTO_NUM.get(str(protocol).upper(), str(protocol).upper())

            if not direction:
                win_ed2 = raw_data.get("win", {})
                if isinstance(win_ed2, dict):
                    win_ed2 = win_ed2.get("eventdata", {})
                if isinstance(win_ed2, dict):
                    initiated = win_ed2.get("initiated") or win_ed2.get("Initiated")
                    if initiated is not None:
                        direction = "outgoing" if str(initiated).lower() == "true" else "incoming"
                if not direction:
                    raw_dir = raw_data.get("direction") or raw_data.get("Direction")
                    if raw_dir:
                        direction = str(raw_dir).lower()
                if not direction and src_ip and dest_ip:
                    s_type = self.classify_ip(src_ip)
                    d_type = self.classify_ip(dest_ip)
                    if s_type == "private" and d_type == "public":
                        direction = "outgoing"
                    elif s_type == "public" and d_type == "private":
                        direction = "incoming"
                    elif s_type == "private" and d_type == "private":
                        direction = "internal"

            if not protocol:
                protocol = "UNKNOWN"
        
        # Temporal
        temporal = self.extract_temporal_context(event_time)
        
        # Flags — fixed schema, all keys always present
        flags = {
            "is_auth_event": event_category == "auth",
            "is_network_event": is_network_event,
            "is_vpn_event": event_category == "vpn",
            "is_process_event": event_category == "process",
            "is_file_event": event_category == "file",
            "is_alert": security.get("signature_id") is not None,
        }
        
        # IP classification
        src_ip_type = self.classify_ip(src_ip)
        dest_ip_type = self.classify_ip(dest_ip)
        
        ip_classification = {
            "src_ip_type": src_ip_type,
            "dest_ip_type": dest_ip_type,
            "is_internal_traffic": (
                src_ip and dest_ip and
                src_ip_type == "private" and dest_ip_type == "private"
            ),
            "is_external_inbound": src_ip_type == "public" and dest_ip_type == "private",
            "is_external_outbound": src_ip_type == "private" and dest_ip_type == "public",
        }
        
        # Network intelligence enrichment
        network_intel_data = {}

        # ASN lookup — fixed schema, always present
        src_asn = self.network_intel.lookup_asn(src_ip, src_ip_type)
        dest_asn = self.network_intel.lookup_asn(dest_ip, dest_ip_type)
        network_intel_data["src_asn"] = src_asn or {}
        network_intel_data["dest_asn"] = dest_asn or {}
        network_intel_data["src_provider"] = (
            self.network_intel.get_provider(src_asn.get("number")) if src_asn else None
        )
        network_intel_data["dest_provider"] = (
            self.network_intel.get_provider(dest_asn.get("number")) if dest_asn else None
        )
        
        # Tor detection — fixed schema, always present
        src_is_tor = bool(src_ip and src_ip_type == "public"
                          and self.network_intel.check_tor_exit(src_ip))
        dest_is_tor = bool(dest_ip and dest_ip_type == "public"
                           and self.network_intel.check_tor_exit(dest_ip))
        network_intel_data["src_tor"] = {"is_exit_node": src_is_tor}
        network_intel_data["dest_tor"] = {"is_exit_node": dest_is_tor}
        network_intel_data["tor_detected"] = src_is_tor or dest_is_tor
        
        # IP reputation — fixed schema, always present
        src_reputation = (self.network_intel.check_reputation(src_ip)
                          if src_ip and src_ip_type == "public" else None)
        dest_reputation = (self.network_intel.check_reputation(dest_ip)
                           if dest_ip and dest_ip_type == "public" else None)

        network_intel_data["src_reputation"] = {
            "ip_reputation": src_reputation["status"] if src_reputation else "clean",
            "confidence": src_reputation["confidence"] if src_reputation else 0.0,
        }
        network_intel_data["dest_reputation"] = {
            "ip_reputation": dest_reputation["status"] if dest_reputation else "clean",
            "confidence": dest_reputation["confidence"] if dest_reputation else 0.0,
        }
        threat_detected = bool(src_reputation or dest_reputation)
        network_intel_data["threat_detected"] = threat_detected
        network_intel_data["threat_confidence"] = max(
            src_reputation["confidence"] if src_reputation else 0.0,
            dest_reputation["confidence"] if dest_reputation else 0.0,
        )
        
        # QUIC detection — fixed schema, always present
        dest_asn_number = dest_asn.get("number") if dest_asn else None
        quic_data = self.network_intel.detect_quic(protocol, dest_port, dest_asn_number)
        network_intel_data["quic"] = quic_data or {"is_quic": False, "confidence": "none"}
        
        # GeoIP lookup
        geo_section = None
        impossible_travel_data = None
        
        if self.geoip_reader:
            src_geo = self.lookup_geo(src_ip, src_ip_type)
            dest_geo = self.lookup_geo(dest_ip, dest_ip_type)
            
            if src_geo or dest_geo:
                geo_section = {}
                
                if src_geo:
                    geo_section["src"] = src_geo
                
                if dest_geo:
                    geo_section["dest"] = dest_geo
                
                if src_geo and dest_geo:
                    # Only calculate distance if both locations have coordinates
                    if (src_geo.get("latitude") is not None and src_geo.get("longitude") is not None and
                        dest_geo.get("latitude") is not None and dest_geo.get("longitude") is not None):
                        distance = self.geo_tracker._calculate_distance(
                            src_geo["latitude"], src_geo["longitude"],
                            dest_geo["latitude"], dest_geo["longitude"]
                        )
                        geo_section["distance_km"] = round(distance, 2)
                        geo_section["cross_continent"] = distance > self.GEO_CROSS_CONTINENT_THRESHOLD_KM
                    
                    # Country comparison can be done even without coordinates
                    geo_section["same_country"] = src_geo.get("country_code") == dest_geo.get("country_code")
                    geo_section["cross_border"] = src_geo.get("country_code") != dest_geo.get("country_code")
                
                tracking_key = subject.get("name") or src_ip
                if tracking_key and src_geo and src_geo.get("latitude") is not None and src_geo.get("longitude") is not None:
                    impossible_travel_data = self.geo_tracker.update_location(
                        tracking_key,
                        src_geo["country"],
                        src_geo["city"],
                        src_geo["latitude"],
                        src_geo["longitude"],
                        event_time,
                        source_ip=src_ip,
                    )
        
        # Auth events: derive direction from IP classification
        if event_category == "auth" and (src_ip or dest_ip):
            if ip_classification.get("is_external_inbound"):
                direction = "incoming"
            elif ip_classification.get("is_external_outbound"):
                direction = "outgoing"
            elif ip_classification.get("is_internal_traffic"):
                direction = "internal"
            else:
                direction = "unknown"

        # Normalization
        normalized_action = self.normalize_action(event)

        if is_network_event:
            normalized_proto = self.normalize_protocol(protocol)
            normalization = {
                "protocol": normalized_proto,
                "action": normalized_action,
                "direction": direction if direction else "unknown",
            }
        elif event_category == "auth" and direction:
            normalization = {
                "protocol": None,
                "action": normalized_action,
                "direction": direction,
            }
        else:
            normalization = {
                "protocol": None,
                "action": normalized_action,
                "direction": None,
            }
        
        # Counters
        counters = self.update_counters(event, event_time)
        
        # Behavioral
        diversity = self.behavior_tracker.update_destination_diversity(
            src_ip, dest_ip, dest_port, event_time
        )
        
        failure_count = 0
        if normalized_action in ["denied", "blocked"]:
            entity_key = f"{src_ip}:{dest_ip}:{dest_port}" if src_ip else "unknown"
            failure_count = self.behavior_tracker.track_failure(entity_key, event_time)
        
        behavioral = {
            "unique_destinations_1h": diversity.get("unique_dest_ips", 0),
            "unique_ports_1h": diversity.get("unique_dest_ports", 0),
            "recent_failures_5m": failure_count,
        }
        
        # Anomalies
        anomalies = self.detect_anomalies(
            counters, diversity, normalized_action, src_ip_type, dest_ip_type, 
            temporal, geo_section, impossible_travel_data, network_intel_data
        )
        
        # Fingerprint
        fingerprint = self.compute_fingerprint(event)
        
        # Host role
        host_role = self.infer_host_role(event)
        
        # Risk score
        risk_score = self.compute_risk_score(
            event, src_ip_type, dest_ip_type, counters, normalized_action,
            diversity, anomalies, failure_count, geo_section, network_intel_data
        )
        
        # Build enrichment section
        enrich_section = {
            "fingerprint": fingerprint,
            "temporal": temporal,
            "flags": flags,
            "classification": ip_classification,
            "normalization": normalization,
            "counters": counters,
            "behavioral": behavioral,
            "anomalies": anomalies,
            "risk_score": risk_score,
        }
        
        # Network intelligence — always present (fixed schema)
        enrich_section["network_intel"] = network_intel_data
        
        # Geo — always present (fixed schema)
        enrich_section["geo"] = geo_section or {}

        # Impossible travel — always present (fixed schema)
        enrich_section["impossible_travel"] = impossible_travel_data or {}

        # Host role — always present (fixed schema)
        enrich_section["inferred_host_role"] = host_role or ""
        
        return enrich_section
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        enrich_section = self.build_enrichment_section(event)
        enriched = event.copy()

        if self.overwrite or "enrich" not in enriched:
            enriched["enrich"] = enrich_section

        # Backfill network.protocol and network.direction for network events
        # so downstream stages always have them even if the normalizer missed them.
        # For non-network events, leave network fields as null.
        cat = enriched.get("event_category")
        if cat in ("network", "vpn"):
            norm = enrich_section.get("normalization", {})
            net = enriched.get("network")
            if isinstance(net, dict):
                if not net.get("protocol"):
                    net["protocol"] = norm.get("protocol", "UNKNOWN")
                if not net.get("direction"):
                    d = norm.get("direction")
                    if d and d != "unknown":
                        net["direction"] = d
        elif cat == "auth":
            # Backfill network.direction for auth events (protocol stays null)
            norm = enrich_section.get("normalization", {})
            d = norm.get("direction")
            if d and d not in ("unknown", None):
                net = enriched.get("network")
                if isinstance(net, dict) and not net.get("direction"):
                    net["direction"] = d

        return enriched
    
    def process_line(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""
        
        try:
            event = json.loads(line)
            enriched = self.enrich_event(event)
            return json.dumps(enriched, separators=(",", ":"), ensure_ascii=False)
        except json.JSONDecodeError:
            minimal_event = {
                "schema_version": "1.0",
                "event_id": "",
                "event_time": "",
                "ingest_time": "",
                "event_category": "",
                "event_action": "",
                "event_outcome": "",
                "subject": {"type": None, "id": None, "name": None, "ip": None, "port": None},
                "object": {"type": None, "id": None, "name": None, "ip": None, "port": None},
                "host": {"id": None, "name": None, "ip": None, "os": {"name": None, "version": None, "family": None}, "type": None},
                "network": {"protocol": None, "direction": None},
                "security": {"signature_id": None, "signature": None, "severity": None, "tags": []},
                "context": {"source": "", "environment": None, "message": "unparsed_input", "raw_event": {"unparsed_line": line}},
                "enrich": {
                    "fingerprint": "",
                    "temporal": {},
                    "flags": {
                        "is_auth_event": False,
                        "is_network_event": False,
                        "is_vpn_event": False,
                        "is_process_event": False,
                        "is_file_event": False,
                        "is_alert": False,
                    },
                    "classification": {},
                    "normalization": {"protocol": None, "action": "unknown", "direction": None},
                    "counters": {},
                    "behavioral": {"unique_destinations_1h": 0, "unique_ports_1h": 0, "recent_failures_5m": 0},
                    "anomalies": {
                        "is_high_frequency": False, "is_port_scan": False,
                        "is_lateral_movement": False, "is_brute_force": False,
                        "is_data_exfil": False, "is_after_hours": False,
                        "cross_continent": False, "cross_border": False,
                        "is_impossible_travel": False, "is_tor_traffic": False,
                        "is_malicious_ip": False, "anomaly_count": 0,
                    },
                    "risk_score": 0,
                    "network_intel": {},
                    "geo": {},
                    "impossible_travel": {},
                    "inferred_host_role": "",
                }
            }
            return json.dumps(minimal_event, separators=(",", ":"), ensure_ascii=False)
    
    def close(self):
        """Close all database readers."""
        if self.geoip_reader:
            self.geoip_reader.close()
        self.network_intel.close()


def main():
    parser = argparse.ArgumentParser(description="Enhanced log enrichment with network intelligence")
    parser.add_argument("--input", default="normalized.jsonl", help="Input JSONL file")
    parser.add_argument("--output", default="enriched.jsonl", help="Output JSONL file")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing enrichment")
    parser.add_argument("--counter-window-seconds", type=int, default=300, help="Rolling counter window")
    parser.add_argument("--geoip-db", help="Path to GeoLite2-City.mmdb")
    parser.add_argument("--asn-db", help="Path to GeoLite2-ASN.mmdb")
    parser.add_argument("--tor-list", help="Path to tor-exit-nodes.txt")
    parser.add_argument("--reputation-db", help="Path to malicious-ips.txt")
    parser.add_argument("--follow", action="store_true",
                        help="Continuously tail input file for new data")
    parser.add_argument("--state-file", default=".state/enricher.state",
                        help="State file for follow mode position tracking")
    parser.add_argument("--poll-interval", type=float, default=0.5,
                        help="Poll interval in seconds for follow mode")
    # Kafka mode
    parser.add_argument("--kafka-brokers", default=None,
                        help="Kafka broker(s) — enables Kafka streaming mode")
    parser.add_argument("--input-topic", default="normalized",
                        help="Kafka input topic (default: normalized)")
    parser.add_argument("--output-topic", default="enriched",
                        help="Kafka output topic (default: enriched)")
    parser.add_argument("--consumer-group", default="enricher",
                        help="Kafka consumer group (default: enricher)")

    args = parser.parse_args()
    
    if (args.geoip_db or args.asn_db) and not GEOIP_AVAILABLE:
        print("✗ Error: geoip2 library not installed", file=sys.stderr)
        print("  Run: pip install geoip2 --break-system-packages", file=sys.stderr)
        sys.exit(1)
    
    enricher = LogEnricher(
        counter_window_seconds=args.counter_window_seconds,
        overwrite=args.overwrite,
        geoip_db_path=args.geoip_db,
        asn_db_path=args.asn_db,
        tor_list_path=args.tor_list,
        reputation_db_path=args.reputation_db
    )
    
    if args.kafka_brokers:
        # --- Kafka streaming mode ---
        from kafka_helpers import run_stage

        def _process(event):
            enriched = enricher.enrich_event(event)
            return [enriched] if enriched else []

        def _key(out):
            return (out.get("subject") or {}).get("ip")

        try:
            run_stage(
                brokers=args.kafka_brokers,
                consumer_group=args.consumer_group,
                input_topic=args.input_topic,
                output_topic=args.output_topic,
                process_fn=_process,
                key_fn=_key,
                stage_name="L2-enricher",
            )
        finally:
            enricher.close()
        return

    if args.follow:
        # --- Streaming / follow mode ---
        from file_tailer import JSONLTailer, append_jsonl

        tailer = JSONLTailer(
            args.input,
            state_file=args.state_file,
            poll_interval=args.poll_interval,
        )
        line_count = 0
        outfile = None
        try:
            outfile = open(args.output, "a", encoding="utf-8")
            print(f"Following {args.input} -> {args.output} ...", file=sys.stderr)

            for event in tailer.follow():
                enriched = enricher.enrich_event(event)
                if enriched:
                    append_jsonl(outfile, enriched)
                    line_count += 1
                    if line_count % 500 == 0:
                        print(f"  Enriched {line_count} events...", file=sys.stderr)

        except KeyboardInterrupt:
            print("\nShutting down enricher...", file=sys.stderr)
        finally:
            tailer.close()
            if outfile:
                outfile.close()
            enricher.close()
            print(f"✓ Enriched {line_count} events (follow mode)", file=sys.stderr)
    else:
        # --- Batch mode (original behaviour) ---
        try:
            with open(args.input, "r", encoding="utf-8") as infile, \
                 open(args.output, "w", encoding="utf-8") as outfile:

                line_count = 0
                for line in infile:
                    enriched_line = enricher.process_line(line)
                    if enriched_line:
                        outfile.write(enriched_line + "\n")
                        line_count += 1

            print(f"\n✓ Network enrichment complete: {line_count} events processed", file=sys.stderr)
            print(f"  Input:  {args.input}", file=sys.stderr)
            print(f"  Output: {args.output}", file=sys.stderr)

            features = []
            if args.geoip_db:
                features.append("GeoIP")
            if args.asn_db:
                features.append("ASN")
            if args.tor_list:
                features.append("Tor Detection")
            if args.reputation_db:
                features.append("IP Reputation")

            if features:
                print(f"  Features: {', '.join(features)}", file=sys.stderr)

        except FileNotFoundError as e:
            print(f"✗ Error: File not found: {e}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"✗ Error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            enricher.close()


if __name__ == "__main__":
    main()
