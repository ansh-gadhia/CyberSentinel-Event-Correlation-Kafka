#!/usr/bin/env python3
"""
Wazuh Log Normalization Pipeline
Production-grade streaming normalizer with robust parsing and OS/device enrichment.
Handles partial JSON, embedded newlines, log rotation, and diverse alert types.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# ROBUST JSON PARSING (Handles partial writes, embedded newlines)
# ============================================================================

class IncrementalJSONParser:
    """
    Incrementally parse JSON objects from a stream that may contain:
    - Partial objects
    - Embedded newlines
    - Interrupted writes
    """
    
    def __init__(self, max_buffer_size: int = 10 * 1024 * 1024):
        self.buffer = ""
        self.max_buffer_size = max_buffer_size
        self.decoder = json.JSONDecoder()
    
    def feed(self, chunk: str) -> List[Dict[str, Any]]:
        """
        Feed new data and extract complete JSON objects.
        Returns list of successfully parsed objects.
        """
        self.buffer += chunk
        objects = []
        
        while self.buffer:
            # Skip whitespace and junk until we find a '{'
            self.buffer = self.buffer.lstrip()
            if not self.buffer:
                break
            
            # If buffer doesn't start with '{', discard until next '{'
            if not self.buffer.startswith('{'):
                next_brace = self.buffer.find('{')
                if next_brace == -1:
                    # No valid JSON start found, clear buffer
                    print(f"Warning: Discarding junk data: {self.buffer[:100]}...", file=sys.stderr)
                    self.buffer = ""
                    break
                else:
                    discarded = self.buffer[:next_brace]
                    print(f"Warning: Discarding junk before JSON: {discarded[:100]}...", file=sys.stderr)
                    self.buffer = self.buffer[next_brace:]
                    continue
            
            # Try to decode a JSON object
            try:
                obj, end_idx = self.decoder.raw_decode(self.buffer)
                objects.append(obj)
                self.buffer = self.buffer[end_idx:]
            except json.JSONDecodeError as e:
                # Incomplete JSON - need more data
                # But if buffer is too large, we may have corrupted data
                if len(self.buffer) > self.max_buffer_size:
                    # Try to recover by finding next '{'
                    next_brace = self.buffer.find('{', 1)
                    if next_brace == -1:
                        # No recovery possible, emit error record
                        fragment = self.buffer[:1000]
                        print(f"Error: Buffer overflow, emitting error record: {fragment}...", file=sys.stderr)
                        objects.append(self._create_error_record(fragment))
                        self.buffer = ""
                    else:
                        # Skip to next potential object
                        discarded = self.buffer[:next_brace]
                        print(f"Warning: Skipping corrupted data: {discarded[:200]}...", file=sys.stderr)
                        self.buffer = self.buffer[next_brace:]
                else:
                    # Wait for more data
                    break
        
        return objects
    
    def _create_error_record(self, fragment: str) -> Dict[str, Any]:
        """Create a minimal alert for unparseable data."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "id": str(uuid.uuid4()),
            "rule": {
                "id": "0",
                "description": "Unparseable alert fragment",
                "level": 0,
                "groups": ["parse_error"]
            },
            "full_log": fragment,
            "_parse_error": True
        }


# ============================================================================
# TIMESTAMP PARSING
# ============================================================================

def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse various timestamp formats to timezone-aware datetime."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    
    # Normalize timezone format
    normalized = ts_str.strip()
    if normalized.endswith('Z'):
        normalized = normalized[:-1] + '+0000'
    
    # Remove colon from timezone offset (e.g., +05:30 -> +0530)
    if len(normalized) > 6:
        tz_match = re.search(r'([+-]\d{2}):(\d{2})$', normalized)
        if tz_match:
            normalized = normalized[:tz_match.start()] + tz_match.group(1) + tz_match.group(2)
    
    # Try multiple formats
    formats = [
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
        '%Y/%m/%d %H:%M:%S',
        '%b %d %H:%M:%S',  # Syslog format
        '%Y-%m-%d',
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(normalized, fmt)
            if dt.tzinfo is None:
                # Assume local timezone
                dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
            return dt
        except ValueError:
            continue
    
    # Try Unix timestamp
    try:
        ts = float(normalized)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OSError):
        pass
    
    return None


def extract_event_time(alert: Dict[str, Any]) -> datetime:
    """Extract most specific event timestamp."""
    # Search common locations in order of preference
    search_paths = [
        ['data', 'timestamp'],
        ['data', '@timestamp'],
        ['data', 'event_time'],
        ['data', 'EventTime'],
        ['data', 'time'],
        ['data', 'datetime'],
        ['data', 'UtcTime'],
        ['data', 'TimeGenerated'],
        ['data', 'win', 'system', 'systemTime'],
        ['timestamp'],
        ['@timestamp'],
    ]
    
    for path in search_paths:
        val = alert
        for key in path:
            if isinstance(val, dict) and key in val:
                val = val[key]
            else:
                val = None
                break
        
        if val:
            ts = parse_timestamp(str(val))
            if ts:
                return ts
    
    # Fallback to current time
    return datetime.now(timezone.utc)


def extract_ingest_time(alert: Dict[str, Any]) -> datetime:
    """Extract Wazuh ingest timestamp."""
    ts = parse_timestamp(alert.get('timestamp', ''))
    return ts if ts else datetime.now(timezone.utc)


# ============================================================================
# FIELD EXTRACTION UTILITIES
# ============================================================================

def safe_get(obj: Any, *keys: str, default=None) -> Any:
    """Safely traverse nested dictionary."""
    if not isinstance(obj, dict):
        return default
    for key in keys:
        if key in obj and obj[key] not in (None, ''):
            return obj[key]
    return default


def deep_search(obj: Dict[str, Any], *key_patterns: str) -> Optional[Any]:
    """
    Recursively search for keys matching patterns (case-insensitive).
    Returns first match found.
    """
    if not isinstance(obj, dict):
        return None
    
    # Check current level
    for pattern in key_patterns:
        pattern_lower = pattern.lower()
        for key, val in obj.items():
            if key.lower() == pattern_lower and val not in (None, ''):
                return val
    
    # Recurse into nested dicts
    for val in obj.values():
        if isinstance(val, dict):
            result = deep_search(val, *key_patterns)
            if result is not None:
                return result
    
    return None


def extract_ip(data: Dict[str, Any], *key_patterns: str) -> Optional[str]:
    """Extract IP address from candidate keys."""
    for pattern in key_patterns:
        val = deep_search(data, pattern)
        if val and isinstance(val, str):
            # Simple IPv4 validation
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val):
                return val
    return None


def extract_port(data: Dict[str, Any], *key_patterns: str) -> Optional[int]:
    """Extract port number from candidate keys."""
    for pattern in key_patterns:
        val = deep_search(data, pattern)
        if val is not None:
            try:
                port = int(val)
                if 0 <= port <= 65535:
                    return port
            except (ValueError, TypeError):
                continue
    return None


_INVALID_USERNAMES = frozenset({
    '/', '-', '.', '*', '(', ')', 'none', 'null', 'n/a', 'unknown', '',
    'system', 'local service', 'network service',
    # Windows service accounts
    'nt authority\\system', 'nt authority\\local service',
    'nt authority\\network service', 'nt authority\\anonymous logon',
    'nt authority\\iusr',
})


def extract_user(data: Dict[str, Any], *key_patterns: str) -> Optional[str]:
    """Extract username from candidate keys."""
    for pattern in key_patterns:
        val = deep_search(data, pattern)
        if val and isinstance(val, str):
            # Normalize escaped backslashes and strip quotes
            cleaned = val.replace('\\\\', '\\')
            cleaned = cleaned.strip().strip('"').strip("'").strip()
            if cleaned and cleaned.lower() not in _INVALID_USERNAMES:
                return cleaned
    return None


# ============================================================================
# OS / DEVICE TYPE DETECTION
# ============================================================================

def detect_os_and_type(alert: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """
    Detect OS family/version and host type using heuristics.
    Returns (os_dict, host_type)
    """
    # Gather hints
    data = alert.get('data', {})
    decoder = alert.get('decoder', {})
    if not isinstance(decoder, dict):
        decoder = {}
    _rule = alert.get('rule', {})
    if not isinstance(_rule, dict):
        _rule = {}
    rule_groups = _rule.get('groups', [])
    location = (alert.get('location') or '').lower()
    full_log = (alert.get('full_log') or '').lower()
    
    all_text = ' '.join([
        str(decoder.get('name', '')).lower(),
        str(decoder.get('parent', '')).lower(),
        location,
        full_log[:500],
        ' '.join(str(g).lower() for g in rule_groups)
    ])
    
    os_info = {'name': None, 'version': None, 'family': None}
    host_type = 'unknown'
    
    # Windows detection
    if any(key in data for key in ['EventID', 'Channel', 'Provider', 'EventData', 'win']):
        os_info['family'] = 'windows'
        # Try to extract version
        if 'windows' in all_text:
            version_match = re.search(r'windows\s*(server\s*)?([\d.]+|xp|vista|7|8|10|11|2008|2012|2016|2019|2022)', all_text)
            if version_match:
                os_info['version'] = version_match.group(0)
        host_type = 'workstation' if any(x in all_text for x in ['workstation', 'desktop', 'win10', 'win11']) else 'server'
    
    elif any(keyword in all_text for keyword in ['windows', 'win32', 'sysmon', 'eventlog', 'microsoft-windows']):
        os_info['family'] = 'windows'
        host_type = 'workstation' if 'desktop' in all_text else 'server'
    
    # Linux detection
    elif any(keyword in all_text for keyword in ['sshd', 'pam', 'auditd', 'journald', 'systemd', '/var/log/', 'linux', 'ubuntu', 'debian', 'centos', 'rhel', 'fedora']):
        os_info['family'] = 'linux'
        # Try to detect distro
        for distro in ['ubuntu', 'debian', 'centos', 'rhel', 'fedora', 'amazon linux', 'alpine']:
            if distro in all_text:
                os_info['name'] = distro
                break
        host_type = 'server'
    
    # macOS detection
    elif any(keyword in all_text for keyword in ['darwin', 'macos', 'osx', 'launchd', 'endpointsecurity', 'apple']):
        os_info['family'] = 'macos'
        host_type = 'workstation'
    
    # Network device detection
    elif any(keyword in all_text for keyword in ['fortigate', 'fortinet', 'cisco', 'paloalto', 'palo alto', 'juniper', 'checkpoint', 'netscaler', 'f5', 'arista']):
        os_info['family'] = 'network_os'
        
        # Specific vendor
        if 'fortigate' in all_text or 'fortinet' in all_text:
            os_info['name'] = 'fortios'
        elif 'cisco' in all_text:
            os_info['name'] = 'cisco_ios'
        elif 'palo' in all_text:
            os_info['name'] = 'pan-os'
        elif 'juniper' in all_text:
            os_info['name'] = 'junos'
        
        # Device type
        if any(x in all_text for x in ['firewall', 'utm', 'ngfw']):
            host_type = 'firewall'
        elif any(x in all_text for x in ['ids', 'ips', 'intrusion']):
            host_type = 'ids'
        elif 'router' in all_text:
            host_type = 'router'
        elif 'switch' in all_text:
            host_type = 'switch'
        else:
            host_type = 'network_device'
    
    # Cloud/container detection
    elif any(keyword in all_text for keyword in ['cloudtrail', 'azure', 'gcp', 'aws', 'kubernetes', 'docker', 'k8s']):
        host_type = 'cloud'
        if 'container' in all_text or 'docker' in all_text or 'k8s' in all_text:
            host_type = 'container'
    
    return os_info, host_type


# ============================================================================
# HOST EXTRACTION
# ============================================================================

def extract_host(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Extract comprehensive host information with OS enrichment."""
    agent = alert.get('agent', {})
    if not isinstance(agent, dict):
        agent = {}
    manager = alert.get('manager', {})
    if not isinstance(manager, dict):
        manager = {}
    predecoder = alert.get('predecoder', {})
    if not isinstance(predecoder, dict):
        predecoder = {}
    
    # Host name priority
    host_name = (
        agent.get('name') or
        predecoder.get('hostname') or
        manager.get('name')
    )
    
    # Detect OS and type
    os_info, host_type = detect_os_and_type(alert)
    
    return {
        'id': agent.get('id'),
        'name': host_name,
        'ip': agent.get('ip'),
        'os': os_info,
        'type': host_type
    }


# ============================================================================
# ENTITY EXTRACTION
# ============================================================================

def _extract_ips_from_log(full_log: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract source and destination IPs from raw log text as a last resort."""
    if not full_log:
        return None, None

    # Pattern: "from [IP] <IP>" is almost always source IP in auth logs
    from_match = re.search(r'\bfrom\s+(?:IP\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', full_log)
    src_ip = from_match.group(1) if from_match else None

    # Pattern: "to <IP>" or "on <IP>" is often destination
    to_match = re.search(r'\b(?:to|on)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', full_log)
    dst_ip = to_match.group(1) if to_match else None

    # Fallback: collect unique IPs in order (first=src, second=dst)
    if not src_ip:
        all_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', full_log)
        # Filter out broadcast/loopback, deduplicate preserving order
        all_ips = list(dict.fromkeys(
            ip for ip in all_ips if not ip.startswith(('0.', '255.', '127.0.0.'))
        ))
        if all_ips:
            src_ip = all_ips[0]
            if len(all_ips) > 1 and not dst_ip:
                dst_ip = all_ips[1]

    return src_ip, dst_ip


def _extract_user_from_log(full_log: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract source and target users from raw log text as a last resort."""
    if not full_log:
        return None, None

    src_user = None
    dst_user = None

    # "Failed password for <user> from ..."
    m = re.search(r'(?:Failed|Accepted)\s+\w+\s+for\s+(invalid\s+user\s+)?(\S+)\s+from', full_log)
    if m:
        dst_user = m.group(2)

    # "Invalid user <user> from ..."
    if not dst_user:
        m = re.search(r'[Ii]nvalid\s+user\s+(\S+)\s+from', full_log)
        if m:
            dst_user = m.group(1)

    # "user=<user>" or "user:<user>"
    if not src_user:
        m = re.search(r'\buser[=:](\S+)', full_log, re.IGNORECASE)
        if m:
            src_user = m.group(1)

    # Validate extracted usernames against invalid list
    if src_user:
        cleaned = src_user.strip().strip('"').strip("'").strip()
        src_user = cleaned if cleaned and cleaned.lower() not in _INVALID_USERNAMES else None
    if dst_user:
        cleaned = dst_user.strip().strip('"').strip("'").strip()
        dst_user = cleaned if cleaned and cleaned.lower() not in _INVALID_USERNAMES else None

    return src_user, dst_user


def extract_entities(alert: Dict[str, Any]) -> Tuple[Dict, Dict]:
    """Extract subject (initiator) and object (target) entities."""
    data = alert.get('data', {})

    # Source/Subject — search data first with extended patterns
    src_ip = extract_ip(data,
        'src_ip', 'srcip', 'source_ip', 'client_ip', 'saddr', 'src', 'srcaddr',
        'SourceAddress', 'ClientIP',
        'IpAddress', 'SourceNetworkAddress', 'CallerIPAddress',
        'ipAddress', 'remote_ip', 'remoteAddress', 'remote_addr',
        'peer_address', 'clientip', 'attacker_ip',
        'ui', 'remip')
    src_port = extract_port(data, 'src_port', 'srcport', 'sport', 'source_port', 'SourcePort')
    src_user = extract_user(data,
        'user', 'username', 'srcuser', 'SubjectUserName', 'UserName',
        'Account', 'SourceUserName',
        'loginUser', 'login_user', 'auth_user', 'caller_user')

    # Destination/Object — extended patterns
    dst_ip = extract_ip(data,
        'dest_ip', 'dstip', 'destination_ip', 'server_ip', 'daddr', 'dst', 'dstaddr',
        'DestinationAddress', 'TargetIP',
        'DestinationNetworkAddress', 'target_ip', 'targetip', 'server_address')
    dst_port = extract_port(data, 'dest_port', 'dstport', 'dport', 'destination_port', 'DestinationPort')
    dst_user = extract_user(data,
        'dstuser', 'targetUserName', 'TargetUserName', 'DestinationUserName',
        'target_user', 'targetuser')

    # Fallback: search entire alert object (covers fields outside data, e.g. Wazuh root-level)
    if not src_ip:
        src_ip = extract_ip(alert, 'srcip', 'src_ip', 'source_ip', 'IpAddress', 'SourceNetworkAddress')
    if not dst_ip:
        dst_ip = extract_ip(alert, 'dstip', 'dest_ip', 'destination_ip', 'DestinationAddress')
    if not src_user:
        src_user = extract_user(alert, 'srcuser', 'user', 'username')
    if not dst_user:
        dst_user = extract_user(alert, 'dstuser', 'TargetUserName', 'targetUserName')

    # Last resort: parse raw log text for IPs and users
    full_log = alert.get('full_log', '')
    if not src_ip or not dst_ip:
        log_src, log_dst = _extract_ips_from_log(full_log)
        if not src_ip:
            src_ip = log_src
        if not dst_ip:
            dst_ip = log_dst
    if not src_user or not dst_user:
        log_src_user, log_dst_user = _extract_user_from_log(full_log)
        if not src_user:
            src_user = log_src_user
        if not dst_user:
            dst_user = log_dst_user

    # Wazuh 'location' fallback: for syslog/agentless sources this is the
    # device IP (e.g. the FortiGate being targeted).  extract_ip validates
    # IPv4 format, so file-path locations like "/var/log/syslog" are rejected.
    if not dst_ip:
        loc = alert.get('location', '')
        if loc and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(loc)):
            dst_ip = loc

    # Object name (file, process, service, etc.)
    obj_name = safe_get(data,
        'file', 'filepath', 'file_path', 'path', 'TargetFilename', 'ObjectName',
        'url', 'domain', 'query', 'dns_query', 'QueryName',
        'process', 'process_name', 'Image', 'ProcessName',
        'service', 'ServiceName', 'registry', 'resource'
    )
    
    # Subject
    subject = {
        'type': 'user' if src_user else ('ip' if src_ip else None),
        'id': src_user or src_ip,
        'name': src_user,
        'ip': src_ip,
        'port': src_port
    }
    
    # Object
    obj_type = None
    if obj_name:
        obj_lower = str(obj_name).lower()
        if any(ext in obj_lower for ext in ['.exe', '.dll', '.sys', '.bin', 'process']):
            obj_type = 'process'
        elif any(x in obj_lower for x in ['http', 'www', 'url']):
            obj_type = 'url'
        elif '/' in obj_lower or '\\' in obj_lower:
            obj_type = 'file'
        else:
            obj_type = 'resource'
    elif dst_ip:
        obj_type = 'ip'
    elif dst_user:
        obj_type = 'user'
    
    obj = {
        'type': obj_type,
        'id': dst_user or obj_name or dst_ip,
        'name': obj_name or dst_user,
        'ip': dst_ip,
        'port': dst_port
    }
    
    return subject, obj


# ============================================================================
# SYSMON PROCESS EXTRACTION
# ============================================================================

def _get_sysmon_eventdata(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return data.win.eventdata dict if present, else None."""
    data = alert.get('data', {})
    win = data.get('win', {})
    if not isinstance(win, dict):
        return None
    ed = win.get('eventdata', {})
    return ed if isinstance(ed, dict) else None


def _get_sysmon_event_id(alert: Dict[str, Any]) -> Optional[int]:
    """Return the numeric Sysmon EventID if this is a Sysmon alert."""
    data = alert.get('data', {})
    win = data.get('win', {})
    if not isinstance(win, dict):
        return None
    # EventID lives in data.win.system.eventID
    sys_block = win.get('system', {})
    if isinstance(sys_block, dict):
        eid = sys_block.get('eventID') or sys_block.get('EventID') or sys_block.get('eventId')
        if eid is not None:
            try:
                return int(eid)
            except (ValueError, TypeError):
                return None
    return None


def _parse_hashes(hash_str: Optional[str]) -> Dict[str, str]:
    """Parse Sysmon hash string like 'MD5=abc,SHA256=def,IMPHASH=ghi'."""
    result = {}
    if not hash_str or not isinstance(hash_str, str):
        return result
    for part in hash_str.split(','):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            result[k.strip().lower()] = v.strip()
    return result


def extract_sysmon_id1(alert: Dict[str, Any]) -> Tuple[Dict, Dict, Dict]:
    """Extract subject, object, and process details for Sysmon EventID=1.

    Returns (subject, object, process) where:
      - subject = executing user
      - object  = created process
      - process = full process detail block
    """
    ed = _get_sysmon_eventdata(alert) or {}

    user = ed.get('user') or ed.get('User')
    image = ed.get('image') or ed.get('Image')
    process_guid = ed.get('processGuid') or ed.get('ProcessGuid')
    pid = ed.get('processId') or ed.get('ProcessId')
    cmd = ed.get('commandLine') or ed.get('CommandLine')
    integrity = ed.get('integrityLevel') or ed.get('IntegrityLevel')
    hashes_str = ed.get('hashes') or ed.get('Hashes')
    parent_guid = ed.get('parentProcessGuid') or ed.get('ParentProcessGuid')
    parent_pid = ed.get('parentProcessId') or ed.get('ParentProcessId')
    parent_image = ed.get('parentImage') or ed.get('ParentImage')
    parent_cmd = ed.get('parentCommandLine') or ed.get('ParentCommandLine')

    subject = {
        'type': 'user' if user else None,
        'id': user,
        'name': user,
        'ip': None,
        'port': None,
    }

    obj = {
        'type': 'process' if (process_guid or image) else None,
        'id': process_guid or image,
        'name': image,
        'ip': None,
        'port': None,
    }

    cur_dir = ed.get('currentDirectory') or ed.get('CurrentDirectory')

    def _safe_int(v):
        if v is None:
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            return None

    process = {
        'guid': process_guid,
        'pid': _safe_int(pid),
        'image': image,
        'command_line': cmd,
        'current_directory': cur_dir,
        'integrity_level': integrity,
        'hashes': _parse_hashes(hashes_str),
        'parent': {
            'guid': parent_guid,
            'pid': _safe_int(parent_pid),
            'image': parent_image,
            'command_line': parent_cmd,
        },
    }

    return subject, obj, process


# ============================================================================
# NETWORK EXTRACTION
# ============================================================================

_PROTO_NUM_MAP = {
    '6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPv6',
    '41': 'IPv6', '47': 'GRE', '50': 'ESP', '51': 'AH',
}

_PROTO_ALLOWED = frozenset({'TCP', 'UDP', 'ICMP', 'QUIC', 'ICMPV6',
                            'IPV6', 'GRE', 'ESP', 'AH'})


_INTERNAL_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_internal_ip(ip_str: str) -> Optional[bool]:
    """Return True if ip is in INTERNAL_CIDRS or RFC1918, False if public, None if invalid."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, AttributeError):
        return None
    for net in _INTERNAL_CIDRS:
        if ip in net:
            return True
    return ip.is_private


def _classify_direction(src_ip: Optional[str], dst_ip: Optional[str]) -> str:
    """CIDR-authoritative direction for UEBA consistency.

    - src internal, dst public  -> outgoing
    - src public,   dst internal -> incoming
    - both internal             -> internal
    - else                      -> unknown
    """
    if not src_ip or not dst_ip:
        return 'unknown'
    src_int = _is_internal_ip(src_ip)
    dst_int = _is_internal_ip(dst_ip)
    if src_int is None or dst_int is None:
        return 'unknown'
    if src_int and not dst_int:
        return 'outgoing'
    if not src_int and dst_int:
        return 'incoming'
    if src_int and dst_int:
        return 'internal'
    return 'unknown'


_FW_ALLOW_ACTIONS = frozenset({'pass', 'accept', 'allow', 'permit'})
_FW_DENY_ACTIONS = frozenset({'block', 'deny', 'drop', 'reject', 'reset'})


# ---- Docker DNS resolver error parsing (journald) ----
_DOCKER_DNS_CLIENT_RE = re.compile(r'client-addr="(\w+):([^":]+):(\d+)"')
_DOCKER_DNS_SERVER_RE = re.compile(r'dns-server="(\w+):([^":]+):(\d+)"')
_DOCKER_DNS_QUESTION_RE = re.compile(r'question=";(\S+?)\s+(\w+)\s+(\w+)"')
_DOCKER_DNS_ERROR_RE = re.compile(r'error="([^"]*)"')


def _extract_docker_dns(alert: Dict[str, Any]):
    """Parse Docker DNS resolver error from journald logs.

    Returns (subject, obj, network, dns_block, outcome) or None if not
    a Docker DNS event.
    """
    decoder = alert.get('decoder', {})
    if not isinstance(decoder, dict):
        decoder = {}
    if (decoder.get('name') or '').lower() != 'docker':
        return None

    msg = alert.get('full_log') or ''
    if not msg:
        data = alert.get('data', {})
        if isinstance(data, dict):
            msg = data.get('message') or data.get('msg') or ''

    # Must contain at least one DNS-specific key-value pair
    if 'dns-server=' not in msg and 'client-addr=' not in msg:
        return None

    # Parse client (subject)
    cm = _DOCKER_DNS_CLIENT_RE.search(msg)
    src_proto = cm.group(1).upper() if cm else None
    src_ip = cm.group(2) if cm else None
    src_port = int(cm.group(3)) if cm else None

    # Parse server (object)
    sm = _DOCKER_DNS_SERVER_RE.search(msg)
    dst_ip = sm.group(2) if sm else None
    dst_port = int(sm.group(3)) if sm else None

    # Protocol from the addr prefix (udp/tcp)
    proto = src_proto or (sm.group(1).upper() if sm else 'UDP')

    # Direction via CIDR classification
    direction = _classify_direction(src_ip, dst_ip) if src_ip and dst_ip else None

    # error= present means failure
    outcome = 'failure' if _DOCKER_DNS_ERROR_RE.search(msg) else 'unknown'

    # DNS question: ";qname\tqclass\tqtype"
    dns_block = {}
    qm = _DOCKER_DNS_QUESTION_RE.search(msg)
    if qm:
        dns_block['qname'] = qm.group(1)
        dns_block['qclass'] = qm.group(2)
        dns_block['qtype'] = qm.group(3)

    subject = {
        'type': 'ip' if src_ip else None,
        'id': src_ip,
        'name': None,
        'ip': src_ip,
        'port': src_port,
    }

    obj = {
        'type': 'ip' if dst_ip else None,
        'id': dst_ip,
        'name': None,
        'ip': dst_ip,
        'port': dst_port,
    }

    network = {
        'protocol': proto,
        'direction': direction,
        'service': None,
    }

    return subject, obj, network, dns_block, outcome


def extract_network(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Extract network protocol and direction.

    Vendor-specific paths
    ---------------------
    * Sysmon Event ID 3  : data.win.eventdata.protocol / .initiated
    * FortiGate          : data.proto (numeric), data.direction
    * Generic            : data.protocol, data.transport, etc.

    Protocol is normalised to uppercase enum (TCP/UDP/ICMP/QUIC/UNKNOWN).
    Direction is normalised to lowercase (outgoing/incoming/unknown).
    """
    data = alert.get('data', {})
    proto = None
    direction = None

    # --- Sysmon Event ID 3 (nested under data.win.eventdata) ---
    win_ed = data.get('win', {})
    if isinstance(win_ed, dict):
        win_ed = win_ed.get('eventdata', {})
    else:
        win_ed = {}
    if isinstance(win_ed, dict):
        sysmon_proto = win_ed.get('protocol') or win_ed.get('Protocol')
        if sysmon_proto:
            proto = str(sysmon_proto).upper()
        initiated = win_ed.get('initiated') or win_ed.get('Initiated')
        if initiated is not None:
            direction = 'outgoing' if str(initiated).lower() == 'true' else 'incoming'

    # --- Generic / FortiGate top-level data fields ---
    if not proto:
        proto = safe_get(data, 'proto', 'protocol', 'transport',
                         'Protocol', 'IPProtocol')
        if proto:
            proto = str(proto).upper()

    # Numeric-to-name mapping (FortiGate sends "6", "17", "1", etc.)
    if proto:
        proto = _PROTO_NUM_MAP.get(proto, proto)
        # Normalise to allowed enum; anything unexpected -> keep as-is
        if proto not in _PROTO_ALLOWED:
            proto = proto  # preserve original uppercase

    # --- Direction ---
    # For non-Sysmon events, CIDR classification is authoritative.
    # raw data.direction is ignored because FortiGate's own label can
    # disagree with the actual src/dst IP classification.
    if not direction:
        src_ip = safe_get(data, 'srcip', 'src_ip', 'source_ip')
        dst_ip = safe_get(data, 'dstip', 'dest_ip', 'destination_ip')
        # Also check Sysmon nested paths
        if not src_ip and isinstance(win_ed, dict):
            src_ip = win_ed.get('sourceIp') or win_ed.get('SourceIp')
        if not dst_ip and isinstance(win_ed, dict):
            dst_ip = win_ed.get('destinationIp') or win_ed.get('DestinationIp')
        if src_ip and dst_ip:
            direction = _classify_direction(str(src_ip), str(dst_ip))
            if direction == 'unknown':
                # Last resort: use raw direction if CIDR gave nothing useful
                raw_dir = safe_get(data, 'direction', 'Direction', 'flow_direction')
                if raw_dir:
                    direction = str(raw_dir).lower()

    return {
        'protocol': proto if proto else None,
        'direction': direction if direction else None,
    }


# ============================================================================
# SECURITY EXTRACTION
# ============================================================================

def extract_security(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Extract security metadata."""
    rule = alert.get('rule', {})
    if not isinstance(rule, dict):
        rule = {}
    data = alert.get('data', {})
    
    sig_id = (
        rule.get('id') or
        deep_search(data, 'signature_id', 'SignatureId', 'EventID', 'event_id')
    )
    
    sig_name = (
        rule.get('description') or
        deep_search(data, 'signature', 'message', 'Message', 'EventName', 'alert.signature')
    )
    
    severity = rule.get('level') or deep_search(data, 'severity', 'Severity', 'Level')
    if severity is not None:
        try:
            severity = int(severity)
        except (ValueError, TypeError):
            pass
    
    # Tags from rule groups
    tags = rule.get('groups', [])
    if not isinstance(tags, list):
        tags = [tags] if tags else []
    
    # Add decoder hints
    decoder = alert.get('decoder', {})
    if not isinstance(decoder, dict):
        decoder = {}
    if decoder.get('name'):
        tags.append(f"decoder:{decoder['name']}")
    if decoder.get('parent'):
        tags.append(f"parent:{decoder['parent']}")
    
    return {
        'signature_id': sig_id,
        'signature': sig_name,
        'severity': severity,
        'tags': tags
    }


# ============================================================================
# EVENT CATEGORIZATION
# ============================================================================

def categorize_event(alert: Dict[str, Any], security: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Infer event_category, event_action, event_outcome.
    Returns (category, action, outcome)
    """
    data = alert.get('data', {})
    tags = security.get('tags', [])
    description = (security.get('signature') or '').lower()
    _decoder = alert.get('decoder', {})
    if not isinstance(_decoder, dict):
        _decoder = {}
    decoder_name = (_decoder.get('name') or '').lower()
    location = (alert.get('location') or '').lower()
    
    all_text = ' '.join([
        description,
        decoder_name,
        location,
        ' '.join(str(t).lower() for t in tags)
    ])
    
    # Category inference
    category = 'other'
    
    # Auth
    if any(kw in all_text for kw in [
        'ssh', 'pam', 'radius', 'kerberos', 'ldap', 'login', 'logon', 'auth',
        'password', 'credential', 'session', 'sudo', 'logoff', 'logout'
    ]):
        category = 'auth'
    
    # Network
    elif any(kw in all_text for kw in [
        'firewall', 'fortigate', 'utm', 'ids', 'ips', 'suricata', 'zeek',
        'netflow', 'network', 'connection', 'traffic', 'packet', 'flow',
        'iptables', 'cisco', 'juniper', 'palo alto'
    ]) or (data.get('src_ip') and data.get('dest_ip')):
        category = 'network'
    
    # Process
    elif any(kw in all_text for kw in [
        'process', 'commandline', 'cmdline', 'execve', 'sysmon', 'execution',
        'spawn', 'fork', 'exec', '4688', 'process creation'
    ]) or deep_search(data, 'process', 'Image', 'ProcessName'):
        category = 'process'
    
    # File
    elif any(kw in all_text for kw in [
        'syscheck', 'fim', 'file', 'integrity', 'registry', 'filesystem'
    ]) or deep_search(data, 'file', 'path', 'TargetFilename'):
        category = 'file'
    
    # DNS
    elif any(kw in all_text for kw in ['dns', 'query', 'domain', 'resolve']) or deep_search(data, 'dns_query', 'QueryName'):
        category = 'dns'
    
    # Web
    elif any(kw in all_text for kw in ['http', 'https', 'web', 'apache', 'nginx', 'iis', 'url']):
        category = 'web'
    
    # Malware
    elif any(kw in all_text for kw in ['malware', 'virus', 'trojan', 'ransomware', 'defender', 'antivirus']):
        category = 'malware'
    
    # Cloud
    elif any(kw in all_text for kw in ['cloudtrail', 'azure', 'gcp', 'aws', 'cloud', 'o365', 'kubernetes']):
        category = 'cloud'
    
    # Policy
    elif any(kw in all_text for kw in ['policy', 'compliance', 'audit', 'violation', 'cis']):
        category = 'policy'
    
    # System
    elif any(kw in all_text for kw in ['system', 'kernel', 'syslog', 'systemd', 'service', 'boot']):
        category = 'system'
    
    # Action inference
    action = 'event'
    
    if category == 'auth':
        if any(kw in all_text for kw in ['login', 'logon', 'sign in', 'opened']):
            action = 'login'
        elif any(kw in all_text for kw in ['logout', 'logoff', 'sign out', 'closed']):
            action = 'logout'
        elif 'session' in all_text:
            action = 'login' if 'open' in all_text else 'logout'
    
    elif category == 'network':
        if any(kw in all_text for kw in ['allow', 'accept', 'permit']):
            action = 'allow'
        elif any(kw in all_text for kw in ['deny', 'block', 'drop', 'reject']):
            action = 'deny'
        elif any(kw in all_text for kw in ['connect', 'establish', 'flow']):
            action = 'connect'
    
    elif category == 'file':
        if any(kw in all_text for kw in ['creat', 'add', 'new']):
            action = 'create'
        elif any(kw in all_text for kw in ['modif', 'change', 'edit', 'write']):
            action = 'modify'
        elif any(kw in all_text for kw in ['delet', 'remov']):
            action = 'delete'
    
    elif category == 'process':
        if any(kw in all_text for kw in ['start', 'creat', 'spawn', 'launch']):
            action = 'start'
        elif any(kw in all_text for kw in ['stop', 'kill', 'terminate']):
            action = 'stop'
    
    elif category == 'dns':
        action = 'dns_query'
    
    elif category == 'web':
        if 'request' in all_text:
            action = 'request'
        elif 'download' in all_text:
            action = 'download'
        elif 'upload' in all_text:
            action = 'upload'
    
    # Outcome inference
    outcome = 'unknown'
    
    if any(kw in all_text for kw in ['success', 'successful', 'accepted', 'allowed', 'granted', 'opened', 'permitted']):
        outcome = 'success'
    elif any(kw in all_text for kw in ['fail', 'failed', 'invalid', 'denied', 'reject', 'block', 'drop', 'refused']):
        outcome = 'failure'
    elif action in ['allow', 'permit']:
        outcome = 'allow'
    elif action in ['deny', 'block', 'drop']:
        outcome = 'deny'
    
    return category, action, outcome


# ============================================================================
# CONTEXT EXTRACTION
# ============================================================================

def infer_source(alert: Dict[str, Any]) -> str:
    """Infer source identifier."""
    decoder = alert.get('decoder', {})
    if not isinstance(decoder, dict):
        decoder = {}
    location = alert.get('location', '')
    
    parts = []
    
    if decoder.get('parent'):
        parts.append(decoder['parent'])
    elif decoder.get('name'):
        parts.append(decoder['name'])
    
    # Add hints from location
    if 'windows' in location.lower():
        if 'windows' not in ' '.join(parts).lower():
            parts.append('windows')
    elif 'linux' in location.lower() or '/var/log' in location:
        if 'linux' not in ' '.join(parts).lower():
            parts.append('linux')
    
    return '-'.join(parts).lower() if parts else 'wazuh'


def extract_message(alert: Dict[str, Any], security: Dict[str, Any]) -> str:
    """Extract best available message."""
    msg = alert.get('full_log')
    if msg:
        return str(msg).strip()
    
    if security.get('signature'):
        return security['signature']
    
    data = alert.get('data', {})
    msg = deep_search(data, 'message', 'Message', 'msg')
    return str(msg).strip() if msg else ''


# ============================================================================
# NORMALIZATION
# ============================================================================

def normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize alert to standard schema."""
    # Handle parse errors
    if alert.get('_parse_error'):
        return {
            'schema_version': '1.0',
            'event_id': str(uuid.uuid4()),
            'event_time': datetime.now(timezone.utc).isoformat(),
            'ingest_time': datetime.now(timezone.utc).isoformat(),
            'event_category': 'other',
            'event_action': 'event',
            'event_outcome': 'unknown',
            'subject': {'type': None, 'id': None, 'name': None, 'ip': None, 'port': None},
            'object': {'type': None, 'id': None, 'name': None, 'ip': None, 'port': None},
            'host': {'id': None, 'name': None, 'ip': None, 'os': {'name': None, 'version': None, 'family': None}, 'type': None},
            'network': {'protocol': None, 'direction': None},
            'security': {'signature_id': '0', 'signature': 'Parse error', 'severity': 0, 'tags': ['parse_error']},
            'context': {
                'source': 'wazuh',
                'environment': None,
                'message': alert.get('full_log', 'Unparseable fragment'),
                'raw_event': {'unparsed_fragment': alert.get('full_log', '')}
            }
        }
    
    # Extract components
    event_time = extract_event_time(alert)
    ingest_time = extract_ingest_time(alert)
    host = extract_host(alert)
    security = extract_security(alert)

    # Categorize (needed early to decide network nulling)
    category, action, outcome = categorize_event(alert, security)

    # --- Vendor fast-paths ---
    process = None
    dns_block = None

    _docker_dns = _extract_docker_dns(alert)
    if _docker_dns is not None:
        subject, obj, network, dns_block, outcome = _docker_dns
        category = 'network'
        action = 'dns_query'
    else:
        sysmon_eid = _get_sysmon_event_id(alert)
        if sysmon_eid == 1:
            subject, obj, process = extract_sysmon_id1(alert)
            category = 'process'
            action = 'start'
            outcome = 'success'
        elif sysmon_eid == 3:
            # Sysmon EventID=3: extract 5-tuple directly from eventdata
            _ed3 = _get_sysmon_eventdata(alert) or {}
            _s_ip = _ed3.get('sourceIp') or _ed3.get('SourceIp')
            _s_port = _ed3.get('sourcePort') or _ed3.get('SourcePort')
            _d_ip = _ed3.get('destinationIp') or _ed3.get('DestinationIp')
            _d_port = _ed3.get('destinationPort') or _ed3.get('DestinationPort')
            _d_host = _ed3.get('destinationHostname') or _ed3.get('DestinationHostname')
            if _d_host and str(_d_host).strip() in ('-', ''):
                _d_host = None
            try:
                _s_port = int(_s_port) if _s_port else None
            except (ValueError, TypeError):
                _s_port = None
            try:
                _d_port = int(_d_port) if _d_port else None
            except (ValueError, TypeError):
                _d_port = None

            _ed3_user = _ed3.get('user') or _ed3.get('User')
            _ed3_image = _ed3.get('image') or _ed3.get('Image')

            subject = {
                'type': 'ip' if _s_ip else None,
                'id': _s_ip,
                'name': _ed3_user,
                'ip': _s_ip,
                'port': _s_port,
            }
            obj = {
                'type': 'ip' if _d_ip else None,
                'id': _d_ip,
                'name': _d_host,
                'ip': _d_ip,
                'port': _d_port,
            }
            if _ed3_image:
                process = {'image': _ed3_image}

            category = 'network'
            action = 'connection'
        else:
            # Active response alerts: extract entities only from top-level data
            # to avoid recursing into data.parameters.alert (a nested copy of
            # the original alert that triggered the response).
            _rule_groups = alert.get('rule', {}).get('groups', [])
            if 'active_response' in _rule_groups:
                _ar_data = alert.get('data', {})
                _ar_srcip = _ar_data.get('srcip')
                _ar_dstuser = _ar_data.get('dstuser')
                _ar_cmd = _ar_data.get('command', '')
                _ar_program = _ar_data.get('parameters', {}).get('program', '')
                subject = {
                    'type': 'ip' if _ar_srcip else 'user',
                    'id': _ar_srcip,
                    'name': _ar_dstuser,
                    'ip': _ar_srcip,
                    'port': None,
                }
                obj = {
                    'type': 'process',
                    'id': _ar_program or None,
                    'name': f"{_ar_program} ({_ar_cmd})" if _ar_program else _ar_cmd,
                    'ip': None,
                    'port': None,
                }
                category = 'system'
                action = f"active_response_{_ar_cmd}" if _ar_cmd else 'active_response'
                outcome = 'success'
            else:
                subject, obj = extract_entities(alert)

    # --- FortiGate-specific fixups (auth + VPN) ---
    _fg_dec = alert.get('decoder', {})
    if not isinstance(_fg_dec, dict):
        _fg_dec = {}
    _is_fortigate = (_fg_dec.get('name') or '').lower() == 'fortigate-firewall-v5'
    _fg_data = alert.get('data', {}) if _is_fortigate else {}

    # --- FortiGate VPN fixup (IPsec DPD, tunnel-up/down, etc.) ---
    if _is_fortigate and str(_fg_data.get('subtype') or '').lower() == 'vpn':
        category = 'vpn'
        action = str(_fg_data.get('action') or 'event').lower().strip()
        _vpn_status = str(_fg_data.get('status') or '').lower().strip()
        if 'fail' in _vpn_status or 'error' in _vpn_status:
            outcome = 'failure'
        elif 'success' in _vpn_status or _vpn_status in ('up',):
            outcome = 'success'

        # Subject = remote peer, Object = local endpoint
        _rem_ip = str(_fg_data.get('remip') or '') or None
        _rem_port = _fg_data.get('remport')
        _loc_ip = str(_fg_data.get('locip') or '') or None
        _loc_port = _fg_data.get('locport')
        try:
            _rem_port = int(_rem_port) if _rem_port else None
        except (ValueError, TypeError):
            _rem_port = None
        try:
            _loc_port = int(_loc_port) if _loc_port else None
        except (ValueError, TypeError):
            _loc_port = None

        subject = {
            'type': 'ip' if _rem_ip else None,
            'id': _rem_ip,
            'name': None,
            'ip': _rem_ip,
            'port': _rem_port,
        }
        obj = {
            'type': 'ip' if _loc_ip else None,
            'id': _loc_ip,
            'name': None,
            'ip': _loc_ip,
            'port': _loc_port,
        }

        # Protocol: IKE/IPsec uses UDP 500 / 4500
        _vpn_ports = {_rem_port, _loc_port}
        _vpn_proto = 'UDP' if _vpn_ports & {500, 4500} else None
        network = {
            'protocol': _vpn_proto,
            'direction': _classify_direction(_rem_ip, _loc_ip) if _rem_ip and _loc_ip else None,
            'service': None,
        }

    # --- Auth fixup (FortiGate status + entity remapping) ---
    elif category == 'auth':
        _auth_status = str(_fg_data.get('status') or '').lower().strip() if _is_fortigate else ''
        if _auth_status == 'failed':
            outcome = 'failure'
        elif _auth_status == 'success':
            outcome = 'success'
        _auth_action = str(_fg_data.get('action') or '').lower().strip() if _is_fortigate else ''
        if _auth_action == 'login':
            action = 'login'

        # FortiGate auth: remap subject=user, object=firewall device.
        # Without this, extract_entities picks up data.dstip (often == srcip)
        # as the object, which breaks is_external_inbound classification.
        if _is_fortigate and _auth_action == 'login':
            # Subject: the account attempting login
            _user = _fg_data.get('dstuser') or _fg_data.get('user')
            _src_ip = _fg_data.get('srcip')
            if not _src_ip:
                # Parse IP from ui field: "https(185.93.89.171)" or bare IP
                _ui = str(_fg_data.get('ui') or '')
                _ui_m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', _ui)
                if _ui_m:
                    _src_ip = _ui_m.group(1)
            subject = {
                'type': 'user' if _user else ('ip' if _src_ip else None),
                'id': _user or _src_ip,
                'name': _user,
                'ip': _src_ip,
                'port': None,
            }

            # Object: the target device (firewall), NOT the user
            _devname = _fg_data.get('devname')
            _loc = str(alert.get('location') or '')
            _fw_ip = _loc if re.match(
                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', _loc
            ) else None
            obj = {
                'type': 'host',
                'id': _devname or _fw_ip,
                'name': _devname,
                'ip': _fw_ip,
                'port': None,
            }

    # Network: only populate for network-category events
    http_block = None
    if category == 'network' and _docker_dns is None:
        network = extract_network(alert)

        # --- Network event fixups (FortiGate + generic firewalls) ---
        data = alert.get('data', {})

        # 1) Action/outcome from raw data.action (authoritative for FW events)
        raw_action = str(data.get('action') or '').lower().strip()
        if raw_action in _FW_ALLOW_ACTIONS:
            action = 'allow'
            outcome = 'success'
        elif raw_action in _FW_DENY_ACTIONS:
            action = 'deny'
            outcome = 'failure'

        # 2) Object must be type="ip" for network events.
        #    FortiGate has data.service/data.app/data.hostname that the
        #    generic extractor may pick up and misclassify as file/url.
        dst_ip = obj.get('ip')
        dst_port = obj.get('port')
        hostname = data.get('hostname') or data.get('dstname')
        obj_name = None
        if hostname and isinstance(hostname, str):
            obj_name = hostname
        elif obj.get('type') == 'ip' and obj.get('name'):
            # Preserve name already set by vendor fast-paths
            # (e.g. Sysmon EventID=3 destinationHostname).
            # Only when type is already 'ip' — avoids keeping bad names
            # from extract_entities (e.g. data.service='HTTPS' → type='url').
            obj_name = obj['name']

        # Service name (HTTPS, DNS, etc.) goes into network.service,
        # NOT object.name — otherwise IP objects get "HTTPS" as name.
        _svc = data.get('service') or data.get('app')
        if _svc and isinstance(_svc, str):
            network['service'] = _svc

        if dst_ip:
            obj = {
                'type': 'ip',
                'id': dst_ip,
                'name': obj_name,
                'ip': dst_ip,
                'port': dst_port,
            }
        elif obj.get('type') in ('file', 'url'):
            # No dst_ip but object was wrongly typed — reset to resource
            obj['type'] = 'resource'

        # 3) HTTP subobject for FortiGate HTTP/HTTPS events
        http_method = data.get('httpmethod') or data.get('HTTPMethod')
        http_url = data.get('url') or data.get('URL')
        http_agent = data.get('agent')
        # agent can be a dict (Wazuh agent block) — only use if string
        if not isinstance(http_agent, str):
            http_agent = None
        http_referrer = data.get('referralurl') or data.get('Referer')
        if http_method or http_url or http_agent or http_referrer:
            http_block = {}
            if http_method:
                http_block['method'] = str(http_method).upper()
            if http_url:
                http_block['url'] = str(http_url)
            if http_agent:
                http_block['user_agent'] = str(http_agent)
            if http_referrer:
                http_block['referrer'] = str(http_referrer)
    elif _docker_dns is None and category != 'vpn':
        network = {'protocol': None, 'direction': None, 'service': None}

    # Context
    source = infer_source(alert)
    message = extract_message(alert, security)

    # Event ID
    event_id = alert.get('id') or alert.get('event_id') or str(uuid.uuid4())

    result = {
        'schema_version': '1.0',
        'event_id': event_id,
        'event_time': event_time.isoformat(),
        'ingest_time': ingest_time.isoformat(),
        'event_category': category,
        'event_action': action,
        'event_outcome': outcome,
        'subject': subject,
        'object': obj,
        'host': host,
        'network': network,
        'security': security,
        'context': {
            'source': source,
            'environment': None,
            'message': message,
            'raw_event': alert
        }
    }

    # Fixed schema — always include all optional blocks with null defaults
    result['process'] = process
    result['http'] = http_block
    result['dns'] = dns_block

    return result


# ============================================================================
# FILE FOLLOWING
# ============================================================================

class FileTailer:
    """Follow file with rotation support."""
    
    def __init__(self, filepath: str, poll_interval: float):
        self.filepath = filepath
        self.poll_interval = poll_interval
        self.file = None
        self.inode = None
        self.position = 0
        self.parser = IncrementalJSONParser()
    
    def open(self):
        """Open or reopen file."""
        try:
            if self.file:
                self.file.close()
            
            self.file = open(self.filepath, 'r', encoding='utf-8', errors='replace')
            stat = os.stat(self.filepath)
            self.inode = stat.st_ino
            self.position = 0
        except FileNotFoundError:
            self.file = None
            self.inode = None
    
    def check_rotation(self) -> bool:
        """Check if file rotated."""
        try:
            stat = os.stat(self.filepath)
            if stat.st_ino != self.inode or stat.st_size < self.position:
                return True
        except FileNotFoundError:
            return True
        return False
    
    def read_chunk(self, size: int = 65536) -> List[Dict[str, Any]]:
        """Read chunk and parse objects."""
        if not self.file:
            self.open()
            if not self.file:
                time.sleep(self.poll_interval)
                return []
        
        if self.check_rotation():
            self.parser = IncrementalJSONParser()  # Reset parser
            self.open()
            if not self.file:
                time.sleep(self.poll_interval)
                return []
        
        # Re-seek to current position before reading — forces SSHFS/NFS
        # to re-check the remote file size instead of returning cached EOF.
        self.file.seek(self.position)
        chunk = self.file.read(size)
        if chunk:
            self.position = self.file.tell()
            return self.parser.feed(chunk)
        else:
            time.sleep(self.poll_interval)
            return []
    
    def close(self):
        """Close file."""
        if self.file:
            self.file.close()


# ============================================================================
# STATE PERSISTENCE
# ============================================================================

def load_state(state_file: str) -> Tuple[Optional[int], Optional[int]]:
    """Load last position and inode."""
    if not os.path.exists(state_file):
        return None, None
    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
            return state.get('position'), state.get('inode')
    except Exception:
        return None, None


def save_state(state_file: str, position: int, inode: int):
    """Save position and inode."""
    try:
        with open(state_file, 'w') as f:
            json.dump({'position': position, 'inode': inode}, f)
    except Exception as e:
        print(f"Warning: Could not save state: {e}", file=sys.stderr)


# ============================================================================
# MAIN PIPELINE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Wazuh Log Normalization Pipeline')
    parser.add_argument('--input', default='/var/ossec/logs/alerts/alerts.json')
    parser.add_argument('--output', default='./normalized.jsonl')
    parser.add_argument('--window-minutes', type=int, default=5)
    parser.add_argument('--poll-interval', type=float, default=0.5)
    parser.add_argument('--state-file', default='./wazuh_normalizer.state')
    parser.add_argument('--follow', action='store_true',
                        help='Continuously follow input file for new data')
    parser.add_argument('--skip-existing', action='store_true',
                        help='Skip to end of file and only process new alerts (useful for SSHFS/remote)')
    # Kafka mode
    parser.add_argument('--kafka-brokers', default=None,
                        help='Kafka broker(s) — enables Kafka output mode')
    parser.add_argument('--output-topic', default='normalized',
                        help='Kafka output topic (default: normalized)')

    args = parser.parse_args()
    
    print(f"Wazuh Normalization Pipeline")
    print(f"  Input: {args.input}")
    print(f"  Output: {args.output}")
    print(f"  Window: {args.window_minutes} minutes")
    
    # Time window
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=args.window_minutes)
    print(f"  Processing from: {window_start.isoformat()}")
    
    # Kafka producer (if enabled)
    kafka_producer = None
    kafka_topic = None
    if args.kafka_brokers:
        from kafka_helpers import create_producer, produce_json
        kafka_producer = create_producer(args.kafka_brokers)
        kafka_topic = args.output_topic
        print(f"  Kafka output: {args.kafka_brokers} / {kafka_topic}")

    # Wait for input
    while not os.path.exists(args.input):
        print(f"Waiting for {args.input}...", file=sys.stderr)
        time.sleep(5)

    # Open output file (skip if Kafka-only)
    output_file = None
    if not kafka_producer:
        output_file = open(args.output, 'a', encoding='utf-8')

    print("Scanning existing alerts...")
    processed = 0
    follow_count = 0
    tailer = FileTailer(args.input, args.poll_interval)

    try:
        # Phase 1: Scan existing
        tailer.open()

        # --skip-existing: jump to end, only process new alerts
        if args.skip_existing and tailer.file:
            tailer.file.seek(0, 2)  # seek to EOF
            tailer.position = tailer.file.tell()
            print(f"  Skipped to end of file (position {tailer.position})")
            # Save state so future restarts resume from here
            if tailer.inode:
                save_state(args.state_file, tailer.position, tailer.inode)
        else:
            # Resume from saved state if available
            saved_pos, saved_inode = load_state(args.state_file)
            if saved_pos is not None and saved_inode is not None and tailer.file:
                current_inode = tailer.inode
                if current_inode == saved_inode:
                    file_size = os.fstat(tailer.file.fileno()).st_size
                    seek_to = min(saved_pos, file_size)
                    tailer.file.seek(seek_to)
                    tailer.position = seek_to
                    print(f"  Resumed from saved position {seek_to}")

        if tailer.file:
            while True:
                alerts = tailer.read_chunk()
                if not alerts:
                    # Check if we've reached EOF
                    current_pos = tailer.file.tell()
                    tailer.file.seek(0, 2)  # Seek to end
                    end_pos = tailer.file.tell()
                    tailer.file.seek(current_pos)  # Seek back
                    
                    if current_pos >= end_pos:
                        break  # EOF reached
                
                for alert in alerts:
                    event_time = extract_event_time(alert)
                    if event_time >= window_start:
                        normalized = normalize_alert(alert)
                        if kafka_producer:
                            src_ip = (normalized.get("subject") or {}).get("ip")
                            produce_json(kafka_producer, kafka_topic, normalized, key=src_ip)
                            if processed % 100 == 0:
                                kafka_producer.poll(0)
                        else:
                            output_file.write(json.dumps(normalized, separators=(',', ':'), ensure_ascii=False) + '\n')
                            output_file.flush()
                        processed += 1
                        if processed % 100 == 0:
                            print(f"  Processed {processed}...")

        if kafka_producer:
            kafka_producer.flush(timeout=10)
        print(f"Scan complete: {processed} events")

        # Phase 2: Follow mode (only with --follow)
        follow_count = 0
        save_counter = 0

        if args.follow:
            print("Following new alerts...")

            while True:
                alerts = tailer.read_chunk()
                for alert in alerts:
                    event_time = extract_event_time(alert)
                    if event_time >= window_start:
                        normalized = normalize_alert(alert)
                        if kafka_producer:
                            src_ip = (normalized.get("subject") or {}).get("ip")
                            produce_json(kafka_producer, kafka_topic, normalized, key=src_ip)
                            if follow_count % 100 == 0:
                                kafka_producer.poll(0)
                        else:
                            output_file.write(json.dumps(normalized, separators=(',', ':'), ensure_ascii=False) + '\n')
                            output_file.flush()
                        follow_count += 1
                        save_counter += 1

                        if save_counter >= 10:
                            save_state(args.state_file, tailer.position, tailer.inode)
                            save_counter = 0
        else:
            print("Batch mode complete (use --follow for continuous mode)")

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        if tailer.inode:
            save_state(args.state_file, tailer.position, tailer.inode)
        tailer.close()
        if kafka_producer:
            kafka_producer.flush(timeout=10)
        if output_file:
            output_file.close()
        print(f"Total: {processed + follow_count} events")


def _run_self_tests():
    """Inline unit tests — run with: python3 normalizer.py --test"""
    passed = 0
    failed = 0

    def _assert(cond, label, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS  {label}")
        else:
            failed += 1
            print(f"  FAIL  {label}  {detail}")

    def _sysmon_alert(eid, eventdata):
        return {
            'id': 'test-1',
            'timestamp': '2026-02-24T10:00:00+0530',
            'rule': {'id': '61603', 'description': 'Sysmon - Event 1', 'level': 5,
                     'groups': ['sysmon', 'sysmon_event1']},
            'decoder': {'name': 'windows_eventchannel', 'parent': 'windows'},
            'location': 'EventChannel',
            'data': {'win': {'system': {'eventID': str(eid)}, 'eventdata': eventdata}},
        }

    def _fg_alert(srcip, dstip, action, proto='6', dstport='443', **extra):
        d = {'proto': proto, 'srcip': srcip, 'dstip': dstip,
             'dstport': dstport, 'action': action}
        d.update(extra)
        return {
            'id': 'test-fg',
            'timestamp': '2026-02-24T10:00:00+0530',
            'rule': {'id': '81602', 'description': 'Fortigate: Traffic.',
                     'level': 3, 'groups': ['fortigate', 'firewall']},
            'decoder': {'name': 'fortigate-firewall-v5',
                        'parent': 'fortigate-firewall-v5'},
            'location': '192.168.1.1',
            'data': d,
        }

    # --- Test 1: Sysmon EventID=1 subject/object ---
    n = normalize_alert(_sysmon_alert(1, {
        'user': 'DESKTOP\\john.doe',
        'processGuid': '{GUID-1234}',
        'processId': '4568',
        'image': 'C:\\Windows\\cmd.exe',
        'commandLine': 'cmd /c whoami',
        'currentDirectory': 'C:\\Users\\john',
        'integrityLevel': 'High',
        'hashes': 'MD5=aaa,SHA256=bbb,IMPHASH=ccc',
        'parentProcessGuid': '{GUID-0000}',
        'parentProcessId': '1234',
        'parentImage': 'C:\\Windows\\explorer.exe',
        'parentCommandLine': 'explorer.exe',
    }))
    _assert(n['subject']['type'] == 'user', 'T1 subject.type=user')
    _assert(n['subject']['id'] == 'DESKTOP\\john.doe', 'T1 subject.id',
            f"got {n['subject']['id']}")
    _assert(n['object']['type'] == 'process', 'T1 object.type=process')
    _assert(n['object']['id'] == '{GUID-1234}', 'T1 object.id=processGuid')
    _assert(n['object']['name'] == 'C:\\Windows\\cmd.exe', 'T1 object.name=image')
    _assert(n['event_action'] == 'start', 'T1 action=start',
            f"got {n['event_action']}")
    _assert(n['event_outcome'] == 'success', 'T1 outcome=success',
            f"got {n['event_outcome']}")
    p = n.get('process', {})
    _assert(p.get('guid') == '{GUID-1234}', 'T1 process.guid')
    _assert(p.get('pid') == 4568, 'T1 process.pid=int', f"got {p.get('pid')}")
    _assert(p.get('current_directory') == 'C:\\Users\\john', 'T1 process.current_directory')
    _assert(p.get('parent', {}).get('pid') == 1234, 'T1 process.parent.pid=int')
    _assert(p.get('parent', {}).get('image') == 'C:\\Windows\\explorer.exe',
            'T1 process.parent.image')

    # --- Test 2: Sysmon EventID=1 hash parsing ---
    h = p.get('hashes', {})
    _assert(h.get('md5') == 'aaa', 'T2 hashes.md5')
    _assert(h.get('sha256') == 'bbb', 'T2 hashes.sha256')
    _assert(h.get('imphash') == 'ccc', 'T2 hashes.imphash')

    # --- Test 3: Sysmon EventID=1 network fields are null ---
    _assert(n['network']['protocol'] is None, 'T3 network.protocol=null',
            f"got {n['network']['protocol']}")
    _assert(n['network']['direction'] is None, 'T3 network.direction=null',
            f"got {n['network']['direction']}")

    # --- Test 4: Fortigate internal traffic ---
    n = normalize_alert(_fg_alert('192.168.1.10', '10.0.0.5', 'pass'))
    _assert(n['network']['direction'] == 'internal', 'T4 direction=internal',
            f"got {n['network']['direction']}")

    # --- Test 5: Fortigate outbound traffic ---
    n = normalize_alert(_fg_alert('192.168.1.119', '72.145.35.104', 'pass'))
    _assert(n['network']['direction'] == 'outgoing', 'T5 direction=outgoing',
            f"got {n['network']['direction']}")

    # --- Test 6: Fortigate allow/pass action/outcome ---
    _assert(n['event_action'] == 'allow', 'T6 action=allow',
            f"got {n['event_action']}")
    _assert(n['event_outcome'] == 'success', 'T6 outcome=success',
            f"got {n['event_outcome']}")

    # --- Bonus: deny ---
    n = normalize_alert(_fg_alert('192.168.1.119', '72.145.35.104', 'block'))
    _assert(n['event_action'] == 'deny', 'T6b action=deny',
            f"got {n['event_action']}")
    _assert(n['event_outcome'] == 'failure', 'T6b outcome=failure',
            f"got {n['event_outcome']}")

    # --- Bonus: object.type=ip for network ---
    _assert(n['object']['type'] == 'ip', 'T6c object.type=ip',
            f"got {n['object']['type']}")

    # --- Test 7: FortiGate auth failure — full entity remapping ---
    fg_auth = {
        'id': 'test-auth',
        'timestamp': '2026-02-24T10:00:00+0530',
        'rule': {'id': '81640', 'description': 'Fortigate: Admin login failed.',
                 'level': 5, 'groups': ['fortigate', 'authentication_failed']},
        'decoder': {'name': 'fortigate-firewall-v5',
                    'parent': 'fortigate-firewall-v5'},
        'location': '192.168.1.10',
        'data': {'action': 'login', 'status': 'failed', 'subtype': 'system',
                 'user': 'Praveen_N', 'srcip': '185.93.89.171',
                 'dstip': '185.93.89.171',
                 'ui': 'https(185.93.89.171)', 'devname': 'VGIL_DC',
                 'msg': 'Administrator Praveen_N login failed from https(185.93.89.171)'},
    }
    n = normalize_alert(fg_auth)
    _assert(n['event_category'] == 'auth', 'T7 category=auth',
            f"got {n['event_category']}")
    _assert(n['event_action'] == 'login', 'T7 action=login',
            f"got {n['event_action']}")
    _assert(n['event_outcome'] == 'failure', 'T7 outcome=failure',
            f"got {n['event_outcome']}")
    # Subject = user with attacker IP
    _assert(n['subject']['type'] == 'user', 'T7 subject.type=user',
            f"got {n['subject']['type']}")
    _assert(n['subject']['id'] == 'Praveen_N', 'T7 subject.id=Praveen_N',
            f"got {n['subject']['id']}")
    _assert(n['subject']['name'] == 'Praveen_N', 'T7 subject.name=Praveen_N',
            f"got {n['subject']['name']}")
    _assert(n['subject']['ip'] == '185.93.89.171', 'T7 subject.ip=attacker',
            f"got {n['subject']['ip']}")
    # Object = firewall device, NOT the user
    _assert(n['object']['type'] == 'host', 'T7 object.type=host',
            f"got {n['object']['type']}")
    _assert(n['object']['name'] == 'VGIL_DC', 'T7 object.name=devname',
            f"got {n['object']['name']}")
    _assert(n['object']['ip'] == '192.168.1.10', 'T7 object.ip=fw_location',
            f"got {n['object']['ip']}")
    _assert(n['object']['id'] != 'Praveen_N', 'T7 object.id!=username',
            f"got {n['object']['id']}")

    # --- Test 7b: FortiGate auth — srcip absent, fall back to ui field ---
    fg_auth_ui = {
        'id': 'test-auth-ui',
        'timestamp': '2026-02-24T10:00:00+0530',
        'rule': {'id': '81640', 'description': 'Fortigate: Admin login failed.',
                 'level': 5, 'groups': ['fortigate', 'authentication_failed']},
        'decoder': {'name': 'fortigate-firewall-v5',
                    'parent': 'fortigate-firewall-v5'},
        'location': '192.168.1.10',
        'data': {'action': 'login', 'status': 'failed',
                 'user': 'admin', 'ui': 'https(10.0.0.50)',
                 'devname': 'FW01'},
    }
    n = normalize_alert(fg_auth_ui)
    _assert(n['subject']['ip'] == '10.0.0.50', 'T7b subject.ip from ui',
            f"got {n['subject']['ip']}")
    _assert(n['object']['ip'] == '192.168.1.10', 'T7b object.ip=location',
            f"got {n['object']['ip']}")

    # --- Test 8: Docker DNS timeout — full field extraction ---
    docker_dns_alert = {
        'id': 'test-dns',
        'timestamp': '2026-02-24T10:00:00+0530',
        'rule': {'id': '100100', 'description': 'Docker: DNS resolver error.',
                 'level': 4, 'groups': ['docker']},
        'decoder': {'name': 'docker', 'parent': 'journald'},
        'location': 'journald',
        'full_log': (
            'level=error msg="query failed" '
            'client-addr="udp:172.19.0.2:55779" '
            'dns-server="udp:8.8.8.8:53" '
            'error="read udp 172.19.0.2:55779->8.8.8.8:53: i/o timeout" '
            'question=";tenzir-node.\tIN\tA"'
        ),
    }
    n = normalize_alert(docker_dns_alert)
    _assert(n['event_category'] == 'network', 'T8 category=network',
            f"got {n['event_category']}")
    _assert(n['event_action'] == 'dns_query', 'T8 action=dns_query',
            f"got {n['event_action']}")
    _assert(n['event_outcome'] == 'failure', 'T8 outcome=failure',
            f"got {n['event_outcome']}")
    _assert(n['subject']['ip'] == '172.19.0.2', 'T8 subject.ip',
            f"got {n['subject']['ip']}")
    _assert(n['subject']['port'] == 55779, 'T8 subject.port',
            f"got {n['subject']['port']}")
    _assert(n['object']['ip'] == '8.8.8.8', 'T8 object.ip',
            f"got {n['object']['ip']}")
    _assert(n['object']['port'] == 53, 'T8 object.port',
            f"got {n['object']['port']}")
    _assert(n['network']['protocol'] == 'UDP', 'T8 protocol=UDP',
            f"got {n['network']['protocol']}")
    _assert(n['network']['direction'] == 'outgoing', 'T8 direction=outgoing',
            f"got {n['network']['direction']}")
    dns = n.get('dns', {})
    _assert(dns.get('qname') == 'tenzir-node.', 'T8 dns.qname',
            f"got {dns.get('qname')}")
    _assert(dns.get('qtype') == 'A', 'T8 dns.qtype',
            f"got {dns.get('qtype')}")
    _assert(dns.get('qclass') == 'IN', 'T8 dns.qclass',
            f"got {dns.get('qclass')}")
    # raw_event preserved
    _assert(n['context']['raw_event'] is docker_dns_alert, 'T8 raw_event preserved')

    # --- Test 9: FortiGate IPsec DPD — VPN entity remapping ---
    vpn_dpd = {
        'id': 'test-vpn',
        'timestamp': '2026-02-24T10:00:00+0530',
        'rule': {'id': '81600', 'description': 'FortiGate: IPsec DPD failed.',
                 'level': 5, 'groups': ['fortigate', 'firewall']},
        'decoder': {'name': 'fortigate-firewall-v5',
                    'parent': 'fortigate-firewall-v5'},
        'location': '192.168.1.1',
        'data': {'logid': '0101037136', 'subtype': 'vpn', 'action': 'dpd',
                 'status': 'dpd_failure',
                 'remip': '125.20.129.238', 'remport': '500',
                 'locip': '182.19.89.41', 'locport': '500',
                 'user': '125.20.129.238'},
    }
    n = normalize_alert(vpn_dpd)
    _assert(n['event_category'] == 'vpn', 'T9 category=vpn',
            f"got {n['event_category']}")
    _assert(n['event_action'] == 'dpd', 'T9 action=dpd',
            f"got {n['event_action']}")
    _assert(n['event_outcome'] == 'failure', 'T9 outcome=failure',
            f"got {n['event_outcome']}")
    _assert(n['subject']['type'] == 'ip', 'T9 subject.type=ip',
            f"got {n['subject']['type']}")
    _assert(n['subject']['ip'] == '125.20.129.238', 'T9 subject.ip=remip',
            f"got {n['subject']['ip']}")
    _assert(n['subject']['port'] == 500, 'T9 subject.port=500',
            f"got {n['subject']['port']}")
    _assert(n['subject']['name'] is None, 'T9 subject.name=null (not user=IP)',
            f"got {n['subject']['name']}")
    _assert(n['object']['type'] == 'ip', 'T9 object.type=ip',
            f"got {n['object']['type']}")
    _assert(n['object']['ip'] == '182.19.89.41', 'T9 object.ip=locip',
            f"got {n['object']['ip']}")
    _assert(n['object']['port'] == 500, 'T9 object.port=500',
            f"got {n['object']['port']}")
    _assert(n['network']['protocol'] == 'UDP', 'T9 protocol=UDP',
            f"got {n['network']['protocol']}")

    # --- Test 10: Sysmon EventID=3 — 5-tuple + process ---
    sysmon3 = _sysmon_alert(3, {
        'sourceIp': '10.200.11.59', 'sourcePort': '50923',
        'destinationIp': '172.217.194.132', 'destinationPort': '443',
        'protocol': 'udp', 'initiated': 'true',
        'user': 'LAPTOP-08MIT8SI\\Asus',
        'image': 'C:\\Program Files\\Opera\\opera.exe',
        'destinationHostname': 'lh3.googleusercontent.com',
    })
    # Override rule for Sysmon EventID=3
    sysmon3['rule'] = {'id': '61650', 'description': 'Sysmon - Event 3',
                       'level': 3, 'groups': ['sysmon', 'sysmon_event3']}
    n = normalize_alert(sysmon3)
    _assert(n['event_category'] == 'network', 'T10 category=network',
            f"got {n['event_category']}")
    _assert(n['subject']['type'] == 'ip', 'T10 subject.type=ip',
            f"got {n['subject']['type']}")
    _assert(n['subject']['ip'] == '10.200.11.59', 'T10 subject.ip',
            f"got {n['subject']['ip']}")
    _assert(n['subject']['port'] == 50923, 'T10 subject.port',
            f"got {n['subject']['port']}")
    _assert(n['subject']['name'] == 'LAPTOP-08MIT8SI\\Asus', 'T10 subject.name=user',
            f"got {n['subject']['name']}")
    _assert(n['object']['type'] == 'ip', 'T10 object.type=ip',
            f"got {n['object']['type']}")
    _assert(n['object']['ip'] == '172.217.194.132', 'T10 object.ip',
            f"got {n['object']['ip']}")
    _assert(n['object']['port'] == 443, 'T10 object.port',
            f"got {n['object']['port']}")
    _assert(n['object']['name'] == 'lh3.googleusercontent.com',
            'T10 object.name=destHostname',
            f"got {n['object']['name']}")
    _assert(n['network']['protocol'] == 'UDP', 'T10 protocol=UDP',
            f"got {n['network']['protocol']}")
    _assert(n['network']['direction'] == 'outgoing', 'T10 direction=outgoing',
            f"got {n['network']['direction']}")
    _assert(n.get('process', {}).get('image') == 'C:\\Program Files\\Opera\\opera.exe',
            'T10 process.image',
            f"got {n.get('process', {}).get('image')}")

    # --- Test 10b: FortiGate service not in object.name ---
    n = normalize_alert(_fg_alert('192.168.1.10', '72.145.35.104', 'pass',
                                  service='HTTPS'))
    _assert(n['object']['name'] is None, 'T10b object.name!=HTTPS',
            f"got {n['object']['name']}")
    _assert(n['network'].get('service') == 'HTTPS', 'T10b network.service=HTTPS',
            f"got {n['network'].get('service')}")

    print(f"\n  {passed} passed, {failed} failed")
    return failed == 0


if __name__ == '__main__':
    if '--test' in sys.argv:
        ok = _run_self_tests()
        sys.exit(0 if ok else 1)
    main()