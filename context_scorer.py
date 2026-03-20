#!/usr/bin/env python3
"""
Context and Scoring Layer (L4)
Enriches correlation incidents with business context and calculates final priority scores.

Features:
- Asset criticality mapping
- User role/privilege context
- Business impact assessment
- Incident priority scoring
- SLA assignment

Usage:
    python3 context_scorer.py --input incidents.jsonl --output scored_incidents.jsonl --config context_config.yaml
"""

import argparse
import json
import sys
import yaml
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AssetContext:
    """Asset and entity context database."""
    
    def __init__(self, config: Dict[str, Any]):
        self.assets = config.get("assets", {})
        self.users = config.get("users", {})
        self.ip_ranges = config.get("ip_ranges", {})
        self.default_asset_criticality = config.get("defaults", {}).get("asset_criticality", "medium")
        self.default_user_privilege = config.get("defaults", {}).get("user_privilege", "standard")
    
    def get_asset_criticality(self, asset_id: str, asset_ip: str = None) -> Dict[str, Any]:
        """Get asset criticality and context."""
        # Check by asset ID
        if asset_id and asset_id in self.assets:
            return self.assets[asset_id]
        
        # Check by IP range
        if asset_ip:
            for ip_range, context in self.ip_ranges.items():
                if self._ip_in_range(asset_ip, ip_range):
                    return context
        
        # Default
        return {
            "criticality": self.default_asset_criticality,
            "business_unit": "unknown",
            "data_classification": "unknown"
        }
    
    def get_user_context(self, username: str) -> Dict[str, Any]:
        """Get user privilege and context."""
        if username and username in self.users:
            return self.users[username]
        
        # Default
        return {
            "privilege_level": self.default_user_privilege,
            "department": "unknown",
            "is_privileged": False
        }
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in range (simple prefix match for now)."""
        # Simple implementation - just check if IP starts with range
        # For production, use ipaddress.ip_network
        if not ip or not ip_range:
            return False
        
        return ip.startswith(ip_range.replace("/24", "").replace("/16", "").rsplit(".", 1)[0])


class BusinessImpactCalculator:
    """Calculate business impact of incidents."""

    # Named constants for impact modifiers
    PRIVILEGED_USER_BONUS = 20
    SENSITIVE_DATA_BONUS = 15
    CRITICAL_BUSINESS_UNIT_BONUS = 10
    MULTI_TACTIC_BONUS = 10
    MULTI_TACTIC_THRESHOLD = 2
    MAX_IMPACT_SCORE = 100
    SENSITIVE_DATA_CLASSES = frozenset({"confidential", "restricted"})
    CRITICAL_BUSINESS_UNITS = frozenset({"finance", "hr", "executive"})
    IMPACT_THRESHOLDS = [(80, "critical"), (60, "high"), (40, "medium")]  # else "low"
    CRITICALITY_MULTIPLIERS = {"critical": 1.3, "high": 1.1, "medium": 1.0, "low": 0.8}

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.impact_matrix = config.get("impact_matrix", {})
    
    def calculate_impact(
        self,
        incident: Dict[str, Any],
        asset_context: Dict[str, Any],
        user_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate business impact score."""
        
        rule = incident.get("rule", {})
        rule_category = rule.get("category", "other")
        rule_severity = rule.get("severity", "medium")
        
        # Base impact from rule category and asset criticality
        base_impact = self._get_base_impact(rule_category, asset_context.get("criticality", "medium"))
        
        # Modifiers
        modifiers = []
        
        # Privileged user involved
        if user_context.get("is_privileged"):
            base_impact += self.PRIVILEGED_USER_BONUS
            modifiers.append("privileged_user")

        # High-value data
        if asset_context.get("data_classification") in self.SENSITIVE_DATA_CLASSES:
            base_impact += self.SENSITIVE_DATA_BONUS
            modifiers.append("sensitive_data")

        # Critical business unit
        if asset_context.get("business_unit") in self.CRITICAL_BUSINESS_UNITS:
            base_impact += self.CRITICAL_BUSINESS_UNIT_BONUS
            modifiers.append("critical_business_unit")

        # Multiple MITRE tactics (complex attack)
        mitre_tactics = rule.get("mitre_tactics", [])
        if len(mitre_tactics) > self.MULTI_TACTIC_THRESHOLD:
            base_impact += self.MULTI_TACTIC_BONUS
            modifiers.append("multi_tactic_attack")

        impact_score = min(self.MAX_IMPACT_SCORE, base_impact)
        
        return {
            "impact_score": impact_score,
            "impact_level": self._get_impact_level(impact_score),
            "modifiers": modifiers,
            "affected_assets": {
                "criticality": asset_context.get("criticality"),
                "business_unit": asset_context.get("business_unit"),
                "data_classification": asset_context.get("data_classification")
            },
            "affected_users": {
                "privilege_level": user_context.get("privilege_level"),
                "is_privileged": user_context.get("is_privileged", False)
            }
        }
    
    # Fallback scores when config doesn't define a category
    _DEFAULT_CATEGORY_SCORES = {
        "threat_intelligence": 70,
        "authentication": 60,
        "reconnaissance": 40,
        "lateral_movement": 80,
        "data_exfiltration": 90,
        "account_compromise": 85,
        "high_risk": 75,
        "anomaly": 30,
        "policy_violation": 20,
        "compliance": 25,
    }

    def _get_base_impact(self, category: str, criticality: str) -> int:
        """Get base impact from config matrix, with hardcoded fallback."""
        # Prefer config impact_matrix if the category is defined there
        matrix_entry = self.impact_matrix.get(category)
        if matrix_entry and criticality in matrix_entry:
            return min(int(matrix_entry[criticality]), self.MAX_IMPACT_SCORE)

        # Fallback to base * criticality multiplier
        base = self._DEFAULT_CATEGORY_SCORES.get(category, 50)
        multiplier = self.CRITICALITY_MULTIPLIERS.get(criticality, 1.0)
        return min(int(base * multiplier), self.MAX_IMPACT_SCORE)

    def _get_impact_level(self, score: int) -> str:
        """Convert impact score to level."""
        for threshold, level in self.IMPACT_THRESHOLDS:
            if score >= threshold:
                return level
        return "low"


class PriorityScorer:
    """Calculate incident priority scores."""

    # Named constants for scoring weights and thresholds
    SEVERITY_WEIGHT = 0.4
    IMPACT_WEIGHT = 0.6
    SEVERITY_SCORES = {"critical": 90, "high": 70, "medium": 50, "low": 30}
    PRIORITY_THRESHOLDS = [(80, "P1"), (60, "P2"), (40, "P3")]  # else P4

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        # Load SLA from config (sla_definitions in context_config.yaml)
        self._sla_map = self._load_sla(config)
    
    def calculate_priority(
        self,
        incident: Dict[str, Any],
        impact_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate incident priority score and SLA."""
        
        rule = incident.get("rule", {})
        rule_severity = rule.get("severity", "medium")
        
        # Get scores
        rule_severity_score = self._severity_to_score(rule_severity)
        impact_score = impact_analysis.get("impact_score", 50)
        
        # Calculate final priority (weighted average)
        priority_score = int(
            rule_severity_score * self.SEVERITY_WEIGHT +
            impact_score * self.IMPACT_WEIGHT
        )
        
        priority_level = self._get_priority_level(priority_score)
        sla = self._get_sla(priority_level)
        
        return {
            "priority_score": priority_score,
            "priority_level": priority_level,
            "sla": sla,
            "components": {
                "rule_severity": rule_severity,
                "rule_severity_score": rule_severity_score,
                "impact_score": impact_score
            }
        }
    
    def _severity_to_score(self, severity: str) -> int:
        """Convert severity to numeric score."""
        return self.SEVERITY_SCORES.get(severity, self.SEVERITY_SCORES.get("medium", 50))

    def _get_priority_level(self, score: int) -> str:
        """Convert priority score to level."""
        for threshold, level in self.PRIORITY_THRESHOLDS:
            if score >= threshold:
                return level
        return "P4"

    @staticmethod
    def _load_sla(config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Load SLA definitions from config, with sensible fallback."""
        sla_defs = config.get("sla_definitions", {})
        fallback = {
            "P1": {"response_time_minutes": 15, "resolution_time_hours": 4,
                    "description": "Critical - Immediate response required"},
            "P2": {"response_time_minutes": 60, "resolution_time_hours": 24,
                    "description": "High - Response within 1 hour"},
            "P3": {"response_time_minutes": 240, "resolution_time_hours": 72,
                    "description": "Medium - Response within 4 hours"},
            "P4": {"response_time_minutes": 1440, "resolution_time_hours": 168,
                    "description": "Low - Response within 1 business day"},
        }
        if not sla_defs:
            return fallback
        # Map config keys (response_minutes -> response_time_minutes, etc.)
        result = {}
        for level in ("P1", "P2", "P3", "P4"):
            cfg = sla_defs.get(level, {})
            if cfg:
                result[level] = {
                    "response_time_minutes": cfg.get("response_minutes",
                                                     fallback.get(level, {}).get("response_time_minutes", 1440)),
                    "resolution_time_hours": cfg.get("resolution_hours",
                                                     fallback.get(level, {}).get("resolution_time_hours", 168)),
                    "description": f"{level} - Escalation: {cfg.get('escalation', 'as needed')}",
                }
            else:
                result[level] = fallback.get(level, fallback["P4"])
        return result

    def _get_sla(self, priority_level: str) -> Dict[str, Any]:
        """Get SLA based on priority — uses config values."""
        return self._sla_map.get(priority_level, self._sla_map.get("P4", {}))


class ContextScoringEngine:
    """Main context and scoring engine."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.asset_context = AssetContext(config)
        self.impact_calculator = BusinessImpactCalculator(config)
        self.priority_scorer = PriorityScorer(config)
        self.scored_incidents = []
    
    def process_incident(self, incident: Dict[str, Any]):
        """Process and score an incident."""
        
        event = incident.get("event", {})
        
        # Extract identifiers
        host_id = event.get("host", {}).get("id")
        host_ip = event.get("host", {}).get("ip")
        username = event.get("subject", {}).get("name")
        
        # Get context
        asset_ctx = self.asset_context.get_asset_criticality(host_id, host_ip)
        user_ctx = self.asset_context.get_user_context(username)
        
        # Calculate business impact
        impact_analysis = self.impact_calculator.calculate_impact(incident, asset_ctx, user_ctx)
        
        # Calculate priority
        priority_analysis = self.priority_scorer.calculate_priority(incident, impact_analysis)
        
        # Build scored incident
        l4_actions = self._generate_actions(incident, impact_analysis, priority_analysis)
        l3_actions = incident.get("recommended_actions", [])
        # Merge L3 + L4 actions, deduplicated, L3 first
        seen = set()
        merged_actions = []
        for a in l3_actions + l4_actions:
            if a not in seen:
                merged_actions.append(a)
                seen.add(a)

        scored_incident = self._build_scored_output(
            incident, asset_ctx, user_ctx,
            impact_analysis, priority_analysis, merged_actions
        )
        self.scored_incidents.append(scored_incident)

    def process_incident_streaming(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Process and score an incident, returning the scored result directly.
        Does NOT accumulate in memory — caller writes to disk."""
        # Extract from correlation incident structure (alerts[], affected_entities)
        event = incident.get("event", {})
        entities = incident.get("affected_entities", {})
        alerts_list = incident.get("alerts", [])
        first_alert = alerts_list[0] if alerts_list else {}
        attack_chain = incident.get("attack_chain", {})

        host_id = (event.get("host", {}).get("id")
                   or (entities.get("affected_hosts", [None])[0] if entities.get("affected_hosts") else None))
        host_ip = event.get("host", {}).get("ip")
        username = (event.get("subject", {}).get("name")
                    or first_alert.get("user")
                    or (entities.get("affected_users", [None])[0] if entities.get("affected_users") else None))

        asset_ctx = self.asset_context.get_asset_criticality(host_id, host_ip)
        user_ctx = self.asset_context.get_user_context(username)

        # Build a synthetic "rule" dict so the impact calculator can find
        # category, severity, and MITRE tactics from the correlation incident.
        if not incident.get("rule"):
            incident = dict(incident)
            incident["rule"] = {
                "category": first_alert.get("category") or "other",
                "severity": incident.get("severity") or first_alert.get("severity") or "medium",
                "mitre_tactics": attack_chain.get("tactics", []),
            }

        impact_analysis = self.impact_calculator.calculate_impact(incident, asset_ctx, user_ctx)
        priority_analysis = self.priority_scorer.calculate_priority(incident, impact_analysis)

        l4_actions = self._generate_actions(incident, impact_analysis, priority_analysis)
        l3_actions = incident.get("recommended_actions", [])
        seen = set()
        merged_actions = []
        for a in l3_actions + l4_actions:
            if a not in seen:
                merged_actions.append(a)
                seen.add(a)

        # Don't accumulate — already written to disk by caller
        return self._build_scored_output(
            incident, asset_ctx, user_ctx,
            impact_analysis, priority_analysis, merged_actions
        )

    # Minimal keys for fusion — everything else lives at the scored output's
    # top level and fusion._resolve_original() reconstructs the rest.
    _FUSION_KEYS = ("alerts", "indicators_of_compromise", "rule", "event",
                     "campaign_id", "metadata", "trigger_point",
                     "original_event_ids")

    # Boilerplate actions added to every incident — filter these from output
    _GENERIC_ACTIONS = frozenset({
        "Initiate incident response procedure",
        "Begin incident response procedure",
        "Document all findings and timeline",
        "Preserve logs and forensic evidence",
        "Notify security stakeholders",
        "Assign to security analyst for investigation",
        "Monitor for escalation",
    })

    @staticmethod
    def _clean_enrichment(enrichment: Dict[str, Any]) -> Dict[str, Any]:
        """Remove empty/null/false-only sections from enrichment."""
        if not enrichment:
            return {}
        result = {}
        for key, val in enrichment.items():
            if val is None:
                continue
            if isinstance(val, dict):
                # Strip empty lists and false bools within the section
                cleaned = {k: v for k, v in val.items()
                           if not (isinstance(v, list) and not v)
                           and not (isinstance(v, bool) and not v)}
                if cleaned:
                    result[key] = cleaned
            elif isinstance(val, bool) and not val:
                continue
            elif isinstance(val, (int, float)) and val:
                result[key] = val
            elif isinstance(val, list) and val:
                result[key] = val
        return result

    # Fixed output schema — every key always present with a typed default.
    _SCHEMA_DEFAULTS = {
        "scored_at": "",
        "incident_id": "",
        "severity": "",
        "priority_level": "",
        "priority_score": 0,
        "title": "",
        "first_seen": "",
        "last_seen": "",
        "duration_seconds": 0,
        "alert_count": 0,
        "trigger_point": {},
        "trigger_summary": "",
        "campaign_id": None,
        "source_ips": [],
        "target_ips": [],
        "affected_hosts": [],
        "affected_users": [],
        "attack_pattern": None,
        "mitre_tactics": [],
        "alert_summary": [],
        "enrichment": {},
        "impact_score": 0,
        "impact_level": "",
        "asset_criticality": "",
        "sla": {},
        "recommended_actions": [],
        "original_event_ids": [],
        "metadata": {},
        "original_incident": {},
    }

    @staticmethod
    def _clean_slim(slim: Dict[str, Any]) -> Dict[str, Any]:
        """Clean the slim original_incident for fusion.

        - Strips enrichment from alerts[0] (already at top level)
        - Strips null values from alerts[0]
        - Removes empty IOC/event dicts
        """
        if "alerts" in slim and slim["alerts"]:
            cleaned_alert = {k: v for k, v in slim["alerts"][0].items()
                            if v is not None and k != "enrichment"}
            slim["alerts"] = [cleaned_alert] if cleaned_alert else []
        if "indicators_of_compromise" in slim and not slim["indicators_of_compromise"]:
            del slim["indicators_of_compromise"]
        if "event" in slim and not slim["event"]:
            del slim["event"]
        return slim

    def _build_scored_output(
        self,
        incident: Dict[str, Any],
        asset_ctx: Dict[str, Any],
        user_ctx: Dict[str, Any],
        impact_analysis: Dict[str, Any],
        priority_analysis: Dict[str, Any],
        merged_actions: List[str],
    ) -> Dict[str, Any]:
        """Build concise scored output with flat top-level fields.

        Everything is surfaced at top level for readability.
        ``original_incident`` keeps only alerts[0], rule, IOCs for fusion.
        Empty lists, empty dicts, and None values are stripped.
        """
        trigger = incident.get("trigger_point", {})
        entities = incident.get("affected_entities", {})
        attack_chain = incident.get("attack_chain", {})

        # Filter generic boilerplate from recommended actions
        specific_actions = [a for a in merged_actions
                           if a not in self._GENERIC_ACTIONS]
        if not specific_actions:
            specific_actions = merged_actions[:3]

        # Clean enrichment — strip empty sections
        enrichment = self._clean_enrichment(
            incident.get("enrichment_summary") or {}
        )

        # Slim original_incident for fusion, then clean it
        slim = {k: incident[k] for k in self._FUSION_KEYS if k in incident}
        slim = self._clean_slim(slim)

        result = {
            "scored_at": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident.get("incident_id") or "",
            "severity": incident.get("severity") or "",
            "priority_level": priority_analysis.get("priority_level") or "",
            "priority_score": priority_analysis.get("priority_score", 0),
            "title": incident.get("title") or "",
            "first_seen": incident.get("first_seen") or "",
            "last_seen": incident.get("last_seen") or "",
            "duration_seconds": incident.get("duration_seconds", 0),
            "alert_count": incident.get("alert_count", 0),
            "trigger_point": trigger or {},
            "trigger_summary": incident.get("trigger_summary") or "",
            "campaign_id": incident.get("campaign_id"),
            "source_ips": entities.get("source_ips", []),
            "target_ips": entities.get("target_ips", []),
            "affected_hosts": entities.get("affected_hosts", []),
            "affected_users": entities.get("affected_users", []),
            "attack_pattern": attack_chain.get("attack_pattern"),
            "mitre_tactics": attack_chain.get("tactics", []),
            "alert_summary": incident.get("alert_summary", []),
            "enrichment": enrichment,
            "impact_score": impact_analysis.get("impact_score", 0),
            "impact_level": impact_analysis.get("impact_level") or "",
            "asset_criticality": asset_ctx.get("criticality") or "",
            "sla": priority_analysis.get("sla", {}),
            "recommended_actions": specific_actions,
            "metadata": incident.get("metadata", {}),
            "original_incident": slim,
        }

        # Ensure every field from fixed schema is present with typed default
        for key, default in self._SCHEMA_DEFAULTS.items():
            if key not in result:
                result[key] = default

        return result

    def _generate_actions(
        self,
        incident: Dict[str, Any],
        impact: Dict[str, Any],
        priority: Dict[str, Any]
    ) -> List[str]:
        """Generate recommended actions based on context."""
        actions = []
        
        # Add rule-based responses
        rule_responses = incident.get("recommended_response", [])
        actions.extend(rule_responses)
        
        # Add priority-based actions
        priority_level = priority.get("priority_level")
        
        if priority_level == "P1":
            actions.extend([
                "Escalate to senior security analyst immediately",
                "Notify on-call security team",
                "Begin incident response procedure"
            ])
        elif priority_level == "P2":
            actions.extend([
                "Assign to security analyst for investigation",
                "Monitor for escalation"
            ])
        
        # Add context-based actions
        if impact["affected_users"].get("is_privileged"):
            actions.append("Review all recent privileged account activity")
        
        if impact["affected_assets"].get("data_classification") in ["confidential", "restricted"]:
            actions.append("Check data access logs for unauthorized access")
        
        return list(set(actions))  # Deduplicate
    
    def get_scored_incidents(self) -> List[Dict[str, Any]]:
        """Get all scored incidents."""
        return self.scored_incidents
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scoring statistics."""
        if not self.scored_incidents:
            return {
                "total_scored": 0,
                "by_priority": {},
                "by_impact_level": {}
            }
        
        from collections import defaultdict
        priority_counts = defaultdict(int)
        impact_counts = defaultdict(int)
        
        for incident in self.scored_incidents:
            priority = incident.get("priority_level", "P4")
            impact = incident.get("impact_level", "unknown")

            priority_counts[priority] += 1
            impact_counts[impact] += 1
        
        return {
            "total_scored": len(self.scored_incidents),
            "by_priority": dict(priority_counts),
            "by_impact_level": dict(impact_counts)
        }


def main():
    parser = argparse.ArgumentParser(description="Context and Scoring Layer")
    parser.add_argument("--input", default="incidents.jsonl", help="Input incidents from correlation (JSONL)")
    parser.add_argument("--output", default="scored_incidents.jsonl", help="Output scored incidents (JSONL)")
    parser.add_argument("--config", default="context_config.yaml", help="Context configuration (YAML)")
    parser.add_argument("--stats", action="store_true", help="Print statistics")
    parser.add_argument("--follow", action="store_true",
                        help="Continuously tail input file for new data")
    parser.add_argument("--state-file", default=".state/scorer.state",
                        help="State file for follow mode position tracking")
    parser.add_argument("--poll-interval", type=float, default=0.5,
                        help="Poll interval in seconds for follow mode")
    # Kafka mode
    parser.add_argument("--kafka-brokers", default=None,
                        help="Kafka broker(s) — enables Kafka streaming mode")
    parser.add_argument("--input-topic", default="incidents",
                        help="Kafka input topic (default: incidents)")
    parser.add_argument("--output-topic", default="scored",
                        help="Kafka output topic (default: scored)")
    parser.add_argument("--consumer-group", default="scorer",
                        help="Kafka consumer group (default: scorer)")

    args = parser.parse_args()
    
    # Load config
    print(f"Loading context configuration from {args.config}...", file=sys.stderr)
    try:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
        print(f"✓ Context configuration loaded", file=sys.stderr)
    except FileNotFoundError:
        print(f"⚠ Config file not found, using defaults", file=sys.stderr)
        config = {}
    except yaml.YAMLError as e:
        print(f"✗ Error parsing YAML: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Initialize engine
    engine = ContextScoringEngine(config)
    
    if args.kafka_brokers:
        # --- Kafka streaming mode ---
        from kafka_helpers import run_stage

        def _process(incident):
            scored = engine.process_incident_streaming(incident)
            return [scored] if scored else []

        def _key(out):
            return out.get("incident_id")

        run_stage(
            brokers=args.kafka_brokers,
            consumer_group=args.consumer_group,
            input_topic=args.input_topic,
            output_topic=args.output_topic,
            process_fn=_process,
            key_fn=_key,
            stage_name="L4-scorer",
        )
        return

    if args.follow:
        # --- Streaming / follow mode ---
        from file_tailer import JSONLTailer, append_jsonl

        tailer = JSONLTailer(
            args.input,
            state_file=args.state_file,
            poll_interval=args.poll_interval,
        )
        incident_count = 0
        try:
            outfile = open(args.output, "a", encoding="utf-8")
            print(f"Following {args.input} -> {args.output} ...", file=sys.stderr)

            for incident in tailer.follow():
                scored = engine.process_incident_streaming(incident)
                append_jsonl(outfile, scored)
                incident_count += 1
                if incident_count % 100 == 0:
                    print(f"  Scored {incident_count} incidents...", file=sys.stderr)

        except KeyboardInterrupt:
            print("\nShutting down scorer...", file=sys.stderr)
        finally:
            tailer.close()
            outfile.close()
            print(f"✓ Scored {incident_count} incidents (follow mode)", file=sys.stderr)
    else:
        # --- Batch mode (original behaviour) ---
        print(f"Processing incidents from {args.input}...", file=sys.stderr)
        incident_count = 0

        try:
            with open(args.input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        incident = json.loads(line)
                        engine.process_incident(incident)
                        incident_count += 1

                    except json.JSONDecodeError:
                        continue

            print(f"✓ Processed {incident_count} incidents", file=sys.stderr)

        except FileNotFoundError:
            print(f"✗ Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)

        # Get scored incidents
        scored = engine.get_scored_incidents()

        # Write output
        print(f"Writing scored incidents to {args.output}...", file=sys.stderr)
        with open(args.output, 'w') as f:
            for incident in scored:
                f.write(json.dumps(incident, separators=(",", ":"), ensure_ascii=False) + "\n")

        print(f"✓ Generated {len(scored)} scored incidents", file=sys.stderr)

    # Print statistics
    if args.stats:
        stats = engine.get_stats()
        print("\n" + "="*60, file=sys.stderr)
        print("CONTEXT & SCORING STATISTICS", file=sys.stderr)
        print("="*60, file=sys.stderr)
        print(f"Total Scored: {stats['total_scored']}", file=sys.stderr)
        print(f"\nBy Priority:", file=sys.stderr)
        for priority, count in sorted(stats['by_priority'].items()):
            print(f"  {priority}: {count}", file=sys.stderr)
        print(f"\nBy Impact Level:", file=sys.stderr)
        for impact, count in sorted(stats['by_impact_level'].items()):
            print(f"  {impact}: {count}", file=sys.stderr)
        print("="*60, file=sys.stderr)


if __name__ == "__main__":
    main()
