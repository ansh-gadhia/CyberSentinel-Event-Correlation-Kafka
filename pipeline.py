#!/usr/bin/env python3
"""
SIEM Pipeline Orchestrator
Runs the correlation pipeline in sequence (batch) or in parallel (--follow).

Architecture:
    L1: Normalization (normalized.jsonl)
    L2: Enrichment (enriched.jsonl)
    L3: Event Correlation (incidents.jsonl)
    L4: Context & Scoring (scored_incidents.jsonl)  <-- final output

Usage:
    Batch:      python3 pipeline.py --input normalized.jsonl --all
    Streaming:  python3 pipeline.py --input /var/ossec/logs/alerts/alerts.json --all --follow
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from datetime import datetime


class PipelineOrchestrator:
    """Orchestrates the complete SIEM pipeline in batch mode."""

    def __init__(self, input_file: str, start_layer: str = "L1"):
        self.input_file = input_file
        self.start_layer = start_layer
        self.results = {}

        # Layer definitions
        self.layers = {
            "L1": {
                "name": "Normalization",
                "script": "normalizer.py",
                "input": input_file,
                "output": "normalized.jsonl",
                "optional": False
            },
            "L2": {
                "name": "Enrichment",
                "script": "enrich_json.py",
                "input": "normalized.jsonl",
                "output": "enriched.jsonl",
                "args": [
                    "--geoip-db", "databases/GeoLite2-City.mmdb",
                    "--asn-db", "databases/GeoLite2-ASN.mmdb",
                    "--tor-list", "databases/tor-exit-nodes.txt",
                    "--reputation-db", "databases/malicious-ips.txt"
                ],
                "optional": False
            },
            "L3": {
                "name": "Event Correlation",
                "script": "unified_correlation_engine.py",
                "input": "enriched.jsonl",
                "output": "incidents.jsonl",
                "args": [
                    "--rules", "correlation_rules.yaml"
                ],
                "optional": False
            },
            "L4": {
                "name": "Context & Scoring",
                "script": "context_scorer.py",
                "input": "incidents.jsonl",
                "output": "scored_incidents.jsonl",
                "args": [
                    "--config", "context_config.yaml"
                ],
                "optional": False
            }
        }

    def run_layer(self, layer_id: str) -> bool:
        """Run a single layer."""
        layer = self.layers[layer_id]

        print(f"\n{'='*60}")
        print(f"  Layer {layer_id}: {layer['name']}")
        print(f"{'='*60}")

        # Check if input exists
        if not os.path.exists(layer["input"]):
            if layer["optional"]:
                print(f"⚠ Input not found: {layer['input']} (optional layer, skipping)")
                return True
            else:
                print(f"✗ Error: Input file not found: {layer['input']}")
                return False

        # Build command
        cmd = [
            "python3",
            layer["script"],
            "--input", layer["input"],
            "--output", layer["output"]
        ]

        # Add additional arguments
        if "args" in layer:
            cmd.extend(layer["args"])

        # Add --stats flag
        cmd.append("--stats")

        print(f"Running: {' '.join(cmd)}")
        print(f"")

        # Execute
        try:
            result = subprocess.run(cmd, check=True, capture_output=False, text=True)

            self.results[layer_id] = {
                "status": "success",
                "output": layer["output"]
            }

            print(f"\n✓ {layer['name']} complete: {layer['output']}")
            return True

        except subprocess.CalledProcessError as e:
            print(f"\n✗ Error running {layer['name']}: {e}")
            self.results[layer_id] = {
                "status": "failed",
                "error": str(e)
            }
            return False

        except FileNotFoundError:
            print(f"\n✗ Error: Script not found: {layer['script']}")
            self.results[layer_id] = {
                "status": "failed",
                "error": f"Script not found: {layer['script']}"
            }
            return False

    def run_pipeline(self):
        """Run the complete pipeline in batch mode."""
        start_time = datetime.now()

        print(f"\n{'#'*60}")
        print(f"#  SIEM Pipeline Orchestrator")
        print(f"#  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'#'*60}")

        # Determine which layers to run
        layer_order = ["L1", "L2", "L3", "L4"]

        start_index = layer_order.index(self.start_layer)
        layers_to_run = layer_order[start_index:]

        print(f"\nLayers to run: {' → '.join(layers_to_run)}")

        # Run layers in order
        for layer_id in layers_to_run:
            success = self.run_layer(layer_id)

            if not success and not self.layers[layer_id]["optional"]:
                print(f"\n✗ Pipeline stopped due to error in {layer_id}")
                self.print_summary(success=False)
                return False

        # Pipeline complete
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        print(f"\n{'#'*60}")
        print(f"#  Pipeline Complete!")
        print(f"#  Duration: {duration:.2f} seconds")
        print(f"{'#'*60}")

        self.print_summary(success=True)
        return True

    def print_summary(self, success: bool):
        """Print pipeline summary."""
        print(f"\n{'='*60}")
        print(f"  Pipeline Summary")
        print(f"{'='*60}")

        for layer_id, result in self.results.items():
            layer = self.layers[layer_id]
            status_symbol = "✓" if result["status"] == "success" else "✗"

            print(f"{status_symbol} {layer_id}: {layer['name']}")

            if result["status"] == "success":
                print(f"   Output: {result['output']}")
            else:
                print(f"   Error: {result.get('error', 'Unknown error')}")

        print(f"{'='*60}")

        if success:
            print(f"\n✓ Final output: scored_incidents.jsonl")
            print(f"\nNext steps:")
            print(f"  1. Review incidents: cat scored_incidents.jsonl | jq '.'")
            print(f"  2. Filter by priority: cat scored_incidents.jsonl | jq 'select(.priority.priority_level == \"P1\")'")
            print(f"  3. Export to SIEM/dashboard")
        else:
            print(f"\n✗ Pipeline did not complete successfully")
            print(f"  Review errors above and fix before retrying")


class StreamingPipelineOrchestrator:
    """
    Launches ALL pipeline processes simultaneously with --follow mode.

    Each downstream JSONLTailer waits for its input file to appear,
    providing natural ordering without explicit sequencing.
    """

    STATE_DIR = ".state"
    SHUTDOWN_TIMEOUT = 10  # seconds to wait before SIGKILL

    def __init__(self, input_file: str, start_layer: str = "L1"):
        self.input_file = input_file
        self.start_layer = start_layer
        self.processes = {}  # layer_id -> Popen
        self._shutting_down = False

        # Ensure state directory exists
        os.makedirs(self.STATE_DIR, exist_ok=True)

        # Layer definitions for streaming mode
        self.layers = {
            "L1": {
                "name": "Normalization",
                "script": "normalizer.py",
                "cmd_extra": [
                    "--input", input_file,
                    "--output", "normalized.jsonl",
                    "--follow",
                    "--state-file", f"{self.STATE_DIR}/normalizer.state",
                ],
            },
            "L2": {
                "name": "Enrichment",
                "script": "enrich_json.py",
                "cmd_extra": [
                    "--input", "normalized.jsonl",
                    "--output", "enriched.jsonl",
                    "--follow",
                    "--state-file", f"{self.STATE_DIR}/enricher.state",
                    "--geoip-db", "databases/GeoLite2-City.mmdb",
                    "--asn-db", "databases/GeoLite2-ASN.mmdb",
                    "--tor-list", "databases/tor-exit-nodes.txt",
                    "--reputation-db", "databases/malicious-ips.txt",
                ],
            },
            "L3": {
                "name": "Event Correlation",
                "script": "unified_correlation_engine.py",
                "cmd_extra": [
                    "--input", "enriched.jsonl",
                    "--output", "incidents.jsonl",
                    "--rules", "correlation_rules.yaml",
                    "--follow",
                    "--state-file", f"{self.STATE_DIR}/correlation.state",
                ],
            },
            "L4": {
                "name": "Context & Scoring",
                "script": "context_scorer.py",
                "cmd_extra": [
                    "--input", "incidents.jsonl",
                    "--output", "scored_incidents.jsonl",
                    "--follow",
                    "--state-file", f"{self.STATE_DIR}/scorer.state",
                    "--config", "context_config.yaml",
                ],
            },
        }

    def _get_layer_order(self):
        """Return the ordered list of layer IDs to launch."""
        return ["L1", "L2", "L3", "L4"]

    def _launch(self, layer_id: str) -> bool:
        """Launch a single layer process."""
        layer = self.layers[layer_id]
        cmd = ["python3", layer["script"]] + layer["cmd_extra"]

        print(f"  Launching {layer_id} ({layer['name']}): {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
            self.processes[layer_id] = proc
            return True
        except FileNotFoundError:
            if layer.get("optional"):
                print(f"  ⚠ Script not found for optional layer {layer_id}, skipping")
                return True
            print(f"  ✗ Script not found: {layer['script']}")
            return False

    def run(self):
        """Launch all processes and monitor them."""
        start_time = datetime.now()

        print(f"\n{'#'*60}")
        print(f"#  SIEM Streaming Pipeline")
        print(f"#  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'#'*60}\n")

        # Install signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Determine layers to launch
        layer_order = self._get_layer_order()
        start_index = layer_order.index(self.start_layer)
        layers_to_run = layer_order[start_index:]

        print(f"Launching layers: {' | '.join(layers_to_run)}\n")

        # Launch ALL simultaneously
        for layer_id in layers_to_run:
            if not self._launch(layer_id):
                print(f"\n✗ Failed to launch {layer_id}, shutting down...")
                self._shutdown()
                return False

        print(f"\n✓ All {len(self.processes)} processes launched")
        print(f"  Press Ctrl+C to stop\n")

        # Monitor loop
        try:
            while not self._shutting_down:
                time.sleep(2)

                # Check for crashed processes
                for layer_id, proc in list(self.processes.items()):
                    ret = proc.poll()
                    if ret is not None and not self._shutting_down:
                        layer = self.layers[layer_id]
                        if layer.get("optional"):
                            print(f"⚠ Optional layer {layer_id} ({layer['name']}) "
                                  f"exited with code {ret}")
                        else:
                            print(f"✗ Layer {layer_id} ({layer['name']}) "
                                  f"crashed with code {ret}")
                            print(f"  Initiating shutdown...")
                            self._shutdown()
                            return False

        except KeyboardInterrupt:
            pass  # handled by signal handler

        self._shutdown()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        print(f"\n{'#'*60}")
        print(f"#  Pipeline stopped after {duration:.1f}s")
        print(f"{'#'*60}")
        return True

    def _signal_handler(self, signum, frame):
        """Handle SIGINT/SIGTERM gracefully."""
        if not self._shutting_down:
            print(f"\nReceived signal {signum}, shutting down...")
            self._shutting_down = True

    def _shutdown(self):
        """Send SIGINT to all children, wait, then SIGKILL stragglers."""
        if not self.processes:
            return

        # Phase 1: Send SIGINT to all
        for layer_id, proc in self.processes.items():
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGINT)
                except OSError:
                    pass

        # Phase 2: Wait for graceful shutdown
        deadline = time.time() + self.SHUTDOWN_TIMEOUT
        for layer_id, proc in self.processes.items():
            remaining = max(0, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                pass

        # Phase 3: SIGKILL stragglers
        for layer_id, proc in self.processes.items():
            if proc.poll() is None:
                print(f"  Force-killing {layer_id}...")
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass

        # Report final status
        print(f"\nProcess Status:")
        for layer_id, proc in self.processes.items():
            layer = self.layers[layer_id]
            code = proc.returncode
            symbol = "✓" if code in (0, -2, None) else "✗"
            print(f"  {symbol} {layer_id} ({layer['name']}): exit code {code}")


class KafkaPipelineOrchestrator(StreamingPipelineOrchestrator):
    """
    Launches pipeline processes with Kafka inter-stage transport.

    L1 still reads from the local file; all stages produce/consume via Kafka.
    Two JSONL sinks (enriched + scored) are launched as additional processes.
    """

    def __init__(self, input_file: str, kafka_brokers: str, start_layer: str = "L1",
                 skip_existing: bool = False):
        # Don't call super().__init__() — we override layers entirely
        self.input_file = input_file
        self.start_layer = start_layer
        self.processes = {}
        self._shutting_down = False
        self.SHUTDOWN_TIMEOUT = 10

        os.makedirs(self.STATE_DIR, exist_ok=True)
        os.makedirs("data/enriched", exist_ok=True)
        os.makedirs("data/scored", exist_ok=True)

        kb = kafka_brokers

        self.layers = {
            "L1": {
                "name": "Normalization",
                "script": "normalizer.py",
                "cmd_extra": [
                    "--input", input_file,
                    "--follow",
                    "--state-file", f"{self.STATE_DIR}/normalizer.state",
                    "--kafka-brokers", kb,
                    "--output-topic", "normalized",
                ] + (["--skip-existing"] if skip_existing else []),
            },
            "L2": {
                "name": "Enrichment",
                "script": "enrich_json.py",
                "cmd_extra": [
                    "--kafka-brokers", kb,
                    "--input-topic", "normalized",
                    "--output-topic", "enriched",
                    "--consumer-group", "enricher",
                    "--geoip-db", "databases/GeoLite2-City.mmdb",
                    "--asn-db", "databases/GeoLite2-ASN.mmdb",
                    "--tor-list", "databases/tor-exit-nodes.txt",
                    "--reputation-db", "databases/malicious-ips.txt",
                ],
            },
            "L3": {
                "name": "Event Correlation",
                "script": "unified_correlation_engine.py",
                "cmd_extra": [
                    "--kafka-brokers", kb,
                    "--input-topic", "enriched",
                    "--output-topic", "incidents",
                    "--consumer-group", "correlation",
                    "--rules", "correlation_rules.yaml",
                    "--input", "/dev/null",  # required by argparse but unused in kafka mode
                ],
            },
            "L4": {
                "name": "Context & Scoring",
                "script": "context_scorer.py",
                "cmd_extra": [
                    "--kafka-brokers", kb,
                    "--input-topic", "incidents",
                    "--output-topic", "scored",
                    "--consumer-group", "scorer",
                    "--config", "context_config.yaml",
                ],
            },
            "enriched-sink": {
                "name": "Enriched JSONL Sink",
                "script": "kafka_jsonl_sink.py",
                "cmd_extra": [
                    "--kafka-brokers", kb,
                    "--topic", "enriched",
                    "--consumer-group", "enriched-file-sink",
                    "--output-dir", "data/enriched",
                    "--prefix", "enriched",
                    "--max-size-mb", "100",
                    "--max-age-minutes", "60",
                ],
                "optional": True,
            },
            "scored-sink": {
                "name": "Scored JSONL Sink",
                "script": "kafka_jsonl_sink.py",
                "cmd_extra": [
                    "--kafka-brokers", kb,
                    "--topic", "scored",
                    "--consumer-group", "scored-file-sink",
                    "--output-dir", "data/scored",
                    "--prefix", "scored_incidents",
                    "--max-size-mb", "100",
                    "--max-age-minutes", "60",
                ],
                "optional": True,
            },
        }

    def run(self):
        """Launch with Kafka health check first."""
        # Check Kafka broker connectivity
        try:
            from kafka_helpers import check_broker, ensure_topics
        except ImportError:
            print("✗ confluent-kafka not installed. Run: pip install confluent-kafka",
                  file=sys.stderr)
            return False

        brokers = self.layers["L2"]["cmd_extra"][
            self.layers["L2"]["cmd_extra"].index("--kafka-brokers") + 1
        ]

        print(f"Checking Kafka broker: {brokers}...")
        if not check_broker(brokers):
            print("✗ Cannot reach Kafka broker. Is Kafka running?", file=sys.stderr)
            return False
        print("✓ Kafka broker reachable\n")

        # Create topics if needed
        ensure_topics(brokers, {
            "normalized": {"num_partitions": 4, "replication_factor": 1},
            "enriched":   {"num_partitions": 4, "replication_factor": 1},
            "incidents":  {"num_partitions": 2, "replication_factor": 1},
            "scored":     {"num_partitions": 2, "replication_factor": 1},
        })
        print()

        # Override layer order to include sinks, then use parent's run()
        # Monkey-patch the layer_order used by super().run()
        self._kafka_layer_order = ["L1", "L2", "L3", "L4", "enriched-sink", "scored-sink"]
        return super().run()

    def _get_layer_order(self):
        """Return layer order including sinks."""
        return getattr(self, "_kafka_layer_order", ["L1", "L2", "L3", "L4"])


def main():
    parser = argparse.ArgumentParser(description="SIEM Pipeline Orchestrator")
    parser.add_argument("--input", required=True, help="Input file (raw logs or normalized logs)")
    parser.add_argument("--from", dest="start_layer", default="L1",
                       choices=["L1", "L2", "L3", "L4"],
                       help="Start from specific layer")
    parser.add_argument("--all", action="store_true", help="Run complete pipeline from L1")
    parser.add_argument("--follow", action="store_true",
                        help="Run in continuous streaming mode (all processes in parallel)")
    parser.add_argument("--kafka-brokers", default=None,
                        help="Kafka broker(s) — enables Kafka mode (e.g. localhost:9092)")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip existing data in input file, only process new events")

    args = parser.parse_args()

    # Determine start layer
    if args.all:
        start_layer = "L1"
    else:
        start_layer = args.start_layer

    if args.kafka_brokers:
        orchestrator = KafkaPipelineOrchestrator(args.input, args.kafka_brokers, start_layer,
                                                  skip_existing=args.skip_existing)
        success = orchestrator.run()
    elif args.follow:
        orchestrator = StreamingPipelineOrchestrator(args.input, start_layer)
        success = orchestrator.run()
    else:
        orchestrator = PipelineOrchestrator(args.input, start_layer)
        success = orchestrator.run_pipeline()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
