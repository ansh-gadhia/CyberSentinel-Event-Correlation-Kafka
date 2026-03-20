#!/usr/bin/env python3
"""
Kafka-to-JSONL file sink with time/size-based rotation.

Consumes messages from a Kafka topic and writes them to rotated JSONL files.
Used to persist enriched events and scored incidents to disk.

Usage:
    python3 kafka_jsonl_sink.py \
        --kafka-brokers localhost:9092 \
        --topic enriched \
        --consumer-group enriched-file-sink \
        --output-dir data/enriched \
        --prefix enriched \
        --max-size-mb 100 \
        --max-age-minutes 60
"""

import argparse
import gzip
import json
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone

from kafka_helpers import (
    check_kafka,
    create_consumer,
    consume_events,
)


class RotatingJSONLWriter:
    """Writes JSONL to files with size and time-based rotation."""

    def __init__(
        self,
        output_dir: str,
        prefix: str,
        max_size_bytes: int,
        max_age_seconds: int,
        compress: bool = True,
    ):
        self.output_dir = output_dir
        self.prefix = prefix
        self.max_size_bytes = max_size_bytes
        self.max_age_seconds = max_age_seconds
        self.compress = compress

        self._file = None
        self._file_path = None
        self._file_size = 0
        self._file_opened_at = 0.0
        self._line_count = 0

        os.makedirs(output_dir, exist_ok=True)

    def write(self, obj: dict):
        """Write one JSON object. Rotates if needed."""
        if self._file is None:
            self._open_new()

        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n"
        line_bytes = len(line.encode("utf-8"))

        self._file.write(line)
        self._file.flush()
        self._file_size += line_bytes
        self._line_count += 1

        # Check rotation
        now = time.time()
        if (self._file_size >= self.max_size_bytes or
                now - self._file_opened_at >= self.max_age_seconds):
            self._rotate()

    def close(self):
        if self._file:
            self._file.close()
            self._file = None
            print(f"  Closed {self._file_path} ({self._line_count} lines)", file=sys.stderr)

    def _open_new(self):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        self._file_path = os.path.join(self.output_dir, f"{self.prefix}_{ts}.jsonl")
        self._file = open(self._file_path, "a", encoding="utf-8")
        self._file_size = 0
        self._file_opened_at = time.time()
        self._line_count = 0
        print(f"  Writing to {self._file_path}", file=sys.stderr)

    def _rotate(self):
        old_path = self._file_path
        old_lines = self._line_count
        self.close()

        # Compress in background
        if self.compress and old_path and os.path.exists(old_path):
            t = threading.Thread(target=self._compress_file, args=(old_path,), daemon=True)
            t.start()

        print(f"  Rotated {old_path} ({old_lines} lines)", file=sys.stderr)
        self._open_new()

    @staticmethod
    def _compress_file(path: str):
        """Gzip a file and remove the original."""
        gz_path = path + ".gz"
        try:
            with open(path, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
                while True:
                    chunk = f_in.read(1024 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)
            os.remove(path)
        except Exception as e:
            print(f"  Warning: compression failed for {path}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Kafka to JSONL file sink with rotation")
    parser.add_argument("--kafka-brokers", required=True, help="Kafka broker(s)")
    parser.add_argument("--topic", required=True, help="Kafka topic to consume")
    parser.add_argument("--consumer-group", required=True, help="Consumer group ID")
    parser.add_argument("--output-dir", required=True, help="Output directory for JSONL files")
    parser.add_argument("--prefix", default="events", help="Filename prefix (default: events)")
    parser.add_argument("--max-size-mb", type=int, default=100,
                        help="Rotate when file exceeds this size in MB (default: 100)")
    parser.add_argument("--max-age-minutes", type=int, default=60,
                        help="Rotate when file is older than this in minutes (default: 60)")
    parser.add_argument("--no-compress", action="store_true",
                        help="Disable gzip compression of rotated files")
    parser.add_argument("--retain-days", type=int, default=7,
                        help="Delete rotated files older than N days (default: 7)")

    args = parser.parse_args()
    check_kafka()

    writer = RotatingJSONLWriter(
        output_dir=args.output_dir,
        prefix=args.prefix,
        max_size_bytes=args.max_size_mb * 1024 * 1024,
        max_age_seconds=args.max_age_minutes * 60,
        compress=not args.no_compress,
    )

    consumer = create_consumer(
        args.kafka_brokers,
        args.consumer_group,
        [args.topic],
        **{"enable.auto.commit": False},  # manual commit after flush
    )

    running = True
    msg_count = 0
    last_commit = time.time()
    last_cleanup = time.time()

    def _shutdown(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(f"\n[sink] {args.topic} -> {args.output_dir}/{args.prefix}_*.jsonl", file=sys.stderr)
    print(f"  Rotation: {args.max_size_mb} MB or {args.max_age_minutes} min", file=sys.stderr)
    print(f"  Compression: {'off' if args.no_compress else 'gzip'}", file=sys.stderr)
    print(f"  Retention: {args.retain_days} days\n", file=sys.stderr)

    try:
        while running:
            event = consume_events(consumer, timeout=1.0)
            if event is not None:
                writer.write(event)
                msg_count += 1

                # Commit offsets every 5 seconds
                now = time.time()
                if now - last_commit >= 5.0:
                    consumer.commit(asynchronous=False)
                    last_commit = now

                if msg_count % 1000 == 0:
                    print(f"  [sink] Written {msg_count} messages", file=sys.stderr)

            # Periodic cleanup of old rotated files
            now = time.time()
            if now - last_cleanup >= 3600:  # hourly
                _cleanup_old_files(args.output_dir, args.retain_days)
                last_cleanup = now

    finally:
        try:
            consumer.commit(asynchronous=False)
        except Exception:
            pass
        consumer.close()
        writer.close()
        print(f"[sink] Stopped. {msg_count} messages written.", file=sys.stderr)


def _cleanup_old_files(directory: str, retain_days: int):
    """Delete rotated .jsonl.gz files older than retain_days."""
    cutoff = time.time() - (retain_days * 86400)
    removed = 0
    try:
        for name in os.listdir(directory):
            if not name.endswith((".jsonl.gz", ".jsonl")):
                continue
            path = os.path.join(directory, name)
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
    except OSError:
        pass
    if removed:
        print(f"  [sink] Cleaned up {removed} old files", file=sys.stderr)


if __name__ == "__main__":
    main()
