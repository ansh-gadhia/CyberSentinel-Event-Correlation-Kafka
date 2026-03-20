#!/usr/bin/env python3
"""
Shared Kafka producer/consumer helpers for the streaming pipeline.

Replaces file_tailer.py for inter-stage communication when Kafka is available.
Each pipeline stage imports create_producer / create_consumer from here.

Requirements:
    pip install confluent-kafka
"""

import json
import logging
import signal
import sys
import time
from typing import Any, Callable, Dict, List, Optional

try:
    from confluent_kafka import Producer, Consumer, KafkaError, KafkaException
    from confluent_kafka.admin import AdminClient, NewTopic
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

logger = logging.getLogger("kafka_helpers")


def check_kafka():
    """Abort early if confluent-kafka is not installed."""
    if not KAFKA_AVAILABLE:
        print("confluent-kafka is not installed.", file=sys.stderr)
        print("  Run: pip install confluent-kafka", file=sys.stderr)
        sys.exit(1)


# ======================================================================
# Producer
# ======================================================================

def create_producer(brokers: str, **overrides) -> "Producer":
    """Create a Kafka Producer with sensible defaults."""
    check_kafka()
    config = {
        "bootstrap.servers": brokers,
        "acks": "all",
        "retries": 5,
        "retry.backoff.ms": 500,
        "linger.ms": 10,
        "batch.size": 65536,
        "compression.type": "lz4",
        "queue.buffering.max.messages": 100000,
    }
    config.update(overrides)
    return Producer(config)


def produce_json(
    producer: "Producer",
    topic: str,
    obj: Dict[str, Any],
    key: Optional[str] = None,
):
    """Produce a single JSON message. Non-blocking; call producer.poll() periodically."""
    value = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    key_bytes = key.encode("utf-8") if key else None
    try:
        producer.produce(topic, value=value, key=key_bytes, callback=_delivery_cb)
    except BufferError:
        # Internal queue full – flush and retry once
        producer.flush(timeout=5)
        producer.produce(topic, value=value, key=key_bytes, callback=_delivery_cb)


def _delivery_cb(err, msg):
    if err is not None:
        logger.error("Delivery failed for key %s: %s", msg.key(), err)


# ======================================================================
# Consumer
# ======================================================================

def create_consumer(
    brokers: str,
    group_id: str,
    topics: List[str],
    **overrides,
) -> "Consumer":
    """Create a Kafka Consumer with sensible defaults, subscribed to *topics*."""
    check_kafka()
    config = {
        "bootstrap.servers": brokers,
        "group.id": group_id,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
        "auto.commit.interval.ms": 5000,
        "max.poll.interval.ms": 300000,
    }
    config.update(overrides)
    consumer = Consumer(config)
    consumer.subscribe(topics)
    return consumer


def consume_events(consumer: "Consumer", timeout: float = 1.0):
    """
    Poll one message. Returns parsed dict or None.

    Caller is responsible for the outer loop and shutdown logic.
    """
    msg = consumer.poll(timeout=timeout)
    if msg is None:
        return None
    if msg.error():
        if msg.error().code() == KafkaError._PARTITION_EOF:
            return None
        logger.error("Consumer error: %s", msg.error())
        return None
    try:
        return json.loads(msg.value().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning("Skipping malformed message at offset %d: %s", msg.offset(), e)
        return None


# ======================================================================
# Topic creation helper
# ======================================================================

def ensure_topics(
    brokers: str,
    topic_configs: Dict[str, Dict[str, int]],
    timeout: float = 10.0,
):
    """
    Create topics if they don't exist.

    topic_configs: {"topic_name": {"num_partitions": 4, "replication_factor": 1}, ...}
    """
    check_kafka()
    admin = AdminClient({"bootstrap.servers": brokers})

    existing = set(admin.list_topics(timeout=timeout).topics.keys())
    new_topics = []
    for name, cfg in topic_configs.items():
        if name not in existing:
            new_topics.append(
                NewTopic(
                    name,
                    num_partitions=cfg.get("num_partitions", 4),
                    replication_factor=cfg.get("replication_factor", 1),
                )
            )

    if not new_topics:
        return

    futures = admin.create_topics(new_topics)
    for topic_name, future in futures.items():
        try:
            future.result()
            print(f"  Created topic: {topic_name}", file=sys.stderr)
        except KafkaException as e:
            # Topic may already exist (race condition) – that's fine
            if "TOPIC_ALREADY_EXISTS" not in str(e):
                print(f"  Warning: could not create {topic_name}: {e}", file=sys.stderr)


# ======================================================================
# Broker health check
# ======================================================================

def check_broker(brokers: str, timeout: float = 5.0) -> bool:
    """Return True if at least one broker is reachable."""
    check_kafka()
    try:
        admin = AdminClient({"bootstrap.servers": brokers})
        meta = admin.list_topics(timeout=timeout)
        return len(meta.brokers) > 0
    except Exception as e:
        print(f"Kafka broker unreachable ({brokers}): {e}", file=sys.stderr)
        return False


# ======================================================================
# Generic consume-process-produce loop
# ======================================================================

def run_stage(
    brokers: str,
    consumer_group: str,
    input_topic: str,
    output_topic: Optional[str],
    process_fn: Callable[[Dict[str, Any]], Optional[List[Dict[str, Any]]]],
    flush_fn: Optional[Callable[[], List[Dict[str, Any]]]] = None,
    flush_interval: int = 60,
    key_fn: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
    stage_name: str = "stage",
):
    """
    Generic consume-process-produce loop.

    process_fn(event) -> list of output dicts (or None/empty to skip)
    flush_fn()        -> list of output dicts (called every flush_interval seconds)
    key_fn(output)    -> partition key string (or None for round-robin)
    """
    consumer = create_consumer(brokers, consumer_group, [input_topic])
    producer = create_producer(brokers) if output_topic else None

    running = True
    event_count = 0
    emit_count = 0
    last_flush = time.time()

    def _shutdown(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(f"[{stage_name}] Consuming {input_topic} -> {output_topic or '(no output)'}", file=sys.stderr)

    try:
        while running:
            event = consume_events(consumer, timeout=1.0)
            if event is not None:
                results = process_fn(event)
                event_count += 1
                if results and producer and output_topic:
                    for out in results:
                        key = key_fn(out) if key_fn else None
                        produce_json(producer, output_topic, out, key=key)
                        emit_count += 1
                if producer:
                    producer.poll(0)  # serve delivery callbacks

                if event_count % 500 == 0:
                    print(f"  [{stage_name}] {event_count} in, {emit_count} out", file=sys.stderr)

            # Periodic flush
            now = time.time()
            if flush_fn and now - last_flush >= flush_interval:
                flush_results = flush_fn()
                if flush_results and producer and output_topic:
                    for out in flush_results:
                        key = key_fn(out) if key_fn else None
                        produce_json(producer, output_topic, out, key=key)
                        emit_count += 1
                last_flush = now

    finally:
        if producer:
            producer.flush(timeout=10)
        consumer.close()
        print(f"[{stage_name}] Stopped. {event_count} consumed, {emit_count} emitted.", file=sys.stderr)
