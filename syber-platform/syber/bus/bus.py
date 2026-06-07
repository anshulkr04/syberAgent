"""
Message bus abstraction (spec §4).

Default: an in-process bus (durable enough for a single-node demo, fully tested).
When KAFKA_BOOTSTRAP is set, a real Kafka producer is used, with topics created
from bus_config/topics.yaml and the ACLs in bus_config/acls.sh applied out of
band. Events are signed SecurityEvent envelopes (spec §4.2).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .schemas import SecurityEvent


class InMemoryBus:
    def __init__(self) -> None:
        self.topics: dict[str, list[dict[str, Any]]] = {}

    def publish(self, topic: str, event: SecurityEvent) -> None:
        event.sign()
        self.topics.setdefault(topic, []).append(event.to_dict())

    def read(self, topic: str) -> list[dict[str, Any]]:
        return self.topics.get(topic, [])

    def close(self) -> None:
        pass


class KafkaBus:
    def __init__(self, bootstrap: str):
        import atexit

        from confluent_kafka import Producer

        self._producer = Producer({"bootstrap.servers": bootstrap})
        self._ensure_topics(bootstrap)
        # Ensure queued messages are delivered when the process exits (otherwise
        # confluent-kafka warns about messages still in transit).
        atexit.register(self.close)

    def _ensure_topics(self, bootstrap: str) -> None:
        try:
            import yaml  # type: ignore
            from confluent_kafka.admin import AdminClient, NewTopic

            cfg_path = Path(__file__).resolve().parent.parent.parent / "bus_config" / "topics.yaml"
            if not cfg_path.is_file():
                return
            spec = yaml.safe_load(cfg_path.read_text())
            admin = AdminClient({"bootstrap.servers": bootstrap})
            topics = [
                NewTopic(t["name"], num_partitions=t.get("partitions", 6),
                         replication_factor=t.get("replication_factor", 1),
                         config={k: str(v) for k, v in t.get("config", {}).items()})
                for t in spec.get("topics", [])
            ]
            for name, fut in admin.create_topics(topics).items():
                try:
                    fut.result()
                except Exception:  # noqa: BLE001 - already exists / benign
                    pass
        except Exception as exc:  # noqa: BLE001
            print(f"[bus] topic creation skipped: {exc}", file=sys.stderr)

    def publish(self, topic: str, event: SecurityEvent) -> None:
        event.sign()
        self._producer.produce(topic, key=event.event_id, value=json.dumps(event.to_dict()).encode())
        self._producer.poll(0)

    def read(self, topic: str) -> list[dict[str, Any]]:
        # Production consumption is handled by the per-agent consumers (spec §4.1).
        return []

    def close(self) -> None:
        try:
            self._producer.flush(5)
        except Exception:  # noqa: BLE001
            pass


_bus: "InMemoryBus | KafkaBus | None" = None


def get_bus() -> "InMemoryBus | KafkaBus":
    """Kafka when KAFKA_BOOTSTRAP is set and reachable (spec §4), else in-process."""
    global _bus
    if _bus is None:
        bootstrap = os.environ.get("KAFKA_BOOTSTRAP")
        if bootstrap:
            try:
                _bus = KafkaBus(bootstrap)
            except Exception as exc:  # noqa: BLE001
                print(f"[bus] KAFKA_BOOTSTRAP set but unavailable ({exc}); using in-process bus", file=sys.stderr)
                _bus = InMemoryBus()
        else:
            _bus = InMemoryBus()
    return _bus
