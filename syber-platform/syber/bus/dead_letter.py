"""
Dead-letter queue handler (spec section 4.3).

Exponential-backoff retry with a max-retries cap, after which the event is
escalated to the platform admin. The spec uses confluent_kafka; this is the
same control logic over an in-process queue so it runs without a Kafka broker.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

MAX_RETRIES = 5
BACKOFF_BASE_S = 2.0


@dataclass
class DLQResult:
    permanently_failed: list[dict[str, Any]] = field(default_factory=list)
    republished: list[dict[str, Any]] = field(default_factory=list)


def process_dlq(
    events: list[dict[str, Any]],
    republish: Callable[[dict[str, Any]], None],
    alert_admin: Callable[[dict[str, Any]], None],
    sleep: Callable[[float], None] = lambda _: None,
) -> DLQResult:
    """Drain a batch of dead-lettered events (spec 4.3).

    `sleep` is injectable so tests don't actually wait through the backoff.
    """
    result = DLQResult()
    for event in events:
        retry_count = event.get("retry_count", 0)
        if retry_count >= MAX_RETRIES:
            alert_admin(event)
            result.permanently_failed.append(event)
            continue
        sleep(BACKOFF_BASE_S ** retry_count)
        event = {**event, "retry_count": retry_count + 1}
        republish(event)
        result.republished.append(event)
    return result
