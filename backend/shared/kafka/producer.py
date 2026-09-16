"""SecuriX Kafka Producer Helper.

Resilient publisher for normalized findings to Kafka findings.raw topic.
Safely falls back if Kafka broker is unreachable or disabled.
"""
import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("securix.kafka.producer")


class FindingProducer:
    """Publishes findings to Kafka with automatic serialization and connection resilience."""

    def __init__(self, bootstrap_servers: Optional[str] = None, topic: Optional[str] = None):
        self.bootstrap = bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "")
        self.topic = topic or os.getenv("KAFKA_TOPIC", "findings.raw")
        self._producer = None
        self._enabled = bool(self.bootstrap)

        if self._enabled:
            self._connect()

    def _connect(self):
        try:
            from kafka import KafkaProducer
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap.split(","),
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                request_timeout_ms=5000,
                retries=3,
            )
            logger.info("Connected to Kafka broker at %s for topic %s", self.bootstrap, self.topic)
        except Exception as e:
            logger.warning("Kafka producer connection failed (%s). Operating in offline mode.", e)
            self._producer = None

    def publish_finding(self, finding: Any) -> bool:
        """Publish a single Finding model or dict to Kafka."""
        return self.publish_batch([finding])

    def publish_batch(self, findings: List[Any]) -> bool:
        """Publish a batch of findings to Kafka."""
        if not self._producer or not findings:
            return False

        try:
            for f in findings:
                payload = f.model_dump(mode="json") if hasattr(f, "model_dump") else f
                self._producer.send(self.topic, value=payload)
            self._producer.flush(timeout=3)
            return True
        except Exception as e:
            logger.error("Error publishing findings to Kafka: %s", e)
            return False

    def close(self):
        if self._producer:
            try:
                self._producer.close(timeout=3)
            except Exception:
                pass
