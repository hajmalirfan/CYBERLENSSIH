"""SecuriX Kafka Consumer Helper.

Listens to Kafka findings.raw topic and passes findings to registered processors.
Runs gracefully in background thread or standalone loop.
"""
import json
import logging
import os
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger("securix.kafka.consumer")


class FindingConsumer:
    """Consumes findings from Kafka and dispatches to handler callbacks."""

    def __init__(
        self,
        handler: Callable[[dict], None],
        bootstrap_servers: Optional[str] = None,
        topic: Optional[str] = None,
        group_id: Optional[str] = "graph-service-group"
    ):
        self.handler = handler
        self.bootstrap = bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "")
        self.topic = topic or os.getenv("KAFKA_TOPIC", "findings.raw")
        self.group_id = group_id
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start_background(self):
        """Start consumer loop in a background daemon thread."""
        if not self.bootstrap:
            logger.info("Kafka consumer disabled (KAFKA_BOOTSTRAP_SERVERS not set).")
            return

        self._running = True
        self._thread = threading.Thread(target=self._consume_loop, daemon=True)
        self._thread.start()
        logger.info("Started Kafka consumer thread for topic %s", self.topic)

    def _consume_loop(self):
        while self._running:
            try:
                from kafka import KafkaConsumer
                consumer = KafkaConsumer(
                    self.topic,
                    bootstrap_servers=self.bootstrap.split(","),
                    group_id=self.group_id,
                    auto_offset_reset="earliest",
                    enable_auto_commit=True,
                    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                    consumer_timeout_ms=1000,
                )
                logger.info("Connected to Kafka topic %s as group %s", self.topic, self.group_id)

                while self._running:
                    msg_batch = consumer.poll(timeout_ms=1000)
                    for topic_partition, messages in msg_batch.items():
                        for msg in messages:
                            try:
                                self.handler(msg.value)
                            except Exception as e:
                                logger.error("Handler error processing Kafka finding: %s", e)
            except Exception as e:
                logger.warning("Kafka consumer error: %s. Retrying in 5s...", e)
                time.sleep(5)

    def stop(self):
        self._running = False
