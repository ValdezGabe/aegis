"""
Observability for the gateway, built on OpenTelemetry.

A security gateway that can't be observed can't be operated. When a request is
blocked at 3am, an operator needs to answer: which layer blocked it, how long
each check took, is one identity getting blocked over and over, is a layer
suddenly slow? This module wires the gateway for exactly those questions.

OpenTelemetry (OTel) is the cloud-native standard for this: a vendor-neutral way
to emit **traces** (the timeline of one request through each guard layer) and
**metrics** (counters and latency histograms aggregated across all requests). We
emit both, then export them wherever the operator's stack lives:

  - OTLP endpoint (Grafana Tempo/Mimir, Jaeger, an OpenTelemetry Collector) when
    OTEL_EXPORTER_OTLP_ENDPOINT is set — the portable default.
  - Console, when nothing is configured, so traces are visible in local dev.
  - Azure Monitor / Application Insights via the azure-monitor-opentelemetry
    distro — an opt-in documented in ARCHITECTURE.md that keeps telemetry in the
    same Azure tenant as the existing Log Analytics decision logs.

main.py calls setup_telemetry(app) once at startup, then uses `tracer` to open
spans and the metric instruments below to record decisions. Nothing here changes
the gateway's security behavior — it only makes that behavior measurable.
"""

import os
import time
from contextlib import contextmanager

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)

SERVICE_NAME = "aegis-gateway"

# These are created for real inside setup_telemetry(). Until then they are no-op
# implementations from the OTel API, so importing this module never fails even if
# telemetry is never configured.
tracer = trace.get_tracer(SERVICE_NAME)

# Metric instruments, populated by setup_telemetry(). Declared here so main.py can
# import them by name.
requests_total = None       # counter: every /chat and /agent request, by decision
blocks_total = None         # counter: blocks, labelled by the layer/control that fired
pii_redactions_total = None # counter: PII fields redacted on the way out
layer_latency = None        # histogram: milliseconds spent in each guard layer


def setup_telemetry(app):
    """
    Configure OpenTelemetry once, at app startup, and instrument FastAPI so every
    HTTP request automatically gets a server span. Choosing the exporter from the
    environment keeps the gateway portable: the same image ships traces to
    Grafana in one cluster and to a plain console in local dev.
    """
    resource = Resource.create({"service.name": SERVICE_NAME})
    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")

    # --- Traces ---
    provider = TracerProvider(resource=resource)
    if otlp_endpoint:
        span_exporter = OTLPSpanExporter()  # reads endpoint/headers from env
        print(f"[TELEMETRY] exporting traces via OTLP to {otlp_endpoint}")
    else:
        span_exporter = ConsoleSpanExporter()
        print("[TELEMETRY] no OTLP endpoint set; exporting traces to console")
    provider.add_span_processor(BatchSpanProcessor(span_exporter))
    trace.set_tracer_provider(provider)

    # --- Metrics ---
    if otlp_endpoint:
        metric_exporter = OTLPMetricExporter()
    else:
        metric_exporter = ConsoleMetricExporter()
    reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=15000)
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))

    # Rebind the module-level handles to real, configured instruments.
    global tracer, requests_total, blocks_total, pii_redactions_total, layer_latency
    tracer = trace.get_tracer(SERVICE_NAME)
    meter = metrics.get_meter(SERVICE_NAME)

    requests_total = meter.create_counter(
        "aegis.requests",
        unit="1",
        description="Total gateway requests, labelled by endpoint and decision.",
    )
    blocks_total = meter.create_counter(
        "aegis.blocks",
        unit="1",
        description="Blocked requests, labelled by the layer/control that blocked them.",
    )
    pii_redactions_total = meter.create_counter(
        "aegis.pii_redactions",
        unit="1",
        description="PII fields redacted from model responses, labelled by type.",
    )
    layer_latency = meter.create_histogram(
        "aegis.layer.latency",
        unit="ms",
        description="Time spent in each guard layer.",
    )

    # Auto-instrument FastAPI: one server span per HTTP request, with method,
    # route, and status code. Our custom spans below nest inside it.
    FastAPIInstrumentor.instrument_app(app)
    print("[TELEMETRY] OpenTelemetry configured")


def count(counter, amount: int = 1, attributes: dict | None = None):
    """Add to a counter, tolerating the pre-setup state where it is still None."""
    if counter is not None:
        counter.add(amount, attributes or {})


@contextmanager
def layer_span(name: str, layer: str):
    """
    Open a span for one guard layer and record how long it took into the
    latency histogram. Usage:

        with layer_span("guard.layer1", "layer1"):
            blocked, reason = check_patterns(message)

    The span name shows up in the trace timeline; the `layer` label lets the
    histogram break latency down per layer (p50/p99 for Layer 1 vs Layer 2, etc).
    """
    start = time.perf_counter()
    with tracer.start_as_current_span(name) as span:
        span.set_attribute("aegis.layer", layer)
        try:
            yield span
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            if layer_latency is not None:
                layer_latency.record(elapsed_ms, {"layer": layer})
            span.set_attribute("aegis.layer.latency_ms", round(elapsed_ms, 2))
