import json
import time
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# OTEL 초기화
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

otlp_exporter = OTLPSpanExporter(endpoint="http://localhost:4318/v1/traces")
trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(otlp_exporter))

falco_log_path = "/var/log/falco_events.json"

with open(falco_log_path, "r") as f:
    f.seek(0, 2)  # EOF로 이동

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue

        try:
            log = json.loads(line.strip())
            print(f"[DEBUG] Parsed log: {log}")
        except json.JSONDecodeError:
            print(f"[DEBUG] JSON decode failed")
            continue

        # OTEL Trace Export
        with tracer.start_as_current_span("FalcoEvent") as span:
            for key, value in log.items():
                span.set_attribute(f"falco.{key}", str(value))

            print(f"[Trace ✅] Falco Event exported to OTEL")
