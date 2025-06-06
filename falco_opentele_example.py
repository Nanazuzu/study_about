import json
import time
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# === 1. Tracer 설정 ===
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

otlp_exporter = OTLPSpanExporter(endpoint="http://localhost:4318/v1/traces")
trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(otlp_exporter))

# === 2. Falco 로그 파일 위치 ===
falco_log_path = "/var/log/falco_events.json"
sent_pids = set()  # 나중에 PID 필터링용

# === 3. 로그 파일 모니터링 ===
with open(falco_log_path, "r") as f:
    # 파일 끝으로 이동
    f.seek(0, 2)

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue

        try:
            log = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        pid = log.get("pid")
        rule = log.get("rule")
        output = log.get("output")

        if pid is None or pid in sent_pids:
            continue  # PID 필터링

        sent_pids.add(pid)

        # === 4. OpenTelemetry Trace 생성 ===
        try:
            with tracer.start_as_current_span(f"FalcoAlert: {rule}") as span:
                span.set_attribute("falco.rule", rule)
                span.set_attribute("falco.pid", pid)
                span.set_attribute("falco.output", output)
                span.set_attribute("falco.priority", log.get("priority", "N/A"))
                span.set_attribute("falco.time", log.get("time", "N/A"))

                print(f"[Trace] Sent for PID: {pid} | Rule: {rule}")
                print(f"[Trace ✅] Sent for PID: {pid} | Rule: {rule}")
        except Exception as e:
            print(f"[Trace ❌] Failed to send span for PID: {pid} | Error: {e}")