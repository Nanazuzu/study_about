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
sent_trace_ids = set()  # TracePID(= pid or proc.name) 필터링용

# === 3. 로그 파일 모니터링 ===
with open(falco_log_path, "r") as f:
    # 파일 끝으로 이동
    f.seek(0, 2)

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue

        print(f"[DEBUG] Raw line: {line.strip()}")  # 🚀 Falco 로그 한 줄 확인

        try:
            log = json.loads(line.strip())
            print(f"[DEBUG] Parsed log: {log}")  # 🚀 json.loads 성공 여부 확인
        except json.JSONDecodeError:
            print(f"[DEBUG] JSON decode failed")
            continue

        pid = log.get("pid")
        proc_name = log.get("proc.name", "unknown_proc")

        # Fallback: pid가 없으면 proc.name 사용
        trace_pid = pid if pid is not None else proc_name

        rule = log.get("rule")
        output = log.get("output")

        # 중복 체크
        if trace_pid in sent_trace_ids:
            print(f"[DEBUG] Skipping duplicate trace_pid: {trace_pid}")
            continue

        sent_trace_ids.add(trace_pid)

        # === 4. OpenTelemetry Trace 생성 ===
        try:
            with tracer.start_as_current_span(f"FalcoAlert: {rule}") as span:
                span.set_attribute("falco.rule", rule)
                span.set_attribute("falco.pid_or_proc", trace_pid)
                span.set_attribute("falco.output", output)
                span.set_attribute("falco.priority", log.get("priority", "N/A"))
                span.set_attribute("falco.time", log.get("time", "N/A"))

                print(f"[Trace ✅] Sent for TracePID: {trace_pid} | Rule: {rule}")

        except Exception as e:
            print(f"[Trace ❌] Failed to send span for TracePID: {trace_pid} | Error: {e}")
