# Falco + OpenTelemetry 연동 테스트

이 프로젝트는 **Falco 보안 이벤트**를 실시간으로 읽어 **OpenTelemetry Trace**로 전송하는 예제입니다.

---

## 📁 파일 구성

### `.yaml` 파일
- Falco 설정 및 룰 파일

설치 경로:
```bash
sudo cp ./*.yaml /etc/falco/

### `.py` 파일
- Falco와 OTEL연결 파일 실행
실행 방법:
```bash
(venv에서) python (.py파일 이름)