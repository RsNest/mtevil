#!/usr/bin/env python3
"""client-stub пробы для infrastructure smoke — ЗАГЛУШКА генератора (этап 4 §16).

Проверяемые события наблюдаемости (не протокольная совместимость!):
1. controlled RST на установленном TCP: connect → SO_LINGER(0) → close
   → клиентский сокет шлёт RST (SEND_RESET в netns клиента, sk != NULL).
2. SYN на закрытый порт: kernel отвечает RST БЕЗ сокета
   (SEND_RESET skaddr=0x0 reason=NO_SOCKET=1 в netns DUT).
3. мусорный HTTP на порт DUT — наблюдение за реакцией (не claim).

Выход: JSONL-строки на stdout; собирается в runs/<id>/raw/events/.
"""
import json
import errno
import socket
import struct
import sys
import time

DUT_HOST = sys.argv[1] if len(sys.argv) > 1 else "mtveil-dut-telemt"
DUT_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
CLOSED_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 9999
ERRORS = 0


def emit(event: dict) -> None:
    global ERRORS
    if event.get("kind") == "probe_error":
        ERRORS += 1
    event["ts_ns"] = time.monotonic_ns()
    event["ts"] = time.time()
    print(json.dumps(event), flush=True)


def probe_controlled_rst() -> None:
    """Открыть TCP до DUT и закрыть с SO_LINGER=0 — клиентский RST."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((DUT_HOST, DUT_PORT))
        local = s.getsockname()
        emit({
            "kind": "connect_established",
            "probe": "controlled-rst",
            "local": f"{local[0]}:{local[1]}",
            "peer_dut": f"{DUT_HOST}:{DUT_PORT}",
        })
        # SO_LINGER (on=1, 0 сек) → close() шлёт RST вместо FIN.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()
        emit({"kind": "rst_sent_linger0", "probe": "controlled-rst",
              "expect": "SEND_RESET in client netns, sk!=NULL"})
    except OSError as e:
        emit({"kind": "probe_error", "probe": "controlled-rst", "error": str(e)})


def probe_closed_port() -> None:
    """SYN на закрытый порт DUT → RST от kernel netns DUT, skaddr=0 (NO_SOCKET)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        result = s.connect_ex((DUT_HOST, CLOSED_PORT))
        if result != errno.ECONNREFUSED:
            raise OSError(result, "closed port did not return ECONNREFUSED")
        emit({"kind": "closed_port_probed", "probe": "closed-port",
              "peer_dut": f"{DUT_HOST}:{CLOSED_PORT}",
              "expect": "SEND_RESET in DUT netns, skaddr=0x0, reason=NO_SOCKET(1)"})
    except OSError as e:
        emit({"kind": "probe_error", "probe": "closed-port", "error": str(e)})
    finally:
        s.close()


def probe_garbage_http() -> None:
    """Сырые не-TLS байты на FakeTLS-порт DUT — только наблюдение реакции."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((DUT_HOST, DUT_PORT))
        s.sendall(b"NOT-TLS GARBAGE\r\n\r\n")
        status = "data"
        try:
            data = s.recv(256)
            if not data:
                status = "eof"
        except socket.timeout:
            data = b""
            status = "timeout"
        emit({"kind": "garbage_http_sent", "probe": "garbage",
              "read_status": status,
              "dut_response_bytes": len(data),
              "dut_response_preview": data[:64].hex()})
    except OSError as e:
        emit({"kind": "probe_error", "probe": "garbage", "error": str(e)})
    finally:
        s.close()


if __name__ == "__main__":
    emit({"kind": "probe_suite_start", "dut": f"{DUT_HOST}:{DUT_PORT}"})
    probe_controlled_rst()
    time.sleep(1)
    probe_closed_port()
    time.sleep(1)
    probe_garbage_http()
    emit({"kind": "probe_suite_end"})
    sys.exit(1 if ERRORS else 0)
