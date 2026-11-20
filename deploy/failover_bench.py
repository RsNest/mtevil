#!/usr/bin/env python3
"""Mass client reconnect failover benchmark for mtevil (edge -> primary/backup egress)."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


def docker_container_stats(container: str) -> dict[str, str]:
    proc = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}", container],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return {"cpu": "нет данных", "mem": "нет данных", "pids": "нет данных"}
    parts = proc.stdout.strip().split("|")
    return {
        "cpu": parts[0] if len(parts) > 0 else "нет данных",
        "mem": parts[1] if len(parts) > 1 else "нет данных",
        "pids": parts[2] if len(parts) > 2 else "нет данных",
    }


def run_probe_once(compose_base: list[str], svc: str, dc: int, timeout_secs: int) -> tuple[bool, float, str]:
    t0 = time.monotonic()
    proc = subprocess.run(
        compose_base
        + [
            "exec",
            "-T",
            svc,
            "mtevil",
            "probe-telegram",
            "--config",
            "/etc/mtevil/config.json",
            "--dc",
            str(dc),
            "--timeout-secs",
            str(timeout_secs),
        ],
        capture_output=True,
        text=True,
    )
    elapsed_ms = (time.monotonic() - t0) * 1000.0
    if proc.returncode == 0:
        return True, elapsed_ms, ""
    err = (proc.stderr or proc.stdout or f"rc={proc.returncode}").strip()
    return False, elapsed_ms, err


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure mass client reconnect on edge when primary egress fails")
    parser.add_argument("--edge-dir", type=Path, required=True, help="Edge deployment directory")
    parser.add_argument("--edge-service", type=str, default="mtevil", help="Edge compose service name")
    parser.add_argument("--edge-container", type=str, required=True, help="Edge container name for docker stats")
    parser.add_argument("--clients", type=int, default=30, help="Number of concurrent reconnecting clients")
    parser.add_argument("--dc", type=int, default=2, help="Telegram DC id")
    parser.add_argument("--timeout-secs", type=int, default=8, help="Per-client probe timeout")
    args = parser.parse_args()

    compose_base = [
        "docker",
        "compose",
        "--env-file",
        str(args.edge_dir / ".env"),
        "-f",
        str(args.edge_dir / "compose.yaml"),
    ]

    stats_before = docker_container_stats(args.edge_container)
    t_wave_start = time.monotonic()
    results: list[tuple[bool, float, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.clients) as pool:
        futs = [
            pool.submit(run_probe_once, compose_base, args.edge_service, args.dc, args.timeout_secs)
            for _ in range(args.clients)
        ]
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())
    wave_ms = (time.monotonic() - t_wave_start) * 1000.0
    stats_after = docker_container_stats(args.edge_container)

    ok_latencies = sorted(lat for ok, lat, _ in results if ok)
    errors = [err for ok, _, err in results if not ok]
    p50 = ok_latencies[len(ok_latencies) // 2] if ok_latencies else None
    p95 = ok_latencies[min(len(ok_latencies) - 1, int(len(ok_latencies) * 0.95))] if ok_latencies else None
    max_lat = ok_latencies[-1] if ok_latencies else None

    summary = {
        "clients_total": args.clients,
        "reconnected_ok": len(ok_latencies),
        "failed": len(errors),
        "wave_total_ms": round(wave_ms, 1),
        "latency_p50_ms": round(p50, 1) if p50 is not None else None,
        "latency_p95_ms": round(p95, 1) if p95 is not None else None,
        "latency_max_ms": round(max_lat, 1) if max_lat is not None else None,
        "edge_stats_before": stats_before,
        "edge_stats_after": stats_after,
        "sample_errors": errors[:3],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if len(ok_latencies) == args.clients else 1


if __name__ == "__main__":
    raise SystemExit(main())
