#!/usr/bin/env python
"""Simple demo runner for Cybersecurity-Project modules.

Usage examples (from project root, with Docker services already up):

    # Module 3: ML-based adaptive honeypot behaviour
    python demo_module_tests.py 3

    # Module 4: Honeypot expansion (Dionaea / Conpot)
    python demo_module_tests.py 4

    # Module 5: MITRE ATT&CK + SIEM
    python demo_module_tests.py 5

    # Module 6: Evaluation engine
    python demo_module_tests.py 6

    # Module 8: Threat intelligence sharing
    python demo_module_tests.py 8

    # Module 9: ELK stack health
    python demo_module_tests.py 9

    # Module 10: Auth / RBAC
    python demo_module_tests.py 10

    # Module 11: Traffic monitor
    python demo_module_tests.py 11

    # Module 12: Secure API & rate limiting
    python demo_module_tests.py 12

This script is intentionally minimal: it just makes HTTP requests and prints
status codes + JSON/text so you can show them quickly in the video and capture
backend/service logs at the same time.
"""

import argparse
import json
import sys
from typing import Callable, Dict, Optional

import requests

BACKEND_URL = "http://localhost:5000"
SERVICE_URLS = {
    "behavioral_analysis": "http://localhost:5001",
    "decoy_generator": "http://localhost:5002",
    "traffic_monitor": "http://localhost:5003",
    "threat_attribution": "http://localhost:5004",
    "threat_intel": "http://localhost:5006",
    "adaptive_deception": "http://localhost:5007",
    "evaluation_engine": "http://localhost:5008",
    # ELK services are not strictly part of this repo but used in docker-compose
    "elasticsearch": "http://localhost:9200",
    "kibana": "http://localhost:5601",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def print_header(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def pretty_print_response(resp: requests.Response, label: Optional[str] = None) -> None:
    """Print HTTP status + a short body snippet for demo purposes."""

    name = label or resp.request.method + " " + (resp.request.url or "")
    print(f"\n--- {name} ---")
    print(f"Status: {resp.status_code}")

    try:
        data = resp.json()
        text = json.dumps(data, indent=2)[:2000]
        print(text)
        if len(text) == 2000:
            print("... (truncated)")
    except ValueError:
        # Not JSON
        body = (resp.text or "")
        if len(body) > 2000:
            body = body[:2000] + "... (truncated)"
        print(body)


def get_test_token() -> str:
    """Call /api/auth/test-token and return the JWT string.

    This endpoint exists only for development/demo; it also creates a test user
    with admin role if needed.
    """

    print_header("Requesting development JWT token from /api/auth/test-token")
    url = f"{BACKEND_URL}/api/auth/test-token"
    resp = requests.get(url, timeout=10)
    pretty_print_response(resp, label="GET /api/auth/test-token")
    resp.raise_for_status()

    data = resp.json()
    token = data.get("token")
    if not token:
        raise RuntimeError("No 'token' field in /api/auth/test-token response")

    user = data.get("user")
    if user:
        print(f"Obtained token for user {user.get('email')} (role={user.get('role')})")
    return token


def auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Module-specific demo routines
# ---------------------------------------------------------------------------


def run_module_3() -> None:
    """Module 3 – ML-based adaptive honeypot behaviour.

    Requires containers: backend, behavioral_analysis, adaptive_deception,
    decoy_generator, db, redis.
    """

    token = get_test_token()

    # Health checks
    print_header("Module 3: health checks (behavioral_analysis, adaptive_deception, decoy_generator)")
    for name in ("behavioral_analysis", "adaptive_deception", "decoy_generator"):
        url = SERVICE_URLS[name] + "/health"
        try:
            resp = requests.get(url, timeout=10)
            pretty_print_response(resp, label=f"GET {name}/health")
        except Exception as exc:
            print(f"ERROR calling {url}: {exc}")

    # Trigger anomaly detection in behavioral_analysis
    print_header("Module 3: trigger /detect on behavioral_analysis to generate log entries")
    detect_url = SERVICE_URLS["behavioral_analysis"] + "/detect"
    payload = {"data": [[0] * 10, [3] * 10]}
    try:
        resp = requests.post(detect_url, json=payload, timeout=30)
        pretty_print_response(resp, label="POST /detect (behavioral_analysis)")
    except Exception as exc:
        print(f"ERROR calling {detect_url}: {exc}")

    # Drive adaptive_deception + decoy_generator to produce fake credentials / filesystem
    print_header("Module 3: generate adaptive credentials and filesystem for a demo session")
    session_id = "demo_session_1"

    # 1) Send an attacker event to adaptive_deception so it writes adaptive_* data into Redis
    event = {
        "session_id": session_id,
        "action": "login_attempt",
        "target": "web_server",
        "success": True,
        "timestamp": __import__("datetime").datetime.now().isoformat(),
    }
    try:
        resp = requests.post(
            SERVICE_URLS["adaptive_deception"] + "/process_event",
            json=event,
            timeout=15,
        )
        pretty_print_response(resp, label="POST /process_event (adaptive_deception)")
    except Exception as exc:
        print(f"ERROR calling adaptive_deception /process_event: {exc}")

    # 2) Fetch adaptive credentials / filesystem / banners from decoy_generator
    for suffix, label in (
        (f"/adaptive/credentials/{session_id}", "GET /adaptive/credentials/<session_id>"),
        (f"/adaptive/filesystem/{session_id}", "GET /adaptive/filesystem/<session_id>"),
        (f"/adaptive/banners/{session_id}", "GET /adaptive/banners/<session_id>"),
    ):
        url = SERVICE_URLS["decoy_generator"] + suffix
        try:
            resp = requests.get(url, timeout=15)
            pretty_print_response(resp, label=label)
        except Exception as exc:
            print(f"ERROR calling {url}: {exc}")


def run_module_4() -> None:
    """Module 4 – Honeypot expansion: Dionaea and Conpot.

    Requires containers: backend, decoy_generator, db, redis.
    """

    token = get_test_token()

    print_header("Module 4: decoy_generator /types and /health")
    try:
        resp = requests.get(SERVICE_URLS["decoy_generator"] + "/health", timeout=10)
        pretty_print_response(resp, label="GET /health (decoy_generator)")
    except Exception as exc:
        print(f"ERROR calling decoy_generator /health: {exc}")

    try:
        resp = requests.get(SERVICE_URLS["decoy_generator"] + "/types", timeout=10)
        pretty_print_response(resp, label="GET /types (decoy_generator)")
    except Exception as exc:
        print(f"ERROR calling decoy_generator /types: {exc}")

    # Deploy a Dionaea honeypot directly via decoy_generator
    print_header("Module 4: deploy Dionaea honeypot via decoy_generator")
    try:
        resp = requests.post(
            SERVICE_URLS["decoy_generator"] + "/deploy/honeypot",
            json={"type": "dionaea"},
            timeout=30,
        )
        pretty_print_response(resp, label="POST /deploy/honeypot (dionaea)")
    except Exception as exc:
        print(f"ERROR deploying dionaea via decoy_generator: {exc}")

    # Deploy via central backend API (uses DB + Decoy model, emits Socket.IO events)
    print_header("Module 4: deploy Dionaea via backend /api/decoys/deploy (requires JWT)")
    try:
        resp = requests.post(
            f"{BACKEND_URL}/api/decoys/deploy",
            headers=auth_headers(token),
            json={"type": "dionaea"},
            timeout=30,
        )
        pretty_print_response(resp, label="POST /api/decoys/deploy (dionaea)")
    except Exception as exc:
        print(f"ERROR deploying dionaea via backend: {exc}")

    print_header("Module 4: list decoys tracked by backend")
    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/decoys", headers=auth_headers(token), timeout=30
        )
        pretty_print_response(resp, label="GET /api/decoys")
    except Exception as exc:
        print(f"ERROR calling /api/decoys: {exc}")


def run_module_5() -> None:
    """Module 5 – MITRE ATT&CK attribution & SIEM integration.

    Requires containers: backend, threat_attribution, redis, plus ELK for full SIEM demo.
    """

    token = get_test_token()

    print_header("Module 5: threat_attribution /health")
    try:
        resp = requests.get(SERVICE_URLS["threat_attribution"] + "/health", timeout=15)
        pretty_print_response(resp, label="GET /health (threat_attribution)")
    except Exception as exc:
        print(f"ERROR calling threat_attribution /health: {exc}")

    print_header("Module 5: backend /api/metrics/summary (uses MITRE mapping)")
    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/metrics/summary",
            headers=auth_headers(token),
            timeout=30,
        )
        pretty_print_response(resp, label="GET /api/metrics/summary")
    except Exception as exc:
        print(f"ERROR calling /api/metrics/summary: {exc}")

    print_header("Module 5: backend /api/attribution/report")
    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/attribution/report",
            headers=auth_headers(token),
            timeout=60,
        )
        pretty_print_response(resp, label="GET /api/attribution/report")
    except Exception as exc:
        print(f"ERROR calling /api/attribution/report: {exc}")

    print_header("Module 5: backend /api/siem/status")
    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/siem/status",
            headers=auth_headers(token),
            timeout=15,
        )
        pretty_print_response(resp, label="GET /api/siem/status")
    except Exception as exc:
        print(f"ERROR calling /api/siem/status: {exc}")


def run_module_6() -> None:
    """Module 6 – Evaluation metrics & automated retraining.

    Requires containers: backend, behavioral_analysis, evaluation_engine, db, redis.
    """

    print_header("Module 6: evaluation_engine /health")
    try:
        resp = requests.get(SERVICE_URLS["evaluation_engine"] + "/health", timeout=15)
        pretty_print_response(resp, label="GET /health (evaluation_engine)")
    except Exception as exc:
        print(f"ERROR calling evaluation_engine /health: {exc}")

    print_header("Module 6: evaluation_engine /scenarios")
    try:
        resp = requests.get(SERVICE_URLS["evaluation_engine"] + "/scenarios", timeout=15)
        pretty_print_response(resp, label="GET /scenarios (evaluation_engine)")
    except Exception as exc:
        print(f"ERROR calling /scenarios: {exc}")

    print_header("Module 6: (optional) run network_scanning test against backend")
    try:
        resp = requests.post(
            SERVICE_URLS["evaluation_engine"] + "/test/network_scanning",
            json={"target_host": "backend"},
            timeout=600,
        )
        pretty_print_response(resp, label="POST /test/network_scanning")
    except Exception as exc:
        print(f"ERROR running evaluation test: {exc}")

    print_header("Module 6: evaluation_engine /statistics")
    try:
        resp = requests.get(SERVICE_URLS["evaluation_engine"] + "/statistics", timeout=30)
        pretty_print_response(resp, label="GET /statistics (evaluation_engine)")
    except Exception as exc:
        print(f"ERROR calling evaluation_engine /statistics: {exc}")


def run_module_8() -> None:
    """Module 8 – Threat intelligence sharing (STIX2 / TAXII).

    Requires containers: backend, threat_intelligence, redis, db.
    """

    print_header("Module 8: threat_intel /health")
    try:
        resp = requests.get(SERVICE_URLS["threat_intel"] + "/health", timeout=15)
        pretty_print_response(resp, label="GET /health (threat_intel)")
    except Exception as exc:
        print(f"ERROR calling threat_intel /health: {exc}")

    print_header("Module 8: threat_intel /statistics")
    try:
        resp = requests.get(SERVICE_URLS["threat_intel"] + "/statistics", timeout=30)
        pretty_print_response(resp, label="GET /statistics (threat_intel)")
    except Exception as exc:
        print(f"ERROR calling /statistics: {exc}")

    print_header("Module 8: threat_intel /servers")
    try:
        resp = requests.get(SERVICE_URLS["threat_intel"] + "/servers", timeout=15)
        pretty_print_response(resp, label="GET /servers (threat_intel)")
    except Exception as exc:
        print(f"ERROR calling /servers: {exc}")

    print_header("Module 8: TAXII discovery endpoint /taxii2/")
    try:
        resp = requests.get(SERVICE_URLS["threat_intel"] + "/taxii2/", timeout=15)
        pretty_print_response(resp, label="GET /taxii2/ (threat_intel)")
    except Exception as exc:
        print(f"ERROR calling /taxii2/: {exc}")


def run_module_9() -> None:
    """Module 9 – Centralized monitoring & logging (ELK)."""

    print_header("Module 9: Elasticsearch cluster health")
    try:
        resp = requests.get(SERVICE_URLS["elasticsearch"] + "/_cluster/health", timeout=15)
        pretty_print_response(resp, label="GET /_cluster/health")
    except Exception as exc:
        print(f"ERROR calling Elasticsearch /_cluster/health: {exc}")

    print_header("Module 9: Kibana API status")
    try:
        resp = requests.get(SERVICE_URLS["kibana"] + "/api/status", timeout=15)
        pretty_print_response(resp, label="GET /api/status (kibana)")
    except Exception as exc:
        print(f"ERROR calling Kibana /api/status: {exc}")

    print_header("Module 9: (optional) list indices in Elasticsearch")
    try:
        resp = requests.get(SERVICE_URLS["elasticsearch"] + "/_cat/indices?v", timeout=15)
        pretty_print_response(resp, label="GET /_cat/indices?v")
    except Exception as exc:
        print(f"ERROR calling Elasticsearch /_cat/indices: {exc}")


def run_module_10() -> None:
    """Module 10 – Authentication, authorization, RBAC."""

    print_header("Module 10: auth help /api/auth/help")
    try:
        resp = requests.get(f"{BACKEND_URL}/api/auth/help", timeout=15)
        pretty_print_response(resp, label="GET /api/auth/help")
    except Exception as exc:
        print(f"ERROR calling /api/auth/help: {exc}")

    token = get_test_token()

    print_header("Module 10: backend /api/dashboard/stats (protected)")
    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/dashboard/stats",
            headers=auth_headers(token),
            timeout=15,
        )
        pretty_print_response(resp, label="GET /api/dashboard/stats")
    except Exception as exc:
        print(f"ERROR calling /api/dashboard/stats: {exc}")


def run_module_11() -> None:
    """Module 11 – Traffic capture with Zeek/tcpdump.

    Requires containers: backend, traffic_monitor, db, redis.
    """

    print_header("Module 11: traffic_monitor /health")
    try:
        resp = requests.get(SERVICE_URLS["traffic_monitor"] + "/health", timeout=15)
        pretty_print_response(resp, label="GET /health (traffic_monitor)")
    except Exception as exc:
        print(f"ERROR calling traffic_monitor /health: {exc}")

    print("Note: starting Zeek/tcpdump requires additional privileges and JWT;\n"
          "for the video demo you can just show /health and optionally /statistics\n"
          "once a capture is running.")


def run_module_12() -> None:
    """Module 12 – Secure API & rate limiting (backend + traffic_monitor)."""

    print_header("Module 12: backend /api/health (unauthenticated)")
    try:
        resp = requests.get(f"{BACKEND_URL}/api/health", timeout=15)
        pretty_print_response(resp, label="GET /api/health")
    except Exception as exc:
        print(f"ERROR calling /api/health: {exc}")

    print_header("Module 12: hit /api/test/rate-limit multiple times to trigger 429")
    url = f"{BACKEND_URL}/api/test/rate-limit"
    for i in range(4):
        try:
            resp = requests.get(url, timeout=10)
            pretty_print_response(resp, label=f"GET /api/test/rate-limit (try {i+1})")
        except Exception as exc:
            print(f"ERROR calling /api/test/rate-limit: {exc}")

    print_header("Module 12: traffic_monitor /health")
    try:
        resp = requests.get(SERVICE_URLS["traffic_monitor"] + "/health", timeout=15)
        pretty_print_response(resp, label="GET /health (traffic_monitor)")
    except Exception as exc:
        print(f"ERROR calling traffic_monitor /health: {exc}")


MODULE_RUNNERS: Dict[str, Callable[[], None]] = {
    "3": run_module_3,
    "4": run_module_4,
    "5": run_module_5,
    "6": run_module_6,
    "8": run_module_8,
    "9": run_module_9,
    "10": run_module_10,
    "11": run_module_11,
    "12": run_module_12,
}


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run demo API calls for a given module (for video recording)",
    )
    parser.add_argument(
        "module",
        metavar="MODULE_ID",
        help="Module number to test (e.g. 3, 4, 5, 6, 8, 9, 10, 11, 12)",
    )

    args = parser.parse_args(argv)
    mod = str(args.module)
    runner = MODULE_RUNNERS.get(mod)
    if not runner:
        print(f"Unknown or unsupported module id: {mod}")
        print("Supported modules:", ", ".join(sorted(MODULE_RUNNERS.keys())))
        return 1

    try:
        runner()
        print("\nDone. Check your Docker logs for each service to show in the video.")
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
