"""
sqli-tester
===========
Deteksi SQL injection yang RINGAN dan TERKENDALI -- bukan wrapper sqlmap.
Cuma kirim 2 payload standar per test point (petik tunggal, boolean
klasik), bandingkan response dengan baseline, cari signature error SQL
umum. TIDAK ADA fungsi extract data, UNION-based dump, atau time-based
blind (SLEEP) di codebase ini sama sekali -- ini properti desain yang
sengaja, bukan kelalaian. detection_only bukan cuma label, itu satu-
satunya mode yang ADA.

Test point (URL + parameter yang mau dites) TIDAK di-auto-discover dari
crawling target -- itu terlalu tidak terkendali untuk target produksi.
Harus dikonfigurasi eksplisit di test_points.json per target_id. Kalau
kosong/tidak ada, service ini tidak menguji apa pun untuk target itu.

Sama seperti service lain: verifikasi ulang whitelist.json sendiri
(defense in depth), tidak percaya begitu saja input dari caller.

Endpoint:
  GET  /health
  POST /scan   body: {"target_id": str}
               return: {"allowed": bool, "reason": str, "findings": [...]}
"""

import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from flask import Flask, request, jsonify

WHITELIST_PATH = Path(os.environ.get("WHITELIST_PATH", "/app/whitelist.json"))
TEST_POINTS_PATH = Path(os.environ.get("TEST_POINTS_PATH", "/app/test_points.json"))
PLACEHOLDER_PATTERN = re.compile(r"^\s*ISI\s*:", re.IGNORECASE)
WIB = timezone(timedelta(hours=7))
STAGE = "sqli"
REQUEST_TIMEOUT = 15
DELAY_BETWEEN_REQUESTS = 0.5  # sopan ke target, jangan spam beruntun

# Hanya 2 payload -- petik tunggal (syntax breaker klasik) dan boolean
# klasik. TIDAK ADA payload time-based (SLEEP/WAITFOR) karena itu
# sengaja membebani database target, terlalu intrusive untuk detection_only.
PAYLOADS = ["'", "' OR '1'='1"]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query():",
    "ora-01756",
    "sqlite3.operationalerror",
    "supplied argument is not a valid mysql",
    "mysql_fetch",
    "microsoft ole db provider for odbc drivers",
    "odbc microsoft access driver",
]

app = Flask(__name__)


# ---------- Duplikat logic gate (defense in depth, sama seperti service lain) ----------

def load_whitelist() -> dict:
    if not WHITELIST_PATH.exists():
        raise FileNotFoundError(f"whitelist.json tidak ditemukan di {WHITELIST_PATH}")
    return json.loads(WHITELIST_PATH.read_text())


def is_placeholder(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        if not value.strip():
            return True
        if PLACEHOLDER_PATTERN.match(value):
            return True
    return False


def find_target(whitelist: dict, target_id: str):
    for t in whitelist.get("authorized_targets", []):
        if t.get("id") == target_id or t.get("host") == target_id:
            return t
    return None


def is_within_window(window_str: str):
    try:
        start_str, end_str = window_str.split("..")
        fmt = "%Y-%m-%d %H:%M"
        start = datetime.strptime(start_str.strip(), fmt).replace(tzinfo=WIB)
        end = datetime.strptime(end_str.strip(), fmt).replace(tzinfo=WIB)
    except (ValueError, AttributeError):
        return False, f"format authorized_window tidak dikenali: '{window_str}'"
    now = datetime.now(WIB)
    if start <= now <= end:
        return True, "dalam jendela waktu yang diizinkan"
    return False, f"di luar jendela waktu yang diizinkan ({start_str.strip()} s/d {end_str.strip()} WIB)"


def gate_check(target_id: str, stage: str):
    try:
        whitelist = load_whitelist()
    except FileNotFoundError as e:
        return False, str(e), None

    target = find_target(whitelist, target_id)
    if target is None:
        return False, f"target '{target_id}' tidak ada di whitelist.json (default: deny)", None

    allowed_stages = target.get("allowed_stages", [])
    excluded_stages = target.get("excluded_stages", [])
    if stage not in allowed_stages or stage in excluded_stages:
        return False, f"stage '{stage}' tidak diizinkan untuk target '{target_id}'", None

    if target.get("type") != "practice":
        auth_ref = target.get("authorization_ref")
        auth_window = target.get("authorized_window")
        if is_placeholder(auth_ref):
            return False, "authorization_ref masih placeholder/kosong", None
        if is_placeholder(auth_window):
            return False, "authorized_window masih placeholder/kosong", None
        within, reason = is_within_window(auth_window)
        if not within:
            return False, reason, None

    return True, "lolos gate check", target


# ---------- Konfigurasi test point (WAJIB eksplisit, tidak di-auto-discover) ----------

def load_test_points(target_id: str) -> list[dict]:
    if not TEST_POINTS_PATH.exists():
        return []
    all_points = json.loads(TEST_POINTS_PATH.read_text())
    return all_points.get(target_id, [])


# ---------- Deteksi ----------

def send_request(url: str, method: str, param: str, value: str,
                  extra_params: dict, cookies: dict) -> requests.Response:
    params = dict(extra_params)
    params[param] = value
    if method.upper() == "GET":
        return requests.get(url, params=params, cookies=cookies, timeout=REQUEST_TIMEOUT)
    return requests.post(url, data=params, cookies=cookies, timeout=REQUEST_TIMEOUT)


def test_single_point(point: dict) -> list[dict]:
    url = point["url"]
    method = point.get("method", "GET")
    param = point["param"]
    baseline_value = point.get("baseline", "1")
    extra_params = point.get("extra_params", {})
    cookies = point.get("cookies", {})
    now = datetime.now(timezone.utc).isoformat()

    findings = []

    baseline_resp = send_request(url, method, param, baseline_value, extra_params, cookies)
    baseline_text = (baseline_resp.text or "").lower()
    baseline_len = len(baseline_resp.text or "")

    for payload in PAYLOADS:
        time.sleep(DELAY_BETWEEN_REQUESTS)
        resp = send_request(url, method, param, payload, extra_params, cookies)
        text = (resp.text or "").lower()

        matched_sig = next(
            (sig for sig in SQLI_ERROR_SIGNATURES if sig in text and sig not in baseline_text),
            None,
        )
        if matched_sig:
            findings.append({
                "source": "sqli_tester",
                "url": url,
                "param": param,
                "payload": payload,
                "indicator": "error_signature",
                "detail": matched_sig,
                "confidence": "high",
                "mode": "detection_only",
                "detected_at": now,
            })
            continue

        # Sinyal lemah kedua: perbedaan panjang response signifikan
        # (boolean-based heuristic, lebih rawan false positive -- ditandai
        # confidence low supaya tidak disamaratakan dengan error_signature).
        length_diff_ratio = abs(len(text) - baseline_len) / max(baseline_len, 1)
        if length_diff_ratio > 0.3:
            findings.append({
                "source": "sqli_tester",
                "url": url,
                "param": param,
                "payload": payload,
                "indicator": "response_length_anomaly",
                "detail": f"baseline={baseline_len} chars, payload={len(text)} chars",
                "confidence": "low",
                "mode": "detection_only",
                "detected_at": now,
            })

    return findings


# ---------- HTTP layer ----------

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    target_id = payload.get("target_id")
    if not target_id:
        return jsonify({"allowed": False, "reason": "target_id wajib diisi", "findings": []}), 400

    allowed, reason, target = gate_check(target_id, STAGE)
    if not allowed:
        return jsonify({"allowed": False, "reason": reason, "findings": []})

    test_points = load_test_points(target_id)
    if not test_points:
        return jsonify({
            "allowed": True,
            "reason": "gate lolos, tapi tidak ada test point dikonfigurasi untuk target ini -- tidak ada yang dites",
            "target_id": target_id,
            "total_found": 0,
            "findings": [],
        })

    findings = []
    errors = []
    for point in test_points:
        try:
            findings.extend(test_single_point(point))
        except requests.RequestException as e:
            errors.append(f"{point.get('url', '?')}: {e}")

    return jsonify({
        "allowed": True,
        "reason": "sqli detection selesai" + (f" ({len(errors)} test point gagal)" if errors else ""),
        "target_id": target_id,
        "total_found": len(findings),
        "findings": findings,
        "errors": errors,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
