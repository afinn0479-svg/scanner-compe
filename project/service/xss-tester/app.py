"""
xss-tester
==========
Deteksi REFLECTED XSS yang ringan dan terkendali. Kirim payload dengan
canary unik (nama tag palsu yang mustahil ada secara alami di halaman
manapun) ke parameter yang dikonfigurasi, cek apakah payload itu
terpantul balik di response TANPA di-escape.

SENGAJA HANYA reflected XSS (parameter yang langsung terpantul di
response yang sama) -- BUKAN stored XSS (form yang disimpan ke database,
mis. kolom komentar/guestbook). Test stored XSS ke target produksi bisa
meninggalkan payload permanen di database sampai dibersihkan manual --
risiko yang tidak sepadan untuk kebutuhan deteksi. Kalau perlu uji stored
XSS, itu di luar scope service ini dan butuh proses cleanup terpisah.

Test point WAJIB dikonfigurasi eksplisit di xss_test_points.json per
target_id -- TIDAK di-auto-discover dari crawling target. Kosong = tidak
ada yang dites.

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
import secrets
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from flask import Flask, request, jsonify

WHITELIST_PATH = Path(os.environ.get("WHITELIST_PATH", "/app/whitelist.json"))
TEST_POINTS_PATH = Path(os.environ.get("TEST_POINTS_PATH", "/app/xss_test_points.json"))
PLACEHOLDER_PATTERN = re.compile(r"^\s*ISI\s*:", re.IGNORECASE)
WIB = timezone(timedelta(hours=7))
STAGE = "xss"
REQUEST_TIMEOUT = 15
DELAY_BETWEEN_REQUESTS = 0.5  # sopan ke target, jangan spam beruntun

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

def make_canary() -> str:
    """Nama tag palsu unik -- mustahil muncul di halaman manapun secara
    alami, jadi kalau ketemu di response berarti pasti dari payload kita."""
    return "xssdet" + secrets.token_hex(6)


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
    extra_params = point.get("extra_params", {})
    cookies = point.get("cookies", {})
    now = datetime.now(timezone.utc).isoformat()

    findings = []

    # Dua varian payload, canary baru tiap payload supaya tidak ambigu:
    # 1. Tag injection langsung
    # 2. Keluar dari konteks atribut HTML dulu (") baru inject tag
    for payload_type in ["tag_injection", "attribute_break"]:
        time.sleep(DELAY_BETWEEN_REQUESTS)
        canary = make_canary()
        if payload_type == "tag_injection":
            payload = f"<{canary}>"
        else:
            payload = f"\"><{canary} x={canary}>"

        resp = send_request(url, method, param, payload, extra_params, cookies)
        text = resp.text or ""

        raw_marker = f"<{canary}"
        if raw_marker in text:
            findings.append({
                "source": "xss_tester",
                "url": url,
                "param": param,
                "payload_type": payload_type,
                "payload": payload,
                "indicator": "unescaped_reflection",
                "detail": f"canary '{canary}' terpantul di response tanpa di-escape (< dan > tidak dikonversi ke entity HTML)",
                "confidence": "high",
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
        "reason": "xss detection selesai" + (f" ({len(errors)} test point gagal)" if errors else ""),
        "target_id": target_id,
        "total_found": len(findings),
        "findings": findings,
        "errors": errors,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
