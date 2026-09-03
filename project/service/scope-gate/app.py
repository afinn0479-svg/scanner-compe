"""
scope-gate
==========
Gatekeeper wajib untuk pipeline Hermes. Default-deny: sebuah scan HANYA
lolos kalau target + stage yang diminta cocok dengan entry di
whitelist.json, dan (khusus target non-practice) authorization_ref &
authorized_window sudah diisi data ASLI -- bukan placeholder "ISI: ...".

Endpoint:
  GET  /health   -> cek service hidup
  POST /check    -> body: {"target_id": str, "stage": str}
                    return: {"allowed": bool, "reason": str, "mode": str|null}
"""

import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import Flask, request, jsonify

WHITELIST_PATH = Path(os.environ.get("WHITELIST_PATH", "/app/whitelist.json"))
PLACEHOLDER_PATTERN = re.compile(r"^\s*ISI\s*:", re.IGNORECASE)
WIB = timezone(timedelta(hours=7))

app = Flask(__name__)


def load_whitelist() -> dict:
    if not WHITELIST_PATH.exists():
        raise FileNotFoundError(f"whitelist.json tidak ditemukan di {WHITELIST_PATH}")
    return json.loads(WHITELIST_PATH.read_text())


def is_placeholder(value) -> bool:
    """Anggap None / string kosong / string 'ISI: ...' sebagai BELUM diisi."""
    if value is None:
        return True
    if isinstance(value, str):
        if not value.strip():
            return True
        if PLACEHOLDER_PATTERN.match(value):
            return True
    return False


def find_target(whitelist: dict, target_id: str) -> dict | None:
    for t in whitelist.get("authorized_targets", []):
        if t.get("id") == target_id or t.get("host") == target_id:
            return t
    return None


def is_within_window(window_str: str) -> tuple[bool, str]:
    """
    Format yang diharapkan: 'YYYY-MM-DD HH:MM..YYYY-MM-DD HH:MM' (WIB).
    Contoh: '2026-09-10 22:00..2026-09-10 23:00'
    Format tidak dikenali -> dianggap TIDAK valid (fail closed, bukan fail open).
    """
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


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/check", methods=["POST"])
def check():
    payload = request.get_json(silent=True) or {}
    target_id = payload.get("target_id")
    stage = payload.get("stage")

    if not target_id or not stage:
        return jsonify({"allowed": False, "reason": "target_id dan stage wajib diisi", "mode": None}), 400

    try:
        whitelist = load_whitelist()
    except FileNotFoundError as e:
        return jsonify({"allowed": False, "reason": str(e), "mode": None}), 500

    target = find_target(whitelist, target_id)
    if target is None:
        return jsonify({
            "allowed": False,
            "reason": f"target '{target_id}' tidak ada di whitelist.json (default: deny)",
            "mode": None,
        })

    allowed_stages = target.get("allowed_stages", [])
    excluded_stages = target.get("excluded_stages", [])
    if stage not in allowed_stages or stage in excluded_stages:
        return jsonify({
            "allowed": False,
            "reason": f"stage '{stage}' tidak diizinkan untuk target '{target_id}'",
            "mode": None,
        })

    # Target non-practice wajib punya bukti otorisasi yang benar-benar terisi
    if target.get("type") != "practice":
        auth_ref = target.get("authorization_ref")
        auth_window = target.get("authorized_window")

        if is_placeholder(auth_ref):
            return jsonify({
                "allowed": False,
                "reason": "authorization_ref masih placeholder/kosong -- wajib diisi nomor surat izin asli",
                "mode": None,
            })

        if is_placeholder(auth_window):
            return jsonify({
                "allowed": False,
                "reason": "authorized_window masih placeholder/kosong -- wajib diisi jendela waktu asli",
                "mode": None,
            })

        within, window_reason = is_within_window(auth_window)
        if not within:
            return jsonify({"allowed": False, "reason": window_reason, "mode": None})

    mode = None
    if stage == "sqli":
        mode = target.get("sqli_mode", "detection_only")
    elif stage == "xss":
        mode = target.get("xss_mode", "detection_only")

    return jsonify({"allowed": True, "reason": "lolos scope-gate", "mode": mode})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
