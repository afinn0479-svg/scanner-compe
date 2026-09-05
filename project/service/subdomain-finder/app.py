"""
subdomain-finder
=================
Recon pasif sisi frontend. Untuk target non-internal, query Certificate
Transparency log publik (crt.sh) -- BUKAN request langsung ke target,
cuma nanya ke database pihak ketiga siapa saja subdomain yang pernah
diterbitkan sertifikatnya untuk domain ini. Untuk target internal_only
(practice/DVWA), dilewati -- tidak relevan untuk container lokal.

Sama seperti scope-gate, service ini TIDAK percaya begitu saja pada
request dari orchestrator -- dia verifikasi ulang ke whitelist.json
sendiri sebelum jalan (defense in depth, independen dari scope-gate).

Endpoint:
  GET  /health
  POST /scan   body: {"target_id": str}
               return: {"allowed": bool, "reason": str, "findings": [...]}
"""

import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from flask import Flask, request, jsonify

WHITELIST_PATH = Path(os.environ.get("WHITELIST_PATH", "/app/whitelist.json"))
PLACEHOLDER_PATTERN = re.compile(r"^\s*ISI\s*:", re.IGNORECASE)
WIB = timezone(timedelta(hours=7))
STAGE = "subdomain"
CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 20

app = Flask(__name__)


# ---------- Duplikat logic gate dari scope-gate (defense in depth) ----------

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
    """Return (allowed: bool, reason: str, target: dict|None)."""
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


# ---------- Logic recon pasif ----------

def query_crtsh(domain: str) -> list[str]:
    """Query crt.sh (agregator CT log publik). Ini nanya ke pihak ketiga,
    bukan request ke target sama sekali."""
    resp = requests.get(
        CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=CRTSH_TIMEOUT
    )
    resp.raise_for_status()
    entries = resp.json()

    subdomains = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name and domain in name:
                subdomains.add(name)
    return sorted(subdomains)


def run_subdomain_scan(target: dict) -> list[dict]:
    if target.get("internal_only"):
        return []  # target lokal (practice), tidak ada subdomain publik yang relevan

    host = target["host"]
    subdomains = query_crtsh(host)
    now = datetime.now(timezone.utc).isoformat()

    return [
        {
            "source": "subdomain_finder",
            "target_id": target["id"],
            "subdomain": sub,
            "method": "certificate_transparency",
            "detected_at": now,
        }
        for sub in subdomains
    ]


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

    try:
        findings = run_subdomain_scan(target)
    except requests.RequestException as e:
        return jsonify({"allowed": True, "reason": f"gate lolos tapi crt.sh gagal: {e}", "findings": []}), 502

    return jsonify({
        "allowed": True,
        "reason": "recon pasif selesai",
        "target_id": target_id,
        "total_found": len(findings),
        "findings": findings,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
