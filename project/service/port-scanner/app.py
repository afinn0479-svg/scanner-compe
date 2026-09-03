"""
port-scanner
============
Wrapper nmap untuk pipeline Hermes. Default: TCP connect scan (-sT, bukan
SYN/stealth), skip host-discovery ping (-Pn karena banyak server block
ICMP), dan hanya top-N port paling umum -- bukan full 65535 port. Untuk
target produksi (sekolah) ini pilihan sadar: traffic yang dikirim harus
terlihat sebagai koneksi TCP biasa, se-non-intrusive mungkin.

Target internal_only (practice/DVWA) boleh discan lebih dalam (top 1000
port) karena tidak ada risiko ke pihak luar.

Sama seperti service lain di pipeline ini: verifikasi ulang whitelist.json
sendiri (defense in depth), tidak percaya begitu saja input dari caller.

Endpoint:
  GET  /health
  POST /scan   body: {"target_id": str}
               return: {"allowed": bool, "reason": str, "findings": [...]}
"""

import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import Flask, request, jsonify

WHITELIST_PATH = Path(os.environ.get("WHITELIST_PATH", "/app/whitelist.json"))
PLACEHOLDER_PATTERN = re.compile(r"^\s*ISI\s*:", re.IGNORECASE)
WIB = timezone(timedelta(hours=7))
STAGE = "portscan"
NMAP_TIMEOUT = 120

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


# ---------- nmap ----------

def run_nmap(host: str, thorough: bool = False) -> list[dict]:
    top_ports = "1000" if thorough else "100"
    cmd = ["nmap", "-sT", "-Pn", "--top-ports", top_ports, "-oX", "-", host]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
    if result.returncode != 0:
        raise RuntimeError(f"nmap gagal (exit {result.returncode}): {result.stderr[:300]}")

    # nmap bisa exit 0 walau host gagal di-resolve ("0 hosts scanned") --
    # itu kegagalan, bukan hasil valid "tidak ada port terbuka". Jangan
    # sampai ini lolos sebagai 0 findings yang menyesatkan.
    if "Failed to resolve" in result.stderr or "0 hosts scanned" in result.stdout:
        raise RuntimeError(f"host '{host}' gagal di-resolve -- cek DNS/nama container: {result.stderr[:200]}")

    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(xml_output: str) -> list[dict]:
    root = ET.fromstring(xml_output)
    now = datetime.now(timezone.utc).isoformat()
    findings = []

    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            findings.append({
                "source": "port_scanner",
                "port": port_el.get("portid"),
                "protocol": port_el.get("protocol"),
                "state": "open",
                "service": service_el.get("name") if service_el is not None else "unknown",
                "product": (service_el.get("product") or "") if service_el is not None else "",
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

    host = target["host"]
    thorough = bool(target.get("internal_only"))

    try:
        findings = run_nmap(host, thorough=thorough)
    except (subprocess.TimeoutExpired, RuntimeError, ET.ParseError) as e:
        return jsonify({"allowed": True, "reason": f"gate lolos tapi nmap gagal: {e}", "findings": []}), 502

    return jsonify({
        "allowed": True,
        "reason": "port scan selesai",
        "target_id": target_id,
        "total_found": len(findings),
        "findings": findings,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
