"""
session-checker — inspeksi PASIF terhadap cookie & token session.
Tidak pernah mencuri/menggunakan cookie siapa pun; hanya membaca flag
keamanan (HttpOnly, Secure, SameSite) dari response header, dan kalau
value-nya berbentuk JWT, decode bagian header (base64, publik, bukan
signature) untuk cek algoritma tanda tangan yang dipakai server sendiri.

Defense-in-depth: sama seperti service lain, verifikasi ulang whitelist.json
sendiri sebelum menyentuh target apa pun.
"""

import base64
import json
import os
from datetime import datetime, time as dtime

from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

WHITELIST_PATH = os.environ.get("WHITELIST_PATH", "/app/whitelist.json")
TEST_POINTS_PATH = os.environ.get("TEST_POINTS_PATH", "/app/session_test_points.json")


def load_json(path):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def is_placeholder(value):
    return (not value) or value.strip().upper().startswith("ISI:")


def in_authorized_window(window_str):
    try:
        date_part, rest = window_str.split(" ", 1)
        time_range = rest.split(" ")[0]
        start_s, end_s = time_range.split("-")
        now = datetime.now()
        if now.strftime("%Y-%m-%d") != date_part:
            return False
        sh, sm = map(int, start_s.split(":"))
        eh, em = map(int, end_s.split(":"))
        return dtime(sh, sm) <= now.time() <= dtime(eh, em)
    except Exception:
        return False


def check_scope(target_id, stage="session"):
    wl = load_json(WHITELIST_PATH)
    if wl is None:
        return False, "whitelist.json tidak ditemukan di service ini"

    targets = {t["id"]: t for t in wl.get("authorized_targets", [])}
    entry = targets.get(target_id)
    if entry is None:
        return False, f"target '{target_id}' tidak ada di whitelist.json (default: deny)"
    if stage not in entry.get("allowed_stages", []):
        return False, f"stage '{stage}' tidak diizinkan untuk target '{target_id}'"
    if stage in entry.get("excluded_stages", []):
        return False, f"stage '{stage}' ada di excluded_stages untuk target '{target_id}'"

    if entry.get("type") == "practice":
        return True, "lolos scope-gate (practice target)"

    if is_placeholder(entry.get("authorization_ref", "")):
        return False, "authorization_ref masih placeholder/kosong -- wajib diisi nomor surat izin asli"
    if is_placeholder(entry.get("authorized_window", "")):
        return False, "authorized_window masih placeholder/kosong"
    if not in_authorized_window(entry.get("authorized_window", "")):
        return False, f"di luar jendela waktu yang diizinkan ({entry.get('authorized_window')})"

    return True, "lolos scope-gate (production, dalam jendela izin)"


def decode_jwt_header_only(token_value):
    """Decode HANYA bagian header JWT (base64, informasi publik).
    Tidak pernah menyentuh/forge signature. Return dict header atau None."""
    parts = token_value.split(".")
    if len(parts) != 3:
        return None
    try:
        seg = parts[0]
        seg += "=" * (-len(seg) % 4)
        header_bytes = base64.urlsafe_b64decode(seg)
        return json.loads(header_bytes)
    except Exception:
        return None


def inspect_cookies(resp):
    findings = []
    for c in resp.cookies:
        has_httponly = c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly")
        same_site = c.get_nonstandard_attr("SameSite") or c.get_nonstandard_attr("samesite")
        issues = []
        if not c.secure:
            issues.append("missing Secure flag")
        if not has_httponly:
            issues.append("missing HttpOnly flag")
        if not same_site:
            issues.append("missing SameSite attribute")
        elif same_site.lower() == "none" and not c.secure:
            issues.append("SameSite=None tanpa Secure flag")

        jwt_header = decode_jwt_header_only(c.value) if c.value else None
        jwt_note = None
        if jwt_header is not None:
            alg = jwt_header.get("alg", "")
            if alg.lower() == "none":
                issues.append("JWT alg='none' -- signature bypass klasik")
            jwt_note = f"terdeteksi JWT, alg={alg}"

        severity = "high" if any("alg='none'" in i for i in issues) else (
            "medium" if issues else "info"
        )

        findings.append({
            "cookie_name": c.name,
            "secure": bool(c.secure),
            "http_only": bool(has_httponly),
            "same_site": same_site,
            "jwt_note": jwt_note,
            "issues": issues,
            "severity": severity,
        })
    return findings


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "session-checker", "mode": "passive_inspection"})


@app.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    target_id = payload.get("target_id")
    if not target_id:
        return jsonify({"error": "target_id wajib diisi"}), 400

    allowed, reason = check_scope(target_id, stage="session")
    if not allowed:
        return jsonify({"allowed": False, "reason": reason, "findings": []}), 200

    cfg = load_json(TEST_POINTS_PATH)
    if cfg is None:
        return jsonify({
            "allowed": True, "reason": reason,
            "error": "session_test_points.json tidak ditemukan di service ini",
            "findings": [],
        }), 200

    points = cfg.get(target_id, [])
    if not points:
        return jsonify({
            "allowed": True, "reason": reason, "findings": [],
            "note": f"tidak ada test point terdaftar untuk '{target_id}'",
        }), 200

    all_findings = []
    for tp in points:
        method = tp.get("method", "GET").upper()
        url = tp["url"]
        cookies = tp.get("cookies", {})
        try:
            if method == "GET":
                resp = requests.get(url, cookies=cookies, timeout=8)
            else:
                resp = requests.post(url, data=tp.get("extra_params", {}), cookies=cookies, timeout=8)
        except requests.RequestException as e:
            all_findings.append({"url": url, "error": str(e), "source": "session_checker", "target_id": target_id})
            continue

        for f in inspect_cookies(resp):
            f["url"] = url
            f["source"] = "session_checker"
            f["target_id"] = target_id
            all_findings.append(f)

    return jsonify({"allowed": True, "reason": reason, "findings": all_findings})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
