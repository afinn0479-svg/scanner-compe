"""
aggregator — menerima findings mentah dari semua tester (subdomain-finder,
port-scanner, sqli-tester, xss-tester, session-checker), dedup, klasifikasi
severity, dan mapping ke kategori OWASP Top 10 (2021). Murni rule-based,
deterministik, tidak melakukan request apa pun ke target -- cuma mengolah
data yang sudah dikirim.
"""

import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Mapping sumber temuan -> kategori OWASP Top 10:2021.
# Beberapa source bisa punya lebih dari satu kategori tergantung isi finding,
# jadi mapping detail dilakukan per-finding di classify_owasp().
SOURCE_DEFAULT_OWASP = {
    "subdomain_finder": "Recon / Attack Surface Discovery (non-OWASP)",
    "port_scanner": "A05:2021 - Security Misconfiguration",
    "sqli_tester": "A03:2021 - Injection",
    "xss_tester": "A03:2021 - Injection",
    "session_checker": "A05:2021 - Security Misconfiguration",
}


def classify_owasp(finding):
    source = finding.get("source", "")
    # override khusus: JWT alg=none itu kegagalan kriptografi, bukan misconfig biasa
    issues = finding.get("issues", []) or []
    if source == "session_checker" and any("alg='none'" in i for i in issues):
        return "A02:2021 - Cryptographic Failures"
    return SOURCE_DEFAULT_OWASP.get(source, "Uncategorized")


def dedup_key(finding):
    return (
        finding.get("source"),
        finding.get("target_id"),
        finding.get("url"),
        finding.get("param") or finding.get("cookie_name") or "",
    )


def dedup_findings(findings):
    seen = {}
    for f in findings:
        key = dedup_key(f)
        # kalau ada duplikat, simpan yang severity-nya paling tinggi
        if key not in seen or SEVERITY_RANK.get(f.get("severity", "info"), 0) > SEVERITY_RANK.get(
            seen[key].get("severity", "info"), 0
        ):
            seen[key] = f
    return list(seen.values())


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "aggregator"})


@app.route("/aggregate", methods=["POST"])
def aggregate():
    payload = request.get_json(silent=True) or {}
    target_id = payload.get("target_id")
    raw_findings = payload.get("findings", [])

    if not target_id:
        return jsonify({"error": "target_id wajib diisi"}), 400
    if not isinstance(raw_findings, list):
        return jsonify({"error": "findings harus berupa list"}), 400

    # buang finding yang cuma noise (severity info tanpa issues, kalau ada field 'error' skip juga)
    usable = [f for f in raw_findings if isinstance(f, dict) and "error" not in f]
    errors = [f for f in raw_findings if isinstance(f, dict) and "error" in f]

    deduped = dedup_findings(usable)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    owasp_summary = {}
    enriched = []

    for f in deduped:
        sev = f.get("severity", "info")
        if sev not in severity_counts:
            sev = "info"
        severity_counts[sev] += 1

        category = classify_owasp(f)
        owasp_summary[category] = owasp_summary.get(category, 0) + 1

        enriched.append({**f, "owasp_category": category})

    highest_severity = "info"
    for sev in ["critical", "high", "medium", "low", "info"]:
        if severity_counts[sev] > 0:
            highest_severity = sev
            break

    report = {
        "run_id": str(uuid.uuid4()),
        "target_id": target_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(enriched),
        "severity_counts": severity_counts,
        "owasp_summary": owasp_summary,
        "highest_severity": highest_severity,
        "collection_errors": errors,
        "findings": enriched,
    }
    return jsonify(report)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
