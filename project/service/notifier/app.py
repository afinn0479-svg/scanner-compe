"""
notifier — menerima laporan teragregasi (output dari aggregator) dan
mengirimkannya lewat email (SMTP) + WhatsApp (HTTP gateway, contoh: Fonnte).
Tidak melakukan scanning apa pun -- murni formatting + dispatch pesan.

Kalau kredensial SMTP/WA tidak lengkap di .env, service ini TIDAK crash --
cuma skip channel yang tidak terkonfigurasi dan laporkan di response
'delivery_status' supaya kelihatan di log/aggregator, bukan gagal diam-diam.
"""

import os
import smtplib
from email.mime.text import MIMEText

from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", SMTP_USER)
EMAIL_TO = os.environ.get("EMAIL_TO", "")

MAX_FINDINGS_IN_MESSAGE = 8


def format_message(report):
    target_id = report.get("target_id", "?")
    sev = report.get("severity_counts", {})
    highest = report.get("highest_severity", "info")
    owasp = report.get("owasp_summary", {})
    findings = report.get("findings", [])
    generated_at = report.get("generated_at", "")
    run_id = report.get("run_id", "")

    lines = [
        f"[Security Scan Report] target={target_id}",
        f"run_id: {run_id}",
        f"waktu: {generated_at}",
        f"highest severity: {highest.upper()}",
        f"total temuan: {report.get('total_findings', 0)}",
        "",
        "Severity breakdown:",
    ]
    for k in ["critical", "high", "medium", "low", "info"]:
        if sev.get(k, 0) > 0:
            lines.append(f"  - {k}: {sev[k]}")

    if owasp:
        lines.append("")
        lines.append("OWASP category breakdown:")
        for cat, count in owasp.items():
            lines.append(f"  - {cat}: {count}")

    if findings:
        lines.append("")
        lines.append(f"Top temuan (maks {MAX_FINDINGS_IN_MESSAGE}):")
        sorted_findings = sorted(
            findings,
            key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                f.get("severity", "info"), 0
            ),
            reverse=True,
        )
        for f in sorted_findings[:MAX_FINDINGS_IN_MESSAGE]:
            src = f.get("source", "?")
            sev_f = f.get("severity", "info")
            url = f.get("url", "")
            cat = f.get("owasp_category", "")
            lines.append(f"  [{sev_f.upper()}] {src} | {cat} | {url}")

    return "\n".join(lines)


def send_email(subject, body):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and EMAIL_TO):
        return {"sent": False, "reason": "SMTP env vars belum lengkap (SMTP_HOST/SMTP_USER/SMTP_PASS/EMAIL_TO)"}
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
        return {"sent": True}
    except Exception as e:
        return {"sent": False, "reason": str(e)}


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "notifier",
        "smtp_configured": bool(SMTP_HOST and SMTP_USER and SMTP_PASS and EMAIL_TO),
    })


@app.route("/notify", methods=["POST"])
def notify():
    report = request.get_json(silent=True) or {}
    if "target_id" not in report:
        return jsonify({"error": "body harus berupa report dari aggregator (butuh field target_id)"}), 400

    body = format_message(report)
    subject = f"[Scan Report] {report.get('target_id')} - severity tertinggi: {report.get('highest_severity','info').upper()}"

    email_result = send_email(subject, body)

    return jsonify({
        "delivery_status": {
            "email": email_result,
        },
        "message_preview": body,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
