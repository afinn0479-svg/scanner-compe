#!/bin/bash
# dvwa_login.sh
# Login otomatis ke DVWA lewat curl, set security level ke low, print PHPSESSID.
# Jalankan langsung dari terminal VPS (tidak perlu browser/SSH tunnel).
#
# Usage: ./dvwa_login.sh [DVWA_URL]
#   default DVWA_URL = http://127.0.0.1:8081

set -e

DVWA_URL="${1:-http://127.0.0.1:8081}"
COOKIE_JAR=$(mktemp)
USERNAME="admin"
PASSWORD="password"

cleanup() { rm -f "$COOKIE_JAR"; }
trap cleanup EXIT

echo "1) Cek & inisialisasi database DVWA (Create/Reset Database)..." >&2
SETUP_PAGE=$(curl -s -c "$COOKIE_JAR" "$DVWA_URL/setup.php")
SETUP_TOKEN=$(echo "$SETUP_PAGE" | grep -oP "name='user_token' value='\K[^']+" || true)

if [ -n "$SETUP_TOKEN" ]; then
  curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$SETUP_TOKEN" \
    "$DVWA_URL/setup.php" > /dev/null
  echo "   database di-create/reset" >&2
else
  echo "   (tidak ada user_token di setup.php, lanjut asumsi db sudah siap)" >&2
fi

echo "2) Ambil halaman login + CSRF token..." >&2
LOGIN_PAGE=$(curl -s -c "$COOKIE_JAR" "$DVWA_URL/login.php")
TOKEN=$(echo "$LOGIN_PAGE" | grep -oP "name='user_token' value='\K[^']+" || true)

if [ -z "$TOKEN" ]; then
  echo "GAGAL: user_token tidak ditemukan di halaman login. Cek apakah DVWA_URL benar dan container hidup." >&2
  exit 1
fi
echo "   token: $TOKEN" >&2

echo "3) POST login..." >&2
curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  --data-urlencode "username=$USERNAME" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "Login=Login" \
  --data-urlencode "user_token=$TOKEN" \
  "$DVWA_URL/login.php" > /dev/null

CHECK=$(curl -s -b "$COOKIE_JAR" "$DVWA_URL/index.php")
if ! echo "$CHECK" | grep -qi "logout"; then
  echo "GAGAL: login tidak berhasil (halaman setelah login tidak mengandung 'Logout'). Cek username/password." >&2
  exit 1
fi
echo "   login sukses" >&2

echo "4) Set security level ke low..." >&2
SEC_PAGE=$(curl -s -b "$COOKIE_JAR" "$DVWA_URL/security.php")
SEC_TOKEN=$(echo "$SEC_PAGE" | grep -oP "name='user_token' value='\K[^']+" || true)

curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  --data-urlencode "security=low" \
  --data-urlencode "seclev_submit=Submit" \
  --data-urlencode "user_token=$SEC_TOKEN" \
  "$DVWA_URL/security.php" > /dev/null
echo "   security level di-set ke low" >&2

PHPSESSID=$(grep -oP "PHPSESSID\s+\K\S+" "$COOKIE_JAR" || true)
if [ -z "$PHPSESSID" ]; then
  echo "GAGAL: PHPSESSID tidak ditemukan di cookie jar setelah login." >&2
  exit 1
fi

echo "" >&2
echo "=== BERHASIL ===" >&2
echo "PHPSESSID=$PHPSESSID"
