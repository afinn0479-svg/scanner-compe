#!/bin/bash
# test-all.sh -- jalankan scan ke target tertentu di semua service scanner
# dan tampilkan hasilnya berurutan.
#
# Pemakaian:
#   bash test-all.sh                  # test ke practice-target (default, aman)
#   bash test-all.sh school-domain    # test ke target production
#
# Untuk target production, script ini BENAR-BENAR mengirim request ke target
# asli kalau authorized_window sedang aktif dan test point sudah diisi.

set -e

TARGET="${1:-practice-target}"
SERVICES="subdomain-finder port-scanner sqli-tester xss-tester session-checker"

echo "======================================================"
echo " Testing pipeline terhadap target: $TARGET"
echo "======================================================"

for svc in $SERVICES; do
  echo ""
  echo "=== $svc ==="
  docker exec "$svc" python3 -c "
import urllib.request, json
body = json.dumps({'target_id': '$TARGET'}).encode()
req = urllib.request.Request(
    'http://127.0.0.1:5000/scan', data=body,
    headers={'Content-Type': 'application/json'}, method='POST'
)
try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(json.dumps(json.loads(resp.read()), indent=2))
except Exception as e:
    print(f'ERROR: {e}')
" || echo "GAGAL menjalankan $svc"
done

echo ""
echo "======================================================"
echo " Selesai. Cek satu per satu -- semua harus 'allowed: true'"
echo " untuk practice-target. Findings kosong = wajar kalau"
echo " test_points belum diisi lengkap."
echo "======================================================"
