#!/bin/bash
# 上传/更新证书到 SSL Manager
# 用法: ./upload-cert.sh <domain> <cert.pem> <key.pem> [chain.pem] [desc]
#
# 示例（Let's Encrypt）:
#   ./upload-cert.sh example.com \
#     /etc/letsencrypt/live/example.com/cert.pem \
#     /etc/letsencrypt/live/example.com/privkey.pem \
#     /etc/letsencrypt/live/example.com/chain.pem \
#     "Let's Encrypt 2025"

set -euo pipefail
BASE="${SSL_MANAGER_URL:-http://localhost:8080}"
TOKEN="${SSL_MANAGER_TOKEN:-}"
DOMAIN="$1"; CERT="$2"; KEY="$3"
CHAIN="${4:-}"; DESC="${5:-}"

[[ -z "$DOMAIN" || -z "$CERT" || -z "$KEY" ]] && {
  echo "Usage: $0 <domain> <cert.pem> <key.pem> [chain.pem] [description]"
  exit 1
}
[[ -f "$CERT" ]] || { echo "❌ cert not found: $CERT"; exit 1; }
[[ -f "$KEY"  ]] || { echo "❌ key not found: $KEY";  exit 1; }

# JSON-escape file content via python3
j() { python3 -c "import sys,json; print(json.dumps(open(sys.argv[1]).read()))" "$1"; }

CHAIN_JSON='""'
[[ -n "$CHAIN" && -f "$CHAIN" ]] && CHAIN_JSON=$(j "$CHAIN")

BODY=$(printf '{"domain":%s,"cert_pem":%s,"key_pem":%s,"chain_pem":%s,"description":%s}' \
  "$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$DOMAIN")" \
  "$(j "$CERT")" "$(j "$KEY")" "$CHAIN_JSON" \
  "$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$DESC")")

HEADERS=(-H "Content-Type: application/json")
[[ -n "$TOKEN" ]] && HEADERS+=(-H "Authorization: Bearer $TOKEN")

echo "📤 Uploading $DOMAIN → $BASE"
curl -sfS -w "\n" -X POST "${HEADERS[@]}" -d "$BODY" "$BASE/api/v1/certs" | python3 -m json.tool
