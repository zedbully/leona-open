#!/usr/bin/env bash
set -euo pipefail

: "${LEONA_ADMIN_BASE_URL:=http://127.0.0.1:8083}"
: "${LEONA_LOCAL_TENANT_NAME:=leona-sdk-local-$(date +%Y%m%d-%H%M%S)}"
: "${LEONA_LOCAL_KEY_OUTPUT:=exports}"

response="$(
  curl -fsS \
    -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"${LEONA_LOCAL_TENANT_NAME}\"}" \
    "${LEONA_ADMIN_BASE_URL%/}/v1/admin/tenants"
)"

python3 - "$LEONA_LOCAL_KEY_OUTPUT" "$response" <<'PY'
import json
import shlex
import sys

mode = sys.argv[1].strip().lower()
payload = json.loads(sys.argv[2])

tenant_id = payload["tenantId"]
name = payload["name"]
key_pair = payload["keyPair"]
app_key = key_pair["appKey"]
secret_key = key_pair["secretKey"]

if mode == "appkey":
    print(app_key)
elif mode == "json":
    print(json.dumps({
        "tenantId": tenant_id,
        "name": name,
        "appKey": app_key,
        "secretKey": secret_key,
    }, ensure_ascii=False, indent=2))
else:
    print(f"export LEONA_API_KEY={shlex.quote(app_key)}")
    print(f"export LEONA_SERVER_TENANT_ID={shlex.quote(tenant_id)}")
    print(f"export LEONA_SERVER_TENANT_NAME={shlex.quote(name)}")
    print(f"export LEONA_SERVER_SECRET_KEY={shlex.quote(secret_key)}")
PY
