#!/bin/bash
set -euo pipefail

MITM_PROXY_PORT=8080
MITM_CONTROL_PORT=8081
MITM_LOG="/tmp/mitm_startup.log"
MITM_CONF_DIR="/home/pentester/.mitmproxy"
MITM_FLOWS_DIR="/workspace/.mitm"
MITM_SCRIPT="/opt/kael-python/mitm_addon.py"
READY_FILE="/tmp/kael-ready"

# A container can be running before the proxy and trust stores are ready. The
# host waits for this marker before handing the sandbox to an agent.
rm -f "$READY_FILE"

if [ ! -f "$MITM_SCRIPT" ]; then
  echo "ERROR: mitmproxy addon not found at $MITM_SCRIPT."
  exit 1
fi

mkdir -p "$MITM_FLOWS_DIR" "$MITM_CONF_DIR"
chown pentester:pentester "$MITM_FLOWS_DIR" "$MITM_CONF_DIR" 2>/dev/null || true

echo "Starting mitmproxy on port ${MITM_PROXY_PORT} (control: ${MITM_CONTROL_PORT})..."
# The published container port is bound to host loopback by the runtime; the
# in-container server listens on all container interfaces so forwarding works.
setsid -w sudo -u pentester env \
  HOME=/home/pentester \
  PYTHONUNBUFFERED=1 \
  KAEL_MITM_FLOWS_PATH="${MITM_FLOWS_DIR}/flows.jsonl" \
  KAEL_MITM_SCOPES_PATH="${MITM_FLOWS_DIR}/scopes.json" \
  KAEL_MITM_CONTROL_HOST=0.0.0.0 \
  KAEL_MITM_CONTROL_PORT="${MITM_CONTROL_PORT}" \
  /usr/bin/mitmdump \
    --listen-port "${MITM_PROXY_PORT}" \
    --set confdir="${MITM_CONF_DIR}" \
    --scripts "${MITM_SCRIPT}" \
    --set "block_global=false" \
    < /dev/null > "$MITM_LOG" 2>&1 &
MITM_PID=$!
echo "Started mitmdump with PID $MITM_PID"

# Record diagnostics if mitmdump exits after startup.
(
  while kill -0 "$MITM_PID" 2>/dev/null; do
    sleep 5
  done
  echo "WARN: mitmdump (PID $MITM_PID) exited at $(date -u +%H:%M:%S)" >> "$MITM_LOG"
) &

MITM_READY=false
for i in {1..30}; do
  if ! kill -0 "$MITM_PID" 2>/dev/null; then
    echo "ERROR: mitmdump exited during startup (attempt $i)."
    break
  fi
  if curl -fsS "http://127.0.0.1:${MITM_CONTROL_PORT}/health" >/dev/null 2>&1; then
    echo "mitmproxy control API ready (attempt $i)."
    MITM_READY=true
    break
  fi
  sleep 1
done

if [ "$MITM_READY" != true ]; then
  echo "ERROR: mitmproxy control API did not become ready."
  echo "=== mitmproxy log tail ==="
  tail -n 50 "$MITM_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

# mitmproxy generates its CA on first startup. Install it for CLI tools and
# Chromium before the sandbox is marked ready.
MITM_CA="${MITM_CONF_DIR}/mitmproxy-ca-cert.pem"
for _ in {1..10}; do
  [ -f "$MITM_CA" ] && break
  sleep 0.5
done
if [ ! -f "$MITM_CA" ]; then
  echo "ERROR: mitmproxy CA not found at $MITM_CA."
  exit 1
fi

sudo cp "$MITM_CA" /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates >/dev/null 2>&1
echo "Installed mitmproxy CA into the system trust store."

sudo -u pentester mkdir -p /home/pentester/.pki/nssdb
if [ ! -f /home/pentester/.pki/nssdb/cert9.db ]; then
  echo "" | sudo -u pentester certutil -N \
    -d sql:/home/pentester/.pki/nssdb --empty-password
fi
sudo -u pentester certutil -D -n "mitmproxy CA" \
  -d sql:/home/pentester/.pki/nssdb 2>/dev/null || true
sudo -u pentester certutil -A -n "mitmproxy CA" -t "C,," \
  -i "$MITM_CA" -d sql:/home/pentester/.pki/nssdb
echo "Installed mitmproxy CA into the Chromium trust store."

export http_proxy="http://127.0.0.1:${MITM_PROXY_PORT}"
export https_proxy="$http_proxy"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$http_proxy"
export ALL_PROXY="$http_proxy"
export KAEL_MITM_CONTROL_URL="http://127.0.0.1:${MITM_CONTROL_PORT}"
export NO_PROXY="localhost,127.0.0.1"

mkdir -p /workspace/.agent-browser-screenshots
touch "$READY_FILE"
echo "Container ready"

cd /workspace
exec "$@"
