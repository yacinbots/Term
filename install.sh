#!/usr/bin/env bash
# Rotating Proxy Gateway — VPS install script
# Ubuntu 22.04+ | Python 3.11+ required
set -euo pipefail

echo "════════════════════════════════════════"
echo "  Rotating Proxy Gateway — Install"
echo "════════════════════════════════════════"

# ── 1. System deps ────────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y -qq python3.11 python3.11-venv python3-pip

# ── 2. Dedicated user (no login shell, no home) ───────────────────────────────
if ! id proxyuser &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin proxyuser
    echo "  Created user: proxyuser"
fi

# ── 3. Install directory ──────────────────────────────────────────────────────
mkdir -p /opt/proxy-gateway
cp gateway.py /opt/proxy-gateway/
cp requirements.txt /opt/proxy-gateway/

# ── 4. Virtualenv + deps ──────────────────────────────────────────────────────
python3.11 -m venv /opt/proxy-gateway/venv
/opt/proxy-gateway/venv/bin/pip install --upgrade pip -q
/opt/proxy-gateway/venv/bin/pip install -r /opt/proxy-gateway/requirements.txt -q

# ── 5. Capability: bind port 443 without root ─────────────────────────────────
setcap 'cap_net_bind_service=+ep' /opt/proxy-gateway/venv/bin/python3.11

# ── 6. Ownership ──────────────────────────────────────────────────────────────
chown -R proxyuser:proxyuser /opt/proxy-gateway

# ── 7. Systemd ────────────────────────────────────────────────────────────────
cp proxy-gateway.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable proxy-gateway
systemctl restart proxy-gateway

# ── 8. Firewall (ufw) — open 443 if ufw is active ───────────────────────────
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 443/tcp comment "proxy-gateway"
    echo "  ufw: port 443 opened"
fi

echo ""
echo "════════════════════════════════════════"
echo "  Install complete."
echo ""
echo "  Proxy endpoint:"
echo "  http://bendjara.duckdns.org:443"
echo "  Auth: yacin:bendjara"
echo ""
echo "  Logs:"
echo "  journalctl -u proxy-gateway -f"
echo "════════════════════════════════════════"

systemctl status proxy-gateway --no-pager
