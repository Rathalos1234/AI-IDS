#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release git nginx

if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg \
    | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  source /etc/os-release
  ARCH=$(dpkg --print-architecture)
  cat <<DOCKER_REPO | tee /etc/apt/sources.list.d/docker.list >/dev/null
deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID $VERSION_CODENAME stable
DOCKER_REPO

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

systemctl enable --now docker
systemctl enable --now nginx

REPO_DEST="/opt/ai-ids"
DEPLOY_USER="${SUDO_USER:-root}"

install -d -m 755 "$REPO_DEST"

mkdir -p "$REPO_DEST/data" "$REPO_DEST/logs" "$REPO_DEST/models" "$REPO_DEST/ssl" "$REPO_DEST/ui/dist"
chown -R "$DEPLOY_USER":"$DEPLOY_USER" "$REPO_DEST"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/nginx.conf" ]; then
  cp "$SCRIPT_DIR/nginx.conf" /etc/nginx/nginx.conf
  systemctl restart nginx
fi

echo "Server bootstrap complete. Deployment directory prepared at $REPO_DEST."