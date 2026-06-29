#!/usr/bin/env bash
set -euo pipefail

echo "Resetting failed Docker units..."
sudo systemctl reset-failed docker.socket docker.service 2>/dev/null || true

echo "Starting Docker socket and daemon..."
sudo systemctl start docker.socket
sudo systemctl start docker
sudo systemctl enable docker.socket docker.service

echo
if docker info &>/dev/null; then
  echo "Docker is running."
  docker info | sed -n '1,8p'
else
  echo "Docker still not reachable. Check logs:" >&2
  echo "  sudo journalctl -u docker.service -n 30 --no-pager" >&2
  exit 1
fi
