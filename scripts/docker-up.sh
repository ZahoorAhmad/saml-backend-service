#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# shellcheck source=scripts/docker-env.sh
source "${ROOT_DIR}/scripts/docker-env.sh"
detect_docker_commands

port_in_use() {
  local port="$1"
  if command -v ss &>/dev/null; then
    ss -tln | grep -q ":${port} "
    return $?
  fi
  if command -v lsof &>/dev/null; then
    lsof -iTCP:"${port}" -sTCP:LISTEN -t &>/dev/null
    return $?
  fi
  return 1
}

if ! "${COMPOSE[@]}" down --remove-orphans 2>/dev/null; then
  echo "Warning: could not stop previous compose project cleanly." >&2
fi

export FRONTEND_PORT="${FRONTEND_PORT:-3000}"
export BACKEND_PORT="${BACKEND_PORT:-8080}"

if port_in_use "${FRONTEND_PORT}" || port_in_use "${BACKEND_PORT}"; then
  echo "Ports ${FRONTEND_PORT} or ${BACKEND_PORT} are already in use." >&2
  echo "Stop the process using them, or run with different ports:" >&2
  echo "  FRONTEND_PORT=3001 BACKEND_PORT=8081 ./scripts/docker-up.sh" >&2
  exit 1
fi

"${COMPOSE[@]}" up -d --build "$@"

echo
echo "SAML stack is running:"
echo "  Frontend: http://localhost:${FRONTEND_PORT}"
echo "  Backend:  http://localhost:${BACKEND_PORT}"
