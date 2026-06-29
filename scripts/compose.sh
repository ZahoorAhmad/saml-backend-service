#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# shellcheck source=scripts/docker-env.sh
source "${ROOT_DIR}/scripts/docker-env.sh"
detect_docker_commands

exec "${COMPOSE[@]}" "$@"
