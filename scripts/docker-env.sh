#!/usr/bin/env bash
set -euo pipefail

# Sets DOCKER and COMPOSE command arrays. Uses sudo when snap Docker cannot stop containers.
detect_docker_commands() {
  if docker compose version &>/dev/null; then
    COMPOSE=(docker compose)
  elif command -v docker-compose &>/dev/null; then
    COMPOSE=(docker-compose)
  else
    echo "Docker Compose is not installed." >&2
    exit 1
  fi

  DOCKER=(docker)
  CHECK_CONTAINER="docker-perm-check-${RANDOM}"

  cleanup_check_container() {
    "${DOCKER[@]}" rm -f "${CHECK_CONTAINER}" &>/dev/null || true
    sudo docker rm -f "${CHECK_CONTAINER}" &>/dev/null || true
  }

  trap cleanup_check_container RETURN

  if ! docker info &>/dev/null; then
    if ! systemctl is-active --quiet docker 2>/dev/null; then
      echo "Docker daemon is not running." >&2
      print_docker_daemon_fix
      exit 1
    fi
    echo "Cannot connect to Docker." >&2
    print_docker_daemon_fix
    exit 1
  fi

  if ! docker run -d --name "${CHECK_CONTAINER}" alpine sleep 30 &>/dev/null; then
    echo "Docker refused to start a test container." >&2
    print_docker_fix
    exit 1
  fi

  if docker stop "${CHECK_CONTAINER}" &>/dev/null && docker rm -f "${CHECK_CONTAINER}" &>/dev/null; then
    CHECK_CONTAINER=""
    trap - RETURN
    return 0
  fi

  if sudo docker stop "${CHECK_CONTAINER}" &>/dev/null && sudo docker rm -f "${CHECK_CONTAINER}" &>/dev/null; then
    CHECK_CONTAINER=""
    trap - RETURN
    DOCKER=(sudo docker)
    COMPOSE=(sudo docker compose)
    if ! sudo docker compose version &>/dev/null; then
      COMPOSE=(sudo docker-compose)
    fi
    echo "Using sudo for Docker (required to stop/recreate containers with snap Docker)." >&2
    return 0
  fi

  echo "Docker cannot stop containers without sudo." >&2
  echo "Run: sudo docker compose up -d --force-recreate --build" >&2
  echo "Or:  ./scripts/compose.sh up -d --force-recreate --build  (prompts for sudo password)" >&2
  print_docker_fix
  exit 1
}

print_docker_daemon_fix() {
  cat <<'EOF'
Start the apt Docker daemon (needed after removing snap docker):

  sudo systemctl reset-failed docker.socket docker.service
  sudo systemctl start docker.socket
  sudo systemctl start docker
  sudo systemctl enable docker.socket docker.service

Verify:

  docker info
  docker compose up -d --force-recreate --build
EOF
}

print_docker_fix() {
  cat <<'EOF'
Docker can start containers but cannot stop them. This breaks "docker compose up --force-recreate".

Snap Docker often has this issue. Fixes:

Option A (recommended): install Docker from apt instead of snap
  sudo snap remove --purge docker
  https://docs.docker.com/engine/install/ubuntu/

Option B: use the project wrapper (auto-sudo when needed)
  ./scripts/compose.sh up -d --force-recreate --build

Option C: run compose with sudo directly
  sudo docker compose up -d --force-recreate --build
EOF
}
