.PHONY: up down logs recreate fix-docker start-docker

up:
	./scripts/docker-up.sh

down:
	./scripts/compose.sh down --remove-orphans

recreate:
	./scripts/compose.sh up -d --force-recreate --build

logs:
	./scripts/compose.sh logs -f

start-docker:
	./scripts/start-docker.sh

fix-docker:
	@echo "If Docker daemon is down after snap -> apt migration:"
	@echo "  make start-docker"
	@echo ""
	@echo "If plain 'docker compose' cannot stop containers:"
	@echo "  ./scripts/compose.sh up -d --force-recreate --build"
	@echo "  sudo docker compose down --remove-orphans"
