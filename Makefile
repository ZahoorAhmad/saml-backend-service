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
	@echo "If you see KeyError: 'id' in watch_events — you are using legacy docker-compose v1."
	@echo "Use Compose v2 instead:"
	@echo "  docker compose up -d --build"
	@echo "  make up"
	@echo "  ./scripts/compose.sh up -d --build"
	@echo ""
	@echo "If Docker daemon is down after snap -> apt migration:"
	@echo "  make start-docker"
	@echo ""
	@echo "If plain 'docker compose' cannot stop containers:"
	@echo "  ./scripts/compose.sh up -d --force-recreate --build"
	@echo "  sudo docker compose down --remove-orphans"
