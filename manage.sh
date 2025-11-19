#!/bin/bash

# Usage: ./manage.sh <action> <env>
# Example: ./manage.sh start dev

ACTION="$1"
ENV="$2"

if [ -z "$ACTION" ] || [ -z "$ENV" ]; then
  echo "Usage: $0 <start|stop|restart> <dev|prod>"
  exit 1
fi

if [ "$ENV" = "dev" ]; then
  COMPOSE_FILE="-f .dev/docker-compose.yml"
  ENV_FILE="--env-file=./platform/tools-server/.env.dev"
else
  COMPOSE_FILE=""
  ENV_FILE=""
fi

case "$ACTION" in
  start)
    if [ "$ENV" = "dev" ]; then
      docker compose $COMPOSE_FILE $ENV_FILE up --build
    else
      docker compose up -d --build
      docker compose logs -fn100
    fi
    ;;
  stop)
    if [ "$ENV" = "dev" ]; then
      docker compose $COMPOSE_FILE $ENV_FILE down
    else
      docker compose down
    fi
    ;;
  restart)
    "$0" stop "$ENV"
    "$0" start "$ENV"
    ;;
  *)
    echo "Unknown action: $ACTION"
    echo "Usage: $0 <start|stop|restart> <dev|prod>"
    exit 1
    ;;
esac
