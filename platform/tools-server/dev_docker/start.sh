#!/bin/bash

# ensure proper permissions inside container in case of host sync (e.g. develop.watch: sync)
WATCH_DIRS=$(find /app -mindepth 1 -maxdepth 1 -type d \
  ! -path "/app/logs" \
  ! -path "/app/.wdm" \
  ! -path "/app/flower" \
  ! -path "/app/media" \
  ! -path "/app/static")
(
    echo "Starting permission watcher..."
    while inotifywait -r -e create,modify,move $WATCH_DIRS; do
        echo "Fixing permissions..."
         find $WATCH_DIRS -type f ! -perm -u+w -exec chmod u+w {} + 2>/dev/null
         find $WATCH_DIRS -type d ! -perm -u+w -exec chmod u+w {} + 2>/dev/null
        sleep 0.5
    done
) &


if [ $# -eq 0 ]; then
    echo "Usage: start.sh [PROCESS_TYPE](server/beat/worker_light/worker_heavy/flower/service_bus/ws_forwarder)"
    exit 1
fi

PROCESS_TYPE=$1
CPU_COUNT=$(nproc)
WEB_CONCURRENCY=$((CPU_COUNT > 1 ? CPU_COUNT : 2))

if [ "$PROCESS_TYPE" = "server" ]; then
    >&2 echo "Starting Django server..."

    python3 manage.py migrate
    python3 manage.py collectstatic --noinput

    if [ "$DEBUG" = "True" ]; then
        echo "DJANGO_DEBUG --> $DEBUG"
        uvicorn core.asgi:application \
          --host 0.0.0.0 \
          --port 8005 \
          --reload \
          --reload-exclude "logs/*" \
          --reload-exclude "media/*" \
          --reload-exclude "static/*" \
          --reload-exclude ".wdm/*" \
          --loop uvloop \
          --http httptools \
          --proxy-headers --forwarded-allow-ips="*" \
          --log-level info 

    else
        uvicorn core.asgi:application \
          --host 0.0.0.0 \
          --port 8005 \
          --workers ${WEB_CONCURRENCY} \
          --loop uvloop \
          --http httptools \
          --proxy-headers --forwarded-allow-ips="*" \
          --log-level info 
    fi
elif [ "$PROCESS_TYPE" = "beat" ]; then
    >&2 echo "Starting Celery beat..."
    celery \
        --app core.celery_app \
        beat \
        --loglevel INFO \
        --scheduler django_celery_beat.schedulers:DatabaseScheduler
elif [ "$PROCESS_TYPE" = "flower" ]; then
    >&2 echo "Starting Celery flower..."
    celery \
        --app core.celery_app \
        flower \
        --basic_auth="${CELERY_FLOWER_USER}:${CELERY_FLOWER_PASSWORD}" \
        --port=5555 --persistent=True --db="/app/flower/flower.dat" \
        --state_save_interval=10000 \
        --loglevel INFO
elif [ "$PROCESS_TYPE" = "worker_heavy" ]; then
    >&2 echo "Starting Celery worker on queue ${HEAVY_QUEUE_NAME}..."
    celery \
        --app core.celery_app \
        worker \
        -Q "${HEAVY_QUEUE_NAME}" \
        --pool=prefork \
        -c 2 \
        --prefetch-multiplier 1 \
        --max-tasks-per-child 20 \
        -n heavy_worker@%h \
        --loglevel INFO 
elif [ "$PROCESS_TYPE" = "worker_light" ]; then
    >&2 echo "Starting Celery worker on queue ${LIGHT_QUEUE_NAME}..."
    celery \
        --app core.celery_app \
        worker \
        -Q "${LIGHT_QUEUE_NAME}" \
        --pool=prefork \
        -c ${WEB_CONCURRENCY} \
        --prefetch-multiplier 2 \
        --max-tasks-per-child 50 \
        -n light_worker@%h \
        --loglevel INFO
elif [ "$PROCESS_TYPE" = "service_bus" ]; then
    >&2 echo "Starting service bus listener..."
    python3 manage.py wrt_queue_listening 
elif [ "$PROCESS_TYPE" = "ws_forwarder" ]; then
    >&2 echo "Starting celery event forwarder..." 
    python3 manage.py celery_event_forwarder 
fi