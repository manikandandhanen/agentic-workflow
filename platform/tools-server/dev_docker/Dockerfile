FROM python:3.12-slim

ENV UV_LINK_MODE=copy
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Change the working directory to the `app` directory
WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

# Copy the project into the image
ADD . /app

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

RUN install -d -m 0755 /app/static/ /app/media/ /app/logs/ /app/schemas/

ARG USERNAME=qgpadmin
ARG USER_UID=1001
ARG USER_GID=1001

RUN groupadd -g ${USER_GID} ${USERNAME} && \
    useradd -u ${USER_UID} -g ${USER_GID} -m ${USERNAME}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="./.venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    inotify-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
    
RUN chmod -R a+rwX /app/static /app/media 
RUN chmod +x dev_docker/start.sh

USER ${USERNAME}:${USERNAME}

# CMD [ "uv", "run", "uvicorn", "core.wsgi:application", "--host", "0.0.0.0", "--port", "8000", "--reload" ]
CMD [ "/app/dev_docker/start.sh", "server" ]