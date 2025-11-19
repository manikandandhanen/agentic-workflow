FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1
        
WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=/app/pyproject.toml \
    --mount=type=bind,source=uv.lock,target=/app/uv.lock \
    uv sync --locked --no-install-project --no-dev 
    
COPY . .

RUN install -d -m 0755 /app/static/ /app/media/ /app/logs/ /app/schemas/

RUN chmod +x /app/docker/*.sh 

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS final

ARG USERNAME=qgpadmin
ARG USER_UID=1001
ARG USER_GID=1001

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

RUN groupadd -g ${USER_GID} ${USERNAME} && \
    useradd -u ${USER_UID} -g ${USER_GID} -m ${USERNAME}

COPY --from=builder --chown=${USERNAME}:${USERNAME} /app /app 

USER ${USERNAME}:${USERNAME}

CMD [ "docker/start.sh", "server" ]
