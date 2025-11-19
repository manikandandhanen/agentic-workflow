# Tools Server

The Tools Server exposes a Django REST API for registering upstream APIs, importing their schemas, and serving normalized “capabilities” that AI agents can safely invoke. It manages provider metadata, schema uploads, normalization, access grants, and cached capability snapshots for downstream MCP servers and automation agents.

## Core Capabilities
- **API Provider Registry** – Create and manage `ApiProvider` records that describe an upstream API surface (name, owner team, base URL, auth strategy, domain allow list).
- **Schema Intake & Discovery** – Upload OpenAPI specifications or fetch them from a URL as `SchemaSource` objects. Uploaded blobs are hashed, cached, and stored for repeated normalization.
- **Schema Normalization** – Parse OpenAPI v3 schemas into `NormalizedCapability` rows. The normalizer builds rich metadata (`wire` payload) so agents know how to call each tool: HTTP method, path, path/query/header maps, scopes, security requirements, request/response examples, and hints about required inputs.
- **Capability Versioning & Notifications** – Each normalization creates a new provider version, batches inserts, and triggers MCP notifications so connected agents hot-reload their tool catalogs.
- **Access Grants & Snapshots** – Teams receive curated capability snapshots (via `CapabilitySnapshotViewSet`) that respect `AccessGrant` approvals, risk level, and enabled flags. Responses are cached and ETagged for efficient polling.
- **Authentication & Governance** – Integrates with tenant-aware user accounts, service principals, JWT auth, and risk-level tracking to meter tool exposure.

## Project Structure
- `accounts/` – Tenant, team, and authentication models plus admin and management commands (e.g., service token minting).
- `core/` – Project settings, URL configuration (`/core/tools/` API namespace), health checks, and reusable mixins.
- `tools/` – API viewsets, serializers, permissions, schema normalization utilities, cached snapshot logic, and templates.
- `docker/`, `dev_docker/` – Container entrypoints and Dockerfiles for local development and production images.
- `manage.py` – Standard Django management entrypoint.

## Getting Started
1. **Clone & Configure**
   - Copy `.env` into `platform/tools-server/.env` and adjust database, Redis, and auth settings as needed.
   - Ensure Docker and Docker Compose are installed.
2. **Launch with Docker Compose**
   ```bash
   docker compose up -d
   ```
   Services include:
   - `core-tools-server` – Django application container (mapped to `localhost:8088` by default).
   - `db` – PostgreSQL 17 (port `5433` exposed).
   - `redis` – Redis 7 (port `6380` exposed).

## Build Initial Dependencies (Post-Deployment)
After containers are running, seed base data (tenants, teams, default roles, etc.) by executing:
```bash
docker exec -it core-tools-server python manage.py build_initial_deps
```
Re-run the command whenever you reset the database or provision a new environment.

## Normalizing API Schemas
1. **Create a Provider**
   ```bash
   curl -X POST http://localhost:8088/core/tools/providers/ \
     -H "Authorization: Bearer <JWT_OR_SERVICE_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Ticketing Provider",
       "owner_team": "<team_uuid>",
       "base_url": "https://ticketing.example.com/api",
       "auth_profile": "bearer_jwt"
     }'
   ```
2. **Upload an OpenAPI Schema**
   ```bash
   curl -X POST http://localhost:8088/core/tools/schemas/ \
     -H "Authorization: Bearer <token>" \
     -F provider=<provider_uuid> \
     -F kind=openapi \
     -F blob=@openapi.yaml
   ```
   Successful uploads trigger normalization and return a sample of the created capabilities, including the enriched `wire` metadata for agent consumption.
3. **(Optional) Discover from URL**
   ```bash
   curl -X POST http://localhost:8088/core/tools/schemas/discover/ \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "provider": "<provider_uuid>",
       "kind": "openapi",
       "url": "https://example.com/openapi.yaml"
     }'
   ```

## Accessing Capability Snapshots
- Use `/core/tools/capability-snapshots/` endpoints to fetch ETagged capability sets scoped to a team.
- Snapshots honor `AccessGrant` approvals and the `enabled` flag on capabilities.
- Cached responses reduce load; when the normalizer updates capabilities it invalidates the cache and notifies MCP listeners.

## Useful Management Commands
- `python manage.py build_initial_deps` – Seed baseline tenant/team/provider data.
- `python manage.py mint_service_token --team <team_slug>` – Create service principal tokens for automation.
- `python manage.py seed_miq_core_admin_account` – Provision an initial admin account when bootstrapping.

## Local Development Tips
- Run tests with `python manage.py test` or the pytest configuration defined in `pyproject.toml`.
- Log files are written under `platform/tools-server/logs/`; static assets under `static/`.
- When iterating on schema normalization, upload schemas via the API (or drop them into `schemas/`) and inspect the resulting `NormalizedCapability` rows in the database or through the API.
- Visit the Swagger UI [API Docs](http://localhost:8089/core/api/v1.0/docs/) and [API Schema](http://localhost:8089/core/api/v1.0/schema/json/)


## Troubleshooting
- **Health Check**: `GET http://localhost:8088/core/healthz/`.
- **Redis/Cache Issues**: Clear the normalization cache by flushing Redis; the normalizer will regenerate capability data on next upload.
- **Database Resets**: After dropping the Postgres volume, rerun migrations and `build_initial_deps`.
