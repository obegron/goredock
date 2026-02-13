![sidewhale logo](assets/sidewhale-logo.png)

`sidewhale` is a small Docker API shim for unprivileged, containerized Testcontainers execution.

It is designed to run as a sidecar (for example in Kubernetes) so tests can use a Docker-compatible API without access to a host Docker socket.

It is not a container runtime and does not try to be Docker-compatible beyond what Testcontainers needs.

## Status

Early project. No compatibility or stability guarantees.

Current focus:

- Kubernetes sidecar usage
- Testcontainers integration tests
- Simple and deterministic behavior

## What Works Right Now

- Basic Testcontainers lifecycle (`create`, `start`, `inspect`, `logs`, `stop`, `delete`)
- Unix socket listener (default: `<state-dir>/docker.sock`) for in-container Docker clients
- Image pulling and rootfs extraction
- Port publishing through TCP proxying
- In-cluster sidecar run in k3d for PostgreSQL test (`DatabaseTest`) passed

## Known Gaps / Limitations

- No registry auth management beyond pass-through headers from clients
- Insecure registry configuration is not implemented as a runtime flag yet
- Oracle image currently fails under `proot` due missing syscall behavior
- Some clients may log noisy `Socket closed` traces when log-follow streams are closed
- No support for many Docker APIs (networks, volumes, build, exec/attach parity, etc.)

## Docker API Support Matrix

Implemented:

- `GET /_ping`
- `GET /version`
- `GET /info`
- `POST /images/create`
- `GET /images/json`
- `GET /images/{name}/json` (returns 404 when not present)
- `POST /containers/create`
- `POST /containers/{id}/start`
- `POST /containers/{id}/stop`
- `POST /containers/{id}/kill`
- `DELETE /containers/{id}`
- `GET /containers/{id}/json`
- `GET /containers/{id}/logs`
- `GET /containers/{id}/stats`
- `POST /containers/{id}/wait`
- `GET /containers/{id}/archive`
- `PUT /containers/{id}/archive`

Partially implemented / best-effort:

- `POST /exec/{id}/start`
- `GET /exec/{id}/json`

Not implemented:

- Most other Docker endpoints return `404`.

## Local Smoke Run

```bash
docker build -t sidewhale:dev .
docker run --rm --network host sidewhale:dev --listen :23750 --listen-unix /tmp/sidewhale/docker.sock
```

Then point Testcontainers (or any Docker API client) to:

```bash
DOCKER_HOST=tcp://127.0.0.1:23750

# Ryuk/inner clients can use:
# DOCKER_HOST=unix:///var/run/docker.sock
```

## Proxy + TLS Interception

Image pulls happen in the `sidewhale` process. Configure proxy and trust settings on the `sidewhale` container itself.

- Proxy env vars: `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`
- Optional insecure mode for intercepted TLS: `--trust-insecure`

Quick smoke test (build image first):

```bash
make image VERSION=dev IMAGE_NAME=sidewhale
make smoke-pull IMAGE_NAME=sidewhale VERSION=dev \
  SIDEWHALE_RUN_ARGS="--trust-insecure" \
  SMOKE_IMAGE=redis:7-alpine
```

Example with proxy env vars:

```bash
HTTPS_PROXY=http://proxy.corp:8080 \
HTTP_PROXY=http://proxy.corp:8080 \
NO_PROXY=127.0.0.1,localhost \
make smoke-pull IMAGE_NAME=sidewhale VERSION=dev \
  SIDEWHALE_RUN_ARGS="--trust-insecure"
```
