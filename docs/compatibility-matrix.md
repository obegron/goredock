# Sidewhale Compatibility Matrix (Host Backend)

Last updated: 2026-02-14

This matrix reflects what we validated in the current upstream test loop (`testcontainers-java` + Sidewhale host backend with `proot`).

Status legend:

- `Confirmed`: validated in our recent runs
- `Partial`: works for some cases; known gaps remain
- `Unsupported`: outside current host-backend scope

## Docker API / Behavior

| Area | Status | Notes |
|---|---|---|
| Container lifecycle (`create/start/stop/delete/inspect`) | Confirmed | Core Testcontainers path is stable. |
| Image pull (`/images/create`) | Confirmed | Streaming progress implemented; digest/local mirror flows exercised. |
| Logs (`/containers/{id}/logs`) | Confirmed | Non-stream and follow flows used in upstream tests. |
| Wait/state (`/containers/{id}/wait`, running status) | Confirmed | Wait/error-state behavior exercised in core tests. |
| Port publishing | Confirmed | Host TCP proxy mapping used broadly across modules. |
| Networks API surface | Partial | Basic endpoints exist, but no real Docker network namespace semantics. |
| Cross-container DNS/service discovery | Unsupported | No embedded DNS; name-based cluster discovery is a known gap. |

## Testcontainers Java Modules

| Module / Test Area | Status | Notes |
|---|---|---|
| Core (`DockerClientFactoryTest`, `ContainerStateTest`, `ImagePullTest`, logs/wait-focused tests) | Confirmed | Core correctness loop repeatedly exercised. |
| PostgreSQL | Confirmed | Project acceptance target; repeatedly validated. |
| Redis (module + smoke variants) | Confirmed | Single-container and repeated smoke runs validated. |
| MySQL | Confirmed | Module tests executed successfully in host mode. |
| MariaDB | Confirmed | Module tests executed successfully in host mode. |
| MSSQL Server | Confirmed | Module tests executed successfully; marked useful target runtime. |
| Vault | Confirmed | Passed after mirroring required images. |
| Solr | Confirmed | Module tests executed successfully in recent loop. |
| JUnit Jupiter integration tests (selected) | Confirmed | Selected inheritance/restart tests validated. |
| MockServer | Partial | Image/runtime path tested; not yet fully closed as stable baseline. |
| Nginx module | Partial | Works only with Sidewhale nginx compat handling; privileged-port behavior is image-sensitive. |
| LDAP (LLDAP) | Partial | Startup behavior improved, but reliability issues remain (bind/process cleanup edge cases). |
| Kafka (single container) | Partial | Some single-node flows can run; cluster scenarios are limited by DNS/network semantics. |
| Kafka cluster examples | Unsupported | Requires container-to-container name resolution/network behavior not provided by host backend. |
| Cassandra | Partial | Hostname/name-resolution sensitivity observed (`UnknownHostException` patterns). |
| Oracle Free | Unsupported | Not reliable under current `proot` constraints. |
| DB2 | Unsupported | Startup/instance setup constraints not satisfied under current runtime model. |
| Compose-based tests | Unsupported | Compose/network feature set is intentionally out of scope. |
| ImageFromDockerfile/build flows | Unsupported | Build API not in MVP scope. |

## Practical Guidance

Best fit today:

- single-container dependency services used by application tests
- JDBC/Redis-like modules that only need lifecycle, ports, logs, and inspect
- mirrored-image environments where external pull pressure is controlled

Known non-fit today:

- distributed cluster tests that depend on Docker DNS/network semantics
- modules/images requiring privileged internal bind behavior without adaptation
- heavy runtime/kernel-sensitive images (for example Oracle/DB2 class)

## Scope Statement

Current Sidewhale target is:

- **High correctness for host-backend Testcontainers essentials**
- **Not** full Docker runtime/network parity

If networking parity becomes a hard requirement, treat it as a separate major milestone rather than incremental tweaks.
