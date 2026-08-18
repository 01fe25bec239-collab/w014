# W-014 Systems Verification & Compliance — Foundation Platform

> **Portfolio Demonstration Notice**: This repository represents a portfolio demonstration foundation. It operates strictly within a **PUBLIC / SYNTHETIC / SANITIZED NON-CUI** boundary. All fixtures, configuration, and data are synthetic or sanitized non-sensitive public artifacts.

---

## 1. Project Purpose & Overview

The **W-014 Foundation Platform** provides the core architectural foundation, backend service composition, database persistence, observability infrastructure, and presentation shell for defense and enterprise compliance verification workflows.

The current implementation reflects the completed **Wave 0 / Vertical Slice 0 (W0 / VS0)** platform bootstrap. It establishes the authoritative system boundaries, monorepo workspace topology, local infrastructure orchestration, database migration harness, telemetry pipeline with automated credential redaction, and an accessible presentation client.

---

## 2. System Architecture & Authority Boundaries

```
                    ┌──────────────────────────────────────────────────────────┐
                    │                   Next.js Presentation                   │
                    │               (@w014/web / React 19 / TS)                │
                    │   - Presentation Shell & Command Client Only             │
                    │   - Holds ZERO domain authority or business truth        │
                    └─────────────────────────────┬────────────────────────────┘
                                                  │ HTTP (JSON / RFC 9457)
                                                  ▼
                    ┌──────────────────────────────────────────────────────────┐
                    │               Authoritative Rust Services                │
                    │            (w014-api / w014-worker / CLI)                │
                    │   - Sole authority for verification & state logic        │
                    │   - Enforces rules, authn/authz & data boundary          │
                    └──────────────┬────────────────────────────┬──────────────┘
                                   │ SQLx (PostgreSQL 18)       │ OTLP (gRPC/HTTP)
                                   ▼                            ▼
┌──────────────────────────────────────────────────┐  ┌──────────────────────────────────────────────────┐
│              PostgreSQL 18 Database              │  │              OpenTelemetry Collector             │
│            (Authoritative Persistence)           │  │            (Telemetry & Tracing Pipeline)        │
└──────────────────────────────────────────────────┘  └──────────────────────────────────────────────────┘
```

The system strictly enforces architectural separation of concerns:

- **Rust Authoritative Backend (`apps/api`, `apps/worker`, `crates/*`)**:
  The Rust backend is the sole authority for business logic, state machines, rule evaluation, data verification, persistence transactions, and security enforcement.
- **Next.js / TypeScript Presentation Shell (`apps/web`)**:
  The web tier serves strictly as a presentation shell and command client. It contains no client-side domain truth, does not make autonomous business decisions, and does not invent or persist domain state.
- **PostgreSQL 18 Persistence Tier (`crates/w014-persistence`)**:
  Database state is authoritatively managed via PostgreSQL 18 using SQLx with migration verification, credential masking, connection pool lifecycle management, and isolated fresh/upgrade test harnesses.
- **Local Infrastructure Orchestration (`tools/w014-cli`, `infra/local`)**:
  Local development containers (PostgreSQL, MinIO, ClamAV, OpenTelemetry Collector) are defined via Docker Compose and orchestrated deterministically through the native CLI.

---

## 3. Repository Structure & Workspace Topology

The repository is organized as a multi-language monorepo consisting of a **14-member Cargo workspace** and a **pnpm-managed Next.js web application**:

```
.
├── Cargo.toml                                # 14-member Cargo workspace manifest
├── rust-toolchain.toml                       # Pinned Rust toolchain (1.97.1)
├── package.json                              # Monorepo root scripts and engines
├── pnpm-workspace.yaml                       # pnpm workspace definition (apps/web)
├── apps/
│   ├── api/                                  # w014-api: Axum HTTP composition root & OpenAPI
│   ├── web/                                  # @w014/web: Next.js 16 presentation shell
│   └── worker/                               # w014-worker: Long-running async worker binary
├── crates/
│   ├── w014-ai-contracts/                    # AI schema contracts & boundary definitions
│   ├── w014-ai-runtime/                      # AI execution runtime integration scaffold
│   ├── w014-application/                     # Application orchestration & use-case scaffold
│   ├── w014-authn/                           # Authentication contracts & identity abstraction
│   ├── w014-authz/                           # Authorization policy engine scaffold
│   ├── w014-document-processing/             # Document ingestion & processing scaffold
│   ├── w014-domain/                          # Domain entity models & verification primitives
│   ├── w014-jobs/                            # Worker runner, lifecycle states & shutdown signals
│   ├── w014-observability/                   # Tracing, OTel initialization & secret redaction
│   ├── w014-persistence/                     # SQLx PostgreSQL runner, pool config & migration harness
│   └── w014-reporting/                       # Compliance & audit report generation scaffold
├── infra/
│   └── local/
│       ├── compose.yaml                      # Local service definitions (Postgres, MinIO, ClamAV, OTel)
│       └── otel-collector-config.yaml        # OpenTelemetry Collector pipeline configuration
└── tools/
    └── w014-cli/                             # w014-cli: Local stack orchestration & migration CLI
```

### Member Breakdown

| Member / Path | Type | Purpose & Responsibility |
|---|---|---|
| `apps/api` (`w014-api`) | Binary | Authoritative Axum HTTP API server, health endpoints (`/health`, `/healthz`), OpenAPI specification (`/openapi.json`), RFC 9457 Problem Details error formatting, and correlation ID middleware. |
| `apps/web` (`@w014/web`) | Next.js App | Presentation shell built with React 19, TypeScript, accessible components, and environment indicators. |
| `apps/worker` (`w014-worker`) | Binary | Asynchronous worker process composition root with structured lifecycle management, signal handling, and graceful shutdown. |
| `tools/w014-cli` (`w014-cli`) | Binary | Developer orchestration CLI providing stack management (`dev-up`, `dev-down`) and migration commands (`migrate`, `migrate status`). |
| `crates/w014-persistence` | Library | PostgreSQL 18 client, connection pooling, credential masking, authoritative SQLx migration runner, and test harnesses. |
| `crates/w014-observability` | Library | Structured logging, OpenTelemetry integration (OTLP gRPC/HTTP), correlation ID propagation/validation, and header/log redaction. |
| `crates/w014-jobs` | Library | Worker lifecycle state machine, runner abstractions, and cooperative shutdown coordination. |
| `crates/w014-domain` | Library | Domain entity definitions and verification models (W0 bootstrap scaffold). |
| `crates/w014-application` | Library | Application service boundaries and use-case handlers (W0 bootstrap scaffold). |
| `crates/w014-authn` | Library | Authentication provider contracts and token handling (W0 bootstrap scaffold). |
| `crates/w014-authz` | Library | Authorization policies and permission evaluation (W0 bootstrap scaffold). |
| `crates/w014-ai-contracts` | Library | AI interaction contracts and safety boundaries (W0 bootstrap scaffold). |
| `crates/w014-ai-runtime` | Library | AI execution runtime interfaces (W0 bootstrap scaffold). |
| `crates/w014-document-processing` | Library | Ingestion, sanitization, and parsing abstractions (W0 bootstrap scaffold). |
| `crates/w014-reporting` | Library | Report generation and artifact formatting (W0 bootstrap scaffold). |

---

## 4. Required Toolchains & Dependencies

The repository pins exact toolchain versions for reproducible builds:

| Toolchain / Runtime | Version | Specification Location |
|---|---|---|
| **Rust** | `1.97.1` | `rust-toolchain.toml` |
| **Node.js** | `24.18.0` | `package.json` (`engines.node`) |
| **pnpm** | `11.22.0` | `package.json` (`packageManager`, `engines.pnpm`) |

### Local Docker Services (`infra/local/compose.yaml`)

| Service Name | Image | Port(s) | Health Check / Purpose |
|---|---|---|---|
| `postgres` | `postgres:18-alpine` | `5432:5432` | `pg_isready -U postgres -d w014_dev` (PostgreSQL 18 relational database) |
| `minio` | `minio/minio:latest` | `9000:9000`<br>`9001:9001` | `mc ready local` (S3-compatible object storage and console) |
| `clamav` | `clamav/clamav:latest` | `3310:3310` | `/usr/local/bin/clamdcheck.sh` (Antivirus scanning daemon) |
| `otel-collector` | `otel/opentelemetry-collector-contrib:latest` | `4317:4317`<br>`4318:4318`<br>`13133:13133` | `/otelcol-contrib validate` (OTLP gRPC/HTTP receiver, debug exporter) |

---

## 5. Verified Operational Commands

All commands below are directly implemented and verified in the repository.

### 5.1 Local Infrastructure Orchestration (`w014-cli`)

Start all local infrastructure services in detached mode and wait for health checks:
```bash
cargo run --bin w014-cli -- dev-up
```

Stop all local infrastructure services cleanly (preserves persistent volumes):
```bash
cargo run --bin w014-cli -- dev-down
```

Display CLI usage and available commands:
```bash
cargo run --bin w014-cli -- help
```

*(Alternatively, Docker Compose can be invoked directly: `docker compose -f infra/local/compose.yaml up -d --wait` and `docker compose -f infra/local/compose.yaml down`)*

### 5.2 Database Migrations (`w014-cli`)

Inspect current database version and applied/pending migration status:
```bash
cargo run --bin w014-cli -- migrate status
```

Apply pending SQLx migrations against the configured database:
```bash
cargo run --bin w014-cli -- migrate run
```

### 5.3 Rust Workspace Build & Verification

Typecheck all workspace crates and binaries:
```bash
cargo check --workspace --all-targets
```

Build all workspace crates and binaries:
```bash
cargo build --workspace
```

Run the complete Rust test suite (unit tests, integration tests, migration harness):
```bash
# Note: Ensure local postgres is running (via `w014-cli dev-up`) for persistence integration tests
cargo test --workspace
```

Run the authoritative API server:
```bash
cargo run --bin w014-api
```

Run the worker process:
```bash
cargo run --bin w014-worker
```

### 5.4 Next.js Web Application (`apps/web`)

Install frontend dependencies:
```bash
pnpm install
```

Run frontend unit and component tests (Vitest + React Testing Library + Axe a11y):
```bash
pnpm test
# Or targeting the package directly:
pnpm --filter @w014/web test
```

Perform TypeScript typechecking:
```bash
pnpm typecheck
# Or targeting the package directly:
pnpm --filter @w014/web typecheck
```

Build the Next.js production bundle:
```bash
pnpm build
# Or targeting the package directly:
pnpm --filter @w014/web build
```

Run the local web development server:
```bash
pnpm --filter @w014/web dev
```

---

## 6. Implementation Status & Maturity

### Current Status: Wave 0 / Vertical Slice 0 (W0 / VS0) Complete

- [x] Monorepo workspace configuration (Cargo 14-member workspace, pnpm workspace).
- [x] Pinned toolchains (Rust 1.97.1, Node 24.18.0, pnpm 11.22.0).
- [x] Local containerized infrastructure (PostgreSQL 18, MinIO, ClamAV, OpenTelemetry Collector).
- [x] Local developer orchestration CLI (`w014-cli dev-up`, `dev-down`, `migrate`).
- [x] Authoritative SQLx migration runner, connection pooling, and fresh/upgrade test harnesses.
- [x] Axum API composition root with health probes (`/health`, `/healthz`), OpenAPI spec (`/openapi.json`), and RFC 9457 Problem Details.
- [x] Long-running worker process lifecycle runner with signal handling and graceful shutdown.
- [x] Structured observability pipeline with OTLP export, correlation ID propagation, and sensitive header/field redaction.
- [x] Next.js presentation shell with accessible components, data boundary badges, and responsive layouts.

### Planned Wave 1+ (W1+) Roadmap

Domain-specific capabilities arrive in subsequent vertical slice phases:
- **Wave 1 (W1)**: Programs, Workspaces & Auth Integration
- **Wave 2 (W2)**: Verification Engine & Preflight Rule Checks
- **Wave 3 (W3)**: Compliance Matrices & CDRL Deliverable Tracking
- **Wave 4 (W4)**: Evidence Tracking & Tamper-Evident Audit Chains

---

## 7. Compliance, Legal & Accreditation Disclaimers

> **IMPORTANT DISCLAIMER**  
> This repository, its code, documentation, and demonstration environments are provided for technical architecture and engineering evaluation purposes only.
>
> Neither this repository nor this README establishes, conveys, or implies:
> - **Production readiness** or **release readiness**;
> - **Legal advice** or legal representation;
> - **Compliance certification** (e.g., CMMC, NIST SP 800-171, ISO 27001);
> - **Security certification** or security clearance;
> - **Controlled Unclassified Information (CUI) production authorization**;
> - **Department of Defense (DoD) accreditation** or Authority to Operate (ATO);
> - **FedRAMP authorization**;
> - **Commercial validation** or commercial fitness for a particular purpose;
> - **Autonomous legal-entitlement determination**;
> - **Autonomous submission authority** on behalf of any entity.
>
> All operational deployments handling sensitive or regulated data require formal accrediting authority review, security authorization, and compliance certification from authorized governing bodies.
