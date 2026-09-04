# syntax=docker/dockerfile:1
# Foundation production parser sandbox image (WI0205 / D3 composition).
#
# Builds the REAL repository binary `w014-parser-sandbox` from locked source and
# packages it with the authoritative Linux/arm64 PDFium runtime plus Tesseract
# OCR runtime. No credentials, no host mounts, no ENTRYPOINT override.
#
# Authoritative image identity: w014-parser-sandbox:local
# Accepted D3 invocation preserved:
#   docker run <mandatory D3 hardened args> w014-parser-sandbox:local w014-parser-sandbox
#
# Pinned PDFium authority (crates/w014-document-processing/src/parser/pdfium_backend.rs):
#   PINNED_PDFIUM_VERSION_STR = pdfium-151.0.7881.0
#   PINNED_PDFIUM_BUILD = 7881
#   Linux aarch64 SHA-256 = 6252fce3da45e7f0dc5b27f4d4e1a1456ca3f7734cdb04f927967df772127478
#   Source: https://github.com/bblanchon/pdfium-binaries/releases/download/chromium%2F7881/pdfium-linux-arm64.tgz
#
# DOCX authority: ooxmlsdk 0.12.0 (compiled from Cargo.lock, never replaced).
# OCR authority: real `tesseract` process, language `eng` (see ocr/tesseract.rs).
#
# Build-time network is limited to deterministic verified fetches:
#   - crates.io (via cargo --locked)
#   - Debian apt (tesseract runtime)
#   - single pinned PDFium artifact (SHA-256 verified, build fails on mismatch)
# Runtime network fetch: ABSENT (D3 enforces --network=none).

# ---------------------------------------------------------------------------
# Pinned base identities (index digests; --platform selects linux/arm64).
# Builder: rust 1.97.1 (matches rust-toolchain.toml channel = "1.97.1").
#   index: sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3
#   arm64 manifest: sha256:b28e5606d830400fabf789f910f9ed2ea22cdd6d51d463c5d0baa30bb2bedb2d
# Runtime: debian bookworm-slim.
#   index: sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
#   arm64 manifest: sha256:6bd27d44e6c32a66bbd72d7cb2b76a8ae3497ec2e5274a81abd1b37f6013fa1f
# ---------------------------------------------------------------------------

FROM --platform=linux/arm64 rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS builder

ARG PDFIUM_BUILD=7881
ARG PDFIUM_VERSION_STR=pdfium-151.0.7881.0
ARG PDFIUM_SHA256=6252fce3da45e7f0dc5b27f4d4e1a1456ca3f7734cdb04f927967df772127478
ARG PDFIUM_URL=https://github.com/bblanchon/pdfium-binaries/releases/download/chromium%2F7881/pdfium-linux-arm64.tgz
ARG REVISION=unknown

ENV CARGO_TERM_COLOR=never \
    CARGO_NET_RETRY=10

WORKDIR /src

# Toolchain + fetch tooling for deterministic verified build-time fetches.
# libclang-dev is required by pdfium-render's bindgen build script.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl pkg-config libssl-dev libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Bounded build context: exact repository manifests/sources only.
# No `COPY . .`. No .env, credentials, SSH keys, sockets, or database state.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY apps/api/Cargo.toml apps/api/Cargo.toml
COPY apps/worker/Cargo.toml apps/worker/Cargo.toml
COPY tools/w014-cli/Cargo.toml tools/w014-cli/Cargo.toml
COPY crates/w014-domain/Cargo.toml crates/w014-domain/Cargo.toml
COPY crates/w014-application/Cargo.toml crates/w014-application/Cargo.toml
COPY crates/w014-persistence/Cargo.toml crates/w014-persistence/Cargo.toml
COPY crates/w014-authn/Cargo.toml crates/w014-authn/Cargo.toml
COPY crates/w014-authz/Cargo.toml crates/w014-authz/Cargo.toml
COPY crates/w014-ai-contracts/Cargo.toml crates/w014-ai-contracts/Cargo.toml
COPY crates/w014-ai-runtime/Cargo.toml crates/w014-ai-runtime/Cargo.toml
COPY crates/w014-document-processing/Cargo.toml crates/w014-document-processing/Cargo.toml
COPY crates/w014-jobs/Cargo.toml crates/w014-jobs/Cargo.toml
COPY crates/w014-reporting/Cargo.toml crates/w014-reporting/Cargo.toml
COPY crates/w014-observability/Cargo.toml crates/w014-observability/Cargo.toml

# Full source for every Rust workspace member (explicit paths; still no secrets).
# Required so cargo workspace metadata resolves with --locked.
COPY crates/w014-domain/ crates/w014-domain/
COPY crates/w014-document-processing/ crates/w014-document-processing/
COPY crates/w014-application/ crates/w014-application/
COPY crates/w014-persistence/ crates/w014-persistence/
COPY crates/w014-authn/ crates/w014-authn/
COPY crates/w014-authz/ crates/w014-authz/
COPY crates/w014-ai-contracts/ crates/w014-ai-contracts/
COPY crates/w014-ai-runtime/ crates/w014-ai-runtime/
COPY crates/w014-jobs/ crates/w014-jobs/
COPY crates/w014-reporting/ crates/w014-reporting/
COPY crates/w014-observability/ crates/w014-observability/
COPY apps/api/ apps/api/
COPY apps/worker/ apps/worker/
COPY tools/w014-cli/ tools/w014-cli/

# Compile the REAL repository binary from locked source.
RUN cargo build \
      --release \
      --locked \
      -p w014-document-processing \
      --bin w014-parser-sandbox \
    && test -x /src/target/release/w014-parser-sandbox \
    && ls -l /src/target/release/w014-parser-sandbox

# Fetch + verify authoritative Linux/arm64 PDFium (fail build on mismatch).
RUN curl -fsSL -o /tmp/pdfium-linux-arm64.tgz "${PDFIUM_URL}" \
    && mkdir -p /tmp/pdfium-extract \
    && tar xzf /tmp/pdfium-linux-arm64.tgz -C /tmp/pdfium-extract \
    && echo "${PDFIUM_SHA256}  /tmp/pdfium-extract/lib/libpdfium.so" | sha256sum -c - \
    && mkdir -p /pdfium \
    && cp /tmp/pdfium-extract/lib/libpdfium.so /pdfium/libpdfium.so \
    && chmod 0555 /pdfium/libpdfium.so \
    && rm -rf /tmp/pdfium-linux-arm64.tgz /tmp/pdfium-extract

# ---------------------------------------------------------------------------
# Runtime: minimal Linux with real parser + PDFium + Tesseract/eng tessdata.
# No compiler toolchain. No Python parser runtime. No credentials.
# No ENTRYPOINT (preserves `docker run image w014-parser-sandbox`).
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime

ARG PDFIUM_VERSION_STR=pdfium-151.0.7881.0
ARG PDFIUM_SHA256=6252fce3da45e7f0dc5b27f4d4e1a1456ca3f7734cdb04f927967df772127478
ARG REVISION=unknown

LABEL org.opencontainers.image.title="w014-parser-sandbox" \
      org.opencontainers.image.description="Foundation production parser sandbox image carrying the real w014-parser-sandbox binary with authoritative PDFium and Tesseract runtime" \
      org.opencontainers.image.source="https://github.com/01fe25bec239-collab/w014" \
      org.opencontainers.image.revision="${REVISION}" \
      w014.parser.binary="w014-parser-sandbox" \
      w014.pdfium.version="${PDFIUM_VERSION_STR}" \
      w014.pdfium.sha256="${PDFIUM_SHA256}" \
      w014.ooxmlsdk.version="0.12.0"

ENV PDFIUM_LIB_PATH=/usr/local/lib/libpdfium.so \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/* \
    && command -v tesseract \
    && tesseract --version \
    && ls -l /usr/share/tesseract-ocr/*/tessdata/eng.traineddata

COPY --from=builder /src/target/release/w014-parser-sandbox /usr/local/bin/w014-parser-sandbox
COPY --from=builder /pdfium/libpdfium.so /usr/local/lib/libpdfium.so

RUN chmod 0555 /usr/local/bin/w014-parser-sandbox /usr/local/lib/libpdfium.so \
    && chmod a+rX /usr/local/bin/w014-parser-sandbox /usr/local/lib/libpdfium.so \
    && ldconfig \
    && command -v w014-parser-sandbox \
    && ls -l /usr/local/bin/w014-parser-sandbox /usr/local/lib/libpdfium.so \
    && echo "${PDFIUM_SHA256}  /usr/local/lib/libpdfium.so" | sha256sum -c - \
    && test -x /usr/bin/tesseract \
    && ! command -v python3 \
    && ! command -v python

WORKDIR /tmp
