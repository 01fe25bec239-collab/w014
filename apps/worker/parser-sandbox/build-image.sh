#!/usr/bin/env bash
# Canonical Foundation build for the authoritative parser sandbox image.
#
# Produces exactly: w014-parser-sandbox:local
# Uses the exact Dockerfile, Cargo --locked (inside the image build),
# fails on build errors and on PDFium hash mismatch, never mutates
# application source, and requires no credentials.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile"
IMAGE="w014-parser-sandbox:local"

if [[ ! -f "${DOCKERFILE}" ]]; then
  echo "build-image: Dockerfile not found at ${DOCKERFILE}" >&2
  exit 1
fi

REVISION="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
echo "build-image: repo=${REPO_ROOT}"
echo "build-image: dockerfile=${DOCKERFILE}"
echo "build-image: revision=${REVISION}"
echo "build-image: image=${IMAGE}"

docker build \
  --platform linux/arm64 \
  -f "${DOCKERFILE}" \
  --build-arg "REVISION=${REVISION}" \
  -t "${IMAGE}" \
  "${REPO_ROOT}"

echo "build-image: built ${IMAGE} from revision ${REVISION}"
docker image inspect "${IMAGE}" --format 'build-image: id={{.Id}} arch={{.Architecture}} os={{.Os}}'
