#!/bin/bash

set -euo pipefail

IMAGE_NAME="erebor:latest"
CONTAINER_NAME="erebor-dev"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

docker build --pull --no-cache -f "${REPO_ROOT}/Dockerfile" -t "${IMAGE_NAME}" "${REPO_ROOT}"

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d --rm --name "${CONTAINER_NAME}" -p "${EREBOR_SERVICE_PORT: -4}":"${EREBOR_SERVICE_PORT: -4}" \
    -e EREBOR_SERVICE_CLIENT_ID \
    -e EREBOR_SERVICE_PORT \
    -e EREBOR_CA_CERT \
    -e EREBOR_SERVER_CERT \
    -e EREBOR_SERVER_KEY \
    -e EREBOR_CLIENT_CERT \
    -e EREBOR_CLIENT_KEY \
    -e EREBOR_S2S_AUTH_URL \
    -e EREBOR_S2S_AUTH_CLIENT_ID \
    -e EREBOR_S2S_AUTH_CLIENT_SECRET \
    -e EREBOR_DB_CA_CERT \
    -e EREBOR_DB_CLIENT_CERT \
    -e EREBOR_DB_CLIENT_KEY \
    -e EREBOR_DATABASE_URL \
    -e EREBOR_DATABASE_NAME \
    -e EREBOR_DATABASE_USERNAME \
    -e EREBOR_DATABASE_PASSWORD \
    -e EREBOR_DATABASE_HMAC_INDEX_SECRET \
    -e EREBOR_FIELD_LEVEL_AES_GCM_SECRET \
    -e EREBOR_USER_AUTH_URL \
    -e EREBOR_USER_JWT_VERIFYING_KEY \
    -e EREBOR_OAUTH_CALLBACK_URL \
    -e EREBOR_OAUTH_CALLBACK_CLIENT_ID \
    -e EREBOR_TASKS_URL \
    -e EREBOR_GALLERY_URL \
    -e EREBOR_PROFILES_URL \
    "${IMAGE_NAME}"