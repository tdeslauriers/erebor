#!/bin/bash

# namespace and ConfigMap name
NAMESPACE="world"
CONFIG_MAP_NAME="cm-gateway-service"

# get url from 1password
GATEWAY_URL=$(op read "op://world_site/erebor_service_container_prod/url")
GATEWAY_PORT=$(op read "op://world_site/erebor_service_container_prod/port")
GATEWAY_CLIENT_ID=$(op read "op://world_site/erebor_service_container_prod/client_id")
GATEWAY_k8_URL=$(op read "op://world_site/erebor_service_container_prod/k8_url")
GATEWAY_k8_PORT=$(op read "op://world_site/erebor_service_container_prod/k8_port")

# validate value is not empty
if [[ -z "$GATEWAY_URL" || -z "$GATEWAY_PORT" || -z "$GATEWAY_CLIENT_ID" ]]; then
  echo "Error: failed to get gateway config vars from 1Password."
  exit 1
fi

# apply cm
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: $CONFIG_MAP_NAME
  namespace: $NAMESPACE
data:
  gateway-client-id: "$GATEWAY_CLIENT_ID"
  gateway-url: "$GATEWAY_URL:$GATEWAY_PORT"
  gateway-port: ":$GATEWAY_PORT"
  gateway-k8-url: "$GATEWAY_k8_URL:$GATEWAY_k8_PORT"
  gateway-k8-port: ":$GATEWAY_k8_PORT"
EOF
