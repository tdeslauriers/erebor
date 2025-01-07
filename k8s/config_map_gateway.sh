#!/bin/bash

# namespace and ConfigMap name
NAMESPACE="world"
CONFIG_MAP_NAME="cm-gateway-service"

# get url from 1password
GATEWAY_URL=$(op read "op://world_site/erebor_service_container_prod/url")
GATEWAY_PORT=$(op read "op://world_site/erebor_service_container_prod/port")
GATEWAY_CLIENT_ID=$(op read "op://world_site/erebor_service_container_prod/client_id")

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
  gateway-url: "$GATEWAY_URL:$GATEWAY_PORT"
  gateway-port: ":$GATEWAY_PORT"
  gateway-client-id: "$GATEWAY_CLIENT_ID"
EOF
