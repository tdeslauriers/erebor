#!/bin/bash

# namespace and ConfigMap name
NAMESPACE="world"
CONFIG_MAP_NAME="cm-gateway-oauth-callback"

# get url from 1password
OAUTH_CALLBACK_URL=$(op read "op://world_site/erebor_oauth_callback_prod/url")
OAUTH_CALLBACK_PORT=$(op read "op://world_site/erebor_oauth_callback_prod/port")
OAUTH_CALLBACK_CLIENT_ID=$(op read "op://world_site/erebor_oauth_callback_prod/client_id")

# validate value is not empty
if [[ -z "$OAUTH_CALLBACK_URL" || -z "$OAUTH_CALLBACK_PORT" || -z "$OAUTH_CALLBACK_CLIENT_ID" ]]; then
  echo "Error: failed to get gateway oauth callback config vars from 1Password."
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
  oauth-callback-url: "$OAUTH_CALLBACK_URL:$OAUTH_CALLBACK_PORT"
  oauth-callback-port: ":$OAUTH_CALLBACK_PORT"
  oauth-callback-client-id: "$OAUTH_CALLBACK_CLIENT_ID"
EOF
