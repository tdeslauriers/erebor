#!/bin/bash

# Service client id and port
export EREBOR_SERVICE_CLIENT_ID=$(op read "op://world_site/erebor_service_app_local/client_id")
export EREBOR_SERVICE_PORT=":$(op read "op://world_site/erebor_service_app_local/port")"

# certs
export EREBOR_CA_CERT=$(op document get "service_ca_dev_cert" --vault world_site | base64 -w 0)

export EREBOR_SERVER_CERT=$(op document get "erebor_service_server_dev_cert" --vault world_site | base64 -w 0)
export EREBOR_SERVER_KEY=$(op document get "erebor_service_server_dev_key" --vault world_site | base64 -w 0)

export EREBOR_CLIENT_CERT=$(op document get "erebor_service_client_dev_cert" --vault world_site | base64 -w 0)
export EREBOR_CLIENT_KEY=$(op document get "erebor_service_client_dev_key" --vault world_site | base64 -w 0)

# S2S Auth creds
export EREBOR_S2S_AUTH_URL=$(op read "op://world_site/ran_service_container_dev/url"):$(op read "op://world_site/ran_service_container_dev/port")
export EREBOR_S2S_AUTH_CLIENT_ID=$(op read "op://world_site/erebor_s2s_login_dev/username")
export EREBOR_S2S_AUTH_CLIENT_SECRET=$(op read "op://world_site/erebor_s2s_login_dev/password")

# Database certs
export EREBOR_DB_CA_CERT=$(op document get "db_ca_dev_cert" --vault world_site | base64 -w 0)

export EREBOR_DB_CLIENT_CERT=$(op document get "erebor_db_client_dev_cert" --vault world_site | base64 -w 0)
export EREBOR_DB_CLIENT_KEY=$(op document get "erebor_db_client_dev_key" --vault world_site | base64 -w 0)

# Database connection details + creds
export EREBOR_DATABASE_URL=$(op read "op://world_site/erebor_db_dev/server"):$(op read "op://world_site/erebor_db_dev/port")
export EREBOR_DATABASE_NAME=$(op read "op://world_site/erebor_db_dev/database")
export EREBOR_DATABASE_USERNAME=$(op read "op://world_site/erebor_db_dev/username")
export EREBOR_DATABASE_PASSWORD=$(op read "op://world_site/erebor_db_dev/password")

# HMAC key for blind index fields in database
export EREBOR_DATABASE_HMAC_INDEX_SECRET=$(op read "op://world_site/erebor_hmac_index_secret_dev/secret")

# Field level encryption key for database fields
export EREBOR_FIELD_LEVEL_AES_GCM_SECRET=$(op read "op://world_site/erebor_aes_gcm_secret_dev/secret")

# User Identity endpoint
export EREBOR_USER_AUTH_URL=$(op read "op://world_site/shaw_service_container_dev/url"):$(op read "op://world_site/shaw_service_container_dev/port")

# Identity jwt verifying key 
export EREBOR_USER_JWT_VERIFYING_KEY=$(op read "op://world_site/shaw_jwt_key_pair_dev/verifying_key")

export EREBOR_OAUTH_CALLBACK_URL=$(op read "op://world_site/erebor_oauth_callback_dev/url"):$(op read "op://world_site/erebor_oauth_callback_dev/port")/callback
export EREBOR_OAUTH_CALLBACK_CLIENT_ID=$(op read "op://world_site/erebor_oauth_callback_dev/client_id")

export EREBOR_TASKS_URL=$(op read "op://world_site/apprentice_service_container_dev/url"):$(op read "op://world_site/apprentice_service_container_dev/port") 
export EREBOR_GALLERY_URL=$(op read "op://world_site/pixie_service_container_dev/url"):$(op read "op://world_site/pixie_service_container_dev/port") 


