#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

oauth_variables="OAUTH_SERVER_ENABLED OAUTH_SERVER_ISSUER OAUTH_SERVER_CLIENT_ID OAUTH_SERVER_REDIRECT_URI OAUTH_SERVER_AUTHORIZATION_CODE_TTL OAUTH_SERVER_ACCESS_TOKEN_TTL OAUTH_SERVER_REFRESH_TOKEN_ABSOLUTE_TTL OAUTH_SERVER_REFRESH_TOKEN_IDLE_TTL OAUTH_SERVER_REQUIRE_PKCE_S256 OAUTH_SERVER_HASH_KEY_VERSION OAUTH_SERVER_HASH_KEY OAUTH_SERVER_PREVIOUS_HASH_KEY_VERSION OAUTH_SERVER_PREVIOUS_HASH_KEY"

for compose_file in \
  deploy/docker-compose.yml \
  deploy/docker-compose.local.yml \
  deploy/docker-compose.standalone.yml \
  deploy/docker-compose.dev.yml
do
  for key in $oauth_variables; do
    key_count=$(grep -Ec "^[[:space:]]*-[[:space:]]*${key}=" "$compose_file" || true)
    if [ "$key_count" -ne 1 ]; then
      printf '%s must pass %s exactly once\n' "$compose_file" "$key" >&2
      exit 1
    fi
  done
done

for key in $oauth_variables; do
  key_count=$(grep -Ec "^${key}=" deploy/.env.example || true)
  if [ "$key_count" -ne 1 ]; then
    printf 'deploy/.env.example must define %s exactly once\n' "$key" >&2
    exit 1
  fi
done

printf 'docker compose OAuth environment test passed\n'
