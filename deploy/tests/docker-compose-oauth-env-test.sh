#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

oauth_variables="OAUTH_SERVER_ENABLED OAUTH_SERVER_CLIENT_ID OAUTH_SERVER_REDIRECT_URI OAUTH_SERVER_AUTHORIZATION_CODE_TTL OAUTH_SERVER_ACCESS_TOKEN_TTL OAUTH_SERVER_REFRESH_TOKEN_ABSOLUTE_TTL OAUTH_SERVER_REFRESH_TOKEN_IDLE_TTL OAUTH_SERVER_REQUIRE_PKCE_S256 OAUTH_SERVER_HASH_KEY_VERSION OAUTH_SERVER_HASH_KEY OAUTH_SERVER_PREVIOUS_HASH_KEY_VERSION OAUTH_SERVER_PREVIOUS_HASH_KEY"

# 2026-10-19: Also verify HTTP Cookie configuration reaches every deployment.
oauth_variables="$oauth_variables OAUTH_SERVER_COOKIE_SECURE"

for compose_file in \
  deploy/docker-compose.yml \
  deploy/docker-compose.local.yml \
  deploy/docker-compose.standalone.yml \
  deploy/docker-compose.dev.yml
do
  # 2026-10-19: Removed issuer must not be passed to new deployments.
  if grep -Eq '^[[:space:]]*-[[:space:]]*OAUTH_SERVER_ISSUER=' "$compose_file"; then
    printf '%s must not pass removed OAUTH_SERVER_ISSUER\n' "$compose_file" >&2
    exit 1
  fi
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

if grep -Eq '^OAUTH_SERVER_ISSUER=' deploy/.env.example; then
  printf 'deploy/.env.example must not define removed OAUTH_SERVER_ISSUER\n' >&2
  exit 1
fi

printf 'docker compose OAuth environment test passed\n'
