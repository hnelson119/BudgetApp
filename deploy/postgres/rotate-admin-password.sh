#!/bin/sh
set -eu

umask 077

log() {
  level="$1"
  event="$2"
  message="$3"
  printf '{"timestamp":"%s","level":"%s","event":"%s","message":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$event" "$message"
}

fail() {
  log "error" "$1" "$2" >&2
  exit 1
}

read_secret() {
  secret_file="$1"
  secret_label="$2"
  if [ ! -f "$secret_file" ] || [ ! -r "$secret_file" ]; then
    fail "database_admin_rotation_configuration_error" "$secret_label file is unavailable"
  fi
  secret_size="$(wc -c < "$secret_file")"
  if [ "$secret_size" -lt 32 ] || [ "$secret_size" -gt 16384 ]; then
    fail "database_admin_rotation_configuration_error" "$secret_label file size is invalid"
  fi
  tr -d '\r\n' < "$secret_file"
}

: "${DATABASE_HOST:?DATABASE_HOST must be set}"
: "${POSTGRES_DB:?POSTGRES_DB must be set}"
: "${POSTGRES_ADMIN_USER:?POSTGRES_ADMIN_USER must be set}"
: "${POSTGRES_ADMIN_PASSWORD_FILE:=/run/secrets/postgres_admin_password}"
: "${POSTGRES_ADMIN_NEW_PASSWORD_FILE:=/run/secrets/postgres_admin_password_next}"

case "$POSTGRES_DB" in
  ""|*[!A-Za-z0-9_]*) fail "database_admin_rotation_configuration_error" "POSTGRES_DB is invalid" ;;
esac
case "$POSTGRES_ADMIN_USER" in
  ""|*[!A-Za-z0-9_]*) fail "database_admin_rotation_configuration_error" "POSTGRES_ADMIN_USER is invalid" ;;
esac

current_password="$(read_secret "$POSTGRES_ADMIN_PASSWORD_FILE" "Current administrator password")"
new_password="$(read_secret "$POSTGRES_ADMIN_NEW_PASSWORD_FILE" "Staged administrator password")"
if [ "$current_password" = "$new_password" ]; then
  fail "database_admin_rotation_configuration_error" "The staged password must be different"
fi

export PGPASSWORD="$current_password"
export BUDGET_NEW_DATABASE_PASSWORD="$new_password"
log "info" "database_admin_rotation_started" "Rotating the PostgreSQL administrator credential"
psql \
  --host "$DATABASE_HOST" \
  --dbname "$POSTGRES_DB" \
  --username "$POSTGRES_ADMIN_USER" \
  --no-password \
  --set ON_ERROR_STOP=1 \
  --set "target_role=$POSTGRES_ADMIN_USER" <<'SQL' >/dev/null
\getenv new_password BUDGET_NEW_DATABASE_PASSWORD
SELECT format('ALTER ROLE %I PASSWORD %L', :'target_role', :'new_password') \gexec
SQL

PGPASSWORD="$new_password" psql \
  --host "$DATABASE_HOST" \
  --dbname "$POSTGRES_DB" \
  --username "$POSTGRES_ADMIN_USER" \
  --no-password \
  --set ON_ERROR_STOP=1 \
  --command "SELECT 1" >/dev/null || \
  fail "database_admin_rotation_verification_failed" "The staged credential could not reconnect"

if PGPASSWORD="$current_password" psql \
  --host "$DATABASE_HOST" \
  --dbname "$POSTGRES_DB" \
  --username "$POSTGRES_ADMIN_USER" \
  --no-password \
  --set ON_ERROR_STOP=1 \
  --command "SELECT 1" >/dev/null 2>&1; then
  fail "database_admin_rotation_retirement_failed" "The retired credential still authenticates"
fi
unset BUDGET_NEW_DATABASE_PASSWORD PGPASSWORD current_password new_password
log "info" "database_admin_rotation_completed" "Administrator rotation and reconnect checks passed"
