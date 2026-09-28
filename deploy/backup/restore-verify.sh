#!/bin/sh
set -eu
set -o pipefail

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

validate_identifier() {
  identifier="$1"
  label="$2"
  case "$identifier" in
    ""|*[!A-Za-z0-9_]*) fail "restore_configuration_error" "$label is invalid" ;;
  esac
}

: "${DATABASE_HOST:?DATABASE_HOST must be set}"
: "${DATABASE_PORT:=5432}"
: "${POSTGRES_DB:?POSTGRES_DB must be set}"
: "${POSTGRES_ADMIN_USER:?POSTGRES_ADMIN_USER must be set}"
: "${RESTIC_REPOSITORY:=/repository}"
: "${RESTIC_PASSWORD_FILE:=/run/secrets/restic_repository_password}"
: "${RESTORE_SNAPSHOT_ID:=latest}"
: "${RESTORE_TARGET_DB:?RESTORE_TARGET_DB must be set}"

validate_identifier "$POSTGRES_DB" "POSTGRES_DB"
validate_identifier "$POSTGRES_ADMIN_USER" "POSTGRES_ADMIN_USER"
validate_identifier "$RESTORE_TARGET_DB" "RESTORE_TARGET_DB"

case "$RESTORE_SNAPSHOT_ID" in
  ""|*[!A-Za-z0-9_-]*) fail "restore_configuration_error" "RESTORE_SNAPSHOT_ID is invalid" ;;
esac

case "$RESTORE_TARGET_DB" in
  "${POSTGRES_DB}_restore_"*) ;;
  *) fail "restore_target_refused" "The target must use the protected restore-test prefix" ;;
esac

if [ "$RESTORE_TARGET_DB" = "$POSTGRES_DB" ]; then
  fail "restore_target_refused" "The live application database cannot be a restore-test target"
fi
if [ ! -d "$RESTIC_REPOSITORY" ] || [ ! -r "$RESTIC_REPOSITORY/config" ]; then
  fail "restore_repository_unavailable" "The encrypted backup repository is unavailable"
fi
if [ ! -s "$RESTIC_PASSWORD_FILE" ]; then
  fail "restore_configuration_error" "Restic repository secret file is missing or empty"
fi

export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE
export RESTIC_CACHE_DIR=/tmp/restic-cache

target_created=false
cleanup() {
  if [ "$target_created" = true ] && [ "${restore_completed:-false}" != true ]; then
    dropdb \
      --host "$DATABASE_HOST" \
      --port "$DATABASE_PORT" \
      --username "$POSTGRES_ADMIN_USER" \
      --if-exists \
      "$RESTORE_TARGET_DB" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

restic --no-lock cat config >/dev/null || \
  fail "restore_repository_unlock_failed" "The encrypted repository could not be opened"

if [ "$RESTORE_SNAPSHOT_ID" = "latest" ]; then
  snapshot_metadata="$(restic --no-lock snapshots \
    --json \
    --host household-budget \
    --tag "database=$POSTGRES_DB")" || \
    fail "restore_snapshot_metadata_failed" "The selected snapshot metadata could not be read"
else
  snapshot_metadata="$(restic --no-lock snapshots \
    --json \
    "$RESTORE_SNAPSHOT_ID")" || \
    fail "restore_snapshot_metadata_failed" "The selected snapshot metadata could not be read"
fi

if [ "$RESTORE_SNAPSHOT_ID" = "latest" ]; then
  selected_snapshot="$(printf '%s' "$snapshot_metadata" | jq -cer '
    select(length > 0)
    | max_by(.time)
  ')" || fail "restore_snapshot_metadata_failed" "No matching snapshot was available"
else
  selected_snapshot="$(printf '%s' "$snapshot_metadata" | jq -cer '
    select(length == 1)
    | .[0]
  ')" || fail "restore_snapshot_metadata_failed" "The snapshot selection was missing or ambiguous"
fi
unset snapshot_metadata

resolved_snapshot_id="$(printf '%s' "$selected_snapshot" | jq -er \
  --arg database "$POSTGRES_DB" '
  select(.hostname == "household-budget")
  | select(.tags | type == "array")
  | select(([.tags[] | select(. == ("database=" + $database))] | length) == 1)
  | .id
  | select(type == "string" and test("^[0-9a-f]{64}$"))
')" || fail "restore_snapshot_metadata_failed" "The snapshot selection was missing or ambiguous"

expected_schema_fingerprint="$(printf '%s' "$selected_snapshot" | jq -er '
  .tags
  | select(type == "array")
  | [.[] | select(startswith("schema"))]
  | select(length == 1)
  | .[0]
  | if startswith("schema-sha256=") then sub("^schema-sha256="; "")
    elif startswith("schema=") then sub("^schema="; "")
    else empty
    end
  | select(test("^[0-9a-f]{64}$"))
')" || fail "restore_schema_tag_invalid" \
  "The snapshot schema tag was missing, ambiguous, or malformed"
unset selected_snapshot

target_exists="$(psql \
  --host "$DATABASE_HOST" \
  --port "$DATABASE_PORT" \
  --username "$POSTGRES_ADMIN_USER" \
  --dbname postgres \
  --no-psqlrc \
  --tuples-only \
  --no-align \
  --set ON_ERROR_STOP=1 \
  --command "SELECT 1 FROM pg_database WHERE datname = '$RESTORE_TARGET_DB'")"

if [ "$target_exists" = "1" ]; then
  fail "restore_target_exists" "The restore-test target already exists; no data was changed"
fi

createdb \
  --host "$DATABASE_HOST" \
  --port "$DATABASE_PORT" \
  --username "$POSTGRES_ADMIN_USER" \
  --template template0 \
  "$RESTORE_TARGET_DB"
target_created=true

log "info" "restore_verification_started" "Restoring the selected snapshot into a new test database"

restic --no-lock dump "$resolved_snapshot_id" "/${POSTGRES_DB}.dump" \
  | pg_restore \
      --host "$DATABASE_HOST" \
      --port "$DATABASE_PORT" \
      --username "$POSTGRES_ADMIN_USER" \
      --dbname "$RESTORE_TARGET_DB" \
      --exit-on-error \
      --single-transaction \
      --no-owner \
      --no-privileges || fail "restore_stream_failed" "The restore verification stream failed"

restored_migration_list="$(psql \
  --host "$DATABASE_HOST" \
  --port "$DATABASE_PORT" \
  --username "$POSTGRES_ADMIN_USER" \
  --dbname "$RESTORE_TARGET_DB" \
  --no-psqlrc \
  --tuples-only \
  --no-align \
  --set ON_ERROR_STOP=1 \
  --command "SELECT app || ':' || name FROM django_migrations ORDER BY app, name")" || \
  fail "restore_schema_verification_failed" "The restored schema could not be verified"
if [ -z "$restored_migration_list" ]; then
  fail "restore_schema_verification_failed" "The restored schema is incomplete"
fi

actual_schema_fingerprint="$(printf '%s' "$restored_migration_list" | sha256sum | cut -d ' ' -f 1)"
unset restored_migration_list resolved_snapshot_id
if [ "$actual_schema_fingerprint" != "$expected_schema_fingerprint" ]; then
  fail "restore_schema_verification_failed" \
    "The restored migration set does not match the snapshot schema tag"
fi
unset actual_schema_fingerprint expected_schema_fingerprint

restore_completed=true
log "info" "restore_verification_completed" \
  "Restore verification completed in the isolated target database"
