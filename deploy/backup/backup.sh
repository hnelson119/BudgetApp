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
    ""|*[!A-Za-z0-9_]*) fail "backup_configuration_error" "$label is invalid" ;;
  esac
}

: "${DATABASE_HOST:?DATABASE_HOST must be set}"
: "${DATABASE_PORT:=5432}"
: "${POSTGRES_DB:?POSTGRES_DB must be set}"
: "${POSTGRES_BACKUP_USER:?POSTGRES_BACKUP_USER must be set}"
: "${APP_RELEASE:=development}"
: "${RESTIC_REPOSITORY:=/repository}"
: "${RESTIC_PASSWORD_FILE:=/run/secrets/restic_repository_password}"
: "${BACKUP_RETENTION_DAILY:=7}"
: "${BACKUP_RETENTION_WEEKLY:=4}"
: "${BACKUP_RETENTION_MONTHLY:=12}"

validate_identifier "$POSTGRES_DB" "POSTGRES_DB"
validate_identifier "$POSTGRES_BACKUP_USER" "POSTGRES_BACKUP_USER"

case "$APP_RELEASE" in
  ""|*[!A-Za-z0-9._-]*) fail "backup_configuration_error" "APP_RELEASE is invalid" ;;
esac

for value in "$BACKUP_RETENTION_DAILY" "$BACKUP_RETENTION_WEEKLY" "$BACKUP_RETENTION_MONTHLY"; do
  case "$value" in
    ""|*[!0-9]*) fail "backup_configuration_error" "Backup retention values must be integers" ;;
  esac
done

if [ ! -d "$RESTIC_REPOSITORY" ] || [ ! -w "$RESTIC_REPOSITORY" ]; then
  fail "backup_repository_unavailable" "The encrypted backup repository is unavailable or read-only"
fi

if [ ! -s "$RESTIC_PASSWORD_FILE" ]; then
  fail "backup_configuration_error" "Restic repository secret file is missing or empty"
fi

export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE
export RESTIC_CACHE_DIR=/tmp/restic-cache

if [ ! -f "$RESTIC_REPOSITORY/config" ]; then
  if find "$RESTIC_REPOSITORY" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    fail "backup_repository_invalid" "The destination is not empty and is not a Restic repository"
  fi
  log "info" "backup_repository_initializing" "Initializing encrypted backup repository"
  restic init >/dev/null
else
  restic cat config >/dev/null || \
    fail "backup_repository_unlock_failed" "The encrypted repository could not be opened"
fi

if ! pg_isready \
  --host "$DATABASE_HOST" \
  --port "$DATABASE_PORT" \
  --username "$POSTGRES_BACKUP_USER" \
  --dbname "$POSTGRES_DB" >/dev/null; then
  fail "backup_database_unavailable" "PostgreSQL is not ready for backup"
fi

migration_list="$(psql \
  --host "$DATABASE_HOST" \
  --port "$DATABASE_PORT" \
  --username "$POSTGRES_BACKUP_USER" \
  --dbname "$POSTGRES_DB" \
  --no-psqlrc \
  --tuples-only \
  --no-align \
  --set ON_ERROR_STOP=1 \
  --command "SELECT app || ':' || name FROM django_migrations ORDER BY app, name")" || \
  fail "backup_schema_read_failed" "The schema version could not be read"

schema_fingerprint="$(printf '%s' "$migration_list" | sha256sum | cut -d ' ' -f 1)"
unset migration_list

snapshot_time="$(date -u +%Y%m%dT%H%M%SZ)"
dump_name="${POSTGRES_DB}.dump"
log "info" "backup_started" "Starting encrypted PostgreSQL backup"

pg_dump \
  --host "$DATABASE_HOST" \
  --port "$DATABASE_PORT" \
  --username "$POSTGRES_BACKUP_USER" \
  --dbname "$POSTGRES_DB" \
  --format=custom \
  --compress=6 \
  --no-owner \
  --no-privileges \
  | restic backup \
      --stdin \
      --stdin-filename "$dump_name" \
      --host household-budget \
      --tag "application=household-budget" \
      --tag "database=$POSTGRES_DB" \
      --tag "release=$APP_RELEASE" \
      --tag "schema=$schema_fingerprint" \
      --tag "created=$snapshot_time" \
      --quiet || fail "backup_stream_failed" "The PostgreSQL backup stream failed"

restic check --quiet || fail "backup_integrity_failed" "Repository integrity verification failed"

restic forget \
  --host household-budget \
  --tag "database=$POSTGRES_DB" \
  --keep-daily "$BACKUP_RETENTION_DAILY" \
  --keep-weekly "$BACKUP_RETENTION_WEEKLY" \
  --keep-monthly "$BACKUP_RETENTION_MONTHLY" \
  --prune \
  --quiet || fail "backup_retention_failed" "Backup succeeded but retention pruning failed"

marker_file="$RESTIC_REPOSITORY/.last-success"
marker_temporary="$RESTIC_REPOSITORY/.last-success.tmp"
printf '%s release=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$APP_RELEASE" > "$marker_temporary" || \
  fail "backup_status_write_failed" "Backup succeeded but its status marker could not be written"
chmod 0600 "$marker_temporary"
mv "$marker_temporary" "$marker_file" || \
  fail "backup_status_write_failed" "Backup succeeded but its status marker could not be committed"

log "info" "backup_completed" "Encrypted PostgreSQL backup and integrity check completed"
