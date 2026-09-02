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

validate_secret_file() {
  secret_file="$1"
  secret_label="$2"
  if [ ! -f "$secret_file" ] || [ ! -r "$secret_file" ]; then
    fail "restic_key_rotation_configuration_error" "$secret_label file is unavailable"
  fi
  secret_size="$(wc -c < "$secret_file")"
  if [ "$secret_size" -lt 32 ] || [ "$secret_size" -gt 16384 ]; then
    fail "restic_key_rotation_configuration_error" "$secret_label file size is invalid"
  fi
}

: "${RESTIC_REPOSITORY:=/repository}"
: "${RESTIC_PASSWORD_FILE:=/run/secrets/restic_repository_password}"
: "${RESTIC_NEW_PASSWORD_FILE:=/run/secrets/restic_repository_password_next}"
: "${RESTIC_CACHE_DIR:=/tmp/restic-cache}"

if [ ! -d "$RESTIC_REPOSITORY" ] || [ ! -w "$RESTIC_REPOSITORY" ]; then
  fail "restic_key_rotation_repository_error" "The encrypted repository is unavailable or read-only"
fi
validate_secret_file "$RESTIC_PASSWORD_FILE" "Current Restic password"
validate_secret_file "$RESTIC_NEW_PASSWORD_FILE" "Staged Restic password"
if cmp -s "$RESTIC_PASSWORD_FILE" "$RESTIC_NEW_PASSWORD_FILE"; then
  fail "restic_key_rotation_configuration_error" "The staged Restic password must be different"
fi

export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE RESTIC_CACHE_DIR
restic cat config >/dev/null 2>&1 || \
  fail "restic_key_rotation_unlock_failed" "The current password could not open the repository"

old_password_file="$RESTIC_PASSWORD_FILE"
log "info" "restic_key_rotation_started" "Rotating the encrypted repository access key"
restic key passwd --new-password-file "$RESTIC_NEW_PASSWORD_FILE" >/dev/null || \
  fail "restic_key_rotation_failed" "Restic did not complete its validated key replacement"

RESTIC_PASSWORD_FILE="$RESTIC_NEW_PASSWORD_FILE"
export RESTIC_PASSWORD_FILE
restic cat config >/dev/null 2>&1 || \
  fail "restic_key_rotation_verification_failed" "The staged password could not reopen the repository"
restic check >/dev/null || \
  fail "restic_key_rotation_verification_failed" "Repository integrity failed after key rotation"

RESTIC_PASSWORD_FILE="$old_password_file"
export RESTIC_PASSWORD_FILE
if restic cat config >/dev/null 2>&1; then
  fail "restic_key_rotation_retirement_failed" "The retired password still opens the repository"
fi
log "info" "restic_key_rotation_completed" "Repository key rotation and integrity verification passed"
