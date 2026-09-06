#!/bin/sh
set -eu

fail() {
  echo "PostgreSQL TLS startup configuration is invalid." >&2
  exit 1
}

certificate_source=/run/secrets/postgres_server_certificate
key_source=/run/secrets/postgres_server_private_key
client_ca_source=/run/secrets/postgres_client_ca_certificate
tls_directory=/run/postgresql-tls

if [ "$(id -u)" != "0" ]; then
  fail
fi
for source in "$certificate_source" "$key_source" "$client_ca_source"; do
  if [ ! -f "$source" ] || [ -L "$source" ] || [ ! -s "$source" ]; then
    fail
  fi
done

umask 077
mkdir -p "$tls_directory"
cp "$certificate_source" "$tls_directory/server.crt"
cp "$key_source" "$tls_directory/server.key"
cp "$client_ca_source" "$tls_directory/client-ca.crt"

: "${POSTGRES_ADMIN_USER:?}"
: "${POSTGRES_RUNTIME_USER:?}"
: "${POSTGRES_MIGRATION_USER:?}"
: "${POSTGRES_BACKUP_USER:?}"
: "${POSTGRES_AUDIT_USER:?}"
for role_value in \
  "$POSTGRES_ADMIN_USER" \
  "$POSTGRES_RUNTIME_USER" \
  "$POSTGRES_MIGRATION_USER" \
  "$POSTGRES_BACKUP_USER" \
  "$POSTGRES_AUDIT_USER"
do
  case "$role_value" in
    ""|*[!A-Za-z0-9_]*) fail ;;
  esac
done

ident_file="$tls_directory/pg_ident.conf"
{
  printf 'budget_service budget-db-bootstrap %s\n' "$POSTGRES_ADMIN_USER"
  printf 'budget_service budget-restore-verify %s\n' "$POSTGRES_ADMIN_USER"
  printf 'budget_service budget-migrate %s\n' "$POSTGRES_MIGRATION_USER"
  printf 'budget_service budget-backup %s\n' "$POSTGRES_BACKUP_USER"
  printf 'budget_service budget-integrity %s\n' "$POSTGRES_AUDIT_USER"
  printf 'budget_service budget-web %s\n' "$POSTGRES_RUNTIME_USER"
  printf 'budget_service budget-notify %s\n' "$POSTGRES_RUNTIME_USER"
  printf 'budget_service budget-import-cleanup %s\n' "$POSTGRES_RUNTIME_USER"
  printf 'budget_service budget-mfa-key-rotate %s\n' "$POSTGRES_RUNTIME_USER"
} > "$ident_file"
chown -R postgres:postgres "$tls_directory"
chmod 0700 "$tls_directory"
chmod 0600 "$tls_directory/server.crt" "$tls_directory/server.key" \
  "$tls_directory/client-ca.crt" "$ident_file"

exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file="$tls_directory/server.crt" \
  -c ssl_key_file="$tls_directory/server.key" \
  -c ssl_ca_file="$tls_directory/client-ca.crt" \
  -c ssl_min_protocol_version=TLSv1.2 \
  -c ssl_max_protocol_version=TLSv1.3 \
  -c ssl_prefer_server_ciphers=on \
  -c ident_file="$ident_file" \
  -c hba_file=/etc/postgresql/pg_hba.conf
