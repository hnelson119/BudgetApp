#!/bin/sh
set -eu

read_secret() {
  secret_file="$1"
  if [ ! -s "$secret_file" ]; then
    echo "Required secret file is missing or empty." >&2
    exit 1
  fi
  tr -d '\r\n' < "$secret_file"
}

validate_secret() {
  value="$1"
  if [ "${#value}" -lt 32 ]; then
    echo "A database secret is shorter than 32 characters." >&2
    exit 1
  fi
  case "$value" in
    *[!A-Za-z0-9+/=]*)
      echo "Database secrets must use the documented base64 format." >&2
      exit 1
      ;;
  esac
}

export PGPASSWORD="$(read_secret /run/secrets/postgres_admin_password)"
runtime_password="$(read_secret /run/secrets/postgres_runtime_password)"
migration_password="$(read_secret /run/secrets/postgres_migration_password)"
backup_password="$(read_secret /run/secrets/postgres_backup_password)"
audit_password="$(read_secret /run/secrets/postgres_audit_password)"

validate_secret "$runtime_password"
validate_secret "$migration_password"
validate_secret "$backup_password"
validate_secret "$audit_password"

{
  printf "\\set runtime_password '%s'\n" "$runtime_password"
  printf "\\set migration_password '%s'\n" "$migration_password"
  printf "\\set backup_password '%s'\n" "$backup_password"
  printf "\\set audit_password '%s'\n" "$audit_password"
  cat <<'SQL'
SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
  :'runtime_user', :'runtime_password'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'runtime_user') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'runtime_user', :'runtime_password') \gexec

SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
  :'migration_user', :'migration_password'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'migration_user') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'migration_user', :'migration_password') \gexec

SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
  :'backup_user', :'backup_password'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'backup_user') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'backup_user', :'backup_password') \gexec

SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L',
  :'audit_user', :'audit_password'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'audit_user') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'audit_user', :'audit_password') \gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'runtime_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'migration_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'backup_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'audit_user') \gexec

SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'runtime_user') \gexec
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'migration_user') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'audit_user') \gexec
SELECT format(
  'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I',
  :'runtime_user'
) \gexec
SELECT format(
  'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'runtime_user'
) \gexec
SELECT format('GRANT SELECT ON ALL TABLES IN SCHEMA public TO %I', :'backup_user') \gexec
SELECT format(
  'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'backup_user'
) \gexec

SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
  'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
  :'migration_user', :'runtime_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
  'GRANT USAGE, SELECT ON SEQUENCES TO %I',
  :'migration_user', :'runtime_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO %I',
  :'migration_user', :'backup_user'
) \gexec
SELECT format('GRANT pg_read_all_data TO %I', :'backup_user') \gexec
SQL
} | psql \
  --host "$DATABASE_HOST" \
  --username "$POSTGRES_ADMIN_USER" \
  --dbname "$POSTGRES_DB" \
  --set ON_ERROR_STOP=1 \
  --set runtime_user="$POSTGRES_RUNTIME_USER" \
  --set migration_user="$POSTGRES_MIGRATION_USER" \
  --set backup_user="$POSTGRES_BACKUP_USER" \
  --set audit_user="$POSTGRES_AUDIT_USER"

unset PGPASSWORD runtime_password migration_password backup_password audit_password
echo "Database roles and grants are ready."
