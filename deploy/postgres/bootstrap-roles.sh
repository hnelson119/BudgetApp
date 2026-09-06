#!/bin/sh
set -eu

cat <<'SQL' | psql \
  --host "$DATABASE_HOST" \
  --username "$POSTGRES_ADMIN_USER" \
  --dbname "$POSTGRES_DB" \
  --set ON_ERROR_STOP=1 \
  --set runtime_user="$POSTGRES_RUNTIME_USER" \
  --set migration_user="$POSTGRES_MIGRATION_USER" \
  --set backup_user="$POSTGRES_BACKUP_USER" \
  --set audit_user="$POSTGRES_AUDIT_USER" \
  --set admin_user="$POSTGRES_ADMIN_USER"
SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT PASSWORD NULL',
  :'runtime_user'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'runtime_user') \gexec
SELECT format('ALTER ROLE %I INHERIT PASSWORD NULL', :'runtime_user') \gexec

SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT PASSWORD NULL',
  :'migration_user'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'migration_user') \gexec
SELECT format('ALTER ROLE %I INHERIT PASSWORD NULL', :'migration_user') \gexec

SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD NULL',
  :'backup_user'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'backup_user') \gexec
SELECT format('ALTER ROLE %I PASSWORD NULL', :'backup_user') \gexec

SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT PASSWORD NULL',
  :'audit_user'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'audit_user') \gexec
SELECT format('ALTER ROLE %I INHERIT PASSWORD NULL', :'audit_user') \gexec
SELECT format('ALTER ROLE %I PASSWORD NULL', :'admin_user') \gexec

SELECT 'CREATE ROLE budget_runtime_access NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'budget_runtime_access') \gexec
SELECT 'CREATE ROLE budget_audit_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'budget_audit_reader') \gexec
SELECT 'CREATE ROLE budget_audit_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'budget_audit_owner') \gexec

SELECT format(
  'GRANT budget_runtime_access TO %I WITH INHERIT TRUE, SET FALSE', :'runtime_user'
) \gexec
SELECT format(
  'GRANT budget_audit_reader TO %I WITH INHERIT TRUE, SET FALSE', :'audit_user'
) \gexec
SELECT format(
  'GRANT budget_audit_owner TO %I WITH INHERIT TRUE, SET TRUE', :'migration_user'
) \gexec

CREATE SCHEMA IF NOT EXISTS budget_audit AUTHORIZATION budget_audit_owner;
ALTER SCHEMA budget_audit OWNER TO budget_audit_owner;
REVOKE ALL ON SCHEMA budget_audit FROM PUBLIC;
SELECT format('GRANT USAGE, CREATE ON SCHEMA budget_audit TO %I', :'migration_user') \gexec
REVOKE CREATE ON SCHEMA budget_audit FROM budget_runtime_access, budget_audit_reader;
GRANT USAGE ON SCHEMA budget_audit TO budget_runtime_access, budget_audit_reader;
SELECT format('GRANT USAGE ON SCHEMA budget_audit TO %I', :'backup_user') \gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'runtime_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'migration_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'backup_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'audit_user') \gexec

SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'runtime_user') \gexec
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'migration_user') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'audit_user') \gexec
SELECT format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', :'runtime_user') \gexec
SELECT format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', :'runtime_user') \gexec
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO budget_runtime_access;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO budget_runtime_access;
SELECT format('GRANT SELECT ON ALL TABLES IN SCHEMA public TO %I', :'backup_user') \gexec
SELECT format(
  'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'backup_user'
) \gexec

SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM %I',
  :'migration_user', :'runtime_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I',
  :'migration_user', :'runtime_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
  'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO budget_runtime_access',
  :'migration_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
  'GRANT USAGE, SELECT ON SEQUENCES TO budget_runtime_access',
  :'migration_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO %I',
  :'migration_user', :'backup_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
  'GRANT USAGE, SELECT ON SEQUENCES TO %I',
  :'migration_user', :'backup_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA budget_audit GRANT SELECT ON TABLES TO %I',
  :'migration_user', :'backup_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA budget_audit '
  'GRANT USAGE, SELECT ON SEQUENCES TO %I',
  :'migration_user', :'backup_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE budget_audit_owner '
  'IN SCHEMA budget_audit GRANT SELECT ON TABLES TO %I',
  :'backup_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE budget_audit_owner '
  'IN SCHEMA budget_audit GRANT USAGE, SELECT ON SEQUENCES TO %I',
  :'backup_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA budget_audit '
  'REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC',
  :'migration_user'
) \gexec
ALTER DEFAULT PRIVILEGES FOR ROLE budget_audit_owner
  IN SCHEMA budget_audit REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
SELECT format('GRANT SELECT ON ALL TABLES IN SCHEMA budget_audit TO %I', :'backup_user') \gexec
SELECT format(
  'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA budget_audit TO %I', :'backup_user'
) \gexec
REVOKE ALL ON ALL TABLES IN SCHEMA budget_audit
  FROM PUBLIC, budget_runtime_access, budget_audit_reader;
SELECT format(
  'GRANT SELECT ON TABLE %I.%I TO budget_runtime_access, budget_audit_reader',
  schemaname, tablename
)
FROM pg_tables
WHERE schemaname = 'budget_audit'
  AND tablename IN ('audit_auditevent', 'audit_audithead', 'audit_auditcheckpoint')
ORDER BY tablename \gexec
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA budget_audit
  FROM PUBLIC, budget_runtime_access, budget_audit_reader;
SELECT 'GRANT EXECUTE ON FUNCTION budget_audit.append_event(
  bigint, uuid, uuid, uuid, timestamp with time zone, varchar, varchar, varchar,
  varchar, jsonb, jsonb, varchar, varchar, varchar, varchar
) TO budget_runtime_access'
WHERE to_regprocedure(
  'budget_audit.append_event(bigint,uuid,uuid,uuid,timestamp with time zone,'
  'varchar,varchar,varchar,varchar,jsonb,jsonb,varchar,varchar,varchar,varchar)'
) IS NOT NULL \gexec
SELECT 'GRANT EXECUTE ON FUNCTION budget_audit.record_checkpoint(
  uuid, uuid, bigint, bigint, varchar, timestamp with time zone, varchar,
  varchar, varchar, varchar, timestamp with time zone
) TO budget_audit_reader'
WHERE to_regprocedure(
  'budget_audit.record_checkpoint(uuid,uuid,bigint,bigint,varchar,'
  'timestamp with time zone,varchar,varchar,varchar,varchar,timestamp with time zone)'
) IS NOT NULL \gexec
DO $block$
BEGIN
  IF EXISTS (
    SELECT FROM pg_authid
    WHERE rolcanlogin AND rolname !~ '^pg_' AND rolpassword IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Production login roles must not have password verifiers';
  END IF;
END;
$block$;
SQL
echo "Database roles and grants are ready."
