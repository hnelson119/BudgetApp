from django.db import migrations

PROTECT_CHECKPOINT_SQL = r"""
ALTER TABLE public.audit_auditcheckpoint SET SCHEMA budget_audit;
ALTER TABLE budget_audit.audit_auditcheckpoint OWNER TO budget_audit_owner;

DROP TRIGGER IF EXISTS audit_checkpoint_reject_mutation
    ON budget_audit.audit_auditcheckpoint;
CREATE TRIGGER audit_checkpoint_reject_mutation
BEFORE UPDATE OR DELETE ON budget_audit.audit_auditcheckpoint
FOR EACH ROW EXECUTE FUNCTION budget_audit.reject_audit_mutation();
DROP TRIGGER IF EXISTS audit_checkpoint_reject_truncate
    ON budget_audit.audit_auditcheckpoint;
CREATE TRIGGER audit_checkpoint_reject_truncate
BEFORE TRUNCATE ON budget_audit.audit_auditcheckpoint
FOR EACH STATEMENT EXECUTE FUNCTION budget_audit.reject_audit_mutation();

CREATE OR REPLACE FUNCTION budget_audit.record_checkpoint(
    p_id uuid,
    p_household_id uuid,
    p_last_sequence bigint,
    p_event_count bigint,
    p_chain_head varchar,
    p_verified_at timestamp with time zone,
    p_signature_algorithm varchar,
    p_signing_key_id varchar,
    p_signature varchar,
    p_external_copy_name varchar,
    p_external_copied_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_last_sequence bigint;
    v_event_count bigint;
    v_chain_head varchar;
BEGIN
    IF p_signature_algorithm <> 'HMAC-SHA256'
       OR p_signature !~ '^[0-9a-f]{64}$'
       OR p_signing_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
       OR p_external_copy_name !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$' THEN
        RAISE EXCEPTION 'invalid audit checkpoint parameters' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(p_household_id::text, 0));
    SELECT last_sequence, event_count, chain_head
      INTO v_last_sequence, v_event_count, v_chain_head
      FROM budget_audit.audit_audithead
     WHERE household_id = p_household_id
     FOR UPDATE;

    IF NOT FOUND
       OR p_last_sequence <> v_last_sequence
       OR p_event_count <> v_event_count
       OR p_chain_head <> v_chain_head THEN
        RAISE EXCEPTION 'checkpoint does not match the protected audit head'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO budget_audit.audit_auditcheckpoint (
        id, household_id, last_sequence, event_count, chain_head, verified_at,
        signature_algorithm, signing_key_id, signature, external_copy_name,
        external_copied_at, created_at
    ) VALUES (
        p_id, p_household_id, p_last_sequence, p_event_count, p_chain_head, p_verified_at,
        p_signature_algorithm, p_signing_key_id, p_signature, p_external_copy_name,
        p_external_copied_at, p_verified_at
    );

    UPDATE budget_audit.audit_audithead
       SET verified_at = p_verified_at,
           updated_at = p_verified_at
     WHERE household_id = p_household_id;
END
$function$;
ALTER FUNCTION budget_audit.record_checkpoint(
    uuid, uuid, bigint, bigint, varchar, timestamp with time zone, varchar,
    varchar, varchar, varchar, timestamp with time zone
) OWNER TO budget_audit_owner;

REVOKE ALL ON TABLE budget_audit.audit_auditcheckpoint
    FROM PUBLIC, budget_runtime_access, budget_audit_reader;
GRANT SELECT ON TABLE budget_audit.audit_auditcheckpoint
    TO budget_runtime_access, budget_audit_reader;
REVOKE ALL ON FUNCTION budget_audit.record_checkpoint(
    uuid, uuid, bigint, bigint, varchar, timestamp with time zone, varchar,
    varchar, varchar, varchar, timestamp with time zone
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION budget_audit.record_checkpoint(
    uuid, uuid, bigint, bigint, varchar, timestamp with time zone, varchar,
    varchar, varchar, varchar, timestamp with time zone
) TO budget_audit_reader;
"""

UNPROTECT_CHECKPOINT_SQL = r"""
DROP FUNCTION IF EXISTS budget_audit.record_checkpoint(
    uuid, uuid, bigint, bigint, varchar, timestamp with time zone, varchar,
    varchar, varchar, varchar, timestamp with time zone
);
DROP TRIGGER IF EXISTS audit_checkpoint_reject_mutation
    ON budget_audit.audit_auditcheckpoint;
DROP TRIGGER IF EXISTS audit_checkpoint_reject_truncate
    ON budget_audit.audit_auditcheckpoint;
ALTER TABLE budget_audit.audit_auditcheckpoint OWNER TO CURRENT_USER;
ALTER TABLE budget_audit.audit_auditcheckpoint SET SCHEMA public;
"""


def protect_checkpoint_schema(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_CHECKPOINT_SQL)


def unprotect_checkpoint_schema(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_CHECKPOINT_SQL)


class Migration(migrations.Migration):
    dependencies = [("audit", "0003_auditcheckpoint")]

    operations = [migrations.RunPython(protect_checkpoint_schema, unprotect_checkpoint_schema)]
