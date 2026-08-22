from django.db import migrations

PROTECT_AUDIT_SQL = r"""
DO $block$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'budget_audit_owner') THEN
        RAISE EXCEPTION 'budget_audit_owner must be created by db-bootstrap before migrations';
    END IF;
END
$block$;

ALTER TABLE public.audit_auditevent SET SCHEMA budget_audit;
ALTER TABLE public.audit_audithead SET SCHEMA budget_audit;
ALTER TABLE budget_audit.audit_auditevent OWNER TO budget_audit_owner;
ALTER TABLE budget_audit.audit_audithead OWNER TO budget_audit_owner;

CREATE OR REPLACE FUNCTION budget_audit.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF current_user = 'budget_audit_owner'
       OR pg_has_role(session_user, 'budget_audit_owner', 'MEMBER') THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        IF TG_OP = 'TRUNCATE' THEN
            RETURN NULL;
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'protected audit records cannot be % by this database role', lower(TG_OP)
        USING ERRCODE = '42501';
END
$function$;
ALTER FUNCTION budget_audit.reject_audit_mutation() OWNER TO budget_audit_owner;

DROP TRIGGER IF EXISTS audit_event_reject_mutation ON budget_audit.audit_auditevent;
CREATE TRIGGER audit_event_reject_mutation
BEFORE UPDATE OR DELETE ON budget_audit.audit_auditevent
FOR EACH ROW EXECUTE FUNCTION budget_audit.reject_audit_mutation();
DROP TRIGGER IF EXISTS audit_event_reject_truncate ON budget_audit.audit_auditevent;
CREATE TRIGGER audit_event_reject_truncate
BEFORE TRUNCATE ON budget_audit.audit_auditevent
FOR EACH STATEMENT EXECUTE FUNCTION budget_audit.reject_audit_mutation();

DROP TRIGGER IF EXISTS audit_head_reject_mutation ON budget_audit.audit_audithead;
CREATE TRIGGER audit_head_reject_mutation
BEFORE UPDATE OR DELETE ON budget_audit.audit_audithead
FOR EACH ROW EXECUTE FUNCTION budget_audit.reject_audit_mutation();
DROP TRIGGER IF EXISTS audit_head_reject_truncate ON budget_audit.audit_audithead;
CREATE TRIGGER audit_head_reject_truncate
BEFORE TRUNCATE ON budget_audit.audit_audithead
FOR EACH STATEMENT EXECUTE FUNCTION budget_audit.reject_audit_mutation();

CREATE OR REPLACE FUNCTION budget_audit.append_event(
    p_sequence bigint,
    p_id uuid,
    p_household_id uuid,
    p_actor_id uuid,
    p_occurred_at timestamp with time zone,
    p_household_timezone varchar,
    p_action varchar,
    p_entity_type varchar,
    p_entity_id varchar,
    p_before_payload jsonb,
    p_after_payload jsonb,
    p_reason varchar,
    p_request_id varchar,
    p_previous_hash varchar,
    p_event_hash varchar
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_last_sequence bigint;
    v_chain_head varchar;
BEGIN
    IF p_sequence < 1
       OR p_previous_hash !~ '^[0-9a-f]{64}$'
       OR p_event_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid audit append parameters' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(p_household_id::text, 0));
    SELECT last_sequence, chain_head
      INTO v_last_sequence, v_chain_head
      FROM budget_audit.audit_audithead
     WHERE household_id = p_household_id
     FOR UPDATE;

    IF NOT FOUND THEN
        IF p_sequence <> 1 OR p_previous_hash <> repeat('0', 64) THEN
            RAISE EXCEPTION 'audit chain does not start at the expected boundary'
                USING ERRCODE = '23514';
        END IF;
    ELSIF p_sequence <> v_last_sequence + 1 OR p_previous_hash <> v_chain_head THEN
        RAISE EXCEPTION 'audit append does not match the protected chain head'
            USING ERRCODE = '23514';
    END IF;

    INSERT INTO budget_audit.audit_auditevent (
        sequence, id, household_id, actor_id, occurred_at, household_timezone,
        action, entity_type, entity_id, before_payload, after_payload, reason,
        request_id, previous_hash, event_hash
    ) VALUES (
        p_sequence, p_id, p_household_id, p_actor_id, p_occurred_at, p_household_timezone,
        p_action, p_entity_type, p_entity_id, p_before_payload, p_after_payload, p_reason,
        p_request_id, p_previous_hash, p_event_hash
    );

    INSERT INTO budget_audit.audit_audithead (
        household_id, last_sequence, event_count, chain_head, verified_at, updated_at
    ) VALUES (
        p_household_id, p_sequence, 1, p_event_hash, NULL, p_occurred_at
    )
    ON CONFLICT (household_id) DO UPDATE SET
        last_sequence = EXCLUDED.last_sequence,
        event_count = budget_audit.audit_audithead.event_count + 1,
        chain_head = EXCLUDED.chain_head,
        verified_at = NULL,
        updated_at = EXCLUDED.updated_at;
END
$function$;
ALTER FUNCTION budget_audit.append_event(
    bigint, uuid, uuid, uuid, timestamp with time zone, varchar, varchar, varchar,
    varchar, jsonb, jsonb, varchar, varchar, varchar, varchar
) OWNER TO budget_audit_owner;

REVOKE ALL ON SCHEMA budget_audit FROM PUBLIC;
REVOKE CREATE ON SCHEMA budget_audit FROM budget_runtime_access, budget_audit_reader;
GRANT USAGE ON SCHEMA budget_audit TO budget_runtime_access, budget_audit_reader;
REVOKE ALL ON TABLE budget_audit.audit_auditevent FROM PUBLIC, budget_runtime_access;
REVOKE ALL ON TABLE budget_audit.audit_audithead FROM PUBLIC, budget_runtime_access;
GRANT SELECT ON TABLE budget_audit.audit_auditevent TO budget_runtime_access, budget_audit_reader;
GRANT SELECT ON TABLE budget_audit.audit_audithead TO budget_runtime_access, budget_audit_reader;
REVOKE ALL ON FUNCTION budget_audit.append_event(
    bigint, uuid, uuid, uuid, timestamp with time zone, varchar, varchar, varchar,
    varchar, jsonb, jsonb, varchar, varchar, varchar, varchar
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION budget_audit.append_event(
    bigint, uuid, uuid, uuid, timestamp with time zone, varchar, varchar, varchar,
    varchar, jsonb, jsonb, varchar, varchar, varchar, varchar
) TO budget_runtime_access;
"""

UNPROTECT_AUDIT_SQL = r"""
DROP FUNCTION IF EXISTS budget_audit.append_event(
    bigint, uuid, uuid, uuid, timestamp with time zone, varchar, varchar, varchar,
    varchar, jsonb, jsonb, varchar, varchar, varchar, varchar
);
DROP TRIGGER IF EXISTS audit_event_reject_mutation ON budget_audit.audit_auditevent;
DROP TRIGGER IF EXISTS audit_event_reject_truncate ON budget_audit.audit_auditevent;
DROP TRIGGER IF EXISTS audit_head_reject_mutation ON budget_audit.audit_audithead;
DROP TRIGGER IF EXISTS audit_head_reject_truncate ON budget_audit.audit_audithead;
DROP FUNCTION IF EXISTS budget_audit.reject_audit_mutation();
ALTER TABLE budget_audit.audit_auditevent OWNER TO CURRENT_USER;
ALTER TABLE budget_audit.audit_audithead OWNER TO CURRENT_USER;
ALTER TABLE budget_audit.audit_auditevent SET SCHEMA public;
ALTER TABLE budget_audit.audit_audithead SET SCHEMA public;
"""


def protect_audit_schema(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_AUDIT_SQL)


def unprotect_audit_schema(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_AUDIT_SQL)


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]

    operations = [migrations.RunPython(protect_audit_schema, unprotect_audit_schema)]
