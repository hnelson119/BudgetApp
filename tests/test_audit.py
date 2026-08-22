from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction

from audit.models import AuditEvent
from audit.services import append_event, verify_household_chain
from households.models import Household, HouseholdMembership

TEST_PASSWORD = "correct-horse-battery-test"  # pragma: allowlist secret
REQUEST_ID = "request-audit-1234"


@pytest.fixture
def household_and_user(db):  # type: ignore[no-untyped-def]
    household = Household.objects.create(name="Audit Household")
    user = get_user_model().objects.create_user(
        email="auditor@example.com",
        password=TEST_PASSWORD,
    )
    HouseholdMembership.objects.create(household=household, user=user)
    return household, user


@pytest.mark.django_db
def test_events_are_canonical_hash_chained_and_verifiable(household_and_user) -> None:  # type: ignore[no-untyped-def]
    household, user = household_and_user
    first = append_event(
        household=household,
        actor=user,
        action="budget.item_created",
        entity_type="budget.item",
        entity_id="item-1",
        request_id=REQUEST_ID,
        after={"amount": Decimal("12.30"), "enabled": True},
    )
    second = append_event(
        household=household,
        actor=user,
        action="budget.item_updated",
        entity_type="budget.item",
        entity_id="item-1",
        request_id="request-audit-5678",
        before={"amount": Decimal("12.30")},
        after={"amount": Decimal("15.00")},
    )

    assert first.sequence == 1
    assert first.after_payload == {"amount": "12.30", "enabled": True}
    assert second.sequence == 2
    assert second.previous_hash == first.event_hash
    assert len(second.event_hash) == 64

    result = verify_household_chain(household)
    assert result.valid is True
    assert result.event_count == 2
    assert result.chain_head == second.event_hash


@pytest.mark.django_db
def test_ordinary_orm_paths_cannot_mutate_or_delete_audit_events(household_and_user) -> None:  # type: ignore[no-untyped-def]
    household, user = household_and_user
    event = append_event(
        household=household,
        actor=user,
        action="household.created",
        entity_type="household",
        entity_id=household.pk,
        request_id=REQUEST_ID,
    )

    event.action = "tampered"
    with pytest.raises(ValidationError, match="cannot be updated"):
        event.save()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        event.delete()
    with pytest.raises(ValidationError, match="cannot be updated"):
        AuditEvent.objects.filter(pk=event.pk).update(action="tampered")
    with pytest.raises(ValidationError, match="cannot be deleted"):
        AuditEvent.objects.filter(pk=event.pk).delete()


@pytest.mark.django_db
def test_external_row_tampering_breaks_integrity_verification(household_and_user) -> None:  # type: ignore[no-untyped-def]
    household, user = household_and_user
    event = append_event(
        household=household,
        actor=user,
        action="goal.created",
        entity_type="goal",
        entity_id="goal-1",
        request_id=REQUEST_ID,
    )
    table_name = connection.ops.quote_name(AuditEvent._meta.db_table)
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE {table_name} SET action = %s WHERE id = %s",
            ["goal.tampered", event.pk.hex],
        )

    result = verify_household_chain(household)
    assert result.valid is False
    assert result.failure_sequence == 1


@pytest.mark.django_db(transaction=True)
def test_domain_change_and_audit_event_roll_back_together(household_and_user) -> None:  # type: ignore[no-untyped-def]
    household, user = household_and_user

    with pytest.raises(RuntimeError, match="force rollback"):
        with transaction.atomic():
            household.name = "Changed Household"
            household.save(update_fields=("name", "updated_at"))
            append_event(
                household=household,
                actor=user,
                action="household.updated",
                entity_type="household",
                entity_id=household.pk,
                request_id=REQUEST_ID,
                before={"name": "Audit Household"},
                after={"name": "Changed Household"},
            )
            raise RuntimeError("force rollback")

    household.refresh_from_db()
    assert household.name == "Audit Household"
    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_audit_actor_must_be_an_active_household_member(household_and_user) -> None:  # type: ignore[no-untyped-def]
    household, _ = household_and_user
    outsider = get_user_model().objects.create_user(
        email="outsider@example.com",
        password=TEST_PASSWORD,
    )

    with pytest.raises(PermissionDenied):
        append_event(
            household=household,
            actor=outsider,
            action="budget.item_created",
            entity_type="budget.item",
            entity_id="item-1",
            request_id=REQUEST_ID,
        )


@pytest.mark.django_db
@pytest.mark.parametrize(
    "payload",
    [
        {"amount": 12.5},
        {"nested": {"password": "must-not-be-recorded"}},  # pragma: allowlist secret
        {"session_id": "must-not-be-recorded"},
    ],
)
def test_audit_payload_rejects_unsafe_types_and_sensitive_keys(
    household_and_user,
    payload: dict[str, object],  # type: ignore[no-untyped-def]
) -> None:
    household, user = household_and_user

    with pytest.raises(ValidationError):
        append_event(
            household=household,
            actor=user,
            action="budget.item_created",
            entity_type="budget.item",
            entity_id="item-1",
            request_id=REQUEST_ID,
            after=payload,
        )
    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_empty_household_chain_is_valid() -> None:
    household = Household.objects.create(name="Empty Household")

    result = verify_household_chain(household)

    assert result.valid is True
    assert result.event_count == 0
