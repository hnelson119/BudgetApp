from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest

from scripts.check_data_classification import (
    INVENTORY_PATH,
    PROJECT_ROOT,
    application_model_labels,
    validate_data_classification,
    validate_inventory_document,
)


def _document() -> dict[str, Any]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_data_classification_accepts_the_production_inventory() -> None:
    assert validate_data_classification() == (4, 15, 45)


def test_data_classification_covers_every_django_model_once() -> None:
    document = _document()
    classified = [model for dataset in document["datasets"] for model in dataset["django_models"]]

    assert len(classified) == len(set(classified))
    assert set(classified) == application_model_labels()


def test_data_classification_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_data_classification.py" in powershell_gate
    assert "scripts/check_data_classification.py" in shell_gate


@pytest.mark.parametrize(
    "mutation",
    (
        lambda document: document["protection_levels"].pop(),
        lambda document: document["datasets"].pop(),
        lambda document: document["datasets"][0].update(level="unknown"),
        lambda document: document["datasets"][0]["django_models"].pop(),
        lambda document: document["datasets"][1]["django_models"].append(
            document["datasets"][0]["django_models"][0]
        ),
        lambda document: document["protection_levels"][3].update(retention=""),
        lambda document: document["summary"].update(datasets=999),
        lambda document: document.update(password_value="do-not-store"),
    ),
)
def test_data_classification_rejects_incomplete_or_unsafe_catalogs(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    document = copy.deepcopy(_document())
    mutation(document)

    with pytest.raises(ValueError):
        validate_inventory_document(PROJECT_ROOT, document)


def test_data_classification_requires_encoded_data_to_inherit_source_protection() -> None:
    document = _document()

    assert all(
        "inherit" in level["encoding_and_masking"].casefold()
        for level in document["protection_levels"]
    )


def test_data_classification_documents_database_encryption_for_sensitive_levels() -> None:
    levels = {level["id"]: level for level in _document()["protection_levels"]}

    for identifier in ("confidential", "restricted"):
        requirement = levels[identifier]["database_level_encryption"].casefold()
        assert "encrypted" in requirement
        assert "release verification" in requirement
