from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_regex_safety import APPLICATION_ROOTS, PROJECT_ROOT, validate_regex_safety


def _application_tree(tmp_path: Path) -> Path:
    for root_name in APPLICATION_ROOTS:
        root = tmp_path / root_name
        root.mkdir(parents=True)
        (root / "safe.py").write_text(
            'import re\nPATTERN = re.compile(r"^[a-z]+$")\n',
            encoding="utf-8",
        )
    return tmp_path


def test_regex_inventory_accepts_the_production_application() -> None:
    regex_calls = validate_regex_safety()

    assert regex_calls
    assert all(path.suffix == ".py" and line > 0 for path, line in regex_calls)


def test_regex_inventory_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_regex_safety.py" in powershell_gate
    assert "scripts/check_regex_safety.py" in shell_gate


def test_regex_inventory_rejects_dynamic_patterns(tmp_path: Path) -> None:
    project_root = _application_tree(tmp_path)
    (project_root / "core/dynamic.py").write_text(
        "import re\ndef unsafe(value, candidate):\n    return re.search(value, candidate)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unreviewed dynamic regular expression"):
        validate_regex_safety(project_root)


def test_regex_inventory_rejects_dynamic_django_patterns(tmp_path: Path) -> None:
    project_root = _application_tree(tmp_path)
    (project_root / "core/dynamic.py").write_text(
        "from django.core.validators import RegexValidator\n"
        "def unsafe(value):\n    return RegexValidator(value)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unreviewed dynamic Django regular expression"):
        validate_regex_safety(project_root)


def test_context_password_pattern_requires_re_escape(tmp_path: Path) -> None:
    project_root = _application_tree(tmp_path)
    (project_root / "identity/password_validation.py").write_text(
        "import re\n"
        "class ContextSpecificPasswordValidator:\n"
        "    def __init__(self, values):\n"
        '        alternatives = "|".join(value for value in values)\n'
        '        self.pattern = re.compile(rf"^(?:{alternatives})$")\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unreviewed dynamic regular expression"):
        validate_regex_safety(project_root)


def test_context_password_pattern_accepts_escaped_alternatives(tmp_path: Path) -> None:
    project_root = _application_tree(tmp_path)
    (project_root / "identity/password_validation.py").write_text(
        "import re\n"
        "class ContextSpecificPasswordValidator:\n"
        "    def __init__(self, values):\n"
        '        alternatives = "|".join(re.escape(value) for value in values)\n'
        '        self.pattern = re.compile(rf"^(?:{alternatives})$")\n',
        encoding="utf-8",
    )

    assert validate_regex_safety(project_root)


@pytest.mark.parametrize(
    "source",
    (
        "import re as expressions\n",
        "from re import search\n",
        "import regex\n",
        "import regex as expressions\n",
        "from regex import search\n",
        "from django.core.validators import RegexValidator as Validator\n",
        "from django.forms import RegexField as Field\n",
    ),
)
def test_regex_inventory_rejects_unreviewed_imports(tmp_path: Path, source: str) -> None:
    project_root = _application_tree(tmp_path)
    (project_root / "core/alternate.py").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match=r"aliases|unreviewed regex"):
        validate_regex_safety(project_root)


@pytest.mark.parametrize(
    ("extra_statement", "interpolation"),
    (
        ('        alternatives += "unsafe"\n', "{alternatives}"),
        ('        if values:\n            alternatives = "unsafe"\n', "{alternatives}"),
        ("", "{alternatives:{values}}"),
        ("", "{alternatives!r}"),
    ),
)
def test_escaped_pattern_exception_rejects_mutation_and_formatting(
    tmp_path: Path, extra_statement: str, interpolation: str
) -> None:
    project_root = _application_tree(tmp_path)
    (project_root / "identity/password_validation.py").write_text(
        "import re\n"
        "class ContextSpecificPasswordValidator:\n"
        "    def __init__(self, values):\n"
        '        alternatives = "|".join(re.escape(value) for value in values)\n'
        + extra_statement
        + '        self.pattern = re.compile(rf"^(?:'
        + interpolation
        + ')$")\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unreviewed dynamic regular expression"):
        validate_regex_safety(project_root)
