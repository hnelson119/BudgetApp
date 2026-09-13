from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_format_string_safety import (
    PROJECT_ROOT,
    RUNTIME_ENTRY_POINTS,
    RUNTIME_ROOTS,
    validate_format_string_safety,
)
from scripts.check_os_command_safety import RUNTIME_ROOTS as COMMAND_RUNTIME_ROOTS


def _runtime_tree(tmp_path: Path) -> Path:
    for root_name in RUNTIME_ROOTS:
        root = tmp_path / root_name
        root.mkdir(parents=True)
        (root / "safe.py").write_text("VALUE = f'{42:04d}'\n", encoding="utf-8")
    for relative_path in RUNTIME_ENTRY_POINTS:
        (tmp_path / relative_path).write_text("VALUE = 1\n", encoding="utf-8")
    return tmp_path


def test_format_string_inventory_accepts_the_production_runtime() -> None:
    file_count, modulo_count, handler_format_count = validate_format_string_safety()

    assert file_count > 0
    assert modulo_count == 11
    assert handler_format_count == 1


def test_format_string_inventory_tracks_the_complete_runtime() -> None:
    assert RUNTIME_ROOTS == COMMAND_RUNTIME_ROOTS
    assert RUNTIME_ENTRY_POINTS == ("manage.py",)


def test_format_string_inventory_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_format_string_safety.py" in powershell_gate
    assert "scripts/check_format_string_safety.py" in shell_gate


@pytest.mark.parametrize(
    ("source", "message"),
    (
        ("VALUE = template.format(user_value)\n", "format method receiver must be a literal"),
        ("VALUE = template.format_map(values)\n", "format method receiver must be a literal"),
        ("VALUE = format(user_value, user_spec)\n", "format specification must be literal"),
        ("VALUE = f'{user_value:{user_width}}'\n", "dynamic f-string format"),
        ("VALUE = '{0:{1}}'.format(value, spec)\n", "nested dynamic format specification"),
        ("VALUE = '{value:{spec}}'.format_map(values)\n", "nested dynamic format specification"),
        ("VALUE = '{'.format(value)\n", "invalid literal format grammar"),
        (
            "VALUE = format_html('{0:{1}}', value, spec)\n",
            "nested dynamic format specification",
        ),
        (
            "VALUE = format_html_join('', '{0:{1}}', values)\n",
            "nested dynamic format specification",
        ),
        ("VALUE = template % user_value\n", "unreviewed percent-format or modulo"),
        (
            "from datetime import datetime\nVALUE = datetime.strptime(value, user_format)\n",
            "datetime parse format must be literal",
        ),
        ("VALUE = current.strftime(user_format)\n", "datetime format string must be literal"),
        (
            "from django.utils.html import format_html\n"
            "VALUE = format_html(user_format, user_value)\n",
            "HTML format string must be literal",
        ),
        (
            "import logging\nunsafe_logger = logging.getLogger(__name__)\n"
            "unsafe_logger.info(user_format, user_value)\n",
            "log message format must be literal",
        ),
        ("from string import Template\nVALUE = Template(user_value)\n", "runtime string templates"),
        ("import string as text\nVALUE = text.Formatter()\n", "runtime string templates"),
        ("from builtins import format as render_value\n", "aliased built-in format"),
    ),
)
def test_format_string_inventory_rejects_dynamic_grammars(
    tmp_path: Path, source: str, message: str
) -> None:
    project_root = _runtime_tree(tmp_path)
    (project_root / "core/unsafe.py").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        validate_format_string_safety(project_root)


def test_format_string_inventory_accepts_literal_grammars_and_django_messages(
    tmp_path: Path,
) -> None:
    project_root = _runtime_tree(tmp_path)
    (project_root / "core/formatted.py").write_text(
        "VALUE = '{name}'.format(name=user_value)\n"
        "FIXED = '{value:04d}'.format_map(values)\n"
        "ESCAPED = '{{name}} {name}'.format(name=user_value)\n"
        "DECIMAL = format(user_value, '.2f')\n"
        "STAMP = current.strftime('%Y-%m-%d')\n"
        "PARSED = datetime.strptime(value, '%Y-%m-%d')\n"
        "messages.error(request, user_message)\n",
        encoding="utf-8",
    )

    assert validate_format_string_safety(project_root)[0] > 0


def test_format_string_inventory_rejects_modified_csv_date_grammar(tmp_path: Path) -> None:
    project_root = _runtime_tree(tmp_path)
    path = project_root / "imports/services/batches.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "from datetime import datetime\n"
        "_DATE_FORMATS: dict[str, tuple[str, ...]] = {'auto': (user_format,)}\n"
        "VALUE = datetime.strptime(normalized, pattern)\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="CSV date-format allowlist"):
        validate_format_string_safety(project_root)
