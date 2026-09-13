from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_output_encoding import (
    APPLICATION_ROOTS as OUTPUT_APPLICATION_ROOTS,
)
from scripts.check_output_encoding import (
    CLIENT_SURFACE_ROOTS,
)
from scripts.check_template_safety import (
    APPLICATION_ROOTS,
    PROJECT_ROOT,
    TEMPLATE_ROOTS,
    validate_template_safety,
)


def _template_tree(tmp_path: Path) -> Path:
    for root_name in APPLICATION_ROOTS:
        root = tmp_path / root_name
        root.mkdir(parents=True)
        (root / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    for relative_root in TEMPLATE_ROOTS:
        root = tmp_path / relative_root
        root.mkdir(parents=True, exist_ok=True)
        (root / "base.html").write_text("<!doctype html><p>Safe</p>", encoding="utf-8")
        (root / "page.html").write_text(
            '{% extends "base.html" %}{% block content %}Safe{% endblock %}',
            encoding="utf-8",
        )
    (tmp_path / "core/views.py").write_text(
        "from django.shortcuts import render\n"
        "def page(request):\n    return render(request, 'page.html', {})\n",
        encoding="utf-8",
    )
    return tmp_path


def test_template_safety_inventory_accepts_the_production_surface() -> None:
    template_count, selection_count, dependency_count = validate_template_safety()

    assert template_count > 0
    assert selection_count > 0
    assert dependency_count > 0


def test_template_safety_inventory_tracks_application_and_template_roots() -> None:
    expected_template_roots = tuple(
        root for root in CLIENT_SURFACE_ROOTS if root.endswith("/templates")
    )

    assert APPLICATION_ROOTS == OUTPUT_APPLICATION_ROOTS
    assert TEMPLATE_ROOTS == expected_template_roots


def test_template_safety_inventory_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_template_safety.py" in powershell_gate
    assert "scripts/check_template_safety.py" in shell_gate


@pytest.mark.parametrize(
    ("source", "message"),
    (
        (
            "from django.shortcuts import render\n"
            "def page(request, selected):\n    return render(request, selected, {})\n",
            "template selection must use a literal template name",
        ),
        (
            "from django.shortcuts import render\n"
            "def page(request):\n    return render(request, 'missing.html', {})\n",
            "unknown template name",
        ),
        (
            "from django.template import Template\nVALUE = Template(user_value)\n",
            "dynamic template API Template",
        ),
        (
            "from django.template import Engine\n"
            "VALUE = Engine.get_default().from_string(user_value)\n",
            "dynamic template API",
        ),
        (
            "from django.template import Engine as TemplateEngine\n",
            "dynamic template API Engine",
        ),
        (
            "from django.shortcuts import render as page_renderer\nVALUE = page_renderer\n",
            "aliased template API render",
        ),
        (
            "from django.template.loader import select_template\n"
            "VALUE = select_template(['page.html', user_value])\n",
            "template selection must use only literal template names",
        ),
    ),
)
def test_template_safety_inventory_rejects_dynamic_python_templates(
    tmp_path: Path, source: str, message: str
) -> None:
    project_root = _template_tree(tmp_path)
    (project_root / "core/unsafe.py").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        validate_template_safety(project_root)


@pytest.mark.parametrize(
    ("content", "message"),
    (
        ("{% extends selected_template %}", "dynamic extends template"),
        ("{% include selected_template %}", "dynamic include template"),
        ('{% include "missing.html" %}', "unknown template name"),
        ('{% include "page.html"|add:suffix %}', "dynamic include template"),
    ),
)
def test_template_safety_inventory_rejects_dynamic_template_dependencies(
    tmp_path: Path, content: str, message: str
) -> None:
    project_root = _template_tree(tmp_path)
    (project_root / TEMPLATE_ROOTS[0] / "unsafe.html").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        validate_template_safety(project_root)
