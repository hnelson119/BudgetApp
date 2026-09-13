from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_client_technologies import CLIENT_SURFACE_ROOTS
from scripts.check_output_encoding import (
    APPLICATION_ROOTS,
    PROJECT_ROOT,
    validate_output_encoding,
)
from scripts.check_output_encoding import (
    CLIENT_SURFACE_ROOTS as OUTPUT_CLIENT_SURFACE_ROOTS,
)


def _output_tree(tmp_path: Path) -> Path:
    for relative_root in CLIENT_SURFACE_ROOTS:
        root = tmp_path / relative_root
        root.mkdir(parents=True)
        (root / "safe.html").write_text(
            '<!doctype html><p>{{ value }}</p><script src="/static/app.js"></script>',
            encoding="utf-8",
        )
        (root / "app.js").write_text(
            'const node = document.createElement("p"); node.textContent = value;',
            encoding="utf-8",
        )
    for root_name in APPLICATION_ROOTS:
        root = tmp_path / root_name
        root.mkdir(parents=True, exist_ok=True)
        (root / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "core/views.py").write_text(
        "from django.http import JsonResponse\n"
        'def live(request):\n    return JsonResponse({"status": "ok"})\n',
        encoding="utf-8",
    )
    return tmp_path


def test_output_encoding_inventory_accepts_the_production_surface() -> None:
    template_count, script_count, json_response_count = validate_output_encoding()

    assert template_count > 0
    assert script_count > 0
    assert json_response_count == 2


def test_output_encoding_inventory_tracks_the_complete_client_surface() -> None:
    assert OUTPUT_CLIENT_SURFACE_ROOTS == CLIENT_SURFACE_ROOTS


def test_output_encoding_inventory_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_output_encoding.py" in powershell_gate
    assert "scripts/check_output_encoding.py" in shell_gate


@pytest.mark.parametrize(
    ("content", "message"),
    (
        ("{% autoescape off %}{{ value }}{% endautoescape %}", "disabled template auto-escaping"),
        ("{{ value|safe }}", "trusted safe template filter"),
        ("<script>const value = '{{ value }}';</script>", "inline executable script"),
    ),
)
def test_output_encoding_inventory_rejects_unsafe_templates(
    tmp_path: Path, content: str, message: str
) -> None:
    project_root = _output_tree(tmp_path)
    (project_root / CLIENT_SURFACE_ROOTS[0] / "unsafe.html").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        validate_output_encoding(project_root)


@pytest.mark.parametrize(
    ("content", "message"),
    (
        ("target.innerHTML = value;", "HTML parsing sink"),
        ("target.insertAdjacentHTML('beforeend', value);", "HTML parsing sink"),
        ('target["innerHTML"] = value;', "HTML parsing sink"),
        ("eval(value);", "dynamic JavaScript execution"),
        ("Function(value)();", "dynamic JavaScript execution"),
        ("new Function(value)();", "dynamic JavaScript execution"),
        ('setTimeout("run()", 10);', "string timer execution"),
        ('target.setAttribute("onclick", value);', "dynamic event-handler attribute"),
        ('target["setAttribute"]("onclick", value);', "dynamic event-handler attribute"),
    ),
)
def test_output_encoding_inventory_rejects_script_injection_sinks(
    tmp_path: Path, content: str, message: str
) -> None:
    project_root = _output_tree(tmp_path)
    (project_root / CLIENT_SURFACE_ROOTS[0] / "unsafe.js").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        validate_output_encoding(project_root)


@pytest.mark.parametrize(
    ("source", "message"),
    (
        (
            "from django.utils.safestring import mark_safe\nVALUE = mark_safe(user_value)\n",
            "trusted HTML API",
        ),
        (
            "from django.utils.safestring import mark_safe as trusted\nVALUE = trusted\n",
            "trusted HTML API",
        ),
        (
            "class TrustedValue:\n    def __html__(self):\n        return self.value\n",
            "custom trusted HTML",
        ),
        (
            "from django.http import HttpResponse\n"
            "def data(request):\n"
            "    return HttpResponse(user_value, content_type='application/json')\n",
            "manual script or JSON media response",
        ),
        (
            "from django.http import JsonResponse\n"
            "def data(request):\n"
            "    return JsonResponse(payload, encoder=CustomEncoder)\n",
            "custom JsonResponse encoding",
        ),
        (
            "from django.http import JsonResponse\n"
            "def data(request):\n"
            "    return JsonResponse(payload, CustomEncoder)\n",
            "custom JsonResponse encoding",
        ),
        (
            "from django.http import JsonResponse\n"
            "def data(request):\n"
            "    return JsonResponse(payload, **options)\n",
            "custom JsonResponse encoding",
        ),
        (
            "from django.http import JsonResponse as JSON\n"
            "def data(request):\n    return JSON(payload, encoder=CustomEncoder)\n",
            "aliased JsonResponse",
        ),
    ),
)
def test_output_encoding_inventory_rejects_python_bypasses(
    tmp_path: Path, source: str, message: str
) -> None:
    project_root = _output_tree(tmp_path)
    (project_root / "core/unsafe.py").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        validate_output_encoding(project_root)
