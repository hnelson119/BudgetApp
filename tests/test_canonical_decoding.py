from __future__ import annotations

from collections import Counter

import pytest
from django.http import QueryDict

from scripts.check_canonical_decoding import (
    PROJECT_ROOT,
    RUNTIME_ENTRY_POINTS,
    RUNTIME_ROOTS,
    decoding_operations,
    validate_canonical_decoding,
    validate_source_decoding,
)
from scripts.check_os_command_safety import RUNTIME_ROOTS as COMMAND_RUNTIME_ROOTS


def test_canonical_decoding_accepts_the_reviewed_production_boundary() -> None:
    runtime_count, file_count, operation_count = validate_canonical_decoding()

    assert runtime_count > 0
    assert file_count == 7
    assert operation_count == 16


def test_canonical_decoding_tracks_the_complete_runtime() -> None:
    assert RUNTIME_ROOTS == COMMAND_RUNTIME_ROOTS
    assert RUNTIME_ENTRY_POINTS == ("manage.py",)


def test_canonical_decoding_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_canonical_decoding.py" in powershell_gate
    assert "scripts/check_canonical_decoding.py" in shell_gate


def test_django_request_decoding_is_single_pass() -> None:
    values = QueryDict("value=%252F&plus=%252B")

    assert values["value"] == "%2F"
    assert values["plus"] == "%2B"


@pytest.mark.parametrize(
    "source",
    (
        "from urllib.parse import unquote\nvalue = unquote(raw)\n",
        "from urllib.parse import unquote as decode_value\nvalue = decode_value(raw)\n",
        "import urllib.parse\nvalue = urllib.parse.parse_qs(raw)\n",
        "import html\nvalue = html.unescape(raw)\n",
        'import codecs\nvalue = codecs.decode(raw, "unicode_escape")\n',
        'value = raw.decode("utf-16")\n',
        'value = raw.decode("utf-8", errors="ignore")\n',
        "import base64\nvalue = base64.b64decode(raw)\n",
    ),
)
def test_canonical_decoding_rejects_repeated_or_ambiguous_decoders(source: str) -> None:
    with pytest.raises(ValueError):
        decoding_operations(source, "unsafe.py")


def test_canonical_decoding_rejects_an_unreviewed_json_parser() -> None:
    source = "import json\nvalue = json.loads(raw)\n"

    with pytest.raises(ValueError):
        validate_source_decoding(source, "new_parser.py", Counter())


def test_canonical_decoding_rejects_double_json_parsing() -> None:
    source = "import json\nvalue = json.loads(json.loads(raw))\n"

    with pytest.raises(ValueError):
        validate_source_decoding(source, "parser.py", Counter({"json.loads": 1}))


def test_canonical_decoding_allows_one_strict_utf8_pass() -> None:
    source = 'value = raw.decode("utf-8", errors="strict")\n'

    assert validate_source_decoding(
        source,
        "parser.py",
        Counter({"bytes.decode:utf-8:strict": 1}),
    )
