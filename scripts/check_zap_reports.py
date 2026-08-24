"""Validate sanitized coverage and blocking results from local ZAP JSON reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_REPORTS = {
    "unauthenticated.json": 4,
    "authenticated-alex.json": 10,
    "authenticated-riley.json": 10,
}


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _validate_report(path: Path, *, minimum_spider_urls: int) -> tuple[int, int]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path.name} is missing or invalid JSON.") from error

    if _items(report.get("afPlanErrors")) or _items(report.get("afPlanWarns")):
        raise ValueError(f"{path.name} contains Automation Framework errors or warnings.")
    statistics = report.get("statistics")
    if not isinstance(statistics, dict):
        raise ValueError(f"{path.name} does not contain scanner statistics.")
    spider_urls = int(statistics.get("stats.spider.url.found", 0))
    if spider_urls < minimum_spider_urls:
        raise ValueError(
            f"{path.name} discovered only {spider_urls} URLs; expected at least "
            f"{minimum_spider_urls}."
        )
    if any(
        "selenium" in str(key).casefold() and str(key).endswith(".failure") for key in statistics
    ):
        raise ValueError(f"{path.name} contains a browser automation failure.")

    alerts: list[dict[str, Any]] = []
    for site in _items(report.get("site")):
        if isinstance(site, dict):
            alerts.extend(item for item in _items(site.get("alerts")) if isinstance(item, dict))
    high_alerts = sum(1 for alert in alerts if int(alert.get("riskcode", 0)) >= 3)
    if high_alerts:
        raise ValueError(f"{path.name} contains {high_alerts} High or Critical alerts.")
    return spider_urls, len(alerts)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: check_zap_reports.py REPORT_DIRECTORY", file=sys.stderr)
        return 2
    report_directory = Path(sys.argv[1])
    failures: list[str] = []
    for report_name, minimum_spider_urls in EXPECTED_REPORTS.items():
        try:
            spider_urls, alert_count = _validate_report(
                report_directory / report_name,
                minimum_spider_urls=minimum_spider_urls,
            )
            print(
                f"{report_name}: {spider_urls} spider URLs, {alert_count} alert types, "
                "no High alerts"
            )
        except ValueError as error:
            failures.append(str(error))
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
