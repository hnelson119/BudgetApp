import os
import subprocess
import sys
from pathlib import Path


def test_production_django_security_check_passes(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "DJANGO_SETTINGS_MODULE": "config.settings.production",
            "DJANGO_ALLOWED_HOSTS": "budget.example.test",
            "DJANGO_CSRF_TRUSTED_ORIGINS": "https://budget.example.test",
            "POSTGRES_DB": "household_budget",
            "POSTGRES_USER": "budget_runtime",
            "DATABASE_HOST": "db",
        }
    )
    environment.pop("DJANGO_SECRET_KEY", None)
    environment.pop("DJANGO_MFA_ENCRYPTION_KEY", None)
    environment.pop("POSTGRES_PASSWORD", None)

    for name in ("DJANGO_SECRET_KEY", "DJANGO_MFA_ENCRYPTION_KEY", "POSTGRES_PASSWORD"):
        secret_path = tmp_path / name.casefold()
        secret_path.write_text((f"value-for-{name}-9Z!" * 6), encoding="utf-8")
        environment[f"{name}_FILE"] = str(secret_path)

    result = subprocess.run(
        [sys.executable, "manage.py", "check", "--deploy"],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "System check identified no issues" in result.stdout
