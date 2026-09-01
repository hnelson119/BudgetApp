import os
import subprocess
import sys
from pathlib import Path


def test_production_django_security_check_passes(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "DJANGO_SETTINGS_MODULE": "config.settings.production",
            "DJANGO_ALLOWED_HOSTS": "budget.example.ts.net",
            "DJANGO_CSRF_TRUSTED_ORIGINS": "https://budget.example.ts.net",
            "APP_ENVIRONMENT": "production",
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


def test_production_database_search_path_includes_protected_audit_schema(tmp_path: Path) -> None:
    settings_file = (Path(__file__).resolve().parents[1] / "config/settings/hardened.py").read_text(
        encoding="utf-8"
    )

    assert '"-c search_path=public,budget_audit"' in settings_file


def test_production_static_assets_do_not_allow_arbitrary_cross_origin_reads() -> None:
    settings_file = (Path(__file__).resolve().parents[1] / "config/settings/hardened.py").read_text(
        encoding="utf-8"
    )

    assert "WHITENOISE_ALLOW_ALL_ORIGINS = False" in settings_file


def test_production_settings_pin_exact_private_ingress_and_proxy_boundary() -> None:
    settings_root = Path(__file__).resolve().parents[1] / "config/settings"
    production_file = (settings_root / "production.py").read_text(encoding="utf-8")
    hardened_file = (settings_root / "hardened.py").read_text(encoding="utf-8")

    assert "Production requires one exact lowercase Tailscale HTTPS hostname." in production_file
    assert "Production CSRF origins must contain only the exact Tailscale HTTPS origin." in (
        production_file
    )
    assert 'MIDDLEWARE.insert(0, "core.middleware.ProxyBoundaryMiddleware")' in hardened_file
    assert 'MIDDLEWARE.insert(2, "core.middleware.HostBoundaryMiddleware")' in hardened_file
    assert "USE_X_FORWARDED_HOST = False" in hardened_file
    assert "SESSION_COOKIE_DOMAIN = None" in hardened_file
    assert "CSRF_COOKIE_DOMAIN = None" in hardened_file
    assert "Shared hardened settings cannot be selected directly." in hardened_file
