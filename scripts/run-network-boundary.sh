#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.yaml"
probe_script="$project_root/deploy/network/run-production-boundary.py"
project_name="budgetapp-network-boundary"
probe_hostname="budget-probe.example.ts.net"
temporary_directory="$(mktemp -d /tmp/budgetapp-network-boundary.XXXXXX)"
secret_directory="$temporary_directory/secrets"
authority_directory="$temporary_directory/postgres-authority"
backup_directory="$temporary_directory/backups"
checkpoint_directory="$temporary_directory/checkpoints"
build_context="$temporary_directory/build-context"
mkdir -m 700 "$secret_directory" "$backup_directory" "$checkpoint_directory"
mkdir -m 700 "$build_context"

for command_name in docker git openssl python3 sudo tar; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "A required production-boundary command is unavailable: $command_name" >&2
    exit 1
  fi
done
build_file_list="$temporary_directory/build-files"
build_archive="$temporary_directory/build-context.tar"
git -C "$project_root" status --short >/dev/null
git -C "$project_root" ls-files --cached --others --exclude-standard -z > "$build_file_list"
tar -C "$project_root" --null --no-recursion --files-from="$build_file_list" \
  -cf "$build_archive"
tar -C "$build_context" -xf "$build_archive"
rm -f -- "$build_file_list" "$build_archive"

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" \
    down --volumes --remove-orphans || true
  case "$temporary_directory" in
    /tmp/budgetapp-network-boundary.*)
      if [ -d "$temporary_directory" ] && [ ! -L "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
      fi
      ;;
    *)
      echo "Refusing to remove an unexpected network-boundary temporary directory." >&2
      exit 1
      ;;
  esac
}
trap cleanup EXIT INT TERM

for secret_name in \
  django_secret_key \
  django_mfa_encryption_key \
  audit_checkpoint_signing_key \
  restic_repository_password
do
  openssl rand -base64 48 | tr -d '\n' > "$secret_directory/$secret_name"
  chmod 440 "$secret_directory/$secret_name"
done
python3 "$project_root/scripts/generate-postgres-tls.py" \
  --authority-directory "$authority_directory" \
  --deployment-directory "$secret_directory" \
  --secret-group-id "$(id -g)"
find "$secret_directory" -mindepth 1 -maxdepth 1 -type f \
  -exec sudo chown root:"$(id -g)" {} +
find "$secret_directory" -mindepth 1 -maxdepth 1 -type f -exec sudo chmod 440 {} +

export APP_ENVIRONMENT=production
export APP_RELEASE=network-boundary-probe
export BUDGET_AUDIT_CHECKPOINT_DIRECTORY="$checkpoint_directory"
export BUDGET_BACKUP_REPOSITORY="$backup_directory"
export BUDGET_BUILD_CONTEXT="$build_context"
export BUDGET_SECRET_DIR="$secret_directory"
export BUDGET_SECRET_GID="$(id -g)"
export DJANGO_ALLOWED_HOSTS="$probe_hostname"
export DJANGO_CSRF_TRUSTED_ORIGINS="https://$probe_hostname"

docker compose -p "$project_name" -f "$compose_file" \
  down --volumes --remove-orphans
docker compose -p "$project_name" -f "$compose_file" \
  up --build --detach db
docker compose -p "$project_name" -f "$compose_file" --profile maintenance \
  run --rm db-bootstrap
docker compose -p "$project_name" -f "$compose_file" --profile maintenance \
  run --build --rm migrate
docker compose -p "$project_name" -f "$compose_file" \
  up --build --detach web ingress

if [ -x "$project_root/.venv/bin/python" ]; then
  probe_python="$project_root/.venv/bin/python"
else
  probe_python=python3
fi
"$probe_python" "$probe_script" \
  --compose-file "$compose_file" \
  --project-name "$project_name" \
  --hostname "$probe_hostname" \
  --secret-directory "$secret_directory"

echo "Disposable production-boundary validation completed."
