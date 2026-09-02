#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.pentest.yaml"
project_name="budgetapp-upgrade-rehearsal"
rollback_target="household_budget_pentest_restore_upgrade_rollback"
temporary_directory="$(mktemp -d /tmp/budgetapp-upgrade-rehearsal.XXXXXX)"
build_context="$temporary_directory/build-context"
mkdir -m 700 "$build_context"

for command_name in docker git tar
do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "A required upgrade-rehearsal command is unavailable: $command_name" >&2
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
export PENTEST_BUILD_CONTEXT="$build_context"
export PENTEST_BACKUP_RELEASE=pentest-upgrade-baseline

compose() {
  docker compose -p "$project_name" -f "$compose_file" --profile upgrade "$@"
}

cleanup() {
  compose down --volumes --remove-orphans || true
  case "$temporary_directory" in
    /tmp/budgetapp-upgrade-rehearsal.*)
      if [ -d "$temporary_directory" ] && [ ! -L "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
      fi
      ;;
    *)
      echo "Refusing to remove an unexpected upgrade-rehearsal temporary directory." >&2
      exit 1
      ;;
  esac
}

trap cleanup EXIT INT TERM
compose down --volumes --remove-orphans

compose build \
  pentest-migrate \
  pentest-seed \
  pentest-web \
  pentest-fixture-verify \
  pentest-backup \
  pentest-restore-verify \
  pentest-restore-audit \
  pentest-upgrade-migrate \
  pentest-upgrade-candidate-web \
  pentest-upgrade-rollback-web \
  pentest-upgrade-verify

compose up --no-build --wait pentest-web
compose run --rm --no-deps pentest-fixture-verify
compose run --rm --no-deps pentest-restore-storage-init
compose run --rm --no-deps pentest-restore-audit \
  python manage.py write_audit_checkpoints
compose run --rm --no-deps pentest-backup
compose run --rm --no-deps pentest-backup \
  /bin/sh /opt/pentest/verify-encrypted-repository.sh

compose stop pentest-web
compose run --rm --no-deps pentest-upgrade-migrate
compose run --rm --no-deps pentest-upgrade-verify
compose up --no-build --wait --no-deps pentest-upgrade-candidate-web
compose run --rm --no-deps pentest-fixture-verify
compose run --rm --no-deps \
  -e PENTEST_RESTORE_EXPECTATION=source-match pentest-restore-audit

compose stop pentest-upgrade-candidate-web
compose up --no-build --wait --no-deps pentest-web
compose run --rm --no-deps pentest-fixture-verify
compose run --rm --no-deps pentest-upgrade-verify
compose stop pentest-web

compose run --rm --no-deps \
  -e RESTIC_PASSWORD_FILE=/run/secrets/restic_repository_password \
  -e RESTORE_TARGET_DB="$rollback_target" \
  pentest-restore-verify
if compose run --rm --no-deps \
  -e RESTIC_PASSWORD_FILE=/run/secrets/restic_repository_password \
  -e RESTORE_TARGET_DB="$rollback_target" \
  pentest-restore-verify; then
  echo "The upgrade rehearsal unexpectedly overwrote its rollback database." >&2
  exit 1
fi

compose run --rm --no-deps -e POSTGRES_DB="$rollback_target" pentest-db-bootstrap
compose run --rm --no-deps \
  -e POSTGRES_DB="$rollback_target" \
  -e PENTEST_RESTORE_EXPECTATION=upgrade-restored-match \
  pentest-fixture-verify
compose run --rm --no-deps \
  -e POSTGRES_DB="$rollback_target" \
  -e PENTEST_RESTORE_EXPECTATION=upgrade-restored-match \
  pentest-restore-audit
compose run --rm --no-deps \
  -e POSTGRES_DB="$rollback_target" \
  -e PENTEST_RESTORE_EXPECTATION=upgrade-restored-match \
  -e PENTEST_UPGRADE_EXPECTATION=restored-baseline \
  pentest-upgrade-verify
compose up --no-build --wait --no-deps pentest-upgrade-rollback-web
compose run --rm --no-deps \
  -e POSTGRES_DB="$rollback_target" \
  -e PENTEST_RESTORE_EXPECTATION=upgrade-restored-match \
  pentest-fixture-verify

echo "Disposable forward-upgrade and clean-database rollback rehearsal completed."
