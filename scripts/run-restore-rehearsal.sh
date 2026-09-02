#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.pentest.yaml"
project_name="budgetapp-restore-rehearsal"
restore_target="household_budget_pentest_restore_rehearsal"
temporary_directory="$(mktemp -d /tmp/budgetapp-restore-rehearsal.XXXXXX)"
build_context="$temporary_directory/build-context"
mkdir -m 700 "$build_context"

for command_name in docker git tar
do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "A required restore-rehearsal command is unavailable: $command_name" >&2
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

compose() {
  docker compose -p "$project_name" -f "$compose_file" --profile restore "$@"
}

cleanup() {
  compose down --volumes --remove-orphans || true
  case "$temporary_directory" in
    /tmp/budgetapp-restore-rehearsal.*)
      if [ -d "$temporary_directory" ] && [ ! -L "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
      fi
      ;;
    *)
      echo "Refusing to remove an unexpected restore-rehearsal temporary directory." >&2
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
  pentest-restic-key-rotate \
  pentest-restore-verify \
  pentest-restore-source-advance \
  pentest-restore-audit
compose up --no-build --wait pentest-web
compose run --rm --no-deps pentest-fixture-verify
compose run --rm --no-deps pentest-restore-storage-init
compose run --rm --no-deps pentest-restore-audit \
  python manage.py write_audit_checkpoints
compose run --rm --no-deps pentest-backup
compose run --rm --no-deps pentest-backup \
  /bin/sh /opt/pentest/verify-encrypted-repository.sh
compose run --rm --no-deps pentest-restic-key-rotate
compose run --rm --no-deps pentest-restore-source-advance
compose run --rm --no-deps pentest-restore-audit

if compose run --rm --no-deps \
  -e RESTORE_TARGET_DB=household_budget_pentest pentest-restore-verify; then
  echo "The restore rehearsal unexpectedly accepted the live database target." >&2
  exit 1
fi

compose run --rm --no-deps \
  -e RESTORE_TARGET_DB="$restore_target" pentest-restore-verify

if compose run --rm --no-deps \
  -e RESTORE_TARGET_DB="$restore_target" pentest-restore-verify; then
  echo "The restore rehearsal unexpectedly overwrote an existing target." >&2
  exit 1
fi

compose run --rm --no-deps -e POSTGRES_DB="$restore_target" pentest-db-bootstrap
compose run --rm --no-deps \
  -e POSTGRES_DB="$restore_target" \
  -e PENTEST_RESTORE_EXPECTATION=restored-match \
  pentest-fixture-verify
compose run --rm --no-deps \
  -e POSTGRES_DB="$restore_target" \
  -e PENTEST_RESTORE_EXPECTATION=restored-match \
  pentest-restore-audit

echo "Disposable encrypted backup, restore, and signed-checkpoint rehearsal completed."
