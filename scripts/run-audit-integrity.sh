#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.pentest.yaml"
project_name="budgetapp-audit-integrity"

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" --profile audit \
    down --volumes --remove-orphans
}

cleanup
trap cleanup EXIT INT TERM

docker compose -p "$project_name" -f "$compose_file" --profile audit \
  up --build --wait pentest-web
docker compose -p "$project_name" -f "$compose_file" --profile audit \
  run --rm --no-deps pentest-fixture-verify
docker compose -p "$project_name" -f "$compose_file" --profile audit \
  run --build --rm --no-deps -e PENTEST_AUDIT_SCENARIO=AUDIT-01 pentest-audit-runtime
docker compose -p "$project_name" -f "$compose_file" --profile audit \
  run --build --rm --no-deps -e PENTEST_AUDIT_SCENARIO=AUDIT-02 pentest-audit-checkpoint
docker compose -p "$project_name" -f "$compose_file" --profile audit \
  run --build --rm --no-deps -e PENTEST_AUDIT_SCENARIO=AUDIT-03 pentest-audit-runtime
docker compose -p "$project_name" -f "$compose_file" --profile audit \
  run --build --rm --no-deps -e PENTEST_AUDIT_SCENARIO=AUDIT-04 pentest-audit-checkpoint

echo "Disposable audit-integrity probes completed."
