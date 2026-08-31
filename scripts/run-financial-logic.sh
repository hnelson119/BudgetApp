#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.pentest.yaml"
project_name="budgetapp-financial-logic"

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" --profile financial \
    down --volumes --remove-orphans
}

cleanup
trap cleanup EXIT INT TERM

docker compose -p "$project_name" -f "$compose_file" --profile financial \
  up --build --wait pentest-web
docker compose -p "$project_name" -f "$compose_file" --profile financial \
  run --rm --no-deps pentest-fixture-verify
docker compose -p "$project_name" -f "$compose_file" --profile financial \
  run --rm --no-deps pentest-auth-sessions
docker compose -p "$project_name" -f "$compose_file" --profile financial \
  run --build --rm --no-deps pentest-financial-logic

echo "Disposable financial-logic probes completed."
