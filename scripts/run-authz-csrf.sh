#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.pentest.yaml"
project_name="budgetapp-authz-csrf"

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" --profile adversarial \
    down --volumes --remove-orphans
}

cleanup
trap cleanup EXIT INT TERM

docker compose -p "$project_name" -f "$compose_file" --profile adversarial \
  up --build --wait pentest-web
docker compose -p "$project_name" -f "$compose_file" --profile adversarial \
  run --rm --no-deps pentest-fixture-verify
docker compose -p "$project_name" -f "$compose_file" --profile adversarial \
  run --rm --no-deps pentest-auth-sessions
docker compose -p "$project_name" -f "$compose_file" --profile adversarial \
  run --rm --no-deps pentest-authz-csrf

echo "Disposable authorization and CSRF probes completed."
