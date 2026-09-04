#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.pentest.yaml"
project_name="budgetapp-session-security"

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" --profile session \
    down --volumes --remove-orphans
}

cleanup
trap cleanup EXIT INT TERM

docker compose -p "$project_name" -f "$compose_file" --profile session \
  up --build --wait pentest-web
docker compose -p "$project_name" -f "$compose_file" --profile session \
  run --build --rm --no-deps pentest-fixture-verify
docker compose -p "$project_name" -f "$compose_file" --profile session \
  run --build --rm --no-deps pentest-auth-sessions
docker compose -p "$project_name" -f "$compose_file" --profile session \
  run --build --rm --no-deps pentest-session-security

echo "Disposable session-security probes completed."
