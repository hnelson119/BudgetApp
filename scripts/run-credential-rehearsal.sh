#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.pentest.yaml"
project_name="budgetapp-credential-rehearsal"

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" --profile rotation \
    down --volumes --remove-orphans
}

cleanup
trap cleanup EXIT INT TERM

docker compose -p "$project_name" -f "$compose_file" --profile rotation \
  up --build --wait pentest-web
docker compose -p "$project_name" -f "$compose_file" --profile rotation \
  run --rm --no-deps pentest-fixture-verify
docker compose -p "$project_name" -f "$compose_file" --profile rotation \
  run --rm --no-deps pentest-auth-sessions
docker compose -p "$project_name" -f "$compose_file" --profile rotation \
  run --rm --no-deps pentest-mfa-key-rotate
docker compose -p "$project_name" -f "$compose_file" --profile rotation stop pentest-web
docker compose -p "$project_name" -f "$compose_file" --profile rotation \
  up --build --wait --no-deps pentest-web-rotated
docker compose -p "$project_name" -f "$compose_file" --profile rotation \
  run --build --rm --no-deps pentest-credential-rehearsal
docker compose -p "$project_name" -f "$compose_file" --profile rotation \
  run --rm --no-deps pentest-db-admin-key-rotate

echo "Disposable lost-device and credential-rotation rehearsal completed."
