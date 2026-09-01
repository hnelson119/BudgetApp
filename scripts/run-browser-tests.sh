#!/bin/sh
set -eu

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.pentest.yaml"
project_name="budgetapp-browser"

cleanup() {
  docker compose -p "$project_name" -f "$compose_file" --profile browser \
    down --volumes --remove-orphans
}

startup_diagnostics() {
  docker compose -p "$project_name" -f "$compose_file" --profile browser \
    logs --no-color --tail 200 \
    pentest-db-bootstrap pentest-migrate pentest-seed pentest-web || true
}

cleanup
trap cleanup EXIT INT TERM

docker compose -p "$project_name" -f "$compose_file" --profile browser \
  build browser-tests
if ! docker compose -p "$project_name" -f "$compose_file" --profile browser \
  up --build --wait pentest-web; then
  startup_diagnostics
  exit 1
fi
docker compose -p "$project_name" -f "$compose_file" --profile browser \
  run --rm --no-deps browser-credentials-init
docker compose -p "$project_name" -f "$compose_file" --profile browser \
  run --rm --no-deps browser-tests

echo "Chromium, Firefox, and WebKit browser checks completed in disposable containers."
