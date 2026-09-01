#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <hostname.ts.net> [compose-project] [secret-directory]" >&2
  exit 2
fi

probe_hostname="$1"
compose_project="${2:-household-budget}"
secret_directory="${3:-/etc/household-budget/secrets}"
project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$project_root/compose.yaml"
temporary_directory="$(mktemp -d /tmp/budgetapp-private-ingress.XXXXXX)"

cleanup() {
  case "$temporary_directory" in
    /tmp/budgetapp-private-ingress.*)
      if [ -d "$temporary_directory" ] && [ ! -L "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
      fi
      ;;
    *)
      echo "Refusing to remove an unexpected private-ingress temporary directory." >&2
      exit 1
      ;;
  esac
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this release preflight as root so it can inspect UFW and deployment secrets." >&2
  exit 1
fi
for command_name in docker tailscale ufw ss python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "A required private-ingress command is unavailable: $command_name" >&2
    exit 1
  fi
done

tailscale status --json > "$temporary_directory/tailscale-status.json"
tailscale serve status --json > "$temporary_directory/serve-status.json"
ufw status verbose > "$temporary_directory/ufw-status.txt"
ss -H -lnt > "$temporary_directory/listeners.txt"

python3 "$project_root/deploy/network/run-production-boundary.py" \
  --compose-file "$compose_file" \
  --project-name "$compose_project" \
  --hostname "$probe_hostname" \
  --secret-directory "$secret_directory"
python3 "$project_root/deploy/network/verify-private-ingress.py" \
  --hostname "$probe_hostname" \
  --tailscale-status "$temporary_directory/tailscale-status.json" \
  --serve-status "$temporary_directory/serve-status.json" \
  --ufw-status "$temporary_directory/ufw-status.txt" \
  --listeners "$temporary_directory/listeners.txt"

echo "Linux VM private-ingress preflight completed without sensitive-data output."
