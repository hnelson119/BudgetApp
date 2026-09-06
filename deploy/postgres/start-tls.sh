#!/bin/sh
set -eu

fail() {
  echo "PostgreSQL TLS startup configuration is invalid." >&2
  exit 1
}

certificate_source=/run/secrets/postgres_server_certificate
key_source=/run/secrets/postgres_server_private_key
tls_directory=/run/postgresql-tls

if [ "$(id -u)" != "0" ]; then
  fail
fi
for source in "$certificate_source" "$key_source"; do
  if [ ! -f "$source" ] || [ -L "$source" ] || [ ! -s "$source" ]; then
    fail
  fi
done

umask 077
mkdir -p "$tls_directory"
cp "$certificate_source" "$tls_directory/server.crt"
cp "$key_source" "$tls_directory/server.key"
chown -R postgres:postgres "$tls_directory"
chmod 0700 "$tls_directory"
chmod 0600 "$tls_directory/server.crt" "$tls_directory/server.key"

exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file="$tls_directory/server.crt" \
  -c ssl_key_file="$tls_directory/server.key" \
  -c ssl_min_protocol_version=TLSv1.2 \
  -c ssl_max_protocol_version=TLSv1.3 \
  -c ssl_prefer_server_ciphers=on \
  -c hba_file=/etc/postgresql/pg_hba.conf
