# syntax=docker/dockerfile:1
FROM golang:1.26.6-alpine3.24@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS restic-builder

ARG RESTIC_VERSION=0.19.1
ARG RESTIC_SHA256=bb9b1a19040744d26d8a79be029d4e6b189c45ccc9d8831d7fe367d3c33df725

ENV GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org

WORKDIR /src/restic
ADD --checksum=sha256:${RESTIC_SHA256} \
    https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic-${RESTIC_VERSION}.tar.gz \
    /tmp/restic.tar.gz

RUN tar --extract --gzip --file /tmp/restic.tar.gz --strip-components=1 \
    && rm /tmp/restic.tar.gz \
    && go get \
        golang.org/x/crypto@v0.55.0 \
        golang.org/x/net@v0.58.0 \
        golang.org/x/text@v0.41.0 \
        google.golang.org/grpc@v1.83.2 \
    && go mod tidy \
    && mkdir -p /out \
    && go run build.go --output /out/restic \
    && /out/restic version

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk upgrade --no-cache \
    && apk add --no-cache postgresql17-client \
    && sed -i \
        '/^postgres:/c\postgres:x:70:70:PostgreSQL user:/nonexistent:/sbin/nologin' \
        /etc/passwd \
    && test "$(id -u postgres)" = "70" \
    && test "$(id -g postgres)" = "70"

COPY --from=restic-builder /out/restic /usr/local/bin/restic
COPY deploy/backup/backup.sh /usr/local/bin/backup.sh
COPY deploy/backup/restore-verify.sh /usr/local/bin/restore-verify.sh
COPY deploy/backup/rotate-restic-key.sh /usr/local/bin/rotate-restic-key.sh

RUN chmod 0555 /usr/local/bin/restic /usr/local/bin/backup.sh \
        /usr/local/bin/restore-verify.sh /usr/local/bin/rotate-restic-key.sh \
    && restic version \
    && pg_dump --version

USER postgres
ENTRYPOINT []
CMD ["/usr/local/bin/backup.sh"]
