# syntax=docker/dockerfile:1
FROM postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73

ARG RESTIC_VERSION=0.19.1
ARG RESTIC_SHA256=f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c

ADD --checksum=sha256:${RESTIC_SHA256} \
    https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_amd64.bz2 \
    /tmp/restic.bz2

RUN bunzip2 /tmp/restic.bz2 \
    && install -m 0755 /tmp/restic /usr/local/bin/restic \
    && rm /tmp/restic \
    && restic version

COPY deploy/backup/backup.sh /usr/local/bin/backup.sh
COPY deploy/backup/restore-verify.sh /usr/local/bin/restore-verify.sh

RUN chmod 0555 /usr/local/bin/backup.sh /usr/local/bin/restore-verify.sh

USER postgres
ENTRYPOINT []
CMD ["/usr/local/bin/backup.sh"]
