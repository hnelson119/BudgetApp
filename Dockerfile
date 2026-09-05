# syntax=docker/dockerfile:1
FROM python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_INDEX_URL=https://pypi.org/simple \
    PIP_EXTRA_INDEX_URL=

RUN apk upgrade --no-cache \
    && addgroup -g 10001 -S budget \
    && adduser -u 10001 -S -D -H -G budget -s /sbin/nologin budget \
    && addgroup -g 10003 -S securityarchive \
    && adduser -u 10003 -S -D -H -G securityarchive -s /sbin/nologin securityarchive

WORKDIR /app

COPY requirements-prod.lock ./
RUN python -m pip install --no-cache-dir -r requirements-prod.lock

COPY audit ./audit
COPY budgets ./budgets
COPY config ./config
COPY core ./core
COPY debts ./debts
COPY goals ./goals
COPY households ./households
COPY identity ./identity
COPY imports ./imports
COPY ledger ./ledger
COPY notifications ./notifications
COPY periods ./periods
COPY reserves ./reserves
COPY schedules ./schedules
COPY spending ./spending

COPY manage.py ./
RUN mkdir -p /app/staticfiles /app/media /run/security-log /var/lib/security-log \
    && chown -R budget:budget /app \
    && chown securityarchive:securityarchive /run/security-log /var/lib/security-log \
    && chmod 0711 /run/security-log \
    && chmod 0700 /var/lib/security-log

USER budget
RUN DJANGO_SETTINGS_MODULE=config.settings.build python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--error-logfile", "-", "--capture-output"]
