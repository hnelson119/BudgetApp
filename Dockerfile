# syntax=docker/dockerfile:1
FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN addgroup -g 10001 -S budget \
    && adduser -u 10001 -S -D -H -G budget -s /sbin/nologin budget

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
RUN mkdir -p /app/staticfiles /app/media && chown -R budget:budget /app

USER budget
RUN DJANGO_SETTINGS_MODULE=config.settings.build python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--error-logfile", "-", "--capture-output"]
