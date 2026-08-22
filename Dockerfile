# syntax=docker/dockerfile:1
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN addgroup --system budget && adduser --system --ingroup budget budget

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
