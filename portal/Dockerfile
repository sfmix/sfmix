FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
# gettext provides msgfmt, needed by `manage.py compilemessages` to build the .mo catalogs.
RUN apt-get update && apt-get install -y --no-install-recommends curl gettext && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN curl -fsSL https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.0/tailwindcss-linux-x64 \
      -o /usr/local/bin/tailwindcss \
    && chmod +x /usr/local/bin/tailwindcss \
    && tailwindcss -i tailwind.input.css -o static/css/tailwind.css --minify

# Compile translation catalogs (.po → .mo). .mo files are gitignored, so they
# must be built into the image for non-English locales to render.
RUN python manage.py compilemessages

RUN python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "ixp_portal.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
