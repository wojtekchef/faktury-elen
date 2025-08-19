# Użyj oficjalnego obrazu Pythona
FROM python:3.11-slim

# Ustaw katalog roboczy
WORKDIR /app

# Skopiuj pliki konfiguracyjne
COPY requirements.txt requirements.txt

# Zainstaluj zależności
RUN pip install --no-cache-dir -r requirements.txt

# Skopiuj resztę aplikacji
COPY . .

# Ustaw zmienne środowiskowe
ENV FLASK_APP=app:app
ENV FLASK_ENV=production

# Komenda startowa: najpierw migracje, potem Gunicorn
CMD ["sh", "-c", "flask db upgrade && gunicorn --bind 0.0.0.0:$PORT app:app"]
