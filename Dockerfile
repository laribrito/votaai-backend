FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

# Cria uma "flag" (argumento de build). O padrão é "dev".
# Para build de produção com collectstatic, use: docker build --build-arg BUILD_ENV=production .
ARG BUILD_ENV=dev
RUN if [ "$BUILD_ENV" = "production" ]; then \
        echo "Ambiente de PRODUÇÃO detectado. Rodando collectstatic..." && \
        python manage.py collectstatic --noinput; \
    else \
        echo "Ambiente de DESENVOLVIMENTO detectado. Pulando collectstatic no build."; \
    fi

EXPOSE 8000

# Move o entrypoint para fora de /app para evitar que o volume do host (Windows) sobrescreva o arquivo corrigido
RUN cp /app/entrypoint.sh /usr/local/bin/entrypoint.sh && \
    dos2unix /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

# Executa pelo entrypoint (que cuida das migrations)
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Comando PADRÃO da imagem (produção).
# NOTA: O docker-compose.yml sobrescreve isso com "runserver" para desenvolvimento local!
CMD ["gunicorn", "setup.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]