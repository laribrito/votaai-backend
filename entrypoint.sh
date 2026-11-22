#!/bin/bash

# Abortar em caso de erro
set -e

# Coletar arquivos estáticos se a variável ENABLE_COLLECTSTATIC for "True"
if [ "$ENABLE_COLLECTSTATIC" = "True" ]; then
    echo "Executando collectstatic..."
    python manage.py collectstatic --noinput
fi

# Rodar migrações se a variável ENABLE_MIGRATIONS for "True"
if [ "$ENABLE_MIGRATIONS" = "True" ]; then
    echo "Executando migrações do banco de dados..."
    python manage.py migrate --noinput
    
    # Criar superusuário automaticamente caso as credenciais sejam passadas no .env
    if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
        echo "Verificando/Criando superusuário inicial..."
        python manage.py createsuperuser --noinput || true
    fi
fi

# Rodar o comando de seed de desenvolvimento se a variável ENABLE_SEED for "True"
if [ "$ENABLE_SEED" = "True" ]; then
    echo "Executando seed inicial do banco de dados (seedDev)..."
    python manage.py seedDev
fi

# Passar o comando padrão do Dockerfile ou docker-compose (ex: gunicorn)
exec "$@"
