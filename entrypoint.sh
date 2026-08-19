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

# Sincronizar arquivos iniciais de mídia para o volume persistente (/media).
# A pasta /app/media vem embutida na imagem Docker (COPY . /app/).
# O volume /media é persistente entre deploys, mas pode estar vazio na primeira vez.
# Este passo garante que arquivos iniciais e placeholders estejam sempre disponíveis
# sem sobrescrever arquivos que já existam no volume (uploads de usuários).
MEDIA_SRC="/app/media"
MEDIA_DST="/media"
if [ -d "$MEDIA_SRC" ]; then
    echo "Sincronizando arquivos de mídia: $MEDIA_SRC → $MEDIA_DST"
    mkdir -p "$MEDIA_DST"
    # Copia apenas arquivos que ainda não existem no destino (não sobrescreve)
    cp -rn "$MEDIA_SRC"/* "$MEDIA_DST"/ 2>/dev/null || true
    echo "Sincronização de mídia concluída."
else
    echo "Aviso: pasta $MEDIA_SRC não encontrada na imagem. Nenhuma mídia copiada."
fi

# Rodar o comando de seed de desenvolvimento se a variável ENABLE_SEED for "True"
if [ "$ENABLE_SEED" = "True" ]; then
    echo "Executando seed inicial do banco de dados (seedDev)..."
    python manage.py seedDev
fi

# Passar o comando padrão do Dockerfile ou docker-compose (ex: gunicorn)
exec "$@"
