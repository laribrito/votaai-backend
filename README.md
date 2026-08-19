# Django DDD API Template

Um template backend pronto para produção construído com **Python 3.12+** e **Django 5.2**, seguindo os princípios de **Domain-Driven Design (DDD)** e **Clean Architecture**.

Já vem com um sistema completo de **Autenticação e Gestão de Usuários** como implementação de referência — pronto para ser estendido com o seu próprio domínio.

---

## ✨ O que está incluído

### 🔐 Autenticação (Token Knox)
- `POST /api/auth/login/` — Login e recebimento de token
- `GET  /api/auth/me/` — Retorna o perfil do usuário autenticado
- `POST /api/auth/logout/` — Invalida o token da sessão atual
- `POST /api/auth/logoutall/` — Invalida todos os tokens (logout global)

### 👥 Gestão de Usuários (CRUD)
- `GET    /api/users/` — Listagem paginada com filtros (cargo, status, busca)
- `GET    /api/users/stats/` — Contagens de usuários ativos/inativos por cargo
- `POST   /api/users/invite/` — Convida um novo usuário por e-mail
- `PATCH  /api/users/me/update/` — Atualização de perfil pelo próprio usuário
- `PATCH  /api/users/<id>/management-update/` — Admin: atualiza qualquer usuário + atribui cargos
- `PATCH  /api/users/<id>/toggle-status/` — Admin: ativa/desativa um usuário
- `GET    /api/roles/` — Lista os cargos disponíveis (Groups do Django)

### 🔑 Gestão de Senhas
- `POST /api/password/reset/request/` — Solicita e-mail de redefinição de senha
- `POST /api/password/reset/confirm/` — Confirma redefinição com token (também ativa usuários convidados)
- `POST /api/password/change/` — Troca de senha (requer autenticação)

### 📖 Documentação da API
- `GET /api/docs/` — Swagger UI
- `GET /api/redoc/` — Interface ReDoc
- `GET /api/schema/` — Schema OpenAPI (YAML/JSON)

---

## 🏗 Arquitetura

```
Raiz do Projeto
├── Api/            # Camada de Entrada: Views, Serializers, Filtros, Paginação, URLs
├── Controllers/    # Orquestradores: Actions (fluxo de negócio) + QuerySets (abstração ORM)
├── Core/           # Mixins Globais: TimestampSchemaMixin, SlugSchemaMixin, PositionSchemaMixin
├── Domain/         # Camada de Negócio: Models (Schema + Proxy), Signals, Choices, Admin
├── Infrastructure/ # Serviços Externos: E-mail, Permissões, Comandos de Gerenciamento
├── Bruno/          # Coleção de client API (app Bruno)
├── media/          # Diretório de uploads de mídia
└── setup/          # Config Django: settings, urls, wsgi, asgi
```

### Fluxo de Dados
```
Request → Api (View valida entrada)
        → Controller (Action orquestra as regras de negócio)
        → Domain (Models + Services interagem com o banco)
        → Controller (retorna dados)
        → Api (Serializer formata a resposta)
        → Response
```

### Convenção de Nomenclatura dos Models
- **`XxxProxy`** — Classe base (Mixin). Contém apenas propriedades computadas, validação de negócio e helpers de RBAC.
- **`Xxx`** — O model Django real (tabela no banco), que herda de `XxxProxy`. Contém campos, relacionamentos e constraints.

---

## 🛠 Stack Tecnológica

| Camada | Tecnologia |
|---|---|
| Linguagem | Python 3.12+ |
| Framework | Django 5.2 + DRF 3.16 |
| Autenticação | django-rest-knox (token-based) |
| Documentação | drf-spectacular (OpenAPI 3.0) |
| Banco de Dados | PostgreSQL 16+ |
| Filtros | django-filter |
| CORS | django-cors-headers |
| Mídia | Pillow |
| Arquivos Estáticos | WhiteNoise |
| Containerização | Docker + Docker Compose |

---

## 🚀 Início Rápido

### Pré-requisitos
- Docker e Docker Compose

### Configuração

```bash
# 1. Copie e configure o arquivo de variáveis de ambiente
cp .env.example .env
# Edite o .env se desejar customizar credenciais, nome da API ou senhas iniciais.

# 2. Build e inicialização do projeto
docker-compose up --build -d
```

> ⚡ **Tudo 100% Automatizado via `entrypoint.sh`:**
> Ao rodar `docker-compose up`, o script do contêiner verifica as variáveis `ENABLE_MIGRATIONS=True` e `ENABLE_SEED=True` no seu `.env` e **executa automaticamente**:
> - As migrações do banco de dados (`manage.py migrate`);
> - A criação da conta superusuário inicial (`admin` / `admin`);
> - A população de cargos (Groups) e permissões via `seed_dev`;
> - A sincronização dos placeholders de mídia para o volume persistente (`/media`).

> 💡 **Dica do Template (`.env.example` Automático):**
> Sempre que você adicionar novas variáveis ao seu arquivo `.env`, você pode gerar ou atualizar o `.env.example` de forma automática sanitizando senhas e chaves secretas com um único comando:
> ```bash
> python manage.py generate-env-example
> ```

API disponível em: `http://localhost:8000/`  
Swagger UI: `http://localhost:8000/api/docs/`  
Django Admin: `http://localhost:8000/admin/`

---

## 🧱 Estendendo o Template

### Adicionando um novo módulo de domínio

**1. Crie o proxy em `Domain/models/proxies/`**
```python
# Domain/models/proxies/meumodulo/meu_model_proxy.py

class MeuModelProxy:
    # Propriedades e métodos de negócio
    @property
    def is_active(self):
        return True
```

**2. Crie o model em `Domain/models/schemas/`**
```python
# Domain/models/schemas/meumodulo/meu_model.py
from django.db import models
from Core.schema_mixins.timestamp_schema_mixin import TimestampSchemaMixin
from Core.schema_mixins.slug_schema_mixin import SlugSchemaMixin
from Domain.models.proxies.meumodulo.meu_model_proxy import MeuModelProxy

class MeuModel(MeuModelProxy, TimestampSchemaMixin, SlugSchemaMixin):
    nome = models.CharField(max_length=255)
    # ... seus campos
```

**3. Crie o queryset em `Controllers/querysets/`**
```python
# Controllers/querysets/meumodulo/meu_model_queryset.py
from django.db import models

class MeuModelQuerySet(models.QuerySet):
    def ativos(self):
        return self.filter(is_active=True)
```

**4. Crie a action em `Controllers/actions/`**
```python
# Controllers/actions/meumodulo/meu_model_actions.py
class MeuModelActions:
    @staticmethod
    def criar(data: dict):
        return MeuModel.objects.create(**data)
```

**5. Crie o serializer em `Api/serializers/`**

**6. Crie a view em `Api/views/`**

**7. Registre a URL em `Api/urls.py`**

**8. Execute as migrations**
```bash
docker-compose exec web python manage.py makemigrations
docker-compose exec web python manage.py migrate
```

---

## 🔄 Mixins Disponíveis (`Core/schema_mixins/`)

| Mixin | Campos Adicionados | Caso de Uso |
|---|---|---|
| `TimestampSchemaMixin` | `created_at`, `updated_at` | Todos os models auditáveis |
| `SlugSchemaMixin` | `slug` | Models com identificadores amigáveis para URL |
| `PositionSchemaMixin` | `position` | Itens de lista ordenáveis |

---

## 📐 Convenções

- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/)
- **Branches**: feature branches, sem push direto para `main`
- **Migrations**: sempre rode `makemigrations` após alterar models; nunca edite migrations geradas manualmente
- **Signals**: eventos de domínio (signals) ficam em `Domain/signals/`; handlers ficam em `Infrastructure/signals/`
- **Permissões**: codenames em `DomainPermissions`, seed em `group_signals.py`, aplicadas em `Infrastructure/permissions/`

---

Desenvolvido como um template reutilizável de API Django DDD ⌨
