## 0.4.0 (2026-10-11)

### Feat

- **api**: implement available elections listing and start election endpoints
- **controllers**: resolve election creator user and normalize voter details
- **infrastructure**: add voting token service and enhance crypto middleware
- **admin**: add email status display and resend action for electoral college
- **migration**: add migrations for voting token and electoral college email status
- **domain**: add voting token model and enhance electoral college tracking
- **crypto**: implement strict payload signature verification

### Refactor

- **election**: standardize machine_public_key across election creation and start flows
- **auth**: require strict device_id and machine_public_key on login
- **admin**: enforce strict device_id and machine_public_key in pre-registration
- **crypto**: standardize on machine_public_key in SEDecryptMiddleware
- **domain**: rename user machine_user to device_id
- **admin**: standardize device_id error key and support public keys in confirmation
- **election**: remove legacy alias cleanup from payload verification
- **auth**: remove legacy alias cleanup from payload verification
- **admin**: remove legacy alias cleanup from payload verification
- **crypto**: remove unused file persistence methods for client public key
- **middleware**: remove client public key file persistence and fallback
- **middleware**: remove payload and nonce aliasing
- **election**: use proxy static method for first name extraction
- **election**: remove signature verification fallbacks on create
- **crypto**: enforce strict payload signature verification
- **admin**: remove fallbacks e aliases no pré-cadastro
- **election**: remove dict comprehension na extração de payload
- **election**: remove fallback logic para chaves públicas
- **auth**: padroniza campo device_id e remove flexibilidade no login
- **admin**: update pre-registration serializer to match desktop payload
- **controllers**: update actions and views to handle raw_data for signature validation

## 0.3.0 (2026-09-26)

### Feat

- **scripts**: adicionar comando comments ao run_commands para puxar revisoes via gh cli
- **election**: adaptar ElectionActions para validar e persistir chaves em ingles
- **auth**: suportar fallback de email e campos em ingles no fluxo de login
- **crypto**: adiciona suporte ao hardware tpm 2.0 no linux
- **auth**: validar codigo totp e assinatura tpm no fluxo de login
- **api**: torna machine_user obrigatorio e valida unicidade no pre-cadastro de admin
- **migration**: adiciona migracoes para machine_public_key e machine_user em User
- **domain**: padroniza machine_public_key e adiciona machine_user ao modelo User
- **api**: adiciona rota e serializers para criacao de eleicao desktop
- **controller**: adiciona criacao atomica de eleicao e assinatura de resposta via tpm
- **admin**: modulariza configuracao do django admin para entidades de eleicao
- **migration**: adiciona migracoes para entidades relacionais de eleicao
- **domain**: adiciona modelos relacionais e proxies de eleicao

### Refactor

- **api**: enforce strict English contract and remove legacy portuguese aliases
- **architecture**: decouple QuerySets from Actions and consume directly in Views
- **admin**: translate PreRegistration flow from portuguese to english
- **election**: padronizar campos do ElectionCreateSerializer exclusivamente em ingles
- **auth**: padronizar campos do LoginSerializer exclusivamente em ingles

## 0.2.0 (2026-09-16)

### Feat

- primeiro commit

## 0.1.0 (2026-09-04)

### Feat

- **crypto**: exige identificacao de dispositivo e criptografia em todas as rotas da api
- **crypto**: adiciona criptografia de resposta e persistencia da chave publica do cliente
- **api**: adiciona rota /ping-desktop para teste de descriptografia com tpm
- adapta a forma de criptografia para não ter limitação de tamanho no payload
- adiciona script de geração de chaves para sistema windows

### Fix

- **cli**: executa commitizen via modulo python e trata encoding no windows

### Refactor

- **crypto**: remove fallback para descriptografia rsa pura e exige modo hibrido
- **crypto**: restringe envio da chave publica do cliente exclusivamente ao envelope json

## 0.0.2 (2026-08-19)

### Fix

- **db**: downgrade do PostgreSQL para versão 16
- **docker**: configura build para desenvolvimento e previne crash de CRLF
- corrige a documentação do README.md sobre schemas e proxies do projeto

### Refactor

- **api**: update views and routes to use camelCase actions
- **api**: adjust serializers and filters for camelCase output and standard validation
- **controllers**: migrate querysets and actions methods to camelCase
- **domain**: update models, choices, admin, and signals
