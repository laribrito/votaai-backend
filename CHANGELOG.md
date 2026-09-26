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
