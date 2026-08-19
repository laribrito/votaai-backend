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
