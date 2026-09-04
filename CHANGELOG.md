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
