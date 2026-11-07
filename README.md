# VotaAí Backend API

API robusta e segura para o ecossistema de votação eletrônica **VotaAí**, construída com **Python 3.12+** e **Django 5.2**, seguindo os princípios de **Domain-Driven Design (DDD)** e **Clean Architecture**.

O sistema implementa criptografia de ponta a ponta (E2EE), integração com módulos de segurança em hardware (**TPM 2.0 / Secure Element** no servidor e **Android KeyStore / StrongBox** nos smartphones eleitores), garantia matemática de anonimato do voto (quebra de correlação com a identidade) e autenticação de administradores vinculada a máquinas físicas 1:1.

---

## ✨ Endpoints da API

### 🖥️ Administração e Autenticação (Desktop)
- `POST /api/admin/pre-registration/start/` — Inicia o pré-cadastro do administrador vinculando máquina física e gerando segredo TOTP
- `POST /api/admin/pre-registration/confirm/` — Confirma o pré-cadastro com código TOTP e assinatura de hardware da máquina
- `POST /api/auth/login/` — Autentica o administrador com 2FA (TOTP) e verificação estrita de assinatura de hardware TPM

### 🗳️ Gestão de Eleições (Desktop)
- `POST /api/election/create/` — Cadastra uma nova eleição com cédula, perguntas, opções e colégio eleitoral
- `POST /api/election/available/` — Lista as eleições criadas e disponíveis para serem iniciadas pela máquina vinculada
- `POST /api/election/start/` — Inicia a eleição, valida a chave criptográfica e despacha tokens únicos de votação por e-mail
- `POST /api/election/close/` — Encerra o período de votação de uma eleição ativa (STARTED), congelando o quórum de votantes e bloqueando novos votos mediante assinatura de hardware da eleição e da máquina

### 🌐 Acompanhamento Público e Monitoramento de Quórum (Público / Mobile / Web)
- `GET /api/election/public/open/` ou `GET /api/public/elections/` — Lista todas as eleições a partir do status de iniciada (`STARTED`, `CLOSED`, `TALLIED`) com dados essenciais, datas (`start_datetime`, `end_datetime`) e métricas de quórum percentual
- `GET /api/election/track/<int:id>/` ou `GET /api/public/elections/<int:id>/` — Acompanha uma eleição específica, exibindo datas de início e finalização, quórum em tempo real ou congelado (`STARTED` / `CLOSED`), porcentagem de quórum e participantes do colegiado eleitoral (indicando `(Ausente)` para quem não votou quando a eleição for encerrada)

### 🌐 Cédula Web e Landing Page (Web / QR Code)
- `GET /votar/` ou `GET /votar/<str:token>/` — Exibe a página com QR Code seguro anti-cache e suporta validação assíncrona (`?check=1`)

### 📱 Processo de Votação (Mobile App)
- `POST /api/vote/request/` — Valida token, atesta integridade de hardware via Android KeyStore (StrongBox/TEE), vincula o dispositivo e entrega a cédula eleitoral cifrada
- `POST /api/vote/cast/` — Valida binding de hardware estrito, quebra a correlação de identidade, deposita o voto anônimo na urna e emite o comprovante eleitoral

### 🔬 Testes e Diagnóstico
- `POST /api/ping-desktop/` — Rota de teste para validação da criptografia de hardware do Desktop (através do `SEDecryptMiddleware`)

### 📖 Documentação da API
- `GET /api/docs/` — Swagger UI interativo
- `GET /api/redoc/` — Interface de documentação ReDoc
- `GET /api/schema/` — Schema OpenAPI 3.0 (YAML/JSON)

---

## 📊 Diagramas das Ações da API

Abaixo estão detalhados os diagramas de sequência de cada ação e fluxo do sistema, ilustrando a comunicação entre os clientes (Desktop, Mobile, Web), o middleware criptográfico, os serviços de hardware (TPM 2.0 e Android StrongBox) e a camada de domínio e persistência.

---

### 0. Camada de Transporte Criptográfico Seguro (`SEDecryptMiddleware`)

Todas as requisições (`POST`, `PUT`, `PATCH`) para rotas protegidas trafegam através de um envelope criptográfico híbrido (**AES-256-GCM** para o payload e **RSA** para a chave simétrica). O `SEDecryptMiddleware` intercepta o tráfego, decodifica a chave simétrica usando o chip **TPM 2.0** do servidor e cifra a resposta com a chave pública da máquina cliente.

```mermaid
sequenceDiagram
    autonumber
    actor Cliente as Cliente (Desktop / Mobile)
    participant MW as SEDecryptMiddleware
    participant TPM as Hardware TPM 2.0 (seCryptoService)
    participant View as API View / Controller

    Note over Cliente,TPM: Envelope Híbrido: AES-256-GCM + RSA
    Cliente->>MW: Requisição HTTP com Envelope Criptografado<br/>(encrypted_payload, encrypted_aes_key, iv, tag)
    MW->>MW: Identifica rota e chave do TPM (Key_1: Desktop / Key_2: Mobile)
    MW->>TPM: Descriptografa AES Key com chave privada RSA do TPM
    TPM-->>MW: Chave AES simétrica (32 bytes)
    MW->>MW: Descriptografa encrypted_payload via AES-GCM
    MW->>MW: Extrai machine_public_key e Nonce de dentro do payload
    alt Assinatura de envelope presente
        MW->>MW: Valida assinatura digital da máquina cliente (RSA-PSS)
    end
    MW->>MW: Sobrescreve request._body com o JSON descriptografado
    MW->>View: Encaminha requisição em texto claro para a camada de aplicação
    View-->>MW: Resposta HTTP da View (Response)
    MW->>MW: Criptografa dados da resposta com a machine_public_key do cliente (AES-GCM híbrido)
    MW-->>Cliente: Resposta HTTP cifrada no envelope híbrido
```

---

### 1. Teste de Hardware Desktop (`POST /api/ping-desktop/`)

Valida a integridade do canal criptográfico entre a aplicação Desktop e o hardware TPM 2.0 do servidor.

```mermaid
sequenceDiagram
    autonumber
    actor Desktop as Aplicação Desktop
    participant MW as SEDecryptMiddleware
    participant TPM as Servidor TPM 2.0
    participant PingView as PingDesktopView

    Desktop->>MW: POST /api/ping-desktop/ (Envelope Criptografado)
    MW->>TPM: Decodifica chave AES usando VotaAI_SecureKey_1
    TPM-->>MW: Chave AES descriptografada
    MW->>MW: Decifra JSON com AES-GCM e registra machine_public_key
    MW->>PingView: POST com request.data em texto claro
    PingView-->>MW: 200 OK: {message: "Sucesso!", data_recebida: {...}}
    MW->>MW: Criptografa resposta com a machine_public_key do Desktop
    MW-->>Desktop: Envelope Criptografado com dados de confirmação
```

---

### 2. Iniciar Pré-Cadastro de Administrador (`POST /api/admin/pre-registration/start/`)

Inicia a vinculação estrita 1:1 de um usuário administrador a uma máquina física autorizada, criando o cadastro pendente e gerando o segredo 2FA (TOTP).

```mermaid
sequenceDiagram
    autonumber
    actor Desktop as Aplicação Desktop
    participant MW as SEDecryptMiddleware
    participant View as AdminPreRegistrationViewSet
    participant Actions as AdminPreRegistrationActions
    participant DB as Banco de Dados (User)
    participant TOTP as TOTPService
    participant TPM as Hardware TPM 2.0

    Desktop->>MW: POST /api/admin/pre-registration/start/<br/>(email, password, machine_public_key, device_id)
    MW->>MW: Descriptografa envelope (Key_1) e valida assinatura RSA-PSS do payload
    MW->>View: Payload decodificado
    View->>Actions: startPreRegistration(validated_data)
    Actions->>Actions: Valida complexidade de senha (min 8 chars, maiúsculas, especiais)
    Actions->>Actions: Valida formato da chave pública RSA da máquina
    Actions->>DB: Verifica duplicidade de email, device_id e machine_public_key
    Actions->>TOTP: generate_secret()
    TOTP-->>Actions: totp_secret
    Actions->>DB: Cria usuário pendente (is_active=False, device_id, machine_public_key, totp_secret)
    Actions->>TOTP: generate_provisioning_uri(totp_secret, email, issuer="VotaAI")
    TOTP-->>Actions: provisioning_uri
    Actions->>TPM: sign_with_tpm(Key_1, "message:provisioning_uri")
    TPM-->>Actions: Assinatura digital do servidor
    Actions-->>View: {message, provisioning_uri, signature}
    View-->>MW: 200 OK
    MW->>MW: Criptografa resposta com machine_public_key do Desktop
    MW-->>Desktop: Envelope Criptografado (URI de provisionamento TOTP)
```

---

### 3. Confirmar Pré-Cadastro com TOTP & Assinatura TPM (`POST /api/admin/pre-registration/confirm/`)

Conclui a ativação do usuário administrador mediante a verificação simultânea da assinatura digital gerada pelo hardware da máquina física e do token 2FA (TOTP).

```mermaid
sequenceDiagram
    autonumber
    actor Desktop as Aplicação Desktop
    participant MW as SEDecryptMiddleware
    participant View as AdminPreRegistrationViewSet
    participant Actions as AdminPreRegistrationActions
    participant DB as Banco de Dados (User / Group)
    participant TOTP as TOTPService
    participant TPM as Hardware TPM 2.0

    Note over Desktop: Usuário obtém código no app autenticador e assina o payload com a chave da máquina
    Desktop->>MW: POST /api/admin/pre-registration/confirm/<br/>(email, device_id, totp_code, signature)
    MW->>MW: Descriptografa envelope (Key_1)
    MW->>View: Payload decodificado
    View->>Actions: confirmPreRegistration(validated_data)
    Actions->>DB: Busca usuário inativo por email
    DB-->>Actions: Instância de User (com machine_public_key e totp_secret)
    Actions->>Actions: Valida assinatura digital da máquina física via SECryptoService
    Actions->>TOTP: verify_totp(user.totp_secret, totp_code)
    alt Código TOTP inválido ou expirado
        Actions-->>View: 400 Bad Request (Código TOTP inválido)
    end
    Actions->>DB: Valida unicidade de device_id e machine_public_key
    Actions->>DB: user.is_active = True & associa ao Grupo "Administrador"
    Actions->>TPM: sign_with_tpm(Key_1, message)
    TPM-->>Actions: Assinatura digital do servidor
    Actions-->>View: {message: "Pré-cadastro confirmado", signature}
    View-->>MW: 200 OK
    MW->>MW: Criptografa resposta com machine_public_key
    MW-->>Desktop: Envelope Criptografado (Administrador ativado)
```

---

### 4. Autenticação Desktop / Login com 2FA & Machine Binding (`POST /api/auth/login/`)

Realiza o login administrativo exigindo credenciais, verificação 2FA (TOTP) e validação matemática de que a requisição partiu da máquina física previamente vinculada.

```mermaid
sequenceDiagram
    autonumber
    actor Desktop as Aplicação Desktop
    participant MW as SEDecryptMiddleware
    participant View as AuthViewSet
    participant Actions as AuthActions
    participant DB as Banco de Dados (User)
    participant TOTP as TOTPService
    participant TPM as SECryptoService
    participant Knox as AuthService (Token Knox)

    Desktop->>MW: POST /api/auth/login/<br/>(username, password, totp_code, device_id, machine_public_key, signature)
    MW->>MW: Descriptografa envelope (Key_1)
    MW->>View: Payload decodificado
    View->>Actions: login(validated_data)
    Actions->>DB: authenticate(username, password)
    alt Credenciais inválidas ou usuário inativo
        Actions-->>View: 401 Unauthorized / 403 Permission Denied
    end
    Actions->>TOTP: verify_totp(user.totp_secret, totp_code)
    alt TOTP ausente ou inválido
        Actions-->>View: 400 Bad Request (Código TOTP inválido)
    end
    Actions->>Actions: Valida vinculação de hardware: device_id == user.device_id
    Actions->>Actions: Valida correspondência de chave: machine_public_key == user.machine_public_key
    Actions->>TPM: verify_payload_signature(user.machine_public_key, payload)
    alt Assinatura digital da máquina inválida
        Actions-->>View: 400 Bad Request (Assinatura de hardware inválida)
    end
    Actions->>Knox: generateTokenForUser(user)
    Knox-->>Actions: Token de Autenticação Knox
    Actions-->>View: {user, token}
    View-->>MW: 200 OK (LoginResponseSerializer)
    MW->>MW: Criptografa resposta com machine_public_key
    MW-->>Desktop: Envelope Criptografado com Token Knox e perfil do administrador
```

---

### 5. Cadastrar Nova Eleição (`POST /api/election/create/`)

Cria atomicamente as entidades relacionais da eleição (Cédula, Perguntas, Opções e Colégio Eleitoral), validando a assinatura de hardware da máquina criadora e gerando assinatura digital de resposta via TPM.

```mermaid
sequenceDiagram
    autonumber
    actor Desktop as Aplicação Desktop
    participant MW as SEDecryptMiddleware
    participant View as ElectionCreateView
    participant Actions as ElectionActions
    participant TPM as Hardware TPM 2.0
    participant DB as Banco de Dados (Election, Question, Option, ElectoralCollege)

    Desktop->>MW: POST /api/election/create/<br/>(title, ballot, electoral_college, public_key, key_handle, signature, machine_public_key)
    MW->>MW: Descriptografa envelope (Key_1)
    MW->>View: Payload decodificado
    View->>Actions: criarEleicao(validated_data)
    Actions->>Actions: Valida estrutura da cédula (perguntas e opções >= 1)
    Actions->>Actions: Valida assinatura digital da máquina física com machine_public_key
    Actions->>DB: Identifica criador vinculado à machine_public_key
    Actions->>DB: Transação Atômica:
    activate DB
    DB->>DB: 1. Cria Election (status=CREATED, public_key, key_handle)
    DB->>DB: 2. Cria Questions e realiza bulk_create de Options
    DB->>DB: 3. Processa eleitores (extrai primeiro nome como apelido) e bulk_create de ElectoralCollege
    deactivate DB
    Actions->>TPM: sign_with_tpm(Key_1, "election.id:questions_count:options_count")
    TPM-->>Actions: Assinatura digital do servidor
    Actions-->>View: {id, questions_count, options_count, signature}
    View-->>MW: 200 OK
    MW->>MW: Criptografa resposta com machine_public_key
    MW-->>Desktop: Envelope Criptografado (Eleição cadastrada com sucesso)
```

---

### 6. Listar Eleições Disponíveis para Início (`POST /api/election/available/`)

Permite à máquina física autorizada consultar quais eleições foram cadastradas e estão aptas para abertura oficial.

```mermaid
sequenceDiagram
    autonumber
    actor Desktop as Aplicação Desktop
    participant MW as SEDecryptMiddleware
    participant View as AvailableElectionsView
    participant DB as Banco de Dados (Election / User)

    Desktop->>MW: POST /api/election/available/ (nonceClient1, machine_public_key)
    MW->>MW: Descriptografa envelope (Key_1)
    MW->>View: Payload decodificado e chave pública em request._machine_public_key
    View->>DB: Identifica administrador vinculado à machine_public_key
    View->>DB: Election.objects.filter(status=CREATED, start_datetime__isnull=True, created_by=user)
    DB-->>View: Lista de eleições criadas prontas para início
    View-->>MW: 200 OK: {nonceClient1, elections: [{keyHandle, titulo}]}
    MW->>MW: Criptografa resposta com machine_public_key e inclui nonceClient1
    MW-->>Desktop: Envelope Criptografado com eleições disponíveis
```

---

### 7. Iniciar Eleição e Despacho de Cédulas (`POST /api/election/start/`)

Valida a chave da eleição, atualiza o status para `STARTED`, assegura as opções padrão ('Branco' e 'Nulo') em todas as perguntas e despacha tokens de uso único criptografados por e-mail para todos os eleitores.

```mermaid
sequenceDiagram
    autonumber
    actor Desktop as Aplicação Desktop
    participant MW as SEDecryptMiddleware
    participant View as StartElectionView
    participant DB as Banco de Dados
    participant TokenService as VotingTokenService
    participant Email as EmailService / SMTP

    Desktop->>MW: POST /api/election/start/<br/>(keyHandle, nonceClient2, election_signature, machine_public_key, signature)
    MW->>MW: Descriptografa envelope (Key_1)
    MW->>View: Payload decodificado
    View->>DB: Busca eleição por key_handle com status CREATED
    View->>View: Valida election_signature com a public_key da eleição
    View->>DB: Atualiza eleição: status = STARTED, start_datetime = now()
    View->>DB: election.ensure_default_ballot_options() (garante Branco e Nulo)
    loop Para cada eleitor em electoral_college
        View->>TokenService: generate_and_dispatch(voter, election)
        TokenService->>TokenService: Gera token randômico de alta entropia e calcula token_hash (SHA-256)
        TokenService->>DB: Salva VotingToken (token_hash, voter, election, is_used=False)
        TokenService->>Email: Dispara e-mail com link de votação e QR Code (/votar/<token>/)
    end
    View-->>MW: 200 OK: {nonceClient2, hora_registrada, emails_enviados, total_colegio, titulo}
    MW->>MW: Criptografa resposta com machine_public_key
    MW-->>Desktop: Envelope Criptografado (Eleição iniciada e e-mails disparados)
```

---

### 8. Fechar Eleição e Congelamento de Quórum (`POST /api/election/close/`)

Valida a chave e a assinatura digital da eleição produzida pelo chip TPM da máquina administradora vinculada, atualiza o status para `CLOSED`, define `end_datetime` e congela imediatamente o quórum de votantes, rejeitando quaisquer novas solicitações ou depósitos de votos.

```mermaid
sequenceDiagram
    autonumber
    actor Desktop as Aplicação Desktop
    participant MW as SEDecryptMiddleware
    participant View as CloseElectionView
    participant Actions as ElectionActions
    participant DB as Banco de Dados
    participant TPM as Hardware TPM 2.0 (seCryptoService)

    Desktop->>MW: POST /api/election/close/<br/>(keyHandle, nonceClient3, election_signature, machine_public_key, signature)
    MW->>TPM: Descriptografa envelope AES com VotaAI_SecureKey_1
    TPM-->>MW: Chave AES simétrica
    MW->>MW: Decifra payload AES-GCM e extrai machine_public_key & nonce
    MW->>View: Payload decodificado em request.data
    View->>Actions: fecharEleicao(data, user, machine_public_key)
    Actions->>DB: Busca Election por keyHandle com status STARTED
    Actions->>Actions: Valida se a máquina física/administrador é o criador da eleição
    Actions->>TPM: SECryptoService.verify_signature(election.public_key, canonical_payload, election_signature)
    alt Assinatura inválida ou máquina não autorizada
        Actions-->>View: 403 Forbidden (Assinatura inválida ou não autorizado)
        View-->>MW: Resposta HTTP 403
    else Assinatura válida
        Actions->>DB: 1. Transição atômica: status = CLOSED, end_datetime = now()
        Actions->>DB: 2. Calcula métricas finais de quórum (total_colegio, votos_registrados, pendentes)
        Actions-->>View: 200 OK: {keyHandle, titulo, status: CLOSED, hora_registrada, total_colegio, votos_registrados, pendentes, porcentagem_quorum, nonceClient3}
        View-->>MW: Resposta HTTP 200
    end
    MW->>MW: Criptografa resposta com a machine_public_key do Desktop (AES-GCM híbrido)
    MW-->>Desktop: Envelope Criptografado com quórum final congelado
```

---

### 9. Cédula Web e Landing Page QR Code (`GET /votar/`, `GET /votar/<token>/`)

Landing page que renderiza o QR Code com cabeçalhos anti-cache estritos e criptografia simétrica AES-256-GCM para ser escaneado exclusivamente pelo aplicativo mobile VotaAí.

```mermaid
sequenceDiagram
    autonumber
    actor Eleitor as Eleitor (Navegador Web)
    participant QRView as VotingQRCodeView
    participant TokenService as VotingTokenService
    participant DB as Banco de Dados (VotingToken)
    actor Mobile as App Mobile VotaAí

    Eleitor->>QRView: GET /votar/<token>/ (ou via fetch assíncrono ?check=1 / ?token_hash=...)
    alt Verificação Assíncrona via JSON (?check=1)
        QRView->>DB: Consulta VotingToken pelo token_hash
        QRView-->>Eleitor: JSON {status: valid|already_used|blocked, secure_qr_code}
    else Renderização HTML da Landing Page
        QRView->>TokenService: _hash_token(raw_token)
        QRView->>DB: Consulta VotingToken pelo hash
        alt Token inválido, já consumido ou bloqueado
            QRView-->>Eleitor: Renderiza template com aviso do status correspondente
        else Token válido
            QRView->>TokenService: build_secure_qr_link(token, election_id)
            Note over TokenService: Cifra payload (token + election_id) com chave simétrica AES-256-GCM
            TokenService-->>QRView: Link seguro cifrado (votaai://votar/?data=...)
            QRView-->>Eleitor: Renderiza página com QR Code dinâmico<br/>(com headers: no-store, no-cache, DENY, no-referrer)
        end
    end
    Note over Eleitor,Mobile: Eleitor abre o app móvel VotaAí e lê o QR Code
    Mobile->>Mobile: Decifra o payload do QR Code usando a chave simétrica do aplicativo
```

---

### 10. Solicitar Cédula Eleitoral Mobile (`POST /api/vote/request/`)

O aplicativo móvel solicita a cédula de votação apresentando o token de uso único, nonce anti-replay e a cadeia de certificados do **Android KeyStore**. A API exige comprovação de hardware seguro (**TEE ou StrongBox**) antes de vincular a chave do smartphone ao token e emitir a cédula eleitoral.

```mermaid
sequenceDiagram
    autonumber
    actor Mobile as App Mobile (Android)
    participant MW as SEDecryptMiddleware
    participant View as VoteRequestView
    participant Actions as VoteActions
    participant Cache as Django Cache (Anti-brute/Nonce)
    participant DB as Banco de Dados
    participant Attest as AndroidAttestationService (KeyStore)

    Mobile->>MW: POST /api/vote/request/<br/>(token, machine_public_key, attestation_certificates, nonce)
    MW->>MW: Descriptografa envelope (Key_2 TPM) e registra machine_public_key
    MW->>View: Payload decodificado
    View->>Actions: requestVote(validated_data, ip_address)
    Actions->>Cache: Checa proteção contra força bruta por IP (limite 10)
    Actions->>DB: Busca VotingToken via SHA-256(token)
    Actions->>Actions: Valida se token não está bloqueado e não foi consumido
    Actions->>Actions: Valida eleição com status STARTED e eleitor has_voted == False
    Actions->>Cache: Valida anti-replay do Nonce
    Actions->>Attest: validate_hardware_key(machine_pub_key, certs, expected_challenge=nonce)
    Note over Attest: Valida cadeia X.509 da raiz do Google.<br/>Exige atestação estrita em hardware (TEE ou StrongBox).
    alt Atestação de hardware rejeitada
        Actions->>DB: token.record_failed_attempt() (bloqueia ao atingir threshold)
        Actions-->>View: 400 Bad Request (Acesso negado: hardware não atestado)
    end
    Actions->>DB: token.record_successful_attempt(machine_pub_key, nonce)
    Actions->>DB: election.ensure_default_ballot_options()
    Actions->>DB: Emite BallotTicket anônimo isolado (id_voto = "VOTE-...")
    Actions-->>View: {election: {id, title, public_key, questions}, voter, attestation, nonce, id_voto}
    View-->>MW: 200 OK
    MW->>MW: Criptografa resposta com machine_public_key do StrongBox
    MW-->>Mobile: Envelope Criptografado com Cédula Eleitoral e ID de Voto anônimo
```

---

### 11. Depositar Cédula Cifrada / Voto Anônimo (`POST /api/vote/cast/`)

O aplicativo móvel cifra as escolhas do eleitor com a chave pública da eleição e assina digitalmente com o chip de hardware. A API realiza o **Hardware Binding Estrito** (garantindo que o voto parta do mesmo dispositivo que solicitou a cédula), quebra completamente a correlação com a identidade do eleitor, deposita o voto anônimo na urna e emite o comprovante eleitoral.

```mermaid
sequenceDiagram
    autonumber
    actor Mobile as App Mobile (Android)
    participant MW as SEDecryptMiddleware
    participant View as VoteCastView
    participant Actions as VoteActions
    participant DB as Banco de Dados
    participant Urna as Tabela Vote (Urna Eleitoral)
    participant Cache as Django Cache (Anti-replay)

    Note over Mobile: App cifra cédula com a chave pública da eleição (content)<br/>e assina o pacote com a chave privada do hardware StrongBox
    Mobile->>MW: POST /api/vote/cast/<br/>(token, machine_public_key, content, nonce, id_voto, signature)
    MW->>MW: Descriptografa envelope (Key_2 TPM)
    MW->>View: Payload decodificado
    View->>Actions: castVote(validated_data, ip_address)
    Actions->>DB: Busca VotingToken via hash e confere integridade
    Actions->>Actions: Hardware Binding Estrito:<br/>token.machine_public_key == request.machine_public_key
    alt Chave de hardware diferente da vinculada na solicitação
        Actions-->>View: 400 Bad Request (Dispositivo móvel não autorizado)
    end
    Actions->>Cache: Valida anti-replay do Nonce
    Actions->>Actions: Valida assinatura digital da cédula (RSA do StrongBox)
    Actions->>DB: Valida existência do BallotTicket anônimo (id_voto)
    Actions->>Actions: Calcula Recibo criptográfico SHA-256 (receipt_id = "VOTE-...")
    Note over Actions,Urna: QUEBRA DE CORRELAÇÃO DE IDENTIDADE:
    Actions->>Urna: Vote.objects.create(id_generated=receipt_id, content=content, election=election)
    Note over Urna: O voto é persistido na urna sem NENHUMA FK ou vínculo com o eleitor!
    Actions->>DB: Consome BallotTicket (is_used=True, used_at=now())
    Actions->>DB: Consome VotingToken (is_used=True) sem timestamp correlacionável
    Actions->>DB: Marca eleitor como votou (voter.has_voted=True)
    Actions-->>View: {receipt, id_voto, election_id, deposited_at, status: "CONFIRMED", nonce}
    View-->>MW: 200 OK
    MW->>MW: Criptografa resposta com a machine_public_key do Mobile
    MW-->>Mobile: Envelope Criptografado com o Comprovante Eleitoral (Recibo)
```

---

### 12. Acompanhamento Público e Monitoramento de Quórum (`GET /api/election/public/open/`, `GET /api/election/track/<id>/`)

Rotas públicas isentas de criptografia de envelope de hardware, permitindo a cidadãos, auditores e aplicativos móveis/web consultar as eleições em andamento e acompanhar o quórum em tempo real. A rota de acompanhamento evolui conforme o ciclo de vida da eleição: exibe quórum dinâmico enquanto `STARTED` e quórum definitivo congelado com data de término (`end_datetime`) quando `CLOSED`. Para eleições encerradas, eleitores que não compareceram à votação são identificados com `(Ausente)` em seu nome. A data de início (`start_datetime`) e a porcentagem de quórum (`quorum_percentage`) são informadas para todas as eleições. Nunca expõe chaves privadas, senhas ou tokens de eleitores.

```mermaid
sequenceDiagram
    autonumber
    actor Publico as Cidadão / App Mobile / Web
    participant View as PublicElectionViewSet
    participant Actions as ElectionActions
    participant DB as Banco de Dados (Election / ElectoralCollege)

    alt 1. Listagem de Eleições para Acompanhamento (GET /api/election/public/open/?search=...)
        Publico->>View: GET /api/election/public/open/?search=...
        View->>Actions: buscarEleicoesAbertas(search_term)
        Actions->>DB: Filtra eleições a partir de iniciada (STARTED, CLOSED, TALLIED)
        DB-->>View: QuerySet com total_voters, voted_count, quorum_percentage, start_datetime e end_datetime
        View-->>Publico: 200 OK: [{id, title, status, start_datetime, end_datetime, total_voters, voted_count, quorum_percentage}]
    else 2. Acompanhamento e Detalhes do Quórum (GET /api/election/track/<id>/)
        Publico->>View: GET /api/election/track/<id>/?has_voted=true&search=...
        View->>DB: Busca Election (exclude status=CREATED) e anota quórum
        DB-->>View: Dados da Eleição e Colegiado Eleitoral
        View->>View: Sanitiza eleitores e anexa "(Ausente)" no nome de não votantes se CLOSED
        View-->>Publico: 200 OK: {id, title, status: STARTED|CLOSED, start_datetime, end_datetime, total_voters, voted_count, pending_count, quorum_percentage, electoral_college: [{id, full_name, email, has_voted}, ...]}
    end
```

---

## 🏗 Arquitetura

```
Raiz do Projeto
├── Api/            # Camada de Entrada: Views, Serializers, Filtros, Paginação, URLs
├── Controllers/    # Orquestradores: Actions (fluxo de negócio) + QuerySets (abstração ORM)
├── Core/           # Mixins Globais: TimestampSchemaMixin, SlugSchemaMixin, PositionSchemaMixin
├── Domain/         # Camada de Negócio: Models (Schema + Proxy), Signals, Choices, Admin
├── Infrastructure/ # Módulos Externos: Criptografia TPM, Android KeyStore, E-mail, Middlewares
├── media/          # Diretório de uploads de mídia
└── setup/          # Configurações Django: settings, urls, wsgi, asgi
```

### Fluxo de Dados
```
Request → Infrastructure (SEDecryptMiddleware decodifica envelope com TPM)
        → Api (View valida entrada via Serializer)
        → Controller (Action orquestra regras, atestação e criptografia)
        → Domain / Infrastructure (Models interagem com DB; Services com hardware)
        → Controller (retorna dados estruturados)
        → Api (Serializer formata a resposta)
        → Infrastructure (SEDecryptMiddleware cifra resposta com chave pública do cliente)
        → Response
```

### Convenção de Nomenclatura dos Models
- **`XxxProxy`** — Classe base (Mixin). Contém propriedades computadas, regras de negócio e validações RBAC.
- **`Xxx`** — O model Django real (tabela no banco), herdando de `XxxProxy`. Contém campos, relacionamentos e constraints.

---

## 🛠 Stack Tecnológica

| Camada | Tecnologia |
|---|---|
| Linguagem | Python 3.12+ |
| Framework | Django 5.2 + DRF 3.16 |
| Autenticação | django-rest-knox (token-based) + TOTP (pyotp) |
| Criptografia & Hardware | TPM 2.0 (tpm2-tools / TSS2 / Windows CNG) + Cryptography (AES-256-GCM / RSA-PSS) |
| Atestação Mobile | Android KeyStore Hardware Attestation (TEE / StrongBox) |
| Documentação | drf-spectacular (OpenAPI 3.0) |
| Banco de Dados | PostgreSQL 16+ |
| Filtros | django-filter |
| CORS | django-cors-headers |
| Mídia & QR Code | Pillow + qrcode |
| Arquivos Estáticos | WhiteNoise |
| Containerização | Docker + Docker Compose |

---

## 🚀 Início Rápido

### Pré-requisitos
- Docker e Docker Compose
- Chip TPM 2.0 disponível no host (ou emulado)

### Configuração

```bash
# 1. Copie e configure o arquivo de variáveis de ambiente
cp .env.example .env
# Edite o .env se desejar customizar credenciais, nome da API ou senhas iniciais.

# 2. Build e inicialização do projeto
docker-compose up --build -d
```

> ⚡ **Automação via `entrypoint.sh`:**
> Ao rodar `docker-compose up`, o contêiner verifica as variáveis `ENABLE_MIGRATIONS=True` e `ENABLE_SEED=True` no seu `.env` e executa automaticamente:
> - As migrações do banco de dados (`manage.py migrate`);
> - A criação da conta superusuário inicial (`admin` / `admin`);
> - A população de cargos (Groups) e permissões via `seed_dev`;
> - A sincronização dos placeholders de mídia para o volume persistente (`/media`).

API disponível em: `http://localhost:8000/`  
Swagger UI: `http://localhost:8000/api/docs/`  
Django Admin: `http://localhost:8000/admin/`

---

## 🔒 Configuração do Hardware de Segurança (TPM 2.0 / Secure Element)

O projeto utiliza **criptografia baseada em hardware (TPM 2.0)** para operações criptográficas seguras (descriptografia do envelope e assinatura digital).

### 🐧 Configuração no Linux (Ubuntu / Zorin / Debian)

1. **Instale os utilitários do TPM 2.0 no sistema:**
   ```bash
   sudo apt update && sudo apt install -y tpm2-tools
   ```

2. **Permita acesso ao dispositivo do TPM (`/dev/tpmrm0`):**
   ```bash
   sudo usermod -aG tss $USER
   ```
   > 💡 *Para aplicar permissão imediata no terminal atual:*
   > ```bash
   > sudo chmod 666 /dev/tpmrm0
   > ```

3. **Gere as chaves criptográficas no chip TPM:**
   ```bash
   python manage.py generate_se_keys
   ```

---

### 🪟 Configuração no Windows

1. Certifique-se de que o TPM 2.0 está habilitado no Windows Defender / Segurança do Dispositivo.
2. Execute a geração de chaves via PowerShell / CNG:
   ```powershell
   python manage.py generate_se_keys
   ```

As informações das chaves públicas geradas no hardware serão salvas no arquivo `se_keys_info.json`.

---

## 📐 Convenções

- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/)
- **Branches**: feature branches, sem push direto para `main`
- **Migrations**: sempre rode `makemigrations` após alterar models; nunca edite migrations geradas manualmente
- **Signals**: eventos de domínio (signals) ficam em `Domain/signals/`; handlers ficam em `Infrastructure/signals/`
- **Permissões**: codenames em `DomainPermissions`, seed em `group_signals.py`, aplicadas em `Infrastructure/permissions/`

---

Desenvolvido para o sistema de votação eletrônica segura **VotaAí** 🗳️
