import json
from django.db import transaction
from django.contrib.auth.models import Group
from rest_framework.exceptions import ValidationError

from Domain.models.schemas.moderation.userSchema import User
from Domain.models.groupChoices import GroupRoles
from Infrastructure.services.totpService import TOTPService
from Infrastructure.services.seCryptoService import SECryptoService
from Infrastructure.validators import PasswordValidator

class AdminPreCadastroActions:
    """
    Orquestra o fluxo de pré-cadastro e confirmação de usuário administrador
    com vinculação de máquina física 1:1, TOTP e assinaturas digitais,
    mantendo os dados diretamente na entidade de usuário.
    """

    @staticmethod
    def iniciarPreCadastro(data: dict, client_pub_key_fallback: str | None = None) -> dict:
        """
        Passo 1 e 2 do fluxo:
        - Recebe email, senha e chave pública da máquina
        - Valida duplicidade e formato da chave pública RSA
        - Cria usuário pendente (inativo) com chave pública e segredo TOTP
        - Gera uri_provisionamento
        - Assina a resposta com a chave do TPM (VotaAI_SecureKey_1)
        """
        email = (data.get('email') or '').strip()
        senha = data.get('senha')
        chave_publica_maquina = (
            data.get('chave_publica_maquina')
            or data.get('machine_public_key')
            or data.get('client_public_key')
            or client_pub_key_fallback
        )

        if not email:
            raise ValidationError({"email": "O e-mail é obrigatório."})

        # Verifica se já existe usuário ativo com esse e-mail
        existing_user = User.objects.filter(email=email).first()
        if existing_user and existing_user.is_active:
            raise ValidationError({"email": "Este e-mail já está cadastrado e ativo no sistema."})

        # Validação completa de senha (mínimo 8 caracteres, maiúsculas, minúsculas, números e caracteres especiais)
        user_for_validation = existing_user or User(username=email, email=email)
        PasswordValidator.validate_password_complexity(senha, user=user_for_validation)

        if not chave_publica_maquina:
            raise ValidationError({"chave_publica_maquina": "A chave pública da máquina é obrigatória."})

        # Valida se a chave pública fornecida é um RSA válido
        try:
            SECryptoService.load_rsa_public_key(chave_publica_maquina)
        except Exception as e:
            raise ValidationError({"chave_publica_maquina": f"Chave pública da máquina inválida: {str(e)}"})


        # Valida se a máquina já está vinculada a outro usuário ativo
        existing_machine_user = User.objects.filter(
            chave_publica_maquina=chave_publica_maquina.strip(),
            is_active=True
        ).exclude(email=email).first()
        if existing_machine_user:
            raise ValidationError({"chave_publica_maquina": "Esta máquina já está vinculada a outro usuário ativo."})

        with transaction.atomic():
            totp_secret = TOTPService.generate_secret()
            if existing_user:
                user = existing_user
                user.set_password(senha)
                user.is_active = False
                user.chave_publica_maquina = chave_publica_maquina.strip()
                user.totp_secret = totp_secret
                user.save()
            else:
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=senha,
                    is_active=False,
                    chave_publica_maquina=chave_publica_maquina.strip(),
                    totp_secret=totp_secret
                )

        uri_provisionamento = TOTPService.generate_provisioning_uri(totp_secret, email, issuer_name="VotaAI")
        mensagem = "Pré-cadastro iniciado com sucesso. Configure o aplicativo autenticador e envie o código TOTP para ativação."

        # Assina com a chave privada da aplicação servidor no hardware TPM
        data_to_sign = f"{mensagem}:{uri_provisionamento}".encode('utf-8')
        try:
            assinatura = SECryptoService.sign_with_tpm('VotaAI_SecureKey_1', data_to_sign)
        except Exception as e:
            raise RuntimeError(f"Erro ao assinar resposta com TPM do servidor: {str(e)}")

        return {
            "mensagem": mensagem,
            "uri_provisionamento": uri_provisionamento,
            "assinatura": assinatura
        }

    @staticmethod
    def confirmarPreCadastro(data: dict) -> dict:
        """
        Passo 3 e 4 do fluxo:
        - Recebe email, codigo_totp e assinatura da máquina
        - Valida a assinatura da máquina usando a chave pública registrada no usuário
        - Valida o código TOTP com o segredo do usuário
        - Ativa o usuário administrador e atribui a role 'Administrador'
        - Assina a mensagem de sucesso com a chave do TPM (VotaAI_SecureKey_1)
        """
        email = (data.get('email') or '').strip()
        codigo_totp = str(data.get('codigo_totp') or '').strip()
        assinatura = (data.get('assinatura') or '').strip()

        if not email:
            raise ValidationError({"email": "O e-mail é obrigatório."})
        if not codigo_totp:
            raise ValidationError({"codigo_totp": "O código TOTP é obrigatório."})
        if not assinatura:
            raise ValidationError({"assinatura": "A assinatura da máquina é obrigatória."})

        user = User.objects.filter(email=email).first()
        if not user:
            raise ValidationError({"email": "Usuário não encontrado."})

        if not user.chave_publica_maquina:
            raise ValidationError({"error": "Nenhuma máquina vinculada a este usuário."})

        if not user.totp_secret:
            raise ValidationError({"error": "Segredo TOTP não configurado para este usuário. Inicie o pré-cadastro novamente."})

        # 1. Valida assinatura da máquina
        candidate_payloads = [
            f"{email}:{codigo_totp}".encode('utf-8'),
            f"{codigo_totp}".encode('utf-8'),
            json.dumps({"codigo_totp": codigo_totp, "email": email}, sort_keys=True).encode('utf-8'),
            json.dumps({"email": email, "codigo_totp": codigo_totp}, sort_keys=True).encode('utf-8'),
            email.encode('utf-8'),
        ]

        is_signature_valid = any(
            SECryptoService.verify_signature(user.chave_publica_maquina, cand, assinatura)
            for cand in candidate_payloads
        )

        if not is_signature_valid:
            raise ValidationError({"assinatura": "Assinatura da máquina inválida ou chave não autorizada."})

        # 2. Valida o código TOTP
        is_totp_valid = TOTPService.verify_totp(user.totp_secret, codigo_totp)
        if not is_totp_valid:
            raise ValidationError({"codigo_totp": "Código TOTP inválido ou expirado."})

        # 3. Ativa usuário e atribui role Administrador
        with transaction.atomic():
            user.is_active = True
            admin_group = Group.objects.filter(name=GroupRoles.ADMIN.value).first()
            if admin_group:
                user.groups.add(admin_group)
            user.save()

        mensagem = "Pré-cadastro confirmado com sucesso. Usuário administrador ativado."
        data_to_sign = mensagem.encode('utf-8')
        assinatura_servidor = SECryptoService.sign_with_tpm('VotaAI_SecureKey_1', data_to_sign)

        return {
            "mensagem": mensagem,
            "assinatura": assinatura_servidor
        }
