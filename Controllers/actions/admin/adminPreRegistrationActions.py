import json
from django.db import transaction
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError

from Domain.models.schemas.moderation.userSchema import User
from Domain.models.groupChoices import GroupRoles
from Infrastructure.services.totpService import TOTPService
from Infrastructure.services.seCryptoService import SECryptoService
from Infrastructure.validators import PasswordValidator

class AdminPreRegistrationActions:
    """
    Orquestra o fluxo de pré-cadastro e confirmação de usuário administrador
    com vinculação de máquina física 1:1, TOTP e assinaturas digitais,
    mantendo os dados diretamente na entidade de usuário.
    """

    @staticmethod
    def startPreRegistration(data: dict, client_pub_key_fallback: str | None = None) -> dict:
        """
        Passo 1 e 2 do fluxo:
        - Recebe email, senha e chave pública da máquina
        - Valida duplicidade e formato da chave pública RSA
        - Cria usuário pendente (inativo) com chave pública e segredo TOTP
        - Gera uri_provisionamento
        - Assina a resposta com a chave do TPM (VotaAI_SecureKey_1)
        """
        email = data.get('email', '').strip()
        password = data.get('password')
        machine_public_key = (
            data.get('machine_public_key')
            or data.get('client_public_key')
            or client_pub_key_fallback
        )
        machine_user = str(
            data.get('machine_user')
            or data.get('device_id')
            or data.get('machine_id')
            or ''
        ).strip()

        if not email:
            raise ValidationError({"email": _("Email is required.")})

        # Verifica se já existe usuário ativo com esse e-mail
        existing_user = User.objects.filter(email=email).first()
        if existing_user and existing_user.is_active:
            raise ValidationError({"email": _("This email is already registered and active in the system.")})

        # Validação completa de senha (mínimo 8 caracteres, maiúsculas, minúsculas, números e caracteres especiais)
        user_for_validation = existing_user or User(username=email, email=email)
        PasswordValidator.validate_password_complexity(password, user=user_for_validation)

        if not machine_public_key:
            raise ValidationError({"machine_public_key": _("Machine public key is required.")})

        # Valida se a chave pública fornecida é um RSA válido
        try:
            SECryptoService.load_rsa_public_key(machine_public_key)
        except Exception as e:
            raise ValidationError({"machine_public_key": _("Invalid machine public key: %(error)s") % {'error': str(e)}})

        # Normaliza chave pública para evitar incompatibilidades de quebra de linha CRLF vs LF
        machine_public_key = machine_public_key.strip().replace('\r\n', '\n')

        if not machine_user:
            raise ValidationError({"machine_user": _("Machine user identifier is required.")})

        # 1. Valida se o usuário de máquina já está vinculado a outro usuário ativo
        existing_machine_user = User.objects.filter(
            machine_user=machine_user,
            is_active=True
        ).exclude(email=email).first()
        if existing_machine_user:
            raise ValidationError({
                "machine_user": _("This machine (%(machine_user)s) is already linked to another active user (%(email)s).") % {
                    'machine_user': machine_user,
                    'email': existing_machine_user.email,
                }
            })


        # 2. Valida se a chave pública já está vinculada a outro usuário ativo
        existing_key_user = User.objects.filter(
            machine_public_key=machine_public_key,
            is_active=True
        ).exclude(email=email).first()
        if existing_key_user:
            raise ValidationError({
                "machine_public_key": _("This public key is already linked to another active user (%(email)s).") % {
                    'email': existing_key_user.email,
                }
            })

        with transaction.atomic():
            totp_secret = TOTPService.generate_secret()
            if existing_user:
                user = existing_user
                user.set_password(password)
                user.is_active = False
                user.machine_public_key = machine_public_key
                user.machine_user = machine_user
                user.totp_secret = totp_secret
                user.save()
            else:
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    is_active=False,
                    machine_public_key=machine_public_key,
                    machine_user=machine_user,
                    totp_secret=totp_secret
                )


        provisioning_uri = TOTPService.generate_provisioning_uri(totp_secret, email, issuer_name="VotaAI")
        message = str(_("Pre-registration started successfully. Configure your authenticator app and send the TOTP code for activation."))

        # Assina com a chave privada da aplicação servidor no hardware TPM
        data_to_sign = f"{message}:{provisioning_uri}".encode('utf-8')
        try:
            signature = SECryptoService.sign_with_tpm('VotaAI_SecureKey_1', data_to_sign)
        except Exception as e:
            raise RuntimeError(f"Error signing response with server TPM: {str(e)}")

        return {
            "message": message,
            "provisioning_uri": provisioning_uri,
            "signature": signature
        }

    @staticmethod
    def confirmPreRegistration(data: dict, raw_data: dict | None = None) -> dict:
        """
        Passo 3 e 4 do fluxo:
        - Recebe email, totp_code e signature da máquina
        - Valida a assinatura da máquina usando a chave pública registrada no usuário
        - Valida o código TOTP com o segredo do usuário
        - Revalida unicidade da máquina/chave
        - Ativa o usuário administrador e atribui a role 'Administrador'
        - Assina a mensagem de sucesso com a chave do TPM (VotaAI_SecureKey_1)
        """
        email = (data.get('email') or '').strip()
        totp_code = str(data.get('totp_code') or '').strip()
        signature = (data.get('signature') or '').strip()

        if not email:
            raise ValidationError({"email": _("Email is required.")})
        if not totp_code:
            raise ValidationError({"totp_code": _("TOTP code is required.")})
        if not signature:
            raise ValidationError({"signature": _("Machine signature is required.")})

        user = User.objects.filter(email=email).first()
        if not user:
            raise ValidationError({"email": _("User not found.")})

        if not user.machine_public_key:
            raise ValidationError({"machine_public_key": _("No machine linked to this user.")})

        if not user.totp_secret:
            raise ValidationError({"totp_code": _("TOTP secret not configured for this user. Please restart pre-registration.")})

        # Revalidação de unicidade no momento da confirmação
        if user.machine_user:
            conflict_user = User.objects.filter(
                machine_user=user.machine_user,
                is_active=True
            ).exclude(id=user.id).first()
            if conflict_user:
                raise ValidationError({
                    "machine_user": _("This machine (%(machine_user)s) has already been activated by another user (%(email)s).") % {
                        'machine_user': user.machine_user,
                        'email': conflict_user.email,
                    }
                })

        if user.machine_public_key:
            conflict_key_user = User.objects.filter(
                machine_public_key=user.machine_public_key,
                is_active=True
            ).exclude(id=user.id).first()
            if conflict_key_user:
                raise ValidationError({
                    "machine_public_key": _("This machine has already been activated by another user (%(email)s).") % {
                        'email': conflict_key_user.email,
                    }
                })

        # 1. Valida assinatura da máquina com suporte a formatos canônicos
        candidate_payloads = [
            f"{email}:{totp_code}".encode('utf-8'),
            f"{totp_code}".encode('utf-8'),
            json.dumps({"totp_code": totp_code, "email": email}, sort_keys=True).encode('utf-8'),
            json.dumps({"email": email, "totp_code": totp_code}, sort_keys=True).encode('utf-8'),
            email.encode('utf-8'),
        ]
        full_payload = dict(raw_data if isinstance(raw_data, dict) else data)
        full_payload.pop('machine_user', None)
        
        is_signature_valid = any(
            SECryptoService.verify_signature(user.machine_public_key, cand, signature)
            for cand in candidate_payloads
        ) or SECryptoService.verify_payload_signature(user.machine_public_key, full_payload) or SECryptoService.verify_payload_signature(user.machine_public_key, data)

        if not is_signature_valid:
            raise ValidationError({"signature": _("Invalid machine signature or unauthorized key.")})

        # 2. Valida o código TOTP
        is_totp_valid = TOTPService.verify_totp(user.totp_secret, totp_code)
        if not is_totp_valid:
            raise ValidationError({"totp_code": _("Invalid or expired TOTP code.")})

        # 3. Ativa usuário e atribui role Administrador
        with transaction.atomic():
            user.is_active = True
            admin_group = Group.objects.filter(name=GroupRoles.ADMIN.value).first()
            if admin_group:
                user.groups.add(admin_group)
            user.save()

        message = str(_("Pre-registration confirmed successfully. Administrator user activated."))
        data_to_sign = message.encode('utf-8')
        server_signature = SECryptoService.sign_with_tpm('VotaAI_SecureKey_1', data_to_sign)

        return {
            "message": message,
            "signature": server_signature
        }

