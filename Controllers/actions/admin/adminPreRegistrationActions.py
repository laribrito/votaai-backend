import hashlib
import hmac
import secrets
from datetime import timedelta

from django.contrib.auth.models import Group
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError

from Domain.models.groupChoices import GroupRoles
from Domain.models.schemas.moderation.userSchema import User
from Infrastructure.services.emailService import EmailService
from Infrastructure.services.seCryptoService import SECryptoService
from Infrastructure.services.totpService import TOTPService
from Infrastructure.validators import PasswordValidator


class AdminPreRegistrationActions:
    """
    Orquestra o fluxo de pré-cadastro e confirmação de usuário administrador
    com vinculação de máquina física 1:1, verificação de e-mail, TOTP e assinaturas digitais,
    mantendo os dados diretamente na entidade de usuário.
    """

    EMAIL_CODE_EXPIRATION_MINUTES = 15
    EMAIL_CODE_MAX_ATTEMPTS = 5

    @staticmethod
    def _hash_verification_code(code: str) -> str:
        return hashlib.sha256(code.encode('utf-8')).hexdigest()

    @staticmethod
    def _sign_tpm_payload(payload_bytes: bytes) -> str:
        try:
            return SECryptoService.sign_with_tpm('VotaAI_SecureKey_1', payload_bytes)
        except Exception as e:
            raise RuntimeError(f"Error signing response with server TPM: {str(e)}")

    @classmethod
    def _issue_and_send_email_verification(cls, user: User) -> None:
        """
        Gera um código de verificação de 6 dígitos, armazena seu hash com validade
        e envia o e-mail HTML de verificação ao gestor da máquina.
        """
        code = f"{secrets.randbelow(1_000_000):06d}"
        user.email_verified = False
        user.email_verification_code_hash = cls._hash_verification_code(code)
        user.email_verification_expires_at = timezone.now() + timedelta(
            minutes=cls.EMAIL_CODE_EXPIRATION_MINUTES
        )
        user.email_verification_attempts = 0
        user.save(update_fields=[
            'email_verified',
            'email_verification_code_hash',
            'email_verification_expires_at',
            'email_verification_attempts',
        ])

        subject = str(_("Vota-i 2.0 - Verificação de e-mail do gestor da máquina"))
        html_message = f"""
            <p>Olá,</p>
            <p>Você iniciou o cadastro como gestor de máquina (administrador) no <strong>Vota-i 2.0</strong>.</p>
            <p>Use o código abaixo para verificar seu endereço de e-mail e prosseguir com a configuração do autenticador (TOTP):</p>
            <div style="margin: 24px 0; text-align: center;">
                <span style="display: inline-block; padding: 14px 28px; font-size: 28px; font-weight: 800; letter-spacing: 6px; background-color: #F4F4F5; border: 1px solid #D4D4D8; border-radius: 10px; color: #111111;">
                    {code}
                </span>
            </div>
            <p style="font-size: 13px; color: #555555;">
                Este código expira em <strong>{cls.EMAIL_CODE_EXPIRATION_MINUTES} minutos</strong>.
                Caso não tenha solicitado este cadastro, ignore este e-mail.
            </p>
        """
        sent = EmailService.sendHtmlEmail(
            subject=subject,
            message=html_message,
            recipient_list=[user.email],
        )
        if not sent:
            raise ValidationError({
                "email": _("Failed to send verification email. Please try again.")
            })

    @staticmethod
    def _validate_pending_user_and_machine(
        data: dict,
        raw_data: dict | None = None,
    ) -> User:
        """
        Valida existência do usuário pendente, unicidade de máquina/chave e assinatura RSA-PSS da máquina.
        """
        email = (data.get('email') or '').strip()
        signature = (data.get('signature') or '').strip()

        if not email:
            raise ValidationError({"email": _("Email is required.")})
        if not signature:
            raise ValidationError({"signature": _("Machine signature is required.")})

        user = User.objects.filter(email=email).first()
        if not user:
            raise ValidationError({"email": _("User not found.")})

        if user.is_active:
            raise ValidationError({"email": _("This email is already registered and active in the system.")})

        if not user.machine_public_key:
            raise ValidationError({"machine_public_key": _("No machine linked to this user.")})

        if user.device_id:
            if str(data.get('device_id') or '').strip() != user.device_id:
                raise ValidationError({
                    "device_id": _("This device does not match the one linked during pre-registration.")
                })

            conflict_user = User.objects.filter(
                device_id=user.device_id,
                is_active=True,
            ).exclude(id=user.id).first()
            if conflict_user:
                raise ValidationError({
                    "device_id": _("This machine (%(device_id)s) has already been activated by another user (%(email)s).") % {
                        'device_id': user.device_id,
                        'email': conflict_user.email,
                    }
                })

        conflict_key_user = User.objects.filter(
            machine_public_key=user.machine_public_key,
            is_active=True,
        ).exclude(id=user.id).first()
        if conflict_key_user:
            raise ValidationError({
                "machine_public_key": _("This machine has already been activated by another user (%(email)s).") % {
                    'email': conflict_key_user.email,
                }
            })

        full_payload = raw_data if isinstance(raw_data, dict) else data
        is_signature_valid = SECryptoService.verify_payload_signature(
            user.machine_public_key,
            full_payload,
        )
        if not is_signature_valid:
            raise ValidationError({"signature": _("Invalid machine signature or unauthorized key.")})

        return user

    @classmethod
    def startPreRegistration(cls, data: dict) -> dict:
        """
        Passo 1 do fluxo:
        - Recebe email, senha, device_id e chave pública da máquina
        - Valida duplicidade, complexidade de senha e formato da chave pública RSA
        - Cria usuário pendente (inativo, email_verified=False)
        - Gera e envia código de verificação de 6 dígitos por e-mail
        - Assina a resposta com a chave do TPM (VotaAI_SecureKey_1)
        """
        email = data.get('email', '').strip()
        password = data.get('password')
        machine_public_key = data.get('machine_public_key')
        device_id = str(data.get('device_id') or '').strip()

        if not email:
            raise ValidationError({"email": _("Email is required.")})

        existing_user = User.objects.filter(email=email).first()
        if existing_user and existing_user.is_active:
            raise ValidationError({"email": _("This email is already registered and active in the system.")})

        user_for_validation = existing_user or User(username=email, email=email)
        PasswordValidator.validate_password_complexity(password, user=user_for_validation)

        if not machine_public_key:
            raise ValidationError({"machine_public_key": _("Machine public key is required.")})

        try:
            SECryptoService.load_rsa_public_key(machine_public_key)
        except Exception as e:
            raise ValidationError({"machine_public_key": _("Invalid machine public key: %(error)s") % {'error': str(e)}})

        machine_public_key = SECryptoService.to_pem_public_key(machine_public_key)

        if not device_id:
            raise ValidationError({"device_id": _("Device ID is required.")})

        existing_device_user = User.objects.filter(
            device_id=device_id,
            is_active=True,
        ).exclude(email=email).first()
        if existing_device_user:
            raise ValidationError({
                "device_id": _("This machine (%(device_id)s) is already linked to another active user (%(email)s).") % {
                    'device_id': device_id,
                    'email': existing_device_user.email,
                }
            })

        existing_key_user = User.objects.filter(
            machine_public_key=machine_public_key,
            is_active=True,
        ).exclude(email=email).first()
        if existing_key_user:
            raise ValidationError({
                "machine_public_key": _("This public key is already linked to another active user (%(email)s).") % {
                    'email': existing_key_user.email,
                }
            })

        with transaction.atomic():
            if existing_user:
                user = existing_user
                user.set_password(password)
                user.is_active = False
                user.machine_public_key = machine_public_key
                user.device_id = device_id
                user.totp_secret = None
                user.email_verified = False
                user.save()
            else:
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    is_active=False,
                    machine_public_key=machine_public_key,
                    device_id=device_id,
                    totp_secret=None,
                    email_verified=False,
                )

            cls._issue_and_send_email_verification(user)

        message = str(_("Pre-registration started successfully. A verification code has been sent to your email."))
        signature = cls._sign_tpm_payload(message.encode('utf-8'))

        return {
            "message": message,
            "signature": signature,
        }

    @classmethod
    def verifyEmail(cls, data: dict, raw_data: dict | None = None) -> dict:
        """
        Passo 2 do fluxo:
        - Recebe email, verification_code e assinatura da máquina
        - Valida a assinatura da máquina e o código enviado por e-mail
        - Marca email_verified=True, gera segredo TOTP e provisioning_uri
        - Assina a resposta com a chave do TPM (VotaAI_SecureKey_1)
        """
        verification_code = str(data.get('verification_code') or '').strip()
        if not verification_code:
            raise ValidationError({"verification_code": _("Verification code is required.")})

        user = cls._validate_pending_user_and_machine(data, raw_data=raw_data)

        if not user.email_verification_code_hash or not user.email_verification_expires_at:
            raise ValidationError({
                "verification_code": _("No pending email verification found. Please restart pre-registration.")
            })

        if timezone.now() > user.email_verification_expires_at:
            raise ValidationError({
                "verification_code": _("Verification code has expired. Please request a new code.")
            })

        if user.email_verification_attempts >= cls.EMAIL_CODE_MAX_ATTEMPTS:
            raise ValidationError({
                "verification_code": _("Too many failed verification attempts. Please request a new code.")
            })

        code_hash = cls._hash_verification_code(verification_code)
        if not hmac.compare_digest(code_hash, user.email_verification_code_hash):
            user.email_verification_attempts += 1
            user.save(update_fields=['email_verification_attempts'])
            raise ValidationError({"verification_code": _("Invalid verification code.")})

        with transaction.atomic():
            totp_secret = TOTPService.generate_secret()
            user.email_verified = True
            user.email_verification_code_hash = None
            user.email_verification_expires_at = None
            user.email_verification_attempts = 0
            user.totp_secret = totp_secret
            user.save(update_fields=[
                'email_verified',
                'email_verification_code_hash',
                'email_verification_expires_at',
                'email_verification_attempts',
                'totp_secret',
            ])

        provisioning_uri = TOTPService.generate_provisioning_uri(totp_secret, user.email, issuer_name="VotaAI")
        message = str(_("Email verified successfully. Configure your authenticator app and send the TOTP code for activation."))

        data_to_sign = f"{message}:{provisioning_uri}".encode('utf-8')
        signature = cls._sign_tpm_payload(data_to_sign)

        return {
            "message": message,
            "provisioning_uri": provisioning_uri,
            "signature": signature,
        }

    @classmethod
    def resendEmailVerification(cls, data: dict, raw_data: dict | None = None) -> dict:
        """
        Reenvia um novo código de verificação de e-mail para o usuário pendente.
        """
        user = cls._validate_pending_user_and_machine(data, raw_data=raw_data)

        if user.email_verified:
            raise ValidationError({"email": _("Email is already verified.")})

        with transaction.atomic():
            cls._issue_and_send_email_verification(user)

        message = str(_("A new verification code has been sent to your email."))
        signature = cls._sign_tpm_payload(message.encode('utf-8'))

        return {
            "message": message,
            "signature": signature,
        }

    @classmethod
    def confirmPreRegistration(cls, data: dict, raw_data: dict | None = None) -> dict:
        """
        Passo 3 do fluxo:
        - Recebe email, totp_code e signature da máquina
        - Valida que o e-mail já foi verificado
        - Valida a assinatura da máquina usando a chave pública registrada no usuário
        - Valida o código TOTP com o segredo do usuário
        - Ativa o usuário administrador e atribui a role 'Administrador'
        - Assina a mensagem de sucesso com a chave do TPM (VotaAI_SecureKey_1)
        """
        totp_code = str(data.get('totp_code') or '').strip()
        if not totp_code:
            raise ValidationError({"totp_code": _("TOTP code is required.")})

        user = cls._validate_pending_user_and_machine(data, raw_data=raw_data)

        if not user.email_verified:
            raise ValidationError({
                "email": _("Email not verified. Please verify your email before confirming pre-registration.")
            })

        if not user.totp_secret:
            raise ValidationError({"totp_code": _("TOTP secret not configured for this user. Please restart pre-registration.")})

        is_totp_valid = TOTPService.verify_totp(user.totp_secret, totp_code)
        if not is_totp_valid:
            raise ValidationError({"totp_code": _("Invalid or expired TOTP code.")})

        with transaction.atomic():
            user.is_active = True
            admin_group = Group.objects.filter(name=GroupRoles.ADMIN.value).first()
            if admin_group:
                user.groups.add(admin_group)
            user.save()

        message = str(_("Pre-registration confirmed successfully. Administrator user activated."))
        server_signature = cls._sign_tpm_payload(message.encode('utf-8'))

        return {
            "message": message,
            "signature": server_signature,
        }
