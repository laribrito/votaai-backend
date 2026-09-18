import json
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, ValidationError
from Controllers.actions.auth.authService import AuthService
from Infrastructure.services.totpService import TOTPService
from Infrastructure.services.seCryptoService import SECryptoService

class AuthActions:
    """
    Orchestrates the login workflow, validation logic, and error handling.
    """

    @staticmethod
    def login(data: dict) -> dict:
        """
        Validates credentials, checks account status, verifies 2FA (TOTP) and hardware integrity,
        and generates an auth token.
        
        Returns:
            dict: A raw dictionary containing the 'user' object and 'token' string.
                  (Formatting is handled by the Api layer).
        """
        username = data.get('username')
        password = data.get('password')
        codigo_totp = str(data.get('codigo_totp') or '').strip()
        assinatura = str(data.get('assinatura') or '').strip()
        usuario_maquina = str(data.get('usuario_maquina') or '').strip()

        # 1. Validate Credentials using Django's internal QuerySet/Auth backend
        user = authenticate(username=username, password=password)

        if user is None:
            from Domain.models.schemas.moderation.userSchema import User
            inactiveUser = User.objects.filter(username=username, is_active=False).first()
            if inactiveUser and inactiveUser.check_password(password):
                raise PermissionDenied("This account is deactivated. Please contact the administrator.")
            raise AuthenticationFailed("Invalid username or password. Please try again.")

        # 2. Check Account Status
        if not user.is_active:
            raise PermissionDenied("This account is deactivated. Please contact the administrator.")

        # 3. Validate 2FA TOTP (if user has TOTP configured)
        if user.totp_secret:
            if not codigo_totp:
                raise ValidationError({
                    "codigo_totp": "O código de autenticação em duas etapas (TOTP) é obrigatório."
                })
            
            is_totp_valid = TOTPService.verify_totp(user.totp_secret, codigo_totp)
            if not is_totp_valid:
                raise ValidationError({
                    "codigo_totp": "Código TOTP inválido ou expirado. Verifique o horário do seu dispositivo autenticador."
                })

        # 4. Validate Machine Identifier (if user is bound to a physical machine)
        if user.machine_user:
            if usuario_maquina and usuario_maquina != user.machine_user:
                raise ValidationError({
                    "usuario_maquina": f"Acesso negado: esta máquina ({usuario_maquina}) não está autorizada para este usuário administrador."
                })

        # 5. Validate Machine Hardware TPM Signature (if user is bound to machine public key)
        if user.chave_publica_maquina:
            if usuario_maquina and not assinatura:
                raise ValidationError({
                    "assinatura": "A assinatura do hardware de segurança (TPM) é obrigatória para este dispositivo."
                })

            if assinatura:
                candidate_payloads = [
                    f"{user.email}:{codigo_totp}".encode('utf-8'),
                    f"{codigo_totp}".encode('utf-8'),
                    json.dumps({"codigo_totp": codigo_totp, "email": user.email}, sort_keys=True).encode('utf-8'),
                    json.dumps({"email": user.email, "codigo_totp": codigo_totp}, sort_keys=True).encode('utf-8'),
                    user.email.encode('utf-8'),
                ]
                is_sig_valid = any(
                    SECryptoService.verify_signature(user.chave_publica_maquina, cand, assinatura)
                    for cand in candidate_payloads
                )
                if not is_sig_valid:
                    raise ValidationError({
                        "assinatura": "Falha de validação do hardware de segurança: assinatura digital da máquina inválida ou não autorizada."
                    })

        # 6. Generate Token via Domain Service
        token = AuthService.generateTokenForUser(user)

        # Return raw objects. Separation of Concerns: Actions don't worry about JSON structure.
        return {
            "user": user,
            "token": token
        }
