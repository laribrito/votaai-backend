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
    def login(data: dict, raw_data: dict | None = None) -> dict:
        """
        Validates credentials, checks account status, verifies 2FA (TOTP) and hardware integrity,
        and generates an auth token.
        
        Returns:
            dict: A raw dictionary containing the 'user' object and 'token' string.
                  (Formatting is handled by the Api layer).
        """
        username = data.get('username')
        password = data.get('password')
        totp_code = str(data.get('totp_code') or '').strip()
        signature = str(data.get('signature') or '').strip()
        machine_user = str(data.get('machine_user') or '').strip()

        # 1. Validate Credentials using Django's internal QuerySet/Auth backend
        user = authenticate(username=username, password=password)

        if user is None:
            from Domain.models.schemas.moderation.userSchema import User
            # Fallback para autenticação caso o cliente tenha enviado o e-mail no campo de login
            user_by_email = User.objects.filter(email=username).first() or \
                            User.objects.filter(username=username).first()
            if user_by_email and user_by_email.check_password(password):
                user = user_by_email
            else:
                inactiveUser = User.objects.filter(username=username, is_active=False).first() or \
                               User.objects.filter(email=username, is_active=False).first()
                if inactiveUser and inactiveUser.check_password(password):
                    raise PermissionDenied("This account is deactivated. Please contact the administrator.")
                raise AuthenticationFailed("Invalid username or password. Please try again.")

        # 2. Check Account Status
        if not user.is_active:
            raise PermissionDenied("This account is deactivated. Please contact the administrator.")

        # 3. Validate 2FA TOTP (if user has TOTP configured)
        if user.totp_secret:
            if not totp_code:
                raise ValidationError({
                    "totp_code": "The two-factor authentication (TOTP) code is required."
                })
            
            is_totp_valid = TOTPService.verify_totp(user.totp_secret, totp_code)
            if not is_totp_valid:
                raise ValidationError({
                    "totp_code": "Invalid or expired TOTP code. Please check your authenticator device's clock."
                })

        # 4. Validate Machine Identifier (if user is bound to a physical machine)
        if user.machine_user:
            if machine_user and machine_user != user.machine_user:
                raise ValidationError({
                    "machine_user": f"Access denied: this machine ({machine_user}) is not authorized for this administrator user."
                })

        # 5. Validate Machine Hardware TPM Signature (if user is bound to machine public key)
        if user.machine_public_key:
            if machine_user and not signature:
                raise ValidationError({
                    "signature": "The hardware security (TPM) signature is required for this device."
                })

            if signature:
                candidate_payloads = [
                    f"{user.email}:{totp_code}".encode('utf-8'),
                    f"{user.username}:{totp_code}".encode('utf-8'),
                    f"{totp_code}".encode('utf-8'),
                    f"{user.email}:{totp_code}:{machine_user}".encode('utf-8'),
                    f"{user.username}:{totp_code}:{machine_user}".encode('utf-8'),
                    f"{machine_user}:{totp_code}".encode('utf-8'),
                    json.dumps({"totp_code": totp_code, "email": user.email}, sort_keys=True).encode('utf-8'),
                    json.dumps({"email": user.email, "totp_code": totp_code}, sort_keys=True).encode('utf-8'),
                    json.dumps({"totp_code": totp_code, "username": user.username}, sort_keys=True).encode('utf-8'),
                    json.dumps({"username": user.username, "totp_code": totp_code}, sort_keys=True).encode('utf-8'),
                    user.email.encode('utf-8'),
                    user.username.encode('utf-8'),
                ]
                full_payload = dict(raw_data if isinstance(raw_data, dict) else data)
                full_payload.pop('machine_user', None)
                is_sig_valid = any(
                    SECryptoService.verify_signature(user.machine_public_key, cand, signature)
                    for cand in candidate_payloads
                ) or SECryptoService.verify_payload_signature(user.machine_public_key, full_payload)
                if not is_sig_valid:
                    raise ValidationError({
                        "signature": "Hardware security validation failed: machine digital signature is invalid or unauthorized."
                    })

        # 6. Generate Token via Domain Service
        token = AuthService.generateTokenForUser(user)

        # Return raw objects. Separation of Concerns: Actions don't worry about JSON structure.
        return {
            "user": user,
            "token": token
        }
