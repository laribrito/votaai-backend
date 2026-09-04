import os
import time
import hmac
import struct
import base64
import hashlib
import urllib.parse

class TOTPService:
    """
    Serviço de Autenticação em Duas Etapas (2FA) via TOTP (RFC 6238 / RFC 4226).
    
    Implementação independente de bibliotecas externas, compatível com Google Authenticator,
    Microsoft Authenticator, Authy e aplicações desktop/mobile padrão.
    """

    @staticmethod
    def generate_secret(byte_length: int = 20) -> str:
        """
        Gera um segredo aleatório criptograficamente seguro codificado em Base32.
        Padrão RFC 6238: 20 bytes (160 bits).
        """
        random_bytes = os.urandom(byte_length)
        return base64.b32encode(random_bytes).decode('utf-8').rstrip('=')

    @staticmethod
    def generate_provisioning_uri(secret: str, email: str, issuer_name: str = "VotaAI") -> str:
        """
        Gera a URI padrão otpauth://totp/... para provisionamento em aplicativos autenticadores
        ou exibição em formato de QR Code.
        """
        clean_email = email.strip()
        label = urllib.parse.quote(f"{issuer_name}:{clean_email}")
        params = urllib.parse.urlencode({
            'secret': secret.strip().upper(),
            'issuer': issuer_name,
            'algorithm': 'SHA1',
            'digits': 6,
            'period': 30
        })
        return f"otpauth://totp/{label}?{params}"

    @staticmethod
    def generate_totp(secret: str, time_step: int = 30, for_time: int | None = None, digits: int = 6) -> str:
        """
        Calcula o código TOTP de 6 dígitos para o instante de tempo especificado (ou time atual).
        """
        if for_time is None:
            for_time = int(time.time())

        counter = for_time // time_step
        counter_bytes = struct.pack(">Q", counter)

        # Trata padding Base32 caso o segredo venha sem '='
        clean_secret = secret.strip().upper()
        padding_needed = (8 - len(clean_secret) % 8) % 8
        clean_secret += "=" * padding_needed

        key_bytes = base64.b32decode(clean_secret, casefold=True)
        hmac_digest = hmac.new(key_bytes, counter_bytes, hashlib.sha1).digest()

        offset = hmac_digest[-1] & 0x0F
        truncated_hash = struct.unpack(">I", hmac_digest[offset:offset+4])[0] & 0x7FFFFFFF
        code = truncated_hash % (10 ** digits)

        return f"{code:0{digits}d}"

    @staticmethod
    def verify_totp(secret: str, token: str, valid_window: int = 1, time_step: int = 30) -> bool:
        """
        Valida o token TOTP enviado pelo usuário considerando uma janela de tolerância
        a pequenos desvios de relógio (±valid_window passos de 30 segundos).
        """
        if not secret or not token:
            return False

        clean_token = str(token).strip()
        if len(clean_token) != 6 or not clean_token.isdigit():
            return False

        now = int(time.time())
        for drift in range(-valid_window, valid_window + 1):
            expected_code = TOTPService.generate_totp(
                secret,
                time_step=time_step,
                for_time=now + (drift * time_step)
            )
            if hmac.compare_digest(clean_token, expected_code):
                return True

        return False
