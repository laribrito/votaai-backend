import hashlib
import secrets
from django.core.mail import send_mail
from django.conf import settings
from Domain.models.schemas.election.votingTokenSchema import VotingToken

class VotingTokenService:
    """
    Service: VotingToken
    Generates, persists, and dispatches single-use voting tokens to electoral college voters.
    The raw token is sent via email; only its SHA-256 hash is stored in the database.
    """

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Returns the SHA-256 hex digest of the raw token string."""
        return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

    @classmethod
    def build_voting_link(cls, raw_token: str) -> str:
        """
        Builds the mobile voting deep link in a decoupled way.
        Supports:
          - Formats with '{token}' placeholder: e.g. 'votaai://votar/{token}'
          - Suffixes ending with '=' or '/': e.g. 'votaai://votar/?token='
          - Base URLs with existing query parameters or simple schemes
        Defaults to settings.MOBILE_VOTING_URL or 'votaai://votar/?token='.
        """
        mobile_url = getattr(settings, 'MOBILE_VOTING_URL', 'votaai://votar/?token=').strip()
        if '{token}' in mobile_url:
            return mobile_url.format(token=raw_token)
        if mobile_url.endswith('=') or mobile_url.endswith('/'):
            return f"{mobile_url}{raw_token}"
        if '?' in mobile_url:
            return f"{mobile_url}&token={raw_token}"
        return f"{mobile_url}?token={raw_token}"

    @staticmethod
    def _b64url(data: bytes) -> str:
        """Codifica bytes em Base64 URL-safe sem padding, conforme especificação do QR v2."""
        import base64
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @classmethod
    def get_qr_signing_private_key_pem(cls) -> bytes:
        """
        Retorna os bytes PEM da chave privada ECDSA P-256 de assinatura de QR Codes.
        Carrega de settings.QR_SIGNING_PRIVATE_KEY ou variável de ambiente.
        """
        raw_key = getattr(settings, 'QR_SIGNING_PRIVATE_KEY', None)
        if not raw_key:
            raise ValueError("QR_SIGNING_PRIVATE_KEY não configurada no settings/ambiente.")
        if isinstance(raw_key, bytes):
            return raw_key
        return raw_key.replace('\\n', '\n').encode('utf-8')

    @classmethod
    def build_signed_qr(cls, raw_token: str, election_id: str = '', ttl_seconds: int = 180, private_key_pem: bytes = None) -> str:
        """
        Gera o conteúdo oficial do QR Code assinado com ECDSA P-256 e SHA-256 (DER).
        Formato: votaai-qr:v2:<payload_b64url>.<assinatura_b64url>

        - O payload é um JSON UTF-8 em Base64 URL-safe sem padding com token, election_id, iat e exp opcional.
        - A assinatura é calculada sobre os bytes ASCII da string payload_b64url.
        - O aplicativo mobile possui apenas a chave pública, garantindo a autenticidade da eleição.
        """
        import json
        import time
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        now = int(time.time())
        payload = {
            'token': raw_token.strip(),
            'election_id': str(election_id) if election_id else '',
            'iat': now,
        }
        if ttl_seconds:
            payload['exp'] = now + ttl_seconds

        payload_json = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
        payload_b64 = cls._b64url(payload_json.encode('utf-8'))

        pem_data = private_key_pem or cls.get_qr_signing_private_key_pem()
        private_key = serialization.load_pem_private_key(pem_data, password=None)
        der_signature = private_key.sign(payload_b64.encode('ascii'), ec.ECDSA(hashes.SHA256()))
        sig_b64 = cls._b64url(der_signature)

        return f"votaai-qr:v2:{payload_b64}.{sig_b64}"

    @classmethod
    def build_secure_qr_link(cls, raw_token: str, election_id: str = '', ttl_seconds: int = 180) -> str:
        """
        Ponto de entrada para obtenção do conteúdo do QR Code de votação.
        Gera o código no formato oficial assinado assimetricamente (votaai-qr:v2:...).
        """
        return cls.build_signed_qr(raw_token, election_id, ttl_seconds=ttl_seconds)

    @classmethod
    def build_web_voting_link(cls, raw_token: str) -> str:
        """
        Builds the web voting link pointing to the ephemeral QR code page.
        Supports server-side validation via query parameter (?token=).
        Defaults to settings.WEB_VOTING_URL or 'http://localhost:8000/votar/?token='.
        """
        web_url = getattr(settings, 'WEB_VOTING_URL', 'http://localhost:8000/votar/?token=').strip()
        if '{token}' in web_url:
            return web_url.format(token=raw_token)
        if web_url.endswith('=') or web_url.endswith('#') or web_url.endswith('/'):
            return f"{web_url}{raw_token}"
        if '?' in web_url:
            return f"{web_url}&token={raw_token}"
        if '#' in web_url:
            return f"{web_url}&token={raw_token}"
        return f"{web_url}?token={raw_token}"

    @classmethod
    def generate_and_dispatch(cls, voter, election) -> int:
        """
        Generates a single-use token for the given voter, stores its hash,
        and sends the voting links (app direct + web QR Code) via email.

        Returns 1 on success, 0 on failure (so callers can sum email counts).
        """
        # Invalidate/delete any previous unused tokens for this voter and election
        VotingToken.objects.filter(voter=voter, election=election, is_used=False).delete()

        raw_token = secrets.token_urlsafe(32)
        token_hash = cls._hash_token(raw_token)

        VotingToken.objects.create(
            token_hash=token_hash,
            voter=voter,
            election=election,
        )

        mobile_voting_link = cls.build_voting_link(raw_token)
        web_voting_link = cls.build_web_voting_link(raw_token)
        election_info_url = getattr(settings, 'ELECTION_INFO_URL', 'http://localhost:5173/eleicoes').strip()
        app_name = getattr(settings, 'APP_NAME', 'VotaAI')
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@votaai.com')

        # Obtém o nome da pessoa para o e-mail (nome completo, apelido ou primeiro nome)
        voter_name = getattr(voter, 'full_name', '') or getattr(voter, 'nickname', '') or getattr(voter, 'first_name', '')
        if not voter_name or voter_name == voter.email.split('@')[0]:
            try:
                from Domain.models.schemas.moderation.userSchema import User
                matched = User.objects.filter(email__iexact=voter.email).first()
                if matched:
                    cand = f"{matched.first_name} {matched.last_name}".strip()
                    if cand:
                        voter_name = cand
            except Exception:
                pass

        if not voter_name:
            voter_name = voter.first_name or voter.email.split('@')[0]

        recipient_display = f"{voter_name} <{voter.email}>" if voter_name and voter_name != voter.email else voter.email
        recipient_list = [recipient_display]

        subject = f"[{app_name}] Seu acesso para votar na eleição: {election.title}"
        info_text = f"\nPara saber mais sobre a eleição atual, acesse: {election_info_url}\n" if election_info_url else ""
        body = (
            f"Olá, {voter_name}!\n\n"
            f"A eleição \"{election.title}\" foi iniciada e sua cédula de votação já está disponível.\n"
            f"{info_text}\n"
            f"OPÇÕES DE ACESSO À CÉDULA:\n\n"
            f"1) Para votar diretamente neste smartphone (com o app instalado):\n"
            f"{mobile_voting_link}\n\n"
            f"2) Para votar usando outro aparelho seguro (exibir QR Code com timer de 3 minutos):\n"
            f"{web_voting_link}\n\n"
            f"ATENÇÃO:\n"
            f"- Este acesso é pessoal, intransferível e de uso único.\n"
            f"- Por segurança em hardware, a votação exige aparelho compatível (Keystore/TPM/Secure Enclave) e sua senha de eleitor.\n"
            f"- A página do QR Code é protegida e expira após 3 minutos de exibição.\n"
            f"- Não compartilhe seu acesso com ninguém.\n\n"
            f"Atenciosamente,\n{app_name}"
        )

        info_html = ""
        if election_info_url:
            info_html = f"""
              <p style="font-size: 14px; line-height: 22px; margin: 0 0 24px 0; color: #4b5563;">
                Para saber mais sobre a eleição atual, <a href="{election_info_url}" target="_blank" rel="noopener noreferrer" style="color: #2563eb; text-decoration: underline; font-weight: 500;">clique aqui para acessar a página de divulgação</a>.
              </p>"""

        html_body = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Acesso à Cédula de Votação</title>
</head>
<body style="margin: 0; padding: 0; background-color: #E6E6E6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #111111;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #E6E6E6; padding: 40px 16px;">
    <tr>
      <td align="center">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 580px; background-color: #FFFFFF; border: 1px solid #D0D0D0; border-radius: 14px; overflow: hidden; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);">
          <!-- Cabeçalho idêntico ao PageHeader do Desktop/Mobile (sem topbar escura) -->
          <tr>
            <td style="padding: 32px 32px 20px 32px; text-align: center; border-bottom: 1px solid #E0E0E0;">
              <h1 style="margin: 0; color: #111111; font-size: 28px; font-weight: 800; letter-spacing: -0.5px;">{app_name}</h1>
              <p style="margin: 6px 0 0 0; color: #555555; font-size: 13px; font-weight: 500;">Sistema Eleitoral • Autenticação Segura</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px;">
              <p style="font-size: 16px; line-height: 24px; margin: 0 0 16px 0; color: #111111;">Olá, <strong>{voter_name}</strong>!</p>
              <p style="font-size: 15px; line-height: 24px; margin: 0 0 20px 0; color: #555555;">A eleição <strong>"{election.title}"</strong> foi iniciada e sua cédula de votação já está disponível.</p>
              {info_html}

              <!-- BOTÃO 1: Redirecionamento Direto para o App Mobile (Primary Blue) -->
              <table border="0" cellspacing="0" cellpadding="0" style="width: 100%; margin: 24px 0 12px 0;">
                <tr>
                  <td align="center" style="border-radius: 10px; background-color: #1E6091;">
                    <a href="{mobile_voting_link}" target="_blank" rel="noopener noreferrer" style="display: block; padding: 14px 24px; font-size: 15px; font-weight: 600; color: #FFFFFF; text-decoration: none; border-radius: 10px; background-color: #1E6091; border: 1px solid #14466B; text-align: center;">
                      📱 Acessar Cédula de Votação (Abrir no Aplicativo)
                    </a>
                  </td>
                </tr>
              </table>

              <!-- DIVISOR COM EXPLICAÇÃO -->
              <div style="text-align: center; margin: 18px 0 14px 0; position: relative;">
                <span style="background-color: #EAEAEA; padding: 4px 12px; border-radius: 999px; font-size: 11px; font-weight: 600; color: #555555; text-transform: uppercase; letter-spacing: 0.5px;">
                  ou para votar em outro aparelho
                </span>
              </div>

              <!-- BOTÃO 2: Página com QR Code (Outline Blue) -->
              <table border="0" cellspacing="0" cellpadding="0" style="width: 100%; margin: 12px 0 24px 0;">
                <tr>
                  <td align="center" style="border-radius: 10px; background-color: #FFFFFF;">
                    <a href="{web_voting_link}" target="_blank" rel="noopener noreferrer" style="display: block; padding: 14px 24px; font-size: 15px; font-weight: 600; color: #1E6091; text-decoration: none; border-radius: 10px; background-color: #FFFFFF; border: 1.5px solid #1E6091; text-align: center;">
                      🖥️ Exibir QR Code na Web (Temporizador de 3 min)
                    </a>
                  </td>
                </tr>
              </table>

              <p style="font-size: 13px; color: #555555; line-height: 20px; margin: 16px 0; text-align: center;">
                Use o botão <strong>Exibir QR Code</strong> caso esteja lendo no computador ou se o aparelho atual não possuir biometria/segurança em hardware.
              </p>

              <!-- AVISO DE SEGURANÇA (Estilo securityNotice do Mobile) -->
              <div style="background-color: #FEF3C7; border: 1px solid #D97706; border-left: 4px solid #D97706; padding: 14px 16px; border-radius: 8px; margin: 24px 0;">
                <p style="margin: 0 0 6px 0; font-weight: 700; color: #92400E; font-size: 13px;">⚠️ ATENÇÃO E SEGURANÇA:</p>
                <ul style="margin: 0; padding-left: 20px; color: #92400E; font-size: 12px; line-height: 19px;">
                  <li>Este acesso é <strong>pessoal, intransferível e de uso único</strong>.</li>
                  <li>Após o depósito do voto no aplicativo, o link expira imediatamente.</li>
                  <li>A exibição do QR Code na web é protegida por temporizador de 3 minutos.</li>
                  <li>Não compartilhe seu e-mail ou código de acesso com terceiros.</li>
                </ul>
              </div>

              <p style="font-size: 12px; color: #888888; line-height: 18px; margin: 24px 0 0 0; text-align: center;">
                Caso o botão não funcione, por favor entre em contato por e-mail.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background-color: #F0F0F0; padding: 20px 32px; border-top: 1px solid #E0E0E0; text-align: center;">
              <p style="font-size: 12px; color: #888888; margin: 0;">Atenciosamente,<br><strong>{app_name}</strong></p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        try:
            send_mail(
                subject=subject,
                message=body,
                from_email=from_email,
                recipient_list=recipient_list,
                html_message=html_body,
                fail_silently=False,
            )
            voter.mark_email_sent()
            return 1
        except Exception:
            return 0

    @classmethod
    def validate_and_consume(cls, raw_token: str, ip_address: str = None):
        """
        Validates a raw token against the database.
        Returns the VotingToken instance if valid and unused, or None.
        Marks the token as used on success.
        """
        token_hash = cls._hash_token(raw_token)
        try:
            token_obj = VotingToken.objects.select_related('voter', 'election').get(
                token_hash=token_hash,
                is_used=False,
            )
            token_obj.mark_as_used(ip_address=ip_address)
            return token_obj
        except VotingToken.DoesNotExist:
            return None
