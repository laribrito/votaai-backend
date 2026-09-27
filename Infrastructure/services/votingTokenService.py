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
    def generate_and_dispatch(cls, voter, election) -> int:
        """
        Generates a single-use token for the given voter, stores its hash,
        and sends the voting link via email.

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

        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173').rstrip('/')
        voting_link = f"{frontend_url}/votar/?token={raw_token}"
        election_info_url = getattr(settings, 'ELECTION_INFO_URL', f"{frontend_url}/eleicoes").strip()
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
            f"Utilize o botão disponibilizado no e-mail em formato HTML para acessar sua cédula de votação com segurança.\n"
            f"Caso o botão não funcione, por favor entre em contato por e-mail.\n\n"
            f"ATENÇÃO:\n"
            f"- Este acesso é pessoal, intransferível e de uso único.\n"
            f"- Após clicar e votar, o link expira imediatamente.\n"
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
<body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1f2937;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f3f4f6; padding: 40px 16px;">
    <tr>
      <td align="center">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 600px; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
          <tr>
            <td style="background-color: #1e3a8a; padding: 24px 32px; text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700; letter-spacing: 0.5px;">{app_name}</h1>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px;">
              <p style="font-size: 16px; line-height: 24px; margin: 0 0 16px 0;">Olá, <strong>{voter_name}</strong>!</p>
              <p style="font-size: 16px; line-height: 24px; margin: 0 0 20px 0;">A eleição <strong>"{election.title}"</strong> foi iniciada e sua cédula de votação já está disponível.</p>
              {info_html}
              <table border="0" cellspacing="0" cellpadding="0" style="margin: 32px auto; text-align: center;">
                <tr>
                  <td align="center" style="border-radius: 6px; background-color: #2563eb;">
                    <a href="{voting_link}" target="_blank" rel="noopener noreferrer" style="display: inline-block; padding: 14px 32px; font-size: 16px; font-weight: 600; color: #ffffff; text-decoration: none; border-radius: 6px; background-color: #2563eb; border: 1px solid #1d4ed8;">
                      Acessar Cédula de Votação
                    </a>
                  </td>
                </tr>
              </table>

              <div style="background-color: #fef2f2; border-left: 4px solid #ef4444; padding: 16px; border-radius: 4px; margin: 24px 0;">
                <p style="margin: 0 0 8px 0; font-weight: 700; color: #991b1b; font-size: 14px;">ATENÇÃO:</p>
                <ul style="margin: 0; padding-left: 20px; color: #7f1d1d; font-size: 13px; line-height: 20px;">
                  <li>Este link é <strong>pessoal, intransferível e de uso único</strong>.</li>
                  <li>Não compartilhe este link com ninguém.</li>
                </ul>
              </div>

              <p style="font-size: 13px; color: #6b7280; line-height: 20px; margin: 24px 0 0 0;">
                Caso o botão não funcione, por favor entre em contato por e-mail.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background-color: #f9fafb; padding: 20px 32px; border-top: 1px solid #e5e7eb; text-align: center;">
              <p style="font-size: 12px; color: #9ca3af; margin: 0;">Atenciosamente,<br><strong>{app_name}</strong></p>
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
