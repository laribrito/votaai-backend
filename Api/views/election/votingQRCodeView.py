from django.views import View
from django.shortcuts import render
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.http import JsonResponse
from Domain.models.schemas.election.votingTokenSchema import VotingToken
from Infrastructure.services.votingTokenService import VotingTokenService


@method_decorator(never_cache, name='dispatch')
class VotingQRCodeView(View):
    """
    Renders the voting QR Code landing page with strict anti-cache headers
    and validates token status (unused vs already consumed).
    
    Security & Validation design:
    - Server-side validation via Django template when ?token= is provided.
    - Ephemeral client-side validation endpoint when #token= is provided via URL hash.
    - Encrypts QR code with AES-256-GCM symmetric key so only VotaAí mobile app can read.
    - Anti-cache headers enforce that browsers, proxies, and intermediaries never cache the page.
    """

    def get(self, request, token=None, *args, **kwargs):
        # 1. Verificação assíncrona/JSON (quando a página chama via fetch ?check=1)
        if request.GET.get('check') == '1' or request.GET.get('token_hash'):
            token_hash = request.GET.get('token_hash', '').strip()
            raw_token = (token or request.GET.get('token', '')).strip()

            if not token_hash and raw_token:
                token_hash = VotingTokenService._hash_token(raw_token)

            if not token_hash:
                return JsonResponse({'status': 'missing_token'}, status=400)

            token_obj = VotingToken.objects.filter(token_hash=token_hash).first()
            if not token_obj:
                return JsonResponse({'status': 'not_found', 'is_used': False})
            if token_obj.is_used:
                return JsonResponse({'status': 'already_used', 'is_used': True})
            if getattr(token_obj, 'is_blocked', False):
                return JsonResponse({'status': 'blocked', 'is_used': False})

            secure_qr_code = ''
            if raw_token:
                try:
                    election_id = str(token_obj.election_id) if hasattr(token_obj, 'election_id') else ''
                    secure_qr_code = VotingTokenService.build_secure_qr_link(raw_token, election_id)
                except Exception:
                    secure_qr_code = ''

            return JsonResponse({'status': 'valid', 'is_used': False, 'secure_qr_code': secure_qr_code})

        # 2. Renderização do Template Django (Validação no Servidor)
        app_name = getattr(settings, 'APP_NAME', 'Vota-ai')
        mobile_url = getattr(settings, 'MOBILE_VOTING_URL', 'votaai://votar/?token=')

        raw_token = (token or request.GET.get('token', '')).strip()
        server_token_status = None
        server_token = ''
        secure_qr_code = ''

        if raw_token:
            token_hash = VotingTokenService._hash_token(raw_token)
            token_obj = VotingToken.objects.filter(token_hash=token_hash).first()
            if not token_obj:
                server_token_status = 'not_found'
            elif token_obj.is_used:
                server_token_status = 'already_used'
            elif getattr(token_obj, 'is_blocked', False):
                server_token_status = 'blocked'
            else:
                server_token_status = 'valid'
                server_token = raw_token
                try:
                    election_id = str(token_obj.election_id) if hasattr(token_obj, 'election_id') else ''
                    secure_qr_code = VotingTokenService.build_secure_qr_link(raw_token, election_id)
                except Exception:
                    secure_qr_code = ''
        else:
            server_token_status = 'missing'

        response = render(request, 'voting/qrcode.html', {
            'app_name': app_name,
            'mobile_url_prefix': mobile_url,
            'server_token_status': server_token_status,
            'server_token': server_token,
            'secure_qr_code': secure_qr_code,
        })

        # Rigorous anti-cache headers and privacy policies (HTTP Response Headers)
        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Referrer-Policy'] = 'no-referrer'

        return response
