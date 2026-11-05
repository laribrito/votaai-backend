from django.test import TestCase, override_settings
from Infrastructure.services.votingTokenService import VotingTokenService


class VotingTokenServiceLinkTestCase(TestCase):
    """
    Test suite for VotingTokenService decoupled mobile deep link generation.
    """

    @override_settings(MOBILE_VOTING_URL='votaai://votar/?token=')
    def test_default_custom_scheme_query_suffix(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "votaai://votar/?token=token123")

    @override_settings(MOBILE_VOTING_URL='votaai://votar?token=')
    def test_custom_scheme_without_trailing_slash(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "votaai://votar?token=token123")

    @override_settings(MOBILE_VOTING_URL='votaai://vote/{token}')
    def test_custom_scheme_with_template_placeholder(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "votaai://vote/token123")

    @override_settings(MOBILE_VOTING_URL='https://votaai.org/votar/?token=')
    def test_https_universal_link_suffix(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "https://votaai.org/votar/?token=token123")

    @override_settings(MOBILE_VOTING_URL='https://votaai.org/votar')
    def test_https_base_url_appends_token_param(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "https://votaai.org/votar?token=token123")

    @override_settings(MOBILE_VOTING_URL='https://votaai.org/votar?channel=email')
    def test_https_with_existing_query_params(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "https://votaai.org/votar?channel=email&token=token123")


class VotingTokenServiceWebLinkTestCase(TestCase):
    """
    Test suite for VotingTokenService web voting link generation (?token= and fallback formats).
    """

    @override_settings(WEB_VOTING_URL='http://localhost:8000/votar/?token=')
    def test_default_web_voting_link_query_param(self):
        link = VotingTokenService.build_web_voting_link("secretToken456")
        self.assertEqual(link, "http://localhost:8000/votar/?token=secretToken456")

    @override_settings(WEB_VOTING_URL='https://votaai.app/votar/?token={token}')
    def test_web_voting_link_with_placeholder(self):
        link = VotingTokenService.build_web_voting_link("secretToken456")
        self.assertEqual(link, "https://votaai.app/votar/?token=secretToken456")

    @override_settings(WEB_VOTING_URL='https://votaai.app/votar')
    def test_web_voting_link_appends_query_param(self):
        link = VotingTokenService.build_web_voting_link("secretToken456")
        self.assertEqual(link, "https://votaai.app/votar?token=secretToken456")

    @override_settings(WEB_VOTING_URL='http://localhost:8000/votar/#token=')
    def test_web_voting_link_hash_fragment_backwards_compat(self):
        link = VotingTokenService.build_web_voting_link("secretToken456")
        self.assertEqual(link, "http://localhost:8000/votar/#token=secretToken456")



from Domain.models.schemas.moderation.userSchema import User
from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
from Domain.models.schemas.election.votingTokenSchema import VotingToken


class VotingQRCodeViewTestCase(TestCase):
    """
    Test suite for VotingQRCodeView anti-cache headers, template rendering,
    and token usage validation (server-side and async endpoint).
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="admin@votaai.org",
            email="admin@votaai.org",
            password="Password123!"
        )
        self.election = Election.objects.create(
            title="Eleição Presidencial Vota ai",
            public_key="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0...",
            key_handle="test_handle_voting_token",
            status=ElectionStatus.STARTED,
            created_by=self.user
        )
        self.voter1 = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Maria Joana Santos",
            email="maria.santos@votaai.org"
        )
        self.voter2 = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Joao Pedro Oliveira",
            email="joao.oliveira@votaai.org"
        )

        self.raw_unused_token = "unused_token_abc_123"
        self.unused_token_hash = VotingTokenService._hash_token(self.raw_unused_token)
        self.unused_token = VotingToken.objects.create(
            token_hash=self.unused_token_hash,
            voter=self.voter1,
            election=self.election,
            is_used=False
        )

        self.raw_used_token = "already_used_token_xyz_789"
        self.used_token_hash = VotingTokenService._hash_token(self.raw_used_token)
        self.used_token = VotingToken.objects.create(
            token_hash=self.used_token_hash,
            voter=self.voter2,
            election=self.election,
            is_used=True
        )

    def test_get_voting_qrcode_view_success(self):
        response = self.client.get('/votar/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response['Content-Type'])

        # Valida cabeçalhos anti-cache estritos
        cache_control = response.headers.get('Cache-Control', '')
        self.assertIn('no-store', cache_control)
        self.assertIn('no-cache', cache_control)
        self.assertIn('must-revalidate', cache_control)
        self.assertEqual(response.headers.get('Pragma'), 'no-cache')
        self.assertEqual(response.headers.get('Expires'), '0')
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(response.headers.get('Referrer-Policy'), 'no-referrer')

        # Valida que o template contém o timer de 3 minutos e extração de hash
        content = response.content.decode('utf-8')
        self.assertIn('Escanear Cédula de Votação', content)
        self.assertIn('03:00', content)
        self.assertIn('extractToken', content)
        self.assertIn('TOTAL_SECONDS = 180', content)
        self.assertIn('location.hash', content)

        # Anti-flicker: sem token válido prévio, a sessão ativa NUNCA é exibida inicialmente
        self.assertIn('id="state-no-token" class="state-card state-error" style="display: block;"', content)
        self.assertIn('id="active-session-wrapper" style="display: none;"', content)

    def test_get_voting_qrcode_view_with_used_token_renders_used_card(self):
        # Validação direta pelo Django Template quando token consumido é passado via query string (?token=...)
        response = self.client.get(f'/votar/?token={self.raw_used_token}')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('Cédula Já Utilizada', content)
        self.assertIn('id="state-already-used"', content)
        self.assertIn('style="display: block;"', content)
        self.assertIn('id="active-session-wrapper" style="display: none;"', content)

    def test_get_voting_qrcode_view_with_path_param_used_token_renders_used_card(self):
        # Validação direta quando token consumido é passado via path (/votar/<token>/)
        response = self.client.get(f'/votar/{self.raw_used_token}/')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('Cédula Já Utilizada', content)
        self.assertIn('id="state-already-used"', content)
        self.assertIn('style="display: block;"', content)
        self.assertIn('id="active-session-wrapper" style="display: none;"', content)

    def test_get_voting_qrcode_view_with_invalid_token_renders_not_found(self):
        response = self.client.get('/votar/?token=token_inexistente_999')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('Cédula Não Localizada', content)
        self.assertIn('id="state-invalid"', content)
        self.assertIn('style="display: block;"', content)
        self.assertIn('id="active-session-wrapper" style="display: none;"', content)

    def test_get_voting_qrcode_view_with_path_param_invalid_token(self):
        response = self.client.get('/votar/token_inexistente_999/')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('Cédula Não Localizada', content)
        self.assertIn('id="state-invalid"', content)
        self.assertIn('style="display: block;"', content)
        self.assertIn('id="active-session-wrapper" style="display: none;"', content)

    def test_get_voting_qrcode_view_with_valid_token_renders_active_session(self):
        response = self.client.get(f'/votar/?token={self.raw_unused_token}')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('serverTokenStatus = "valid"', content)
        self.assertIn(f'serverToken = "{self.raw_unused_token}"', content)
        self.assertNotIn('id="active-session-wrapper" style="display: none;"', content)

    def test_get_voting_qrcode_view_with_path_param_valid_token(self):
        response = self.client.get(f'/votar/{self.raw_unused_token}/')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('serverTokenStatus = "valid"', content)
        self.assertIn(f'serverToken = "{self.raw_unused_token}"', content)
        self.assertNotIn('id="active-session-wrapper" style="display: none;"', content)

    def test_get_voting_qrcode_view_with_blocked_token(self):
        raw_blocked_token = "blocked_token_123"
        blocked_token_hash = VotingTokenService._hash_token(raw_blocked_token)
        VotingToken.objects.create(
            token_hash=blocked_token_hash,
            voter=self.voter1,
            election=self.election,
            is_used=False,
            is_blocked=True
        )
        response = self.client.get(f'/votar/?token={raw_blocked_token}')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('Cédula Bloqueada', content)
        self.assertIn('id="state-invalid"', content)
        self.assertIn('style="display: block;"', content)
        self.assertIn('id="active-session-wrapper" style="display: none;"', content)

    def test_check_token_status_endpoint_returns_already_used(self):
        response = self.client.get(f'/votar/?check=1&token_hash={self.used_token_hash}')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get('status'), 'already_used')
        self.assertTrue(data.get('is_used'))

    def test_check_token_status_endpoint_returns_valid(self):
        response = self.client.get(f'/votar/?check=1&token_hash={self.unused_token_hash}')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get('status'), 'valid')
        self.assertFalse(data.get('is_used'))

    def test_check_token_status_endpoint_returns_not_found(self):
        response = self.client.get('/votar/?check=1&token_hash=hash_totalmente_invalido')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get('status'), 'not_found')
        self.assertFalse(data.get('is_used'))



    def test_signed_qr_code_generation_and_verification(self):
        import base64
        import json
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        code = VotingTokenService.build_secure_qr_link("MeuTokenSeguro123", "eleicao-teste")
        self.assertTrue(code.startswith("votaai-qr:v2:"))

        body = code[len("votaai-qr:v2:"):]
        self.assertIn(".", body)
        payload_b64, sig_b64 = body.split(".", 1)

        # Decodifica payload JSON
        def pad_b64(s):
            return s + "=" * ((4 - len(s) % 4) % 4)

        payload_bytes = base64.urlsafe_b64decode(pad_b64(payload_b64))
        payload = json.loads(payload_bytes.decode('utf-8'))
        self.assertEqual(payload['token'], "MeuTokenSeguro123")
        self.assertEqual(payload['election_id'], "eleicao-teste")
        self.assertIn('iat', payload)
        self.assertIn('exp', payload)

        # Valida a assinatura ECDSA P-256 com a chave pública oficial embutida no Mobile
        public_key_b64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELCNngOqmiTYGoPVhe91LA7bzpC15IbLmODVPGW093r5DRzcvVAkyaTOurA9/K16Mv20SespIJ851Fw8wkzHVtw=="
        public_key = serialization.load_der_public_key(base64.b64decode(public_key_b64))

        sig_der = base64.urlsafe_b64decode(pad_b64(sig_b64))
        # Deve verificar sem lançar exceção
        public_key.verify(sig_der, payload_b64.encode('ascii'), ec.ECDSA(hashes.SHA256()))

    def test_voting_qrcode_view_renders_signed_qr_code(self):
        response = self.client.get(f'/votar/?token={self.raw_unused_token}')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertTrue('votaai-qr:v2:' in content or 'votaai\\u002Dqr:v2:' in content)
