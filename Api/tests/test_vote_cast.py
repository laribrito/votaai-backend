import os
import json
import base64
import struct
import datetime
from pathlib import Path
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.questionSchema import Question
from Domain.models.schemas.election.optionSchema import Option
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
from Domain.models.schemas.election.votingTokenSchema import VotingToken
from Domain.models.schemas.election.voteSchema import Vote
from Domain.models.schemas.election.ballotTicketSchema import BallotTicket
from Domain.models.schemas.moderation.userSchema import User
from Infrastructure.services.votingTokenService import VotingTokenService

class VoteCastViewTests(APITestCase):
    def setUp(self):
        base_dir = getattr(settings, 'BASE_DIR', Path.cwd())
        keys_path = os.path.join(base_dir, 'se_keys_info.json')

        if not os.path.exists(keys_path):
            self.skipTest("Arquivo se_keys_info.json não encontrado.")

        with open(keys_path, 'r') as f:
            keys_info = json.load(f)

        mobile_key_info = next((k for k in keys_info if k['KeyName'] == 'VotaAI_SecureKey_2'), None)
        self.assertIsNotNone(mobile_key_info, "Chave VotaAI_SecureKey_2 não encontrada no se_keys_info.json")

        pub_key_blob = base64.b64decode(mobile_key_info['PublicKeyBase64'])
        magic, bitlen, cbpubexp, cbmodulus, cbprime1, cbprime2 = struct.unpack('<IIIIII', pub_key_blob[:24])
        offset = 24
        exp_bytes = pub_key_blob[offset:offset+cbpubexp]
        offset += cbpubexp
        mod_bytes = pub_key_blob[offset:offset+cbmodulus]
        e = int.from_bytes(exp_bytes, byteorder='big')
        n = int.from_bytes(mod_bytes, byteorder='big')
        self.backend_public_key = rsa.RSAPublicNumbers(e, n).public_key()

        # Par de chaves RSA do dispositivo StrongBox do eleitor
        self.device_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.device_public_pem = self.device_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Usuário criador da eleição
        self.creator = User.objects.create_user(
            username='admin.elections@votaai.org',
            email='admin.elections@votaai.org',
            password='AdminPassword123!',
            is_active=True
        )

        # Eleição iniciada
        self.election = Election.objects.create(
            title="Eleição Diretoria Geral 2026",
            public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
            key_handle="0x81010002",
            status=ElectionStatus.STARTED,
            start_datetime=timezone.now(),
            created_by=self.creator
        )

        # Eleitor
        self.voter = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Maria da Silva Santos",
            email="maria.silva@votaai.org",
            nickname="Maria",
            has_voted=False
        )

        # Token de votação já vinculado à máquina após a solicitação da cédula
        self.raw_token = "token-secreto-mobile-cast-99999"
        self.token_hash = VotingTokenService._hash_token(self.raw_token)
        self.voting_token = VotingToken.objects.create(
            token_hash=self.token_hash,
            voter=self.voter,
            election=self.election,
            is_used=False,
            machine_public_key=self.device_public_pem,
            nonce="nonce-initial-req-001"
        )

        self.default_nonce = "nonce-cast-vote-002"
        self.encrypted_ballot_content = "ENC_BALLOT_PAYLOAD_CIPHERED_WITH_ELECTION_PUBKEY_XYZ_123"
        self.url = reverse('vote-cast')

    def _encrypt_request_body(self, payload_dict: dict) -> dict:
        """Cifra o payload com AES-GCM + RSA (VotaAI_SecureKey_2) simulando o App Mobile."""
        json_bytes = json.dumps(payload_dict).encode('utf-8')
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        aesgcm = AESGCM(aes_key)

        cipher_and_tag = aesgcm.encrypt(iv, json_bytes, None)
        ciphertext = cipher_and_tag[:-16]
        tag = cipher_and_tag[-16:]

        encrypted_aes_key = self.backend_public_key.encrypt(
            aes_key,
            padding.PKCS1v15()
        )

        return {
            "encrypted_payload": base64.b64encode(ciphertext).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }

    def _decrypt_response_body(self, response_data: dict) -> dict:
        """Descriptografa a resposta do backend usando a chave privada do dispositivo móvel."""
        encrypted_payload = base64.b64decode(response_data['encrypted_payload'])
        encrypted_aes_key = base64.b64decode(response_data['encrypted_aes_key'])
        iv = base64.b64decode(response_data['iv'])
        tag = base64.b64decode(response_data['tag'])

        aes_key = self.device_private_key.decrypt(
            encrypted_aes_key,
            padding.PKCS1v15()
        )

        aesgcm = AESGCM(aes_key)
        decrypted_bytes = aesgcm.decrypt(iv, encrypted_payload + tag, None)
        return json.loads(decrypted_bytes.decode('utf-8'))

    def _generate_mock_attestation_cert(self, security_level: int, challenge: str = None, key=None) -> str:
        """Gera um certificado X.509 mock contendo a extensão Android Key Attestation."""
        target_key = key or self.device_private_key
        ch_bytes = (challenge or "default-challenge").encode('utf-8')
        inner_asn1 = (
            b'\x02\x01\x03' +
            bytes([0x0a, 0x01, security_level]) +
            b'\x02\x01\x04' +
            bytes([0x0a, 0x01, security_level]) +
            b'\x04' + bytes([len(ch_bytes)]) + ch_bytes
        )
        ext_value = b'\x30' + bytes([len(inner_asn1)]) + inner_asn1

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Android KeyStore StrongBox Mock CA'),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            target_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17'), ext_value),
            critical=False
        ).sign(target_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def test_cast_vote_success(self):
        """Verifica o depósito da cédula com sucesso, persistência anônima em Vote e consumo do token."""
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": self.encrypted_ballot_content,
            "nonce": self.default_nonce
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        resp_data = response.json()
        decrypted_data = self._decrypt_response_body(resp_data)

        self.assertIn('receipt', decrypted_data)
        self.assertTrue(decrypted_data['receipt'].startswith('VOTE-'))
        self.assertEqual(decrypted_data['status'], 'CONFIRMED')
        self.assertEqual(decrypted_data['election_id'], self.election.id)
        self.assertEqual(decrypted_data['nonce'], self.default_nonce)

        # Confirma que o voto foi persistido anonimamente na tabela Vote
        vote_obj = Vote.objects.filter(id_generated=decrypted_data['receipt']).first()
        self.assertIsNotNone(vote_obj)
        self.assertEqual(vote_obj.content, self.encrypted_ballot_content)
        self.assertEqual(vote_obj.election_id, self.election.id)

        # Confirma que o token foi marcado como usado
        self.voting_token.refresh_from_db()
        self.assertTrue(self.voting_token.is_used)
        self.assertIsNone(self.voting_token.used_at)  # Timestamp descorrelacionado para sigilo anônimo

        # Confirma que o eleitor foi marcado como tendo votado
        self.voter.refresh_from_db()
        self.assertTrue(self.voter.has_voted)

    def test_cast_vote_with_signature(self):
        """Verifica o depósito da cédula acompanhada de assinatura digital StrongBox válida."""
        sig_bytes = self.device_private_key.sign(
            self.encrypted_ballot_content.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')

        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": self.encrypted_ballot_content,
            "nonce": "nonce-signed-vote-003",
            "signature": sig_b64
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        decrypted_data = self._decrypt_response_body(response.json())
        self.assertEqual(decrypted_data['status'], 'CONFIRMED')
        self.assertTrue(decrypted_data['receipt'].startswith('VOTE-'))

    def test_cast_vote_invalid_token(self):
        """Token inexistente deve ser rejeitado com erro de validação."""
        payload = {
            "token": "token-inexistente-xyz",
            "machine_public_key": self.device_public_pem,
            "content": self.encrypted_ballot_content,
            "nonce": "nonce-invalid-004"
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        decrypted = self._decrypt_response_body(response.json())
        self.assertIn('token', decrypted)

    def test_cast_vote_already_consumed_token(self):
        """Tentativa de reutilizar token já consumido deve ser terminantemente rejeitada."""
        self.voting_token.is_used = True
        self.voting_token.save()

        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": self.encrypted_ballot_content,
            "nonce": "nonce-reuse-005"
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        decrypted = self._decrypt_response_body(response.json())
        self.assertIn('token', decrypted)

    def test_cast_vote_different_device_rejected(self):
        """Tentativa de submeter voto com chave pública de máquina diferente da vinculada é rejeitada."""
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pub_pem = other_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        payload = {
            "token": self.raw_token,
            "machine_public_key": other_pub_pem,
            "content": self.encrypted_ballot_content,
            "nonce": "nonce-different-dev-006"
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cast_vote_election_not_started(self):
        """Tentativa de depositar voto em eleição ainda não iniciada ou já fechada é bloqueada."""
        self.election.status = ElectionStatus.CLOSED
        self.election.save()

        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": self.encrypted_ballot_content,
            "nonce": "nonce-closed-007"
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        decrypted = self._decrypt_response_body(response.json())
        self.assertIn('election', decrypted)

    def test_cast_vote_voter_already_voted(self):
        """Eleitor que já consta como votou não pode depositar outro voto."""
        self.voter.has_voted = True
        self.voter.save()

        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": self.encrypted_ballot_content,
            "nonce": "nonce-voter-voted-008"
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        decrypted = self._decrypt_response_body(response.json())
        self.assertIn('voter', decrypted)

    def test_cast_vote_nonce_replay_rejected(self):
        """Tentativa de reaproveitar o mesmo nonce é barrada pela validação anti-replay."""
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": self.encrypted_ballot_content,
            "nonce": "nonce-initial-req-001"  # Nonce já registrado no VotingToken
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        decrypted = self._decrypt_response_body(response.json())
        self.assertIn('nonce', decrypted)

    def test_cast_vote_layered_model_with_exposed_id_and_tee_signature(self):
        """
        Verifica o modelo em 3 camadas:
        Camada 1 (Eleição): Cédula cifrada com chave da eleição e ID do Voto exposto.
        Camada 2 (Identidade): Pacote assinado com chave do TEE do Eleitor (SHA256withRSA).
        Camada 3 (Rede): Envelope Híbrido com chave pública da API.
        """
        vote_id = "voto-uuid-audit-12345"
        # Cria o BallotTicket emitido previamente pelo backend
        ticket = BallotTicket.objects.create(
            election=self.election,
            id_voto=vote_id,
            is_used=False
        )

        pacote_cifrado = "BASE64_CIPHERED_BALLOT_WITH_ELECTION_PUBLIC_KEY"
        ballot_package = {
            "id_voto": vote_id,
            "pacote_cifrado": pacote_cifrado
        }
        content_json = json.dumps(ballot_package)

        # Camada 2: Assinatura PKCS1v15 SHA256 (compatível com Android SHA256withRSA)
        sig_bytes = self.device_private_key.sign(
            content_json.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')

        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": content_json,
            "id_voto": vote_id,
            "nonce": "nonce-layered-test-010",
            "signature": sig_b64
        }
        # Camada 3: Cifra o conjunto assinado em Envelope Híbrido com a Chave Pública da API
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        decrypted_data = self._decrypt_response_body(response.json())
        self.assertEqual(decrypted_data['status'], 'CONFIRMED')
        self.assertTrue(decrypted_data['receipt'].startswith('VOTE-'))
        self.assertEqual(decrypted_data['id_voto'], vote_id)
        self.assertEqual(decrypted_data['nonce'], "nonce-layered-test-010")

        # Verifica persistência anônima
        vote_obj = Vote.objects.filter(id_generated=decrypted_data['receipt']).first()
        self.assertIsNotNone(vote_obj)
        self.assertEqual(vote_obj.content, content_json)

        # Verifica consumo do BallotTicket com seu próprio timestamp isolado
        ticket.refresh_from_db()
        self.assertTrue(ticket.is_used)
        self.assertIsNotNone(ticket.used_at)

    def test_cast_vote_with_unrecognized_ballot_ticket_rejected(self):
        """id_voto que não existe na tabela BallotTicket da eleição é rejeitado."""
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": json.dumps({"id_voto": "VOTE-NONEXISTENT-999", "pacote_cifrado": "CIPHER"}),
            "id_voto": "VOTE-NONEXISTENT-999",
            "nonce": "nonce-unrecog-ticket"
        }
        envelope = self._encrypt_request_body(payload)
        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        decrypted = self._decrypt_response_body(response.json())
        self.assertIn('id_voto', decrypted)

    def test_cast_vote_with_already_used_ballot_ticket_rejected(self):
        """id_voto que já foi consumido anteriormente é rejeitado prevenindo duplo depósito."""
        used_ticket_id = "VOTE-USED-TICKET-ALREADY"
        BallotTicket.objects.create(
            election=self.election,
            id_voto=used_ticket_id,
            is_used=True,
            used_at=timezone.now()
        )
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "content": json.dumps({"id_voto": used_ticket_id, "pacote_cifrado": "CIPHER"}),
            "id_voto": used_ticket_id,
            "nonce": "nonce-used-ticket"
        }
        envelope = self._encrypt_request_body(payload)
        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        decrypted = self._decrypt_response_body(response.json())
        self.assertIn('id_voto', decrypted)

    def test_cast_vote_missing_content(self):
        """Ausência do conteúdo da cédula preenchida resulta em erro 400."""
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "nonce": "nonce-missing-009"
        }
        envelope = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        decrypted = self._decrypt_response_body(response.json())
        self.assertIn('content', decrypted)

    def test_cast_vote_after_regenerating_id_voto(self):
        """
        Garante que o eleitor pode solicitar cédula, não finalizar a votação com o id antigo,
        gerar um novo id_voto e depositar com sucesso o voto com o novo id_voto.
        """
        from Controllers.actions.vote.voteActions import VoteActions

        # 1ª solicitação de cédula: gera id_voto_1
        nonce_1 = "nonce-reissue-test-1"
        cert_1 = self._generate_mock_attestation_cert(security_level=2, challenge=nonce_1)
        req_1 = VoteActions.requestVote({
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [cert_1],
            "nonce": nonce_1
        })
        id_voto_1 = req_1["id_voto"]

        # Votante NÃO finalizou com id_voto_1

        # 2ª solicitação de cédula: gera id_voto_2 com chave atualizada do hardware
        second_device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        second_device_pem = second_device_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        nonce_2 = "nonce-reissue-test-2"
        cert_2 = self._generate_mock_attestation_cert(security_level=2, challenge=nonce_2, key=second_device_key)
        req_2 = VoteActions.requestVote({
            "token": self.raw_token,
            "machine_public_key": second_device_pem,
            "attestation_certificates": [cert_2],
            "nonce": nonce_2
        })
        id_voto_2 = req_2["id_voto"]
        self.assertNotEqual(id_voto_1, id_voto_2)

        # Depósito do voto com id_voto_2 e a chave do segundo dispositivo
        ballot_content = json.dumps({"id_voto": id_voto_2, "pacote_cifrado": "CIPHER-LAYER-1"})
        signature = second_device_key.sign(
            ballot_content.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        sig_b64 = base64.b64encode(signature).decode('utf-8')

        cast_payload = {
            "token": self.raw_token,
            "machine_public_key": second_device_pem,
            "content": ballot_content,
            "nonce": "nonce-cast-final-99",
            "signature": sig_b64,
            "id_voto": id_voto_2
        }
        envelope = self._encrypt_request_body(cast_payload)
        response = self.client.post(self.url, data=envelope, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Decifra a resposta usando a chave do segundo dispositivo
        enc_json = response.json()
        enc_aes_key = second_device_key.decrypt(base64.b64decode(enc_json["encrypted_aes_key"]), padding.PKCS1v15())
        aesgcm = AESGCM(enc_aes_key)
        decrypted = json.loads(aesgcm.decrypt(
            base64.b64decode(enc_json["iv"]),
            base64.b64decode(enc_json["encrypted_payload"]) + base64.b64decode(enc_json["tag"]),
            None
        ).decode('utf-8'))
        self.assertEqual(decrypted["status"], "CONFIRMED")
        self.assertEqual(decrypted["id_voto"], id_voto_2)

        # Confirma que token e eleitor foram marcados como finalizados
        self.voting_token.refresh_from_db()
        self.assertTrue(self.voting_token.is_used)
        self.voter.refresh_from_db()
        self.assertTrue(self.voter.has_voted)

        # Confirma que o ticket id_voto_2 foi marcado como usado
        ticket_2 = BallotTicket.objects.get(id_voto=id_voto_2)
        self.assertTrue(ticket_2.is_used)

        # Tentativa subsequente com id_voto_1 é bloqueada pois o token já foi consumido
        cast_again_payload = {
            "token": self.raw_token,
            "machine_public_key": second_device_pem,
            "content": json.dumps({"id_voto": id_voto_1, "pacote_cifrado": "CIPHER"}),
            "nonce": "nonce-cast-replay-88",
            "id_voto": id_voto_1
        }
        envelope_again = self._encrypt_request_body(cast_again_payload)
        res_again = self.client.post(self.url, data=envelope_again, format='json')
        self.assertEqual(res_again.status_code, status.HTTP_400_BAD_REQUEST)
