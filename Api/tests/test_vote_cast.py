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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.questionSchema import Question
from Domain.models.schemas.election.optionSchema import Option
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
from Domain.models.schemas.election.votingTokenSchema import VotingToken
from Domain.models.schemas.election.voteSchema import Vote
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
        self.assertIsNotNone(self.voting_token.used_at)

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
