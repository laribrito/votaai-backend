import os
import json
import base64
import struct
from pathlib import Path
from datetime import timedelta
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
from Domain.models.schemas.election.votingTokenSchema import VotingToken
from Domain.models.schemas.moderation.userSchema import User
from Controllers.actions.vote.voteActions import VoteActions
from Infrastructure.services.votingTokenService import VotingTokenService


class ElectionCloseTests(APITestCase):
    def setUp(self):
        base_dir = getattr(settings, 'BASE_DIR', Path.cwd())
        keys_path = os.path.join(base_dir, 'se_keys_info.json')

        if not os.path.exists(keys_path):
            self.skipTest("Arquivo se_keys_info.json não encontrado. Execute generate_se_keys primeiro.")

        with open(keys_path, 'r') as f:
            keys_info = json.load(f)

        desktop_key_info = next((k for k in keys_info if k['KeyName'] == 'VotaAI_SecureKey_1'), None)
        self.assertIsNotNone(desktop_key_info, "Chave VotaAI_SecureKey_1 não encontrada no se_keys_info.json")

        pub_key_blob = base64.b64decode(desktop_key_info['PublicKeyBase64'])
        magic, bitlen, cbpubexp, cbmodulus, cbprime1, cbprime2 = struct.unpack('<IIIIII', pub_key_blob[:24])
        offset = 24
        exp_bytes = pub_key_blob[offset:offset+cbpubexp]
        offset += cbpubexp
        mod_bytes = pub_key_blob[offset:offset+cbmodulus]
        e = int.from_bytes(exp_bytes, byteorder='big')
        n = int.from_bytes(mod_bytes, byteorder='big')
        self.backend_public_key = rsa.RSAPublicNumbers(e, n).public_key()

        # Gera par de chaves RSA da máquina cliente Desktop
        self.machine_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.machine_public_pem = self.machine_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Usuário criador da eleição associado à máquina física
        self.user = User.objects.create_user(
            username='admin.close@votaai.org',
            email='admin.close@votaai.org',
            password='Password123!',
            is_active=True,
            machine_public_key=self.machine_public_pem.strip()
        )

        # Chave RSA da eleição
        self.election_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.election_public_pem = self.election_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.key_handle = "close_election_handle_1001"

        # Cria eleição já em andamento (STARTED)
        self.election = Election.objects.create(
            title="Eleição Diretoria Executiva 2026",
            public_key=self.election_public_pem,
            key_handle=self.key_handle,
            status=ElectionStatus.STARTED,
            start_datetime=timezone.now() - timedelta(hours=3),
            created_by=self.user
        )

        # Eleitores: 4 no total (3 votaram, 1 pendente = 75% quórum)
        self.voter_1 = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Alice Silva",
            email="alice@votaai.org",
            has_voted=True
        )
        self.voter_2 = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Bob Santos",
            email="bob@votaai.org",
            has_voted=True
        )
        self.voter_3 = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Carol Mendes",
            email="carol@votaai.org",
            has_voted=True
        )
        self.voter_4 = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Daniel Oliveira",
            email="daniel@votaai.org",
            has_voted=False
        )

        self.url_close = reverse('election-close')

    def _encrypt_request_body(self, payload_dict: dict) -> dict:
        json_bytes = json.dumps(payload_dict).encode('utf-8')
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        aesgcm = AESGCM(aes_key)

        encrypted_data = aesgcm.encrypt(iv, json_bytes, None)
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

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

    def _decrypt_response_body(self, response) -> dict:
        enc_json = response.json()
        enc_aes_key_bytes = base64.b64decode(enc_json["encrypted_aes_key"])
        decrypted_aes_key = self.machine_private_key.decrypt(
            enc_aes_key_bytes,
            padding.PKCS1v15()
        )

        aesgcm = AESGCM(decrypted_aes_key)
        iv = base64.b64decode(enc_json["iv"])
        ciphertext = base64.b64decode(enc_json["encrypted_payload"])
        tag = base64.b64decode(enc_json["tag"])

        decrypted_bytes = aesgcm.decrypt(iv, ciphertext + tag, None)
        return json.loads(decrypted_bytes.decode('utf-8'))

    def test_close_election_flow_success(self):
        """Fluxo completo de encerramento de eleição via envelope híbrido e assinatura de chave de eleição."""
        nonce = "test-nonce-close-999"
        payload = {
            "msg": "CLOSE_ELECTION",
            "keyHandle": self.key_handle,
            "nonceClient3": nonce
        }

        # Assina o payload canônico com a chave privada da eleição
        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        sig_bytes = self.election_private_key.sign(
            payload_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        payload["election_signature"] = base64.b64encode(sig_bytes).decode('utf-8')
        payload["machine_public_key"] = self.machine_public_pem

        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_close, data=enc_body, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        decrypted_resp = self._decrypt_response_body(response)
        self.assertEqual(decrypted_resp.get("status"), ElectionStatus.CLOSED)
        self.assertEqual(decrypted_resp.get("keyHandle"), self.key_handle)
        self.assertEqual(decrypted_resp.get("titulo"), "Eleição Diretoria Executiva 2026")
        self.assertEqual(decrypted_resp.get("nonceClient3"), nonce)
        self.assertEqual(decrypted_resp.get("total_colegio"), 4)
        self.assertEqual(decrypted_resp.get("votos_registrados"), 3)
        self.assertEqual(decrypted_resp.get("pendentes"), 1)
        self.assertEqual(decrypted_resp.get("porcentagem_quorum"), 75.0)
        self.assertIn("hora_registrada", decrypted_resp)

        # Verifica persistência no banco
        self.election.refresh_from_db()
        self.assertEqual(self.election.status, ElectionStatus.CLOSED)
        self.assertIsNotNone(self.election.end_datetime)

    def test_close_election_invalid_signature_fails_403(self):
        """Assinatura da eleição inválida ou adulterada deve retornar 403 Forbidden."""
        nonce = "test-nonce-invalid-sig"
        payload = {
            "msg": "CLOSE_ELECTION",
            "keyHandle": self.key_handle,
            "nonceClient3": nonce,
            "election_signature": base64.b64encode(b"invalid_signature_bytes_12345").decode('utf-8'),
            "machine_public_key": self.machine_public_pem
        }

        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_close, data=enc_body, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        decrypted_resp = self._decrypt_response_body(response)
        self.assertIn("error", decrypted_resp)

        # Eleição continua STARTED
        self.election.refresh_from_db()
        self.assertEqual(self.election.status, ElectionStatus.STARTED)

    def test_close_election_from_unauthorized_machine_fails_403(self):
        """Tentativa de fechar por uma máquina que não criou a eleição deve falhar com 403."""
        other_machine_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_machine_pem = other_machine_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        nonce = "test-nonce-other-machine"
        payload = {
            "msg": "CLOSE_ELECTION",
            "keyHandle": self.key_handle,
            "nonceClient3": nonce
        }

        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        sig_bytes = self.election_private_key.sign(
            payload_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        payload["election_signature"] = base64.b64encode(sig_bytes).decode('utf-8')
        payload["machine_public_key"] = other_machine_pem

        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_close, data=enc_body, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Decifra com a chave da outra máquina para inspecionar
        enc_json = response.json()
        enc_aes_key_bytes = base64.b64decode(enc_json["encrypted_aes_key"])
        decrypted_aes_key = other_machine_priv.decrypt(enc_aes_key_bytes, padding.PKCS1v15())
        aesgcm = AESGCM(decrypted_aes_key)
        decrypted_bytes = aesgcm.decrypt(
            base64.b64decode(enc_json["iv"]),
            base64.b64decode(enc_json["encrypted_payload"]) + base64.b64decode(enc_json["tag"]),
            None
        )
        data = json.loads(decrypted_bytes.decode('utf-8'))
        self.assertIn("error", data)

    def test_close_already_closed_election_fails_400(self):
        """Tentar fechar eleição que já está CLOSED retorna 400."""
        self.election.status = ElectionStatus.CLOSED
        self.election.save()

        nonce = "test-nonce-already-closed"
        payload = {
            "msg": "CLOSE_ELECTION",
            "keyHandle": self.key_handle,
            "nonceClient3": nonce
        }
        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        sig_bytes = self.election_private_key.sign(payload_str.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        payload["election_signature"] = base64.b64encode(sig_bytes).decode('utf-8')
        payload["machine_public_key"] = self.machine_public_pem

        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_close, data=enc_body, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_close_not_started_election_fails_400(self):
        """Tentar fechar eleição com status CREATED retorna 400."""
        self.election.status = ElectionStatus.CREATED
        self.election.save()

        nonce = "test-nonce-created"
        payload = {
            "msg": "CLOSE_ELECTION",
            "keyHandle": self.key_handle,
            "nonceClient3": nonce
        }
        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        sig_bytes = self.election_private_key.sign(payload_str.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        payload["election_signature"] = base64.b64encode(sig_bytes).decode('utf-8')
        payload["machine_public_key"] = self.machine_public_pem

        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_close, data=enc_body, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_close_nonexistent_election_fails_404(self):
        """Key handle inexistente retorna 404."""
        nonce = "test-nonce-404"
        payload = {
            "msg": "CLOSE_ELECTION",
            "keyHandle": "nonexistent_key_handle_9999",
            "nonceClient3": nonce,
            "election_signature": "mock_signature",
            "machine_public_key": self.machine_public_pem
        }

        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_close, data=enc_body, format='json')

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_voting_blocked_immediately_after_close(self):
        """Garante que qualquer tentativa de votação seja rejeitada após o fechamento da eleição."""
        raw_token = "secure_token_for_daniel"
        token_hash = VotingTokenService._hash_token(raw_token)
        VotingToken.objects.create(
            election=self.election,
            voter=self.voter_4,
            token_hash=token_hash,
            is_used=False
        )

        # Fecha a eleição
        self.election.status = ElectionStatus.CLOSED
        self.election.end_datetime = timezone.now()
        self.election.save()

        # Tentativa de solicitar cédula com o token do eleitor
        from rest_framework.exceptions import ValidationError as DRFValidationError
        with self.assertRaises(DRFValidationError) as ctx:
            VoteActions.requestVote({
                "token": raw_token,
                "machine_public_key": self.machine_public_pem,
                "nonce": "attempt_nonce",
                "attestation_certificates": []
            })
        self.assertIn("closed", str(ctx.exception))

    def test_tracking_endpoint_reflects_closed_status_immediately(self):
        """A rota de acompanhamento público deve refletir imediatamente o status CLOSED e quórum final."""
        # Fecha a eleição via endpoint
        nonce = "test-nonce-track-reflect"
        payload = {
            "msg": "CLOSE_ELECTION",
            "keyHandle": self.key_handle,
            "nonceClient3": nonce
        }
        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        sig_bytes = self.election_private_key.sign(payload_str.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
        payload["election_signature"] = base64.b64encode(sig_bytes).decode('utf-8')
        payload["machine_public_key"] = self.machine_public_pem

        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_close, data=enc_body, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Consulta a rota de acompanhamento público
        url_track = reverse('public-election-detail', args=[self.election.id])
        track_resp = self.client.get(url_track)

        self.assertEqual(track_resp.status_code, status.HTTP_200_OK)
        track_data = track_resp.json()
        self.assertEqual(track_data['status'], ElectionStatus.CLOSED)
        self.assertEqual(track_data['total_voters'], 4)
        self.assertEqual(track_data['voted_count'], 3)
        self.assertEqual(track_data['pending_count'], 1)
        self.assertEqual(track_data['quorum_percentage'], 75.0)
        self.assertEqual(len(track_data['electoral_college']), 4)
