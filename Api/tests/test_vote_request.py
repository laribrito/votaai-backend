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
from Domain.models.schemas.moderation.userSchema import User
from Infrastructure.services.votingTokenService import VotingTokenService

class VoteRequestViewTests(APITestCase):
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

        # Par de chaves RSA da máquina/dispositivo móvel do eleitor
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

        # Perguntas e opções
        self.question = Question.objects.create(
            election=self.election,
            question="Quem deve ser o Presidente?",
            order=1
        )
        self.option_a = Option.objects.create(question=self.question, label="Chapa 1 - Renovação")
        self.option_b = Option.objects.create(question=self.question, label="Chapa 2 - Continuidade")

        # Eleitor
        self.voter = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Maria da Silva Santos",
            email="maria.silva@votaai.org",
            nickname="Maria",
            has_voted=False
        )

        # Token de votação
        self.raw_token = "token-secreto-mobile-xyz-12345"
        self.token_hash = VotingTokenService._hash_token(self.raw_token)
        self.voting_token = VotingToken.objects.create(
            token_hash=self.token_hash,
            voter=self.voter,
            election=self.election,
            is_used=False
        )

        self.default_nonce = "nonce-strongbox-001"
        self.url = reverse('vote-request')

    def _generate_mock_attestation_cert(self, security_level: int, challenge: str = None) -> str:
        """
        Gera um certificado X.509 mock contendo a extensão Android Key Attestation (OID 1.3.6.1.4.1.11129.2.1.17).
        security_level:
            0 = Software
            1 = TrustedEnvironment (TEE)
            2 = StrongBox (Hardware dedicado)
        """
        ch_bytes = (challenge or self.default_nonce).encode('utf-8')
        inner_asn1 = (
            b'\x02\x01\x03' +  # attestationVersion = 3
            bytes([0x0a, 0x01, security_level]) +  # attestationSecurityLevel (ENUMERATED)
            b'\x02\x01\x04' +  # keymasterVersion = 4
            bytes([0x0a, 0x01, security_level]) +  # keymasterSecurityLevel (ENUMERATED)
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
            self.device_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17'), ext_value),
            critical=False
        ).sign(self.device_private_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def _encrypt_request_body(self, payload_dict: dict) -> dict:
        """Cifra o payload com AES-GCM + RSA (VotaAI_SecureKey_2) simulando o App Mobile."""
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
            "tag": base64.b64encode(tag).decode('utf-8'),
        }

    def _decrypt_response_body(self, response) -> dict:
        """Decifra a resposta do servidor com a chave privada do dispositivo móvel."""
        enc_json = response.json()
        self.assertIn("encrypted_payload", enc_json)
        self.assertIn("encrypted_aes_key", enc_json)

        enc_aes_key_bytes = base64.b64decode(enc_json["encrypted_aes_key"])
        decrypted_aes_key = self.device_private_key.decrypt(
            enc_aes_key_bytes,
            padding.PKCS1v15()
        )

        aesgcm = AESGCM(decrypted_aes_key)
        iv = base64.b64decode(enc_json["iv"])
        ciphertext = base64.b64decode(enc_json["encrypted_payload"])
        tag = base64.b64decode(enc_json["tag"])

        decrypted_bytes = aesgcm.decrypt(iv, ciphertext + tag, None)
        return json.loads(decrypted_bytes.decode('utf-8'))

    def test_vote_request_success_with_strongbox_hardware(self):
        """
        Solicita cédula com chave atestada em StrongBox (nível 2) e nonce válido:
        Deve ser aceita com sucesso (HTTP 200).
        """
        strongbox_cert = self._generate_mock_attestation_cert(security_level=2, challenge=self.default_nonce)
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [strongbox_cert],
            "nonce": self.default_nonce
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = self._decrypt_response_body(response)
        self.assertEqual(data['election']['id'], self.election.id)
        self.assertEqual(data['election']['title'], "Eleição Diretoria Geral 2026")
        self.assertEqual(len(data['election']['questions']), 1)
        self.assertEqual(len(data['election']['questions'][0]['options']), 2)

        self.assertEqual(data['voter']['email'], "maria.silva@votaai.org")
        self.assertEqual(data['voter']['nickname'], "Maria")

        self.assertEqual(data['nonce'], self.default_nonce)
        self.assertTrue(data['attestation']['is_hardware_backed'])
        self.assertEqual(data['attestation']['security_level'], "StrongBox")
        self.assertTrue(data['attestation']['verified'])

        # Valida que a chave da máquina foi registrada no banco e falhas zeradas
        self.voting_token.refresh_from_db()
        self.assertEqual(self.voting_token.machine_public_key.strip(), self.device_public_pem.strip())
        self.assertEqual(self.voting_token.nonce, self.default_nonce)
        self.assertEqual(self.voting_token.failed_attempts, 0)

    def test_vote_request_nonce_replay_rejected(self):
        """
        Reutilizar o mesmo nonce já utilizado anteriormente deve ser rejeitado (anti-replay).
        """
        strongbox_cert = self._generate_mock_attestation_cert(security_level=2, challenge="nonce-anti-replay-999")
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [strongbox_cert],
            "nonce": "nonce-anti-replay-999"
        }
        body = self._encrypt_request_body(payload)

        # 1ª tentativa com sucesso
        res1 = self.client.post(self.url, data=body, format='json')
        self.assertEqual(res1.status_code, status.HTTP_200_OK)

        # 2ª tentativa com o MESMO nonce -> DEVE SER REJEITADA
        res2 = self.client.post(self.url, data=body, format='json')
        self.assertEqual(res2.status_code, status.HTTP_400_BAD_REQUEST)
        data2 = self._decrypt_response_body(res2)
        self.assertIn('nonce', data2)

    def test_vote_request_different_device_rejected(self):
        """
        Se o token já foi vinculado a um dispositivo, a tentativa de uso por outro dispositivo
        deve ser rejeitada e contabilizada como tentativa inválida.
        """
        # Vincula o token à primeira chave
        self.voting_token.machine_public_key = self.device_public_pem
        self.voting_token.save()

        # Gera segunda chave de um dispositivo invasor/diferente
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pub_pem = other_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        nonce_invader = "nonce-different-device-123"
        strongbox_cert = self._generate_mock_attestation_cert(security_level=2, challenge=nonce_invader)

        payload = {
            "token": self.raw_token,
            "machine_public_key": other_pub_pem,
            "attestation_certificates": [strongbox_cert],
            "nonce": nonce_invader
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # A resposta é cifrada de volta para a chave enviada no payload (other_key)
        enc_json = response.json()
        enc_aes_key = other_key.decrypt(base64.b64decode(enc_json["encrypted_aes_key"]), padding.PKCS1v15())
        aesgcm = AESGCM(enc_aes_key)
        decrypted = json.loads(aesgcm.decrypt(
            base64.b64decode(enc_json["iv"]),
            base64.b64decode(enc_json["encrypted_payload"]) + base64.b64decode(enc_json["tag"]),
            None
        ).decode('utf-8'))

        self.assertIn('machine_public_key', decrypted)

        # Verifica que contabilizou falha
        self.voting_token.refresh_from_db()
        self.assertEqual(self.voting_token.failed_attempts, 1)

    def test_vote_request_excessive_failed_attempts_locks_token(self):
        """
        Após 3 tentativas inválidas consecutivas, o token é bloqueado (is_blocked=True).
        """
        for i in range(3):
            # Envia tentativa inválida (challenge errado)
            bad_cert = self._generate_mock_attestation_cert(security_level=2, challenge="challenge-errado")
            payload = {
                "token": self.raw_token,
                "machine_public_key": self.device_public_pem,
                "attestation_certificates": [bad_cert],
                "nonce": f"nonce-tentativa-{i}"
            }
            body = self._encrypt_request_body(payload)
            res = self.client.post(self.url, data=body, format='json')
            self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

        self.voting_token.refresh_from_db()
        self.assertEqual(self.voting_token.failed_attempts, 3)
        self.assertTrue(self.voting_token.is_blocked)
        self.assertIsNotNone(self.voting_token.blocked_at)

        # 4ª tentativa mesmo com tudo correto deve ser rejeitada porque o token está bloqueado
        good_cert = self._generate_mock_attestation_cert(security_level=2, challenge="nonce-apos-bloqueio")
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [good_cert],
            "nonce": "nonce-apos-bloqueio"
        }
        res_blocked = self.client.post(self.url, data=self._encrypt_request_body(payload), format='json')
        self.assertEqual(res_blocked.status_code, status.HTTP_400_BAD_REQUEST)
        data = self._decrypt_response_body(res_blocked)
        self.assertIn("blocked", str(data.get("token")).lower())

    def test_vote_request_tee_level_accepted(self):
        """
        Solicita cédula com chave gerada em TEE (nível 1 - ARM TrustZone):
        Deve ser ACEITA com sucesso (200 OK), pois é hardware seguro.
        """
        nonce = "nonce-tee-test"
        tee_cert = self._generate_mock_attestation_cert(security_level=1, challenge=nonce)
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [tee_cert],
            "nonce": nonce
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = self._decrypt_response_body(response)
        self.assertIn('election', data)
        self.assertEqual(data['election']['title'], self.election.title)
        self.assertEqual(data['attestation']['security_level'], 'TrustedEnvironment')
        self.assertTrue(data['attestation']['is_hardware_backed'])

    def test_vote_request_software_level_rejected(self):
        """
        Solicita cédula com chave gerada em Software (nível 0):
        Deve ser REJEITADA.
        """
        nonce = "nonce-soft-test"
        software_cert = self._generate_mock_attestation_cert(security_level=0, challenge=nonce)
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [software_cert],
            "nonce": nonce
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = self._decrypt_response_body(response)
        self.assertIn('attestation_certificates', data)

    def test_vote_request_missing_attestation_certificates_rejected(self):
        """
        Solicitação sem certificados de atestação deve ser REJEITADA (obrigatório StrongBox).
        """
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "nonce": "nonce-sem-cert"
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = self._decrypt_response_body(response)
        self.assertIn('attestation_certificates', data)

    def test_vote_request_invalid_token_returns_400(self):
        """Token inexistente retorna erro 400."""
        nonce = "nonce-invalid-token"
        strongbox_cert = self._generate_mock_attestation_cert(security_level=2, challenge=nonce)
        payload = {
            "token": "token-totalmente-invalido-999",
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [strongbox_cert],
            "nonce": nonce
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = self._decrypt_response_body(response)
        self.assertIn('token', data)

    def test_vote_request_already_consumed_token_returns_400(self):
        """Token já utilizado (is_used=True) é rejeitado."""
        self.voting_token.is_used = True
        self.voting_token.save()

        nonce = "nonce-token-used"
        strongbox_cert = self._generate_mock_attestation_cert(security_level=2, challenge=nonce)
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [strongbox_cert],
            "nonce": nonce
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = self._decrypt_response_body(response)
        self.assertIn('token', data)

    def test_vote_request_election_not_started_returns_400(self):
        """Eleição que ainda não foi iniciada (CREATED) não permite solicitar voto."""
        self.election.status = ElectionStatus.CREATED
        self.election.save()

        nonce = "nonce-elec-created"
        strongbox_cert = self._generate_mock_attestation_cert(security_level=2, challenge=nonce)
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [strongbox_cert],
            "nonce": nonce
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = self._decrypt_response_body(response)
        self.assertIn('election', data)

    def test_vote_request_voter_already_voted_returns_400(self):
        """Eleitor que já consta com has_voted=True é rejeitado."""
        self.voter.has_voted = True
        self.voter.save()

        nonce = "nonce-already-voted"
        strongbox_cert = self._generate_mock_attestation_cert(security_level=2, challenge=nonce)
        payload = {
            "token": self.raw_token,
            "machine_public_key": self.device_public_pem,
            "attestation_certificates": [strongbox_cert],
            "nonce": nonce
        }
        body = self._encrypt_request_body(payload)

        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = self._decrypt_response_body(response)
        self.assertIn('voter', data)
