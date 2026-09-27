import os
import json
import base64
import struct
from pathlib import Path
from django.conf import settings
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

from django.core import mail
from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
from Domain.models.schemas.moderation.userSchema import User

class ElectionAvailableAndStartTests(APITestCase):
    def setUp(self):
        base_dir = getattr(settings, 'BASE_DIR', Path.cwd())
        keys_path = os.path.join(base_dir, 'se_keys_info.json')
        self.client_key_file = os.path.join(base_dir, 'desktop_public_key.txt')

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

        # Gera par de chaves RSA da máquina cliente
        self.machine_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.machine_public_pem = self.machine_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.client_key_file = os.path.join(base_dir, 'desktop_public_key.txt')
        self._original_client_key_content = None
        if os.path.exists(self.client_key_file):
            try:
                with open(self.client_key_file, 'r', encoding='utf-8') as f:
                    self._original_client_key_content = f.read()
            except Exception:
                pass

        # Salva chave do cliente para o middleware
        with open(self.client_key_file, 'w', encoding='utf-8') as f:
            f.write(self.machine_public_pem)

        # Cria usuário associado à máquina
        self.user = User.objects.create_user(
            username='admin.machine@votaai.org',
            email='admin.machine@votaai.org',
            password='Password123!',
            is_active=True,
            machine_public_key=self.machine_public_pem.strip()
        )

        # Chave da eleição
        self.election_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.election_public_pem = self.election_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.key_handle = "test_election_handle_123"

        # Cria eleição CREATED sem start_datetime
        self.election = Election.objects.create(
            title="Eleição Teste Disponível",
            public_key=self.election_public_pem,
            key_handle=self.key_handle,
            status=ElectionStatus.CREATED,
            created_by=self.user
        )

        self.voter = ElectoralCollege.objects.create(
            election=self.election,
            full_name="Carlos Alberto Silva",
            email="carlos.silva@votaai.org",
        )

        self.url_available = reverse('election-available')
        self.url_start = reverse('election-start')

    def tearDown(self):
        if self._original_client_key_content is not None:
            try:
                with open(self.client_key_file, 'w', encoding='utf-8') as f:
                    f.write(self._original_client_key_content)
            except Exception:
                pass
        elif os.path.exists(self.client_key_file):
            try:
                os.remove(self.client_key_file)
            except Exception:
                pass

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

    def test_fetch_available_elections_returns_matching_nonce_and_elections(self):
        nonce = "test-nonce-12345"
        payload = {
            "msg": "FETCH_AVAILABLE",
            "nonceClient1": nonce
        }
        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_available, data=enc_body, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        decrypted_resp = self._decrypt_response_body(response)
        self.assertEqual(decrypted_resp.get("nonceClient1"), nonce)
        self.assertIn("elections", decrypted_resp)
        self.assertEqual(len(decrypted_resp["elections"]), 1)
        self.assertEqual(decrypted_resp["elections"][0]["keyHandle"], self.key_handle)
        self.assertEqual(decrypted_resp["elections"][0]["titulo"], "Eleição Teste Disponível")

    def test_election_creation_without_user_fails_atomically(self):
        with self.assertRaises(ValueError):
            Election.objects.create(
                title="Eleição Sem Criador Explícito",
                public_key=self.election_public_pem,
                key_handle="unassigned_handle_999",
                status=ElectionStatus.CREATED,
                created_by=None
            )

    def test_fetch_available_elections_strictly_filters_by_user(self):
        other_user = User.objects.create_user(
            username='other.admin@votaai.org',
            email='other.admin@votaai.org',
            password='Password123!',
            is_active=True,
            machine_public_key="other_key_pem"
        )
        Election.objects.create(
            title="Eleição De Outro Usuário",
            public_key=self.election_public_pem,
            key_handle="other_handle_999",
            status=ElectionStatus.CREATED,
            created_by=other_user
        )
        nonce = "test-nonce-strict"
        payload = {
            "msg": "FETCH_AVAILABLE",
            "nonceClient1": nonce
        }
        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_available, data=enc_body, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        decrypted_resp = self._decrypt_response_body(response)
        titles = [e["titulo"] for e in decrypted_resp.get("elections", [])]
        self.assertNotIn("Eleição De Outro Usuário", titles)
        self.assertIn("Eleição Teste Disponível", titles)

    def test_start_election_flow_success(self):
        nonce = "test-nonce-67890"
        payload = {
            "msg": "START_ELECTION",
            "keyHandle": self.key_handle,
            "nonceClient2": nonce
        }
        # Assina com chave da eleição
        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        sig_bytes = self.election_private_key.sign(
            payload_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        payload["election_signature"] = base64.b64encode(sig_bytes).decode('utf-8')

        enc_body = self._encrypt_request_body(payload)
        response = self.client.post(self.url_start, data=enc_body, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        decrypted_resp = self._decrypt_response_body(response)
        self.assertEqual(decrypted_resp.get("nonceClient2"), nonce)
        self.assertIn("hora_registrada", decrypted_resp)

        self.election.refresh_from_db()
        self.assertEqual(self.election.status, ElectionStatus.STARTED)
        self.assertIsNotNone(self.election.start_datetime)

        # Valida que o e-mail de votação foi disparado com o botão HTML, nome e apelido corretos
        self.voter.refresh_from_db()
        self.assertTrue(self.voter.email_sent)
        self.assertEqual(self.voter.nickname, "Carlos")  # Apelido é estritamente o primeiro nome

        self.assertEqual(len(mail.outbox), 1)
        sent_mail = mail.outbox[0]
        self.assertIn("Carlos Alberto Silva", sent_mail.to[0])
        self.assertIn("carlos.silva@votaai.org", sent_mail.to[0])
        self.assertIn("Olá, Carlos Alberto Silva!", sent_mail.body)

        # Valida que o HTML contém o botão estilizado com o link para votação
        html_alternatives = [content for content, mimetype in getattr(sent_mail, 'alternatives', []) if mimetype == 'text/html']
        self.assertTrue(len(html_alternatives) > 0)
        html_content = html_alternatives[0]
        self.assertIn("Acessar Cédula de Votação", html_content)
        self.assertIn("/votar/?token=", html_content)
        self.assertIn("Olá, <strong>Carlos Alberto Silva</strong>!", html_content)
        self.assertIn("Caso o botão não funcione, por favor entre em contato por e-mail.", html_content)
        self.assertIn("acessar a página de divulgação", html_content)
        self.assertNotIn("Se você não solicitou este e-mail", html_content)
        self.assertNotIn("Se você não solicitou este e-mail", sent_mail.body)
