import os
import json
import base64
import struct
from pathlib import Path
from django.conf import settings
from django.urls import reverse
from django.contrib.auth.models import Group
from rest_framework.test import APITestCase
from rest_framework import status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

from Domain.models.schemas.moderation.userSchema import User
from Domain.models.groupChoices import GroupRoles
from Infrastructure.services.totpService import TOTPService
from Infrastructure.services.seCryptoService import SECryptoService

class AuthLoginTests(APITestCase):
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

        # Gera par de chaves RSA simulando a máquina do cliente Desktop
        self.machine_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.machine_public_pem = self.machine_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.device_id = "dev-test-login-machine"
        self.admin_email = "admin.login@votaai.org"
        self.password = "StrongAdminPass123!"

        # Cria grupo Administrador caso não exista
        self.admin_group, _ = Group.objects.get_or_create(name=GroupRoles.ADMIN.value)

        # Usuário Admin com 2FA e máquina vinculada
        self.totp_secret = TOTPService.generate_secret()
        self.admin_user = User.objects.create_user(
            username=self.admin_email,
            email=self.admin_email,
            password=self.password,
            is_active=True,
            machine_public_key=self.machine_public_pem,
            machine_user=self.device_id,
            totp_secret=self.totp_secret
        )
        self.admin_user.groups.add(self.admin_group)

        # Usuário comum sem 2FA
        self.regular_email = "regular.user@votaai.org"
        self.regular_password = "RegularPass123!"
        self.regular_user = User.objects.create_user(
            username=self.regular_email,
            email=self.regular_email,
            password=self.regular_password,
            is_active=True
        )

        self.url_login = reverse('auth-login')

    def _sign_payload(self, payload_dict: dict, private_key=None) -> str:
        """Assina o payload canônico em formato JSON estrito usando RSA-PSS."""
        key = private_key or self.machine_private_key
        canonical_dict = {k: v for k, v in payload_dict.items() if k != 'signature'}
        canonical_bytes = json.dumps(
            canonical_dict,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False
        ).encode('utf-8')
        sig_bytes = key.sign(
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(sig_bytes).decode('utf-8')

    def _encrypt_request_body(self, payload_dict: dict) -> dict:
        payload_copy = dict(payload_dict)
        if 'machine_public_key' not in payload_copy:
            payload_copy['machine_public_key'] = self.machine_public_pem

        json_bytes = json.dumps(payload_copy).encode('utf-8')
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
            "client_public_key": self.machine_public_pem
        }

    def _decrypt_response_body(self, response) -> dict:
        enc_json = response.json()
        self.assertIn("encrypted_payload", enc_json)
        self.assertIn("encrypted_aes_key", enc_json)

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

    def test_login_success_with_valid_totp_and_signature(self):
        totp_code = TOTPService.generate_totp(self.totp_secret)
        payload = {
            "username": self.admin_email,
            "password": self.password,
            "totp_code": totp_code,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        payload["signature"] = self._sign_payload(payload)

        enc_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_login, enc_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("token", resp_data)
        self.assertIn("user", resp_data)
        self.assertEqual(resp_data["user"]["email"], self.admin_email)

    def test_login_fails_with_invalid_totp(self):
        invalid_totp = "000000"
        payload = {
            "username": self.admin_email,
            "password": self.password,
            "totp_code": invalid_totp,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        payload["signature"] = self._sign_payload(payload)

        enc_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_login, enc_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("totp_code", resp_data)

    def test_login_fails_with_missing_totp_when_required(self):
        payload = {
            "username": self.admin_email,
            "password": self.password,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }

        enc_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_login, enc_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("totp_code", resp_data)

    def test_login_fails_with_invalid_signature(self):
        totp_code = TOTPService.generate_totp(self.totp_secret)
        # Assina com outra chave privada não cadastrada
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        payload = {
            "username": self.admin_email,
            "password": self.password,
            "totp_code": totp_code,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        payload["signature"] = self._sign_payload(payload, private_key=rogue_key)

        enc_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_login, enc_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("signature", resp_data)

    def test_login_fails_with_unauthorized_machine(self):
        totp_code = TOTPService.generate_totp(self.totp_secret)
        payload = {
            "username": self.admin_email,
            "password": self.password,
            "totp_code": totp_code,
            "device_id": "rogue-unauthorized-machine-id",
            "machine_public_key": self.machine_public_pem
        }
        payload["signature"] = self._sign_payload(payload)

        enc_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_login, enc_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("device_id", resp_data)

    def test_login_regular_user_without_totp_succeeds(self):
        payload = {
            "username": self.regular_email,
            "password": self.regular_password,
            "machine_public_key": self.machine_public_pem
        }

        enc_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_login, enc_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("token", resp_data)
        self.assertIn("user", resp_data)
        self.assertEqual(resp_data["user"]["email"], self.regular_email)

