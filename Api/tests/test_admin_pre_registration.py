import os
import re
import json
import base64
import struct
from datetime import timedelta
from pathlib import Path
from django.conf import settings
from django.core import mail
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

from Domain.models.schemas.moderation.userSchema import User
from Domain.models.groupChoices import GroupRoles
from Infrastructure.services.totpService import TOTPService
from Infrastructure.services.seCryptoService import SECryptoService

class AdminPreRegistrationTests(APITestCase):
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

        # Gera chave RSA da máquina do cliente (Desktop)
        self.machine_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.machine_public_pem = self.machine_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.device_id = "dev-test-suite-machine"
        self.url_start = reverse('admin-pre-registration-start')
        self.url_verify_email = reverse('admin-pre-registration-verify-email')
        self.url_resend_email = reverse('admin-pre-registration-resend-email')
        self.url_confirm = reverse('admin-pre-registration-confirm')

    def _extract_verification_code(self, email_address: str) -> str:
        """Extrai o código de 6 dígitos enviado no último e-mail da outbox para o destinatário."""
        for message in reversed(mail.outbox):
            if email_address in message.to:
                match = re.search(r'\b(\d{6})\b', message.body)
                if match:
                    return match.group(1)
        self.fail(f"Código de verificação não encontrado na outbox para {email_address}")

    def _verify_email_for_user(self, email: str, device_id: str | None = None) -> dict:
        """Helper para executar a etapa de verificação de e-mail nos testes."""
        code = self._extract_verification_code(email)
        req_verify = {
            "email": email,
            "verification_code": code,
            "device_id": device_id or self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_verify["signature"] = self._sign_payload(req_verify)
        response = self.client.post(
            self.url_verify_email,
            data=self._encrypt_request_body(req_verify),
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return self._decrypt_response_body(response)

    def _sign_payload(self, payload_dict: dict) -> str:
        """Gera a assinatura canônica RSA-PSS do payload para simular o hardware TPM."""
        canonical_dict = {k: v for k, v in payload_dict.items() if k != 'signature'}
        canonical_bytes = json.dumps(
            canonical_dict,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False
        ).encode('utf-8')
        sig_bytes = self.machine_private_key.sign(
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(sig_bytes).decode('utf-8')

    def _encrypt_request_body(self, payload_dict: dict) -> dict:
        """Helper para simular o cliente Desktop cifrando a requisição com Sign-then-Encrypt."""
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
        """Helper para simular o cliente Desktop descriptografando a resposta do servidor com a chave privada da máquina."""
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

        from Infrastructure.services.seCryptoService import SECryptoService
        decrypted_bytes = SECryptoService.unpad_iso7816_4(aesgcm.decrypt(iv, ciphertext + tag, None))
        return json.loads(decrypted_bytes.decode('utf-8'))

    def test_full_admin_pre_registration_flow_success(self):
        """
        Testa o fluxo completo de pré-cadastro com verificação de e-mail:
        1. Desktop -> API: email, senha, chave_publica_maquina, device_id (cifrado) -> envia código por e-mail
        2. Desktop -> API: email, verification_code, assinatura da máquina -> valida código e retorna provisioning_uri (TOTP)
        3. Desktop -> API: email, totp_code, assinatura da máquina -> ativa usuário com role Administrador.
        """
        admin_email = "admin.electoral@votaai.org"
        admin_pass = "SenhaUltraSegura!2026"

        # -------------------------------------------------------------
        # ETAPA 1: Iniciar pré-cadastro (envia código de verificação por e-mail)
        # -------------------------------------------------------------
        req_step1 = {
            "email": admin_email,
            "password": admin_pass,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step1["signature"] = self._sign_payload(req_step1)
        body_step1 = self._encrypt_request_body(req_step1)
        response_step1 = self.client.post(self.url_start, data=body_step1, format='json')
        self.assertEqual(response_step1.status_code, status.HTTP_200_OK)

        resp_step1 = self._decrypt_response_body(response_step1)
        self.assertIn("message", resp_step1)
        self.assertIn("signature", resp_step1)
        self.assertNotIn("provisioning_uri", resp_step1)

        server_sig_valid_step1 = SECryptoService.verify_signature(
            self.backend_public_key,
            resp_step1["message"].encode('utf-8'),
            resp_step1["signature"]
        )
        self.assertTrue(server_sig_valid_step1, "Assinatura do servidor no passo 1 é inválida!")

        # Valida o estado no modelo User antes da verificação de e-mail
        user = User.objects.filter(email=admin_email).first()
        self.assertIsNotNone(user)
        self.assertFalse(user.is_active, "Usuário deveria estar inativo até a confirmação final.")
        self.assertFalse(user.email_verified, "E-mail ainda não deveria estar verificado.")
        self.assertEqual(user.machine_public_key, self.machine_public_pem.strip())
        self.assertIsNone(user.totp_secret)

        # -------------------------------------------------------------
        # ETAPA 2: Verificar e-mail com código de 6 dígitos
        # -------------------------------------------------------------
        resp_step2 = self._verify_email_for_user(admin_email)
        self.assertIn("message", resp_step2)
        self.assertIn("provisioning_uri", resp_step2)
        self.assertIn("signature", resp_step2)

        provisioning_uri = resp_step2["provisioning_uri"]
        message_step2 = resp_step2["message"]
        data_signed_by_server = f"{message_step2}:{provisioning_uri}".encode('utf-8')
        server_sig_valid_step2 = SECryptoService.verify_signature(
            self.backend_public_key,
            data_signed_by_server,
            resp_step2["signature"]
        )
        self.assertTrue(server_sig_valid_step2, "Assinatura do servidor no passo 2 é inválida!")

        user.refresh_from_db()
        self.assertTrue(user.email_verified)
        self.assertIsNotNone(user.totp_secret)
        self.assertIsNone(user.email_verification_code_hash)

        # -------------------------------------------------------------
        # ETAPA 3: Confirmar pré-cadastro com TOTP e Assinatura da Máquina
        # -------------------------------------------------------------
        totp_code = TOTPService.generate_totp(user.totp_secret)

        req_step3 = {
            "email": admin_email,
            "totp_code": totp_code,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step3["signature"] = self._sign_payload(req_step3)

        body_step3 = self._encrypt_request_body(req_step3)
        response_step3 = self.client.post(self.url_confirm, data=body_step3, format='json')
        self.assertEqual(response_step3.status_code, status.HTTP_200_OK)

        resp_step4 = self._decrypt_response_body(response_step3)
        self.assertIn("message", resp_step4)
        self.assertIn("signature", resp_step4)

        message_step4 = resp_step4["message"]
        server_sig_valid_step4 = SECryptoService.verify_signature(
            self.backend_public_key,
            message_step4.encode('utf-8'),
            resp_step4["signature"]
        )
        self.assertTrue(server_sig_valid_step4, "Assinatura do servidor no passo 3 é inválida!")

        user.refresh_from_db()
        self.assertTrue(user.is_active, "Usuário deveria estar ativo após a confirmação TOTP!")
        self.assertTrue(user.groups.filter(name=GroupRoles.ADMIN.value).exists(), "Usuário deve pertencer ao grupo Administrador!")

    def test_confirm_with_invalid_totp_fails(self):
        """Valida que código TOTP incorreto rejeita a confirmação com erro 400."""
        admin_email = "admin.totpfail@votaai.org"
        req_step1 = {
            "email": admin_email,
            "password": "SenhaValida123!",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step1["signature"] = self._sign_payload(req_step1)
        self.client.post(self.url_start, data=self._encrypt_request_body(req_step1), format='json')
        self._verify_email_for_user(admin_email)

        invalid_totp = "000000"

        req_step3 = {
            "email": admin_email,
            "totp_code": invalid_totp,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step3["signature"] = self._sign_payload(req_step3)

        response = self.client.post(self.url_confirm, data=self._encrypt_request_body(req_step3), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_data = self._decrypt_response_body(response)
        self.assertIn("totp_code", resp_data)

    def test_confirm_with_invalid_machine_signature_fails(self):
        """Valida que assinatura da máquina forjada/inválida rejeita a confirmação com erro 400."""
        admin_email = "admin.sigfail@votaai.org"
        req_step1 = {
            "email": admin_email,
            "password": "SenhaValida123!",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step1["signature"] = self._sign_payload(req_step1)
        self.client.post(self.url_start, data=self._encrypt_request_body(req_step1), format='json')
        self._verify_email_for_user(admin_email)

        user = User.objects.get(email=admin_email)
        totp_code = TOTPService.generate_totp(user.totp_secret)

        # Assina com outra chave privada que NÃO é a chave pública registrada
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        req_step3 = {
            "email": admin_email,
            "totp_code": totp_code,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        canonical_json = json.dumps(req_step3, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        forged_sig = other_key.sign(
            canonical_json.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        req_step3["signature"] = base64.b64encode(forged_sig).decode('utf-8')

        response = self.client.post(self.url_confirm, data=self._encrypt_request_body(req_step3), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_data = self._decrypt_response_body(response)
        self.assertIn("signature", resp_data)

    def test_pre_registration_with_already_active_user_fails(self):
        """Valida que tentar pré-cadastrar um e-mail de usuário já ativo retorna erro 400."""
        active_email = "active.admin@votaai.org"
        User.objects.create_user(
            username=active_email,
            email=active_email,
            password="SenhaExistente123",
            is_active=True
        )

        req = {
            "email": active_email,
            "password": "NovaSenha123!",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req["signature"] = self._sign_payload(req)
        response = self.client.post(self.url_start, data=self._encrypt_request_body(req), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_data = self._decrypt_response_body(response)
        self.assertIn("email", resp_data)

    def test_pre_registration_with_weak_password_fails(self):
        """Valida que senhas sem caracteres especiais, números ou maiúsculas são rejeitadas."""
        weak_passwords = [
            "senhafraca",          # sem maiúscula, número, caractere especial
            "SenhaFracaSemNum",    # sem número, caractere especial
            "Senha123",            # sem caractere especial
            "12345678!",           # sem letras
            "Aa1!",                # tamanho < 8
        ]

        for weak_pass in weak_passwords:
            req = {
                "email": f"teste.{abs(hash(weak_pass))}@votaai.org",
                "password": weak_pass,
                "device_id": self.device_id,
                "machine_public_key": self.machine_public_pem
            }
            req["signature"] = self._sign_payload(req)
            response = self.client.post(self.url_start, data=self._encrypt_request_body(req), format='json')
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                f"A senha fraca '{weak_pass}' deveria ter sido rejeitada com status 400!"
            )
            resp_data = self._decrypt_response_body(response)
            self.assertIn("password", resp_data)

    def test_pre_registration_with_same_machine_user_fails(self):
        """Valida que tentar pré-cadastrar outro admin para a mesma máquina física (device_id) retorna erro 400."""
        existing_admin_email = "existing.machine.admin@votaai.org"
        
        # Cria admin ativo vinculado a esse device_id
        User.objects.create_user(
            username=existing_admin_email,
            email=existing_admin_email,
            password="SenhaExistente123!",
            is_active=True,
            device_id=self.device_id
        )

        req = {
            "email": "intruder.admin@votaai.org",
            "password": "OutraSenhaForte!123",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req["signature"] = self._sign_payload(req)
        response = self.client.post(
            self.url_start,
            data=self._encrypt_request_body(req),
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_data = self._decrypt_response_body(response)
        self.assertIn("device_id", resp_data)

    def test_pre_registration_without_machine_user_fails(self):
        """Valida que tentar pré-cadastrar sem identificador de máquina (device_id) retorna erro 400."""
        req = {
            "email": "no.machine@votaai.org",
            "password": "SenhaValida123!",
            "machine_public_key": self.machine_public_pem
        }
        req["signature"] = self._sign_payload(req)
        response = self.client.post(self.url_start, data=self._encrypt_request_body(req), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("device_id", resp_data)

    def test_desktop_real_client_flow_success(self):
        """
        Valida o fluxo exato realizado pelo VotaAI Desktop:
        O Desktop inclui machine_public_key e device_id no payload ANTES de gerar
        a assinatura canônica RSA-PSS, e depois cifra o envelope com AES-GCM + RSA do TPM.
        """
        admin_email = "real.desktop@votaai.org"
        password = "SenhaSuperSegura123!"
        device_id = "dev-desktop-hw-test"

        # 1. Payload montado pelo AuthController do Desktop
        desktop_start_payload = {
            "email": admin_email,
            "password": password,
            "device_id": device_id,
            "machine_public_key": self.machine_public_pem
        }

        # 2. Canonical JSON assinado pelo EncryptionController do Desktop
        canonical_json = json.dumps(desktop_start_payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        envelope_sig = self.machine_private_key.sign(
            canonical_json.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        desktop_start_payload["signature"] = base64.b64encode(envelope_sig).decode('utf-8')

        # 3. Cifra com chave do TPM do servidor
        req_step1 = self._encrypt_request_body(desktop_start_payload)
        response_step1 = self.client.post(self.url_start, data=req_step1, format='json')
        self.assertEqual(response_step1.status_code, status.HTTP_200_OK)

        resp_data1 = self._decrypt_response_body(response_step1)
        self.assertIn("message", resp_data1)

        # 3.5. Verificação de e-mail
        resp_verify = self._verify_email_for_user(admin_email, device_id=device_id)
        self.assertIn("provisioning_uri", resp_verify)

        # 4. Confirmação com TOTP
        user = User.objects.get(email=admin_email)
        totp_code = TOTPService.generate_totp(user.totp_secret)

        confirm_payload = {
            "email": admin_email,
            "totp_code": totp_code,
            "device_id": device_id,
            "machine_public_key": self.machine_public_pem
        }
        canonical_confirm = json.dumps(confirm_payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        confirm_sig = self.machine_private_key.sign(
            canonical_confirm.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        confirm_payload["signature"] = base64.b64encode(confirm_sig).decode('utf-8')

        req_step2 = self._encrypt_request_body(confirm_payload)
        response_step2 = self.client.post(self.url_confirm, data=req_step2, format='json')
        self.assertEqual(response_step2.status_code, status.HTTP_200_OK)

        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertTrue(user.groups.filter(name=GroupRoles.ADMIN.value).exists())

    def test_confirm_without_email_verification_fails(self):
        """Valida que tentar confirmar o pré-cadastro sem verificar o e-mail retorna erro 400."""
        admin_email = "unverified.admin@votaai.org"
        req_step1 = {
            "email": admin_email,
            "password": "SenhaValida123!",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step1["signature"] = self._sign_payload(req_step1)
        self.client.post(self.url_start, data=self._encrypt_request_body(req_step1), format='json')

        req_confirm = {
            "email": admin_email,
            "totp_code": "123456",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_confirm["signature"] = self._sign_payload(req_confirm)

        response = self.client.post(self.url_confirm, data=self._encrypt_request_body(req_confirm), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("email", resp_data)

    def test_verify_email_with_invalid_code_fails(self):
        """Valida que código de verificação de e-mail incorreto retorna 400 e incrementa tentativas."""
        admin_email = "invalid.code@votaai.org"
        req_step1 = {
            "email": admin_email,
            "password": "SenhaValida123!",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step1["signature"] = self._sign_payload(req_step1)
        self.client.post(self.url_start, data=self._encrypt_request_body(req_step1), format='json')

        req_verify = {
            "email": admin_email,
            "verification_code": "999999",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_verify["signature"] = self._sign_payload(req_verify)
        response = self.client.post(self.url_verify_email, data=self._encrypt_request_body(req_verify), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("verification_code", resp_data)

        user = User.objects.get(email=admin_email)
        self.assertFalse(user.email_verified)
        self.assertEqual(user.email_verification_attempts, 1)

    def test_verify_email_with_expired_code_fails(self):
        """Valida que código de verificação expirado retorna erro 400."""
        admin_email = "expired.code@votaai.org"
        req_step1 = {
            "email": admin_email,
            "password": "SenhaValida123!",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step1["signature"] = self._sign_payload(req_step1)
        self.client.post(self.url_start, data=self._encrypt_request_body(req_step1), format='json')

        code = self._extract_verification_code(admin_email)
        User.objects.filter(email=admin_email).update(
            email_verification_expires_at=timezone.now() - timedelta(minutes=1)
        )

        req_verify = {
            "email": admin_email,
            "verification_code": code,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_verify["signature"] = self._sign_payload(req_verify)
        response = self.client.post(self.url_verify_email, data=self._encrypt_request_body(req_verify), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_data = self._decrypt_response_body(response)
        self.assertIn("verification_code", resp_data)

    def test_verify_email_max_attempts_and_resend_success(self):
        """Valida bloqueio após 5 tentativas inválidas e desbloqueio ao reenviar novo código."""
        admin_email = "resend.code@votaai.org"
        req_step1 = {
            "email": admin_email,
            "password": "SenhaValida123!",
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_step1["signature"] = self._sign_payload(req_step1)
        self.client.post(self.url_start, data=self._encrypt_request_body(req_step1), format='json')

        first_code = self._extract_verification_code(admin_email)
        wrong_code = "000000" if first_code != "000000" else "111111"

        for _ in range(5):
            req_bad = {
                "email": admin_email,
                "verification_code": wrong_code,
                "device_id": self.device_id,
                "machine_public_key": self.machine_public_pem
            }
            req_bad["signature"] = self._sign_payload(req_bad)
            resp = self.client.post(self.url_verify_email, data=self._encrypt_request_body(req_bad), format='json')
            self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

        # Mesmo com o código correto, deve falhar por exceder tentativas
        req_blocked = {
            "email": admin_email,
            "verification_code": first_code,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_blocked["signature"] = self._sign_payload(req_blocked)
        resp_blocked = self.client.post(self.url_verify_email, data=self._encrypt_request_body(req_blocked), format='json')
        self.assertEqual(resp_blocked.status_code, status.HTTP_400_BAD_REQUEST)

        # Reenvia novo código
        req_resend = {
            "email": admin_email,
            "device_id": self.device_id,
            "machine_public_key": self.machine_public_pem
        }
        req_resend["signature"] = self._sign_payload(req_resend)
        resp_resend = self.client.post(self.url_resend_email, data=self._encrypt_request_body(req_resend), format='json')
        self.assertEqual(resp_resend.status_code, status.HTTP_200_OK)

        # Agora verifica com o novo código
        resp_verify = self._verify_email_for_user(admin_email)
        self.assertIn("provisioning_uri", resp_verify)




