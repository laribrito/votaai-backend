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

from Domain.models.schemas.moderation.userSchema import User
from Domain.models.groupChoices import GroupRoles
from Infrastructure.services.totpService import TOTPService
from Infrastructure.services.seCryptoService import SECryptoService

class AdminPreCadastroTests(APITestCase):
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

        # Gera chave RSA da máquina do cliente (Desktop)
        self.machine_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.machine_public_pem = self.machine_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.url_iniciar = reverse('admin-pre-cadastro-iniciar')
        self.url_confirmar = reverse('admin-pre-cadastro-confirmar')

    def tearDown(self):
        if os.path.exists(self.client_key_file):
            os.remove(self.client_key_file)

    def _encrypt_request_body(self, payload_dict: dict) -> dict:
        """Helper para simular o cliente Desktop cifrando a requisição com a chave do TPM do servidor."""
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
            "client_public_key": self.machine_public_pem
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

        decrypted_bytes = aesgcm.decrypt(iv, ciphertext + tag, None)
        return json.loads(decrypted_bytes.decode('utf-8'))

    def test_full_admin_pre_cadastro_flow_success(self):
        """
        Testa o fluxo completo de pré-cadastro e confirmação conforme o diagrama de sequência:
        1. Desktop -> API: email, senha, chave_publica_maquina (cifrado)
        2. API -> Desktop: mensagem, uri_provisionamento (assinado com TPM, cifrado para a máquina)
        3. Desktop -> API: email, codigo_totp (assinado com a máquina, cifrado para o servidor)
        4. API -> Desktop: mensagem (assinado com TPM, cifrado para a máquina), ativa usuário com role Administrador.
        """
        admin_email = "admin.electoral@votaai.org"
        admin_pass = "SenhaUltraSegura!2026"

        # -------------------------------------------------------------
        # ETAPA 1 & 2: Iniciar pré-cadastro
        # -------------------------------------------------------------
        req_step1 = {
            "email": admin_email,
            "senha": admin_pass,
            "chave_publica_maquina": self.machine_public_pem
        }
        body_step1 = self._encrypt_request_body(req_step1)
        response_step1 = self.client.post(self.url_iniciar, data=body_step1, format='json')
        self.assertEqual(response_step1.status_code, status.HTTP_200_OK)

        resp_step2 = self._decrypt_response_body(response_step1)
        self.assertIn("mensagem", resp_step2)
        self.assertIn("uri_provisionamento", resp_step2)
        self.assertIn("assinatura", resp_step2)

        # Valida a assinatura digital do TPM do servidor
        uri_provisionamento = resp_step2["uri_provisionamento"]
        mensagem_step2 = resp_step2["mensagem"]
        data_signed_by_server = f"{mensagem_step2}:{uri_provisionamento}".encode('utf-8')
        server_sig_valid = SECryptoService.verify_signature(
            self.backend_public_key,
            data_signed_by_server,
            resp_step2["assinatura"]
        )
        self.assertTrue(server_sig_valid, "Assinatura do servidor no passo 2 é inválida!")

        # Valida o estado no modelo User
        user = User.objects.filter(email=admin_email).first()
        self.assertIsNotNone(user)
        self.assertFalse(user.is_active, "Usuário deveria estar inativo até a confirmação TOTP.")
        self.assertEqual(user.chave_publica_maquina, self.machine_public_pem.strip())
        self.assertIsNotNone(user.totp_secret)

        # -------------------------------------------------------------
        # ETAPA 3 & 4: Confirmar pré-cadastro com TOTP e Assinatura da Máquina
        # -------------------------------------------------------------
        # Desktop gera o código TOTP a partir do segredo provisionado
        totp_code = TOTPService.generate_totp(user.totp_secret)

        # Desktop assina a confirmação com a chave privada da máquina física
        data_to_sign_by_machine = f"{admin_email}:{totp_code}".encode('utf-8')
        machine_signature_bytes = self.machine_private_key.sign(
            data_to_sign_by_machine,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        machine_signature_b64 = base64.b64encode(machine_signature_bytes).decode('utf-8')

        req_step3 = {
            "email": admin_email,
            "codigo_totp": totp_code,
            "assinatura": machine_signature_b64
        }
        body_step3 = self._encrypt_request_body(req_step3)
        response_step3 = self.client.post(self.url_confirmar, data=body_step3, format='json')
        self.assertEqual(response_step3.status_code, status.HTTP_200_OK)

        resp_step4 = self._decrypt_response_body(response_step3)
        self.assertIn("mensagem", resp_step4)
        self.assertIn("assinatura", resp_step4)

        # Valida a assinatura digital do servidor no passo 4
        mensagem_step4 = resp_step4["mensagem"]
        server_sig_valid_step4 = SECryptoService.verify_signature(
            self.backend_public_key,
            mensagem_step4.encode('utf-8'),
            resp_step4["assinatura"]
        )
        self.assertTrue(server_sig_valid_step4, "Assinatura do servidor no passo 4 é inválida!")

        # Valida ativação e role no modelo User
        user.refresh_from_db()
        self.assertTrue(user.is_active, "Usuário deveria estar ativo após a confirmação TOTP!")
        self.assertTrue(user.groups.filter(name=GroupRoles.ADMIN.value).exists(), "Usuário deve pertencer ao grupo Administrador!")

    def test_confirm_with_invalid_totp_fails(self):
        """Valida que código TOTP incorreto rejeita a confirmação com erro 400."""
        admin_email = "admin.totpfail@votaai.org"
        req_step1 = {
            "email": admin_email,
            "senha": "SenhaValida123!",
            "chave_publica_maquina": self.machine_public_pem
        }
        self.client.post(self.url_iniciar, data=self._encrypt_request_body(req_step1), format='json')

        user = User.objects.get(email=admin_email)
        invalid_totp = "000000"

        data_to_sign = f"{admin_email}:{invalid_totp}".encode('utf-8')
        sig_bytes = self.machine_private_key.sign(data_to_sign, padding.PKCS1v15(), hashes.SHA256())

        req_step3 = {
            "email": admin_email,
            "codigo_totp": invalid_totp,
            "assinatura": base64.b64encode(sig_bytes).decode('utf-8')
        }
        response = self.client.post(self.url_confirmar, data=self._encrypt_request_body(req_step3), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_data = self._decrypt_response_body(response)
        self.assertIn("codigo_totp", resp_data)

    def test_confirm_with_invalid_machine_signature_fails(self):
        """Valida que assinatura da máquina forjada/inválida rejeita a confirmação com erro 400."""
        admin_email = "admin.sigfail@votaai.org"
        req_step1 = {
            "email": admin_email,
            "senha": "SenhaValida123!",
            "chave_publica_maquina": self.machine_public_pem
        }
        self.client.post(self.url_iniciar, data=self._encrypt_request_body(req_step1), format='json')

        user = User.objects.get(email=admin_email)
        totp_code = TOTPService.generate_totp(user.totp_secret)

        # Assina com outra chave privada que NÃO é a chave pública registrada
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged_sig = other_key.sign(f"{admin_email}:{totp_code}".encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())

        req_step3 = {
            "email": admin_email,
            "codigo_totp": totp_code,
            "assinatura": base64.b64encode(forged_sig).decode('utf-8')
        }
        response = self.client.post(self.url_confirmar, data=self._encrypt_request_body(req_step3), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_data = self._decrypt_response_body(response)
        self.assertIn("assinatura", resp_data)

    def test_pre_cadastro_with_already_active_user_fails(self):
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
            "senha": "NovaSenha123!",
            "chave_publica_maquina": self.machine_public_pem
        }
        response = self.client.post(self.url_iniciar, data=self._encrypt_request_body(req), format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_data = self._decrypt_response_body(response)
        self.assertIn("email", resp_data)

    def test_pre_cadastro_with_weak_password_fails(self):
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
                "senha": weak_pass,
                "chave_publica_maquina": self.machine_public_pem
            }
            response = self.client.post(self.url_iniciar, data=self._encrypt_request_body(req), format='json')
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                f"A senha fraca '{weak_pass}' deveria ter sido rejeitada com status 400!"
            )
            resp_data = self._decrypt_response_body(response)
            self.assertIn("senha", resp_data)

