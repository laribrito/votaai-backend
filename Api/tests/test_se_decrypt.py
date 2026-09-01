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
from cryptography.hazmat.primitives import serialization

class SEDecryptMiddlewareTests(APITestCase):
    def setUp(self):
        # Lê a chave pública gerada anteriormente do se_keys_info.json na raiz do projeto
        base_dir = getattr(settings, 'BASE_DIR', Path.cwd())
        keys_path = os.path.join(base_dir, 'se_keys_info.json')
        self.client_key_file = os.path.join(base_dir, 'desktop_public_key.txt')
        
        # Limpa arquivo de chave anterior se existir
        if os.path.exists(self.client_key_file):
            os.remove(self.client_key_file)
        
        if not os.path.exists(keys_path):
            self.skipTest("Arquivo se_keys_info.json não encontrado. Rode 'manage.py generate_se_keys' primeiro.")
            
        with open(keys_path, 'r') as f:
            keys_info = json.load(f)
            
        desktop_key_info = next((k for k in keys_info if k['KeyName'] == 'VotaAI_SecureKey_1'), None)
        self.assertIsNotNone(desktop_key_info, "Chave Desktop não encontrada no arquivo se_keys_info.json")
        
        pub_key_blob = base64.b64decode(desktop_key_info['PublicKeyBase64'])
        
        # Faz o parse da chave BCRYPT_RSAKEY_BLOB da Microsoft CNG (mesma lógica do Desktop App)
        magic, bitlen, cbpubexp, cbmodulus, cbprime1, cbprime2 = struct.unpack('<IIIIII', pub_key_blob[:24])
        offset = 24
        exp_bytes = pub_key_blob[offset:offset+cbpubexp]
        offset += cbpubexp
        mod_bytes = pub_key_blob[offset:offset+cbmodulus]
        
        e = int.from_bytes(exp_bytes, byteorder='big')
        n = int.from_bytes(mod_bytes, byteorder='big')
        
        self.backend_public_key = rsa.RSAPublicNumbers(e, n).public_key()
        self.url = reverse('ping-desktop')

    def tearDown(self):
        if os.path.exists(self.client_key_file):
            os.remove(self.client_key_file)

    def test_ping_desktop_without_client_key_returns_400_error(self):
        """
        Quando o cliente NÃO envia sua chave pública (e não há chave salva),
        a API retorna erro 400 exigindo a chave pública para criptografar a resposta.
        """
        original_payload = {"mensagem_secreta": "Teste sem chave do cliente", "id_teste": 100}
        json_payload_bytes = json.dumps(original_payload).encode('utf-8')
        
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        
        encrypted_data = aesgcm.encrypt(iv, json_payload_bytes, None)
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]
        
        encrypted_aes_key = self.backend_public_key.encrypt(
            aes_key,
            padding.PKCS1v15()
        )
        
        body = {
            "encrypted_payload": base64.b64encode(ciphertext).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }
        
        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertIn('error', response_data)

    def test_full_roundtrip_with_client_public_key_and_encrypted_response(self):
        """
        Ciclo completo (Ida e Volta criptografada):
        1. Desktop envia dados cifrados + sua própria chave pública RSA.
        2. Backend TPM descriptografa os dados de entrada.
        3. Backend salva a chave do Desktop em desktop_public_key.txt.
        4. Backend criptografa o JSON de resposta com a chave pública do Desktop.
        5. Desktop recebe o pacote cifrado e descriptografa com sua chave privada RSA.
        """
        # 1. Desktop gera seu próprio par de chaves RSA em memória
        client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        client_public_pem = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # 2. Desktop prepara o payload original a ser enviado
        original_request = {
            "acao": "pre_cadastro_admin",
            "admin_email": "admin@votaai.org",
            "token_solicitacao": "xyz-789"
        }
        json_request_bytes = json.dumps(original_request).encode('utf-8')

        # 3. Desktop cifra o request para o Backend (usando a Chave Pública do Backend)
        aes_key_req = os.urandom(32)
        iv_req = os.urandom(12)
        aesgcm_req = AESGCM(aes_key_req)
        
        encrypted_req_data = aesgcm_req.encrypt(iv_req, json_request_bytes, None)
        ciphertext_req = encrypted_req_data[:-16]
        tag_req = encrypted_req_data[-16:]

        encrypted_aes_key_req = self.backend_public_key.encrypt(
            aes_key_req,
            padding.PKCS1v15()
        )

        body = {
            "encrypted_payload": base64.b64encode(ciphertext_req).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key_req).decode('utf-8'),
            "iv": base64.b64encode(iv_req).decode('utf-8'),
            "tag": base64.b64encode(tag_req).decode('utf-8'),
            "client_public_key": client_public_pem # Envio da chave do cliente!
        }

        # 4. Envia a chamada HTTP
        response = self.client.post(self.url, data=body, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 5. Verifica se o arquivo desktop_public_key.txt foi gerado na raiz
        self.assertTrue(os.path.exists(self.client_key_file), "Arquivo desktop_public_key.txt não foi criado!")
        with open(self.client_key_file, 'r', encoding='utf-8') as f:
            saved_key = f.read().strip()
        self.assertEqual(saved_key, client_public_pem.strip())

        # 6. Verifica se a resposta foi criptografada pelo backend
        encrypted_response_json = response.json()
        self.assertIn("encrypted_payload", encrypted_response_json)
        self.assertIn("encrypted_aes_key", encrypted_response_json)
        self.assertIn("iv", encrypted_response_json)
        self.assertIn("tag", encrypted_response_json)

        # 7. Desktop descriptografa a resposta usando sua Chave Privada
        encrypted_resp_aes_key_bytes = base64.b64decode(encrypted_response_json["encrypted_aes_key"])
        decrypted_resp_aes_key = client_private_key.decrypt(
            encrypted_resp_aes_key_bytes,
            padding.PKCS1v15()
        )

        resp_aesgcm = AESGCM(decrypted_resp_aes_key)
        resp_iv = base64.b64decode(encrypted_response_json["iv"])
        resp_ciphertext = base64.b64decode(encrypted_response_json["encrypted_payload"])
        resp_tag = base64.b64decode(encrypted_response_json["tag"])

        decrypted_response_bytes = resp_aesgcm.decrypt(
            resp_iv,
            resp_ciphertext + resp_tag,
            None
        )
        decrypted_response_data = json.loads(decrypted_response_bytes.decode('utf-8'))

        # 8. Valida o conteúdo final da resposta
        self.assertIn("data_recebida", decrypted_response_data)
        self.assertEqual(decrypted_response_data["data_recebida"]["acao"], "pre_cadastro_admin")
        self.assertEqual(decrypted_response_data["data_recebida"]["admin_email"], "admin@votaai.org")
