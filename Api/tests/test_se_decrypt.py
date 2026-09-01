import os
import json
import base64
import struct
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa

class SEDecryptMiddlewareTests(APITestCase):
    def setUp(self):
        # Lê a chave pública gerada anteriormente do se_keys_info.json na raiz do projeto
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        keys_path = os.path.join(base_dir, 'se_keys_info.json')
        
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
        
        self.public_key = rsa.RSAPublicNumbers(e, n).public_key()
        self.url = reverse('ping-desktop')

    def test_ping_desktop_with_hybrid_encryption(self):
        """
        Gera um payload híbrido criptografado, envia para a API, 
        e valida se o middleware descriptografou usando o Secure Element corretamente.
        """
        # 1. Cria o payload original
        original_payload = {"mensagem_secreta": "Este é um teste automatizado do TPM!", "id_teste": 999}
        json_payload_bytes = json.dumps(original_payload).encode('utf-8')
        
        # 2. Criptografia AES-GCM
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        
        encrypted_data = aesgcm.encrypt(iv, json_payload_bytes, None)
        tag_length = 16
        ciphertext = encrypted_data[:-tag_length]
        tag = encrypted_data[-tag_length:]
        
        # 3. Criptografia RSA da chave AES
        encrypted_aes_key = self.public_key.encrypt(
            aes_key,
            padding.PKCS1v15()
        )
        
        # 4. Monta o body para enviar à API
        body = {
            "encrypted_payload": base64.b64encode(ciphertext).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }
        
        # 5. Envia o POST (o middleware interceptará)
        response = self.client.post(self.url, data=body, format='json')
        
        # 6. Validações
        self.assertEqual(response.status_code, status.HTTP_200_OK, f"A rota falhou: {response.content}")
        
        # O Django DEVE ter recebido o JSON em texto claro dentro da View
        response_data = response.json()
        self.assertIn('data_recebida', response_data)
        self.assertEqual(response_data['data_recebida']['mensagem_secreta'], original_payload['mensagem_secreta'])
        self.assertEqual(response_data['data_recebida']['id_teste'], original_payload['id_teste'])
