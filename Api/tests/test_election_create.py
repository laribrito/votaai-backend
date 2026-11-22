import os
import json
import base64
import struct
from pathlib import Path
from django.conf import settings
from django.contrib.auth.models import Group
from django.urls import reverse
from knox.models import AuthToken
from rest_framework.test import APITestCase
from rest_framework import status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

from Domain.models.groupChoices import GroupRoles
from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.questionSchema import Question
from Domain.models.schemas.election.optionSchema import Option
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
from Domain.models.schemas.moderation.userSchema import User
from Infrastructure.services.seCryptoService import SECryptoService


class ElectionCreateTests(APITestCase):
    """
    Testes de integração para a rota Desktop de criação de eleição:
    POST /api/election/create/
    Valida criptografia híbrida de transporte (TPM), assinatura da máquina cliente,
    persistência e assinatura digital do servidor.
    """

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

        # Gera par de chaves RSA da máquina física cliente (Desktop)
        self.machine_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.machine_public_pem = self.machine_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Cria usuário associado à máquina física para validação de vínculo obrigatório
        self.user = User.objects.create_user(
            username='admin.desktop@votaai.org',
            email='admin.desktop@votaai.org',
            password='Password123!',
            is_active=True,
            machine_public_key=self.machine_public_pem.strip()
        )
        self.admin_group, _ = Group.objects.get_or_create(name=GroupRoles.ADMIN.value)
        self.user.groups.add(self.admin_group)
        _, self.auth_token = AuthToken.objects.create(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.auth_token}")

        # URL da rota de criação de eleição
        self.url_create = reverse('election-create')

    def _sign_payload(self, payload_dict: dict, private_key=None) -> str:
        """Gera assinatura RSA-PSS sobre o JSON canônico (Sign-then-Encrypt)."""
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

    def _encrypt_request_body(self, payload_dict: dict, private_key=None, sign: bool = True) -> dict:
        """Simula o cliente Desktop cifrando a requisição com a chave pública do servidor no TPM."""
        body = dict(payload_dict)
        if sign and 'machine_public_key' in body and 'signature' not in body:
            body['signature'] = self._sign_payload(body, private_key=private_key)
        json_bytes = json.dumps(body).encode('utf-8')
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
        """Simula o cliente Desktop decifrando a resposta do servidor com a chave privada da máquina."""
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

    def _sign_with_machine_key(self, data: bytes) -> str:
        """Gera assinatura digital RSA-SHA256 com a chave privada da máquina."""
        signature_bytes = self.machine_private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature_bytes).decode('utf-8')

    def test_create_election_success_flow(self):
        """
        Valida o fluxo completo de cadastro de eleição:
        1. Desktop monta dados (titulo, cedula, colegiadoEleitoral, chavePublica, keyHandle)
        2. Desktop assina com chave privada da máquina
        3. Desktop cifra envelope para o servidor
        4. API decifra, valida assinatura da máquina, cria eleição, assina resposta com TPM
        5. Desktop decifra resposta e valida id, qtdPerguntas, qtdOpcoes e assinatura do servidor.
        """
        titulo = "Eleição Diretoria 2026"
        chave_publica_eleicao = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE..."
        key_handle = "0x81010002"
        colegiado = [
            {"email": "eleitor1@votaai.org", "full_name": "Eleitor Um", "password": "SenhaDoEleitor123!"},
            {"email": "eleitor2@votaai.org", "full_name": "Eleitor Dois"},
            {"email": "eleitor3@votaai.org", "full_name": "Eleitor Três"}
        ]
        cedula = [
            {
                "question": "Escolha o Presidente",
                "options": [
                    {"label": "Chapa 1 - Inovação"},
                    {"label": "Chapa 2 - Renovação"},
                    {"label": "Branco / Nulo"}
                ]
            },
            {
                "question": "Aprova as novas contas?",
                "options": [
                    {"label": "Sim"},
                    {"label": "Não"}
                ]
            }
        ]

        req_payload = {
            "title": titulo,
            "ballot": cedula,
            "electoral_college": colegiado,
            "public_key": chave_publica_eleicao,
            "key_handle": key_handle,
            "machine_public_key": self.machine_public_pem
        }
        canonical_bytes = json.dumps(req_payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        machine_signature = self._sign_with_machine_key(canonical_bytes)
        req_payload["signature"] = machine_signature

        # Cifra envelope para o servidor
        encrypted_body = self._encrypt_request_body(req_payload)

        # Envia requisição
        response = self.client.post(self.url_create, data=encrypted_body, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Decifra resposta com a chave privada da máquina
        decrypted_response = self._decrypt_response_body(response)

        self.assertIn("id", decrypted_response)
        self.assertIn("questions_count", decrypted_response)
        self.assertIn("options_count", decrypted_response)
        self.assertIn("signature", decrypted_response)

        election_id = decrypted_response["id"]
        qtd_perguntas = decrypted_response["questions_count"]
        qtd_opcoes = decrypted_response["options_count"]
        assinatura_servidor = decrypted_response["signature"]

        # Verifica contagens: 2 perguntas e 5 opções no total (3 + 2)
        self.assertEqual(qtd_perguntas, 2)
        self.assertEqual(qtd_opcoes, 5)

        # Valida assinatura do servidor via hardware TPM
        expected_server_payload = f"{election_id}:{qtd_perguntas}:{qtd_opcoes}".encode('utf-8')
        is_server_sig_valid = SECryptoService.verify_signature(
            self.backend_public_key,
            expected_server_payload,
            assinatura_servidor
        )
        self.assertTrue(is_server_sig_valid, "Assinatura digital do servidor no TPM é inválida!")

        # Valida persistência no banco de dados normalizado
        election = Election.objects.filter(id=election_id).first()
        self.assertIsNotNone(election)
        self.assertEqual(election.title, titulo)
        self.assertEqual(election.key_handle, key_handle)
        expected_fp = SECryptoService.get_machine_fingerprint(self.machine_public_pem)
        self.assertEqual(election.machine_fingerprint, expected_fp)
        self.assertTrue(election.machine_fingerprint.startswith("mach_"))
        self.assertEqual(election.status, ElectionStatus.CREATED)
        self.assertEqual(election.created_by, self.user)
        self.assertEqual(election.questions_count, 2)
        self.assertEqual(election.options_count, 5)

        # Valida criação das entidades Question no banco
        questions_db = list(election.questions.all().order_by('order'))
        self.assertEqual(len(questions_db), 2)
        self.assertEqual(questions_db[0].order, 1)
        self.assertEqual(questions_db[0].question, "Escolha o Presidente")
        self.assertEqual(questions_db[0].options.count(), 3)
        self.assertEqual(questions_db[1].order, 2)
        self.assertEqual(questions_db[1].question, "Aprova as novas contas?")
        self.assertEqual(questions_db[1].options.count(), 2)

        # Valida opções salvas
        options_q1 = [o.label for o in questions_db[0].options.all()]
        self.assertIn("Chapa 1 - Inovação", options_q1)
        self.assertIn("Branco / Nulo", options_q1)

        # Valida criação do Colégio Eleitoral
        voters_db = list(election.electoral_college.all())
        self.assertEqual(len(voters_db), 3)
        for voter in voters_db:
            self.assertFalse(voter.has_voted, "Eleitor recém-cadastrado deve ter has_voted=False")
        emails_db = [v.email for v in voters_db]
        self.assertIn("eleitor1@votaai.org", emails_db)
        self.assertIn("eleitor2@votaai.org", emails_db)

        # Valida que a senha foi gravada exclusivamente como hash criptográfico
        voter1 = election.electoral_college.filter(email="eleitor1@votaai.org").first()
        self.assertIsNotNone(voter1)
        self.assertNotEqual(voter1.password, "SenhaDoEleitor123!", "Senha não pode estar em texto claro!")
        self.assertTrue(voter1.password.startswith("pbkdf2_sha256$"), "Senha deve ser hash PBKDF2!")
        self.assertTrue(voter1.check_password("SenhaDoEleitor123!"), "check_password deve validar a senha original!")
        self.assertFalse(voter1.check_password("SenhaIncorreta!"), "check_password deve rejeitar senha errada!")

        # Valida que nickname é automaticamente o primeiro nome do nome completo
        self.assertEqual(voter1.nickname, "Eleitor", "Nickname deve ser o primeiro nome extraído de full_name")
        self.assertEqual(voter1.first_name, "Eleitor", "first_name deve retornar o primeiro nome do eleitor")

        # Valida criação individual via ORM e preenchimento automático de nickname no save()
        individual_voter = ElectoralCollege(
            election=election,
            full_name="Carlos Eduardo Silveira",
            email="carlos.eduardo@votaai.org"
        )
        individual_voter.save()
        self.assertEqual(individual_voter.nickname, "Carlos", "Nickname deve ser auto-preenchido com primeiro nome no save()")


    def test_create_election_with_invalid_machine_signature_fails(self):
        """Valida que uma assinatura inválida da máquina física é rejeitada pelo middleware com erro 403."""
        req_payload = {
            "title": "Eleição Inválida",
            "ballot": [
                {
                    "question": "Pergunta 1",
                    "options": ["Opção A", "Opção B"]
                }
            ],
            "electoral_college": ["user1@votaai.org"],
            "public_key": "chave_falsa_123",
            "key_handle": "0x81010099",
            "signature": base64.b64encode(b"assinatura_invalida_totalmente_falsa").decode('utf-8'),
            "machine_public_key": self.machine_public_pem
        }

        encrypted_body = self._encrypt_request_body(req_payload, sign=False)
        response = self.client.post(self.url_create, data=encrypted_body, format='json')

        # A resposta de erro também é cifrada pelo middleware
        decrypted_response = self._decrypt_response_body(response)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("error", decrypted_response)

    def test_create_election_without_questions_fails(self):
        """Valida que cédula sem perguntas é rejeitada com erro 400."""
        titulo = "Eleição Vazia"
        chave_pub = "chave_pub_123"
        key_handle = "handle_123"

        req_payload = {
            "title": titulo,
            "ballot": [],
            "electoral_college": ["user1@votaai.org"],
            "public_key": chave_pub,
            "key_handle": key_handle,
            "machine_public_key": self.machine_public_pem
        }
        req_payload["signature"] = self._sign_payload(req_payload)

        encrypted_body = self._encrypt_request_body(req_payload)
        response = self.client.post(self.url_create, data=encrypted_body, format='json')

        decrypted_response = self._decrypt_response_body(response)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("ballot", decrypted_response)

    def test_create_two_elections_with_duplicate_key_handle_fails_but_distinct_handles_share_machine_fingerprint(self):
        """
        Valida que duas eleições na mesma máquina devem ter key_handle únicos,
        e ambas compartilham o mesmo machine_fingerprint não-replicável.
        """
        ballot_data = [{"question": "Pergunta 1", "options": ["Sim", "Não"]}]
        college_data = ["eleitor1@votaai.org"]

        # 1ª Eleição
        payload1 = {
            "title": "Eleição 1",
            "ballot": ballot_data,
            "electoral_college": college_data,
            "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
            "key_handle": "votaai_election_aa11bb22cc33dd44",
            "machine_public_key": self.machine_public_pem
        }
        canonical1 = json.dumps(payload1, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        payload1["signature"] = self._sign_with_machine_key(canonical1)
        resp1 = self.client.post(self.url_create, data=self._encrypt_request_body(payload1), format='json')
        self.assertEqual(resp1.status_code, status.HTTP_200_OK)

        # Tentativa com o mesmo key_handle deve falhar com 400
        payload_dup = dict(payload1)
        payload_dup.pop("signature", None)
        payload_dup["title"] = "Eleição Duplicada"
        canonical_dup = json.dumps(payload_dup, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        payload_dup["signature"] = self._sign_with_machine_key(canonical_dup)
        resp_dup = self.client.post(self.url_create, data=self._encrypt_request_body(payload_dup), format='json')
        self.assertEqual(resp_dup.status_code, status.HTTP_400_BAD_REQUEST)
        dec_dup = self._decrypt_response_body(resp_dup)
        self.assertIn("key_handle", dec_dup)

        # 2ª Eleição com key_handle distinto sucede e mantém o mesmo machine_fingerprint
        payload2 = dict(payload1)
        payload2.pop("signature", None)
        payload2["title"] = "Eleição 2"
        payload2["key_handle"] = "votaai_election_ee55ff6677889900"
        canonical2 = json.dumps(payload2, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        payload2["signature"] = self._sign_with_machine_key(canonical2)
        resp2 = self.client.post(self.url_create, data=self._encrypt_request_body(payload2), format='json')
        self.assertEqual(resp2.status_code, status.HTTP_200_OK)

        el1 = Election.objects.get(key_handle="votaai_election_aa11bb22cc33dd44")
        el2 = Election.objects.get(key_handle="votaai_election_ee55ff6677889900")
        self.assertNotEqual(el1.key_handle, el2.key_handle)
        self.assertEqual(el1.machine_fingerprint, el2.machine_fingerprint)
        self.assertTrue(el1.machine_fingerprint.startswith("mach_"))

    def test_create_election_without_auth_token_fails_401(self):
        """Requisição sem cabeçalho Authorization deve ser rejeitada com 401."""
        req_payload = {
            "title": "Eleição Sem Token",
            "ballot": [{"question": "Pergunta 1", "options": ["Sim", "Não"]}],
            "electoral_college": ["eleitor1@votaai.org"],
            "public_key": "chave_pub_123",
            "key_handle": "votaai_election_no_auth_01",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_body = self._encrypt_request_body(req_payload)
        self.client.credentials()
        response = self.client.post(self.url_create, data=encrypted_body, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_election_non_admin_user_fails_403(self):
        """Usuário autenticado fora do grupo Administrador deve ser rejeitado com 403."""
        regular_user = User.objects.create_user(
            username='regular.create@votaai.org',
            email='regular.create@votaai.org',
            password='Password123!',
            is_active=True,
            machine_public_key=self.machine_public_pem.strip()
        )
        _, regular_token = AuthToken.objects.create(regular_user)
        req_payload = {
            "title": "Eleição Usuário Comum",
            "ballot": [{"question": "Pergunta 1", "options": ["Sim", "Não"]}],
            "electoral_college": ["eleitor1@votaai.org"],
            "public_key": "chave_pub_123",
            "key_handle": "votaai_election_non_admin_01",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_body = self._encrypt_request_body(req_payload)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {regular_token}")
        response = self.client.post(self.url_create, data=encrypted_body, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


