import os
import json
import base64
import struct
import hashlib
from pathlib import Path
from django.conf import settings
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone
from knox.models import AuthToken
from rest_framework.test import APITestCase
from rest_framework import status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

from Domain.models.groupChoices import GroupRoles
from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.voteSchema import Vote
from Domain.models.schemas.election.tallySchema import Tally
from Domain.models.schemas.election.questionSchema import Question
from Domain.models.schemas.election.optionSchema import Option
from Domain.models.schemas.moderation.userSchema import User


class ElectionTallyTests(APITestCase):
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

        # Chave da máquina desktop autorizada
        self.machine_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.machine_public_pem = self.machine_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Usuário criador da eleição
        self.user = User.objects.create_user(
            username='admin.tally@votaai.org',
            email='admin.tally@votaai.org',
            password='Password123!',
            is_active=True,
            machine_public_key=self.machine_public_pem.strip()
        )
        self.admin_group, _ = Group.objects.get_or_create(name=GroupRoles.ADMIN.value)
        self.user.groups.add(self.admin_group)
        _, self.auth_token = AuthToken.objects.create(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.auth_token}")

        # Chave RSA exclusiva da eleição
        self.election_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.election_public_pem = self.election_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.election_private_pem = self.election_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        self.key_handle = "tally_election_handle_2001"

        # Cria eleição em estado CLOSED (pronta para apuração)
        self.election = Election.objects.create(
            title="Eleição para Reitor 2026",
            public_key=self.election_public_pem,
            key_handle=self.key_handle,
            machine_signature="sig_setup_tally",
            status=ElectionStatus.CLOSED,
            start_datetime=timezone.now(),
            end_datetime=timezone.now(),
            created_by=self.user
        )

        self.question = Question.objects.create(
            election=self.election,
            question="Quem deve ser o Reitor?",
            order=1
        )
        self.option_1 = Option.objects.create(
            question=self.question,
            label="Chapa 1 - Renovação"
        )
        self.option_2 = Option.objects.create(
            question=self.question,
            label="Chapa 2 - Avanço"
        )

        # Adiciona votos cifrados de teste
        voto_cifrado_1 = self.election_private_key.public_key().encrypt(
            b'{"question": "Reitor 2026", "option": "Chapa 1"}',
            padding.PKCS1v15()
        )
        voto_cifrado_2 = self.election_private_key.public_key().encrypt(
            b'{"question": "Reitor 2026", "option": "Chapa 2"}',
            padding.PKCS1v15()
        )

        self.vote_1 = Vote.objects.create(
            id_generated="VOTE-RECEIPT-0001",
            content=json.dumps({"id_voto": "BALLOT-1", "pacote_cifrado": base64.b64encode(voto_cifrado_1).decode('utf-8')}),
            election=self.election
        )
        self.vote_2 = Vote.objects.create(
            id_generated="VOTE-RECEIPT-0002",
            content=json.dumps({"id_voto": "BALLOT-2", "pacote_cifrado": base64.b64encode(voto_cifrado_2).decode('utf-8')}),
            election=self.election
        )

        self.url_votes = reverse('election-tally-votes')
        self.url_tally = reverse('election-tally')

    def _sign_payload(self, payload_dict: dict, private_key=None) -> str:
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
        decrypted_payload_bytes = aesgcm.decrypt(
            base64.b64decode(enc_json["iv"]),
            base64.b64decode(enc_json["encrypted_payload"]) + base64.b64decode(enc_json["tag"]),
            None
        )
        return json.loads(decrypted_payload_bytes.decode('utf-8'))

    def test_get_votes_for_closed_election(self):
        """Desktop autenticado consegue obter a lista de votos cifrados para apuração."""
        nonce = "test-tally-nonce-votes-1"
        payload = {
            "keyHandle": self.key_handle,
            "nonceClient": nonce,
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_votes, data=encrypted_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        res_data = self._decrypt_response_body(response)

        self.assertEqual(res_data["keyHandle"], self.key_handle)
        self.assertTrue(res_data.get("machine_fingerprint", "").startswith("mach_"))
        self.assertEqual(res_data["status"], "CLOSED")
        self.assertEqual(res_data["total_votos"], 2)
        self.assertEqual(len(res_data["votes"]), 2)
        self.assertIn("questions", res_data)
        self.assertEqual(len(res_data["questions"]), 1)
        self.assertEqual(res_data["questions"][0]["question"], self.question.question)
        self.assertIn("abstention_percentage", res_data)
        self.assertEqual(res_data["nonceClient"], nonce)

    def test_get_votes_unauthorized_machine_fails(self):
        """Máquina diferente da criadora não pode obter os votos enquanto CLOSED."""
        rogue_machine = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_pub_pem = rogue_machine.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        payload = {
            "keyHandle": self.key_handle,
            "nonceClient": "rogue-nonce-1",
            "machine_public_key": rogue_pub_pem
        }
        encrypted_req = self._encrypt_request_body(payload, private_key=rogue_machine)
        response = self.client.post(self.url_votes, data=encrypted_req, format='json')

        # Retorna 403 Forbidden cifrado
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_votes_for_started_election_fails(self):
        """Não permite obter votos para apuração enquanto a eleição ainda estiver STARTED."""
        self.election.status = ElectionStatus.STARTED
        self.election.save()

        payload = {
            "keyHandle": self.key_handle,
            "nonceClient": "started-nonce-1",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_votes, data=encrypted_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_tally_election_success(self):
        """Primeira apuração soberana salva o Tally e grava a chave privada no servidor."""
        tally_hash = hashlib.sha256(b"canonical_tally_audit_results").hexdigest()
        nonce = "test-tally-nonce-submit-1"
        payload = {
            "keyHandle": self.key_handle,
            "tally_hash": tally_hash,
            "private_key": self.election_private_pem,
            "results": {
                "Quem deve ser o Reitor?": {"Chapa 1 - Renovação": 1, "Chapa 2 - Avanço": 1}
            },
            "nonceClient": nonce,
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_tally, data=encrypted_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        res_data = self._decrypt_response_body(response)

        self.assertEqual(res_data["keyHandle"], self.key_handle)
        self.assertTrue(res_data.get("machine_fingerprint", "").startswith("mach_"))
        self.assertEqual(res_data["status"], "TALLIED")
        self.assertEqual(res_data["tally_hash"], tally_hash)
        self.assertIn("abstention_percentage", res_data)
        self.assertEqual(res_data["nonceClient"], nonce)

        # Confirma persistência no banco
        self.election.refresh_from_db()
        self.assertEqual(self.election.status, ElectionStatus.TALLIED)
        self.assertEqual(self.election.private_key.strip(), self.election_private_pem.strip())

        tally_obj = Tally.objects.filter(election=self.election).first()
        self.assertIsNotNone(tally_obj)
        self.assertEqual(tally_obj.tally_hash, tally_hash)

    def test_tally_with_mismatched_private_key_fails(self):
        """Rejeita se a chave privada enviada não corresponder à chave pública da eleição."""
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_priv_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        payload = {
            "keyHandle": self.key_handle,
            "tally_hash": "dummy_hash",
            "private_key": other_priv_pem,
            "nonceClient": "nonce-mismatch",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_tally, data=encrypted_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_tally_unauthorized_machine_fails(self):
        """Máquina não autorizada não pode submeter a primeira apuração."""
        rogue_machine = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_pub_pem = rogue_machine.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        payload = {
            "keyHandle": self.key_handle,
            "tally_hash": "hash_rogue",
            "private_key": self.election_private_pem,
            "results": {
                "Quem deve ser o Reitor?": {"Chapa 1 - Renovação": 1, "Chapa 2 - Avanço": 1}
            },
            "nonceClient": "nonce-rogue",
            "machine_public_key": rogue_pub_pem
        }
        encrypted_req = self._encrypt_request_body(payload, private_key=rogue_machine)
        response = self.client.post(self.url_tally, data=encrypted_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_tally_election_already_tallied_fails(self):
        """Não permite apurar novamente uma eleição que já se encontra TALLIED."""
        self.election.status = ElectionStatus.TALLIED
        self.election.save()

        payload = {
            "keyHandle": self.key_handle,
            "tally_hash": "hash_dup",
            "private_key": self.election_private_pem,
            "results": {
                "Quem deve ser o Reitor?": {"Chapa 1 - Renovação": 1, "Chapa 2 - Avanço": 1}
            },
            "nonceClient": "nonce-dup",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_tally, data=encrypted_req, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_public_tracking_reveals_private_key_and_votes_when_tallied(self):
        """Uma vez TALLIED, qualquer pessoa pode obter a private_key e os votos pelo endpoint público."""
        # 1. Apura a eleição com sucesso
        tally_hash = hashlib.sha256(b"public_audit_data").hexdigest()
        payload = {
            "keyHandle": self.key_handle,
            "tally_hash": tally_hash,
            "private_key": self.election_private_pem,
            "results": {
                "Quem deve ser o Reitor?": {"Chapa 1 - Renovação": 1, "Chapa 2 - Avanço": 1}
            },
            "nonceClient": "nonce-public-track",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        resp_tally = self.client.post(self.url_tally, data=encrypted_req, format='json')
        self.assertEqual(resp_tally.status_code, status.HTTP_200_OK)

        # 2. Requisita endpoint público aberto (sem autenticação)
        url_track = reverse('election-track-retrieve', kwargs={'pk': self.election.id})
        resp_public = self.client.get(url_track)

        self.assertEqual(resp_public.status_code, status.HTTP_200_OK)
        data = resp_public.json()

        self.assertEqual(data["status"], "TALLIED")
        self.assertIsNotNone(data["private_key"])
        self.assertEqual(data["private_key"].strip(), self.election_private_pem.strip())
        self.assertTrue(len(data["tallies"]) > 0)
        self.assertEqual(data["tallies"][0]["tally_hash"], tally_hash)
        self.assertEqual(len(data["votes"]), 2)
        self.assertIn("tally_results", data)
        self.assertIsNotNone(data["tally_results"])
        self.assertEqual(data["tally_results"]["tally_hash"], tally_hash)
        self.assertTrue(len(data["tally_results"]["questions"]) > 0)

    def test_tally_without_results_fails(self):
        """Rejeita apuração sem o campo results obrigatório."""
        payload = {
            "keyHandle": self.key_handle,
            "tally_hash": "hash_no_results",
            "private_key": self.election_private_pem,
            "nonceClient": "nonce-no-res",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_tally, data=encrypted_req, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.election.refresh_from_db()
        self.assertEqual(self.election.status, ElectionStatus.CLOSED)

    def test_tally_zeroed_results_when_votes_exist_fails(self):
        """Rejeita apuração com contagem zerada de votos quando a urna possui cédulas."""
        payload = {
            "keyHandle": self.key_handle,
            "tally_hash": "hash_zeroed",
            "private_key": self.election_private_pem,
            "results": {
                "Quem deve ser o Reitor?": {
                    "Chapa 1 - Renovação": 0,
                    "Chapa 2 - Avanço": 0
                }
            },
            "nonceClient": "nonce-zeroed",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        response = self.client.post(self.url_tally, data=encrypted_req, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.election.refresh_from_db()
        self.assertEqual(self.election.status, ElectionStatus.CLOSED)

    def test_get_votes_without_auth_token_fails_401(self):
        """Obter votos para apuração sem header Authorization retorna 401."""
        payload = {
            "keyHandle": self.key_handle,
            "nonceClient": "nonce-tv-no-auth",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        self.client.credentials()
        response = self.client.post(self.url_votes, data=encrypted_req, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_votes_tampered_envelope_signature_fails_403(self):
        """Assinatura RSA-PSS de envelope adulterada em /tally/votes/ retorna 403."""
        payload = {
            "keyHandle": self.key_handle,
            "nonceClient": "nonce-tv-bad-sig",
            "machine_public_key": self.machine_public_pem,
            "signature": base64.b64encode(b"assinatura_tally_adulterada").decode('utf-8')
        }
        encrypted_req = self._encrypt_request_body(payload, sign=False)
        response = self.client.post(self.url_votes, data=encrypted_req, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_votes_non_admin_user_fails_403(self):
        """Usuário comum fora do grupo Administrador não pode acessar /tally/votes/."""
        regular_user = User.objects.create_user(
            username='regular.tally@votaai.org',
            email='regular.tally@votaai.org',
            password='Password123!',
            is_active=True,
            machine_public_key=self.machine_public_pem.strip()
        )
        _, regular_token = AuthToken.objects.create(regular_user)
        payload = {
            "keyHandle": self.key_handle,
            "nonceClient": "nonce-tv-non-admin",
            "machine_public_key": self.machine_public_pem
        }
        encrypted_req = self._encrypt_request_body(payload)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {regular_token}")
        response = self.client.post(self.url_votes, data=encrypted_req, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
