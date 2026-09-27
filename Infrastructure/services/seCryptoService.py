import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

logger = logging.getLogger(__name__)

# Configuração do Windows CNG (carregado apenas quando em ambiente Windows)
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    # Carrega a DLL nativa do Windows CNG (Cryptography Next Generation)
    ncrypt = ctypes.windll.ncrypt

    # Constante para indicar padding PKCS#1
    NCRYPT_PAD_PKCS1_FLAG = 0x00000002

    # Mapeamento dos tipos de argumentos e retorno para garantir chamadas seguras em C
    ncrypt.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.LPCWSTR, wintypes.DWORD]
    ncrypt.NCryptOpenStorageProvider.restype = wintypes.LONG

    ncrypt.NCryptOpenKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    ncrypt.NCryptOpenKey.restype = wintypes.LONG

    ncrypt.NCryptDecrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    ncrypt.NCryptDecrypt.restype = wintypes.LONG

    ncrypt.NCryptSignHash.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD
    ]
    ncrypt.NCryptSignHash.restype = wintypes.LONG

    ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
    ncrypt.NCryptFreeObject.restype = wintypes.LONG

    class BCRYPT_PKCS1_PADDING_INFO(ctypes.Structure):
        _fields_ = [("pszAlgId", wintypes.LPCWSTR)]


class SECryptoService:
    # =========================================================================
    # Helpers para Linux TPM 2.0 (tpm2-tools)
    # =========================================================================
    @classmethod
    def _get_base_dir(cls) -> Path:
        return Path(getattr(settings, 'BASE_DIR', Path.cwd()))

    @classmethod
    def _get_tpm_keys_dir(cls) -> Path:
        tpm_dir = cls._get_base_dir() / '.tpm_keys'
        tpm_dir.mkdir(parents=True, exist_ok=True)
        return tpm_dir

    @classmethod
    def _ensure_linux_tpm_context(cls, key_name: str) -> Path:
        """
        Garante que o contexto TPM da chave (.ctx) está disponível e carregado no TPM 2.0.
        """
        tpm_dir = cls._get_tpm_keys_dir()
        key_ctx = tpm_dir / f"{key_name}.ctx"
        primary_ctx = tpm_dir / 'primary.ctx'
        key_pub = tpm_dir / f"{key_name}.pub"
        key_priv = tpm_dir / f"{key_name}.priv"

        if not key_pub.exists() or not key_priv.exists():
            raise FileNotFoundError(
                f"Arquivos de chave TPM para '{key_name}' não encontrados em {tpm_dir}. "
                "Execute 'python manage.py generate_se_keys' para gerar as chaves no chip TPM 2.0."
            )

        if not primary_ctx.exists():
            res_p = subprocess.run([
                "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa", "-c", str(primary_ctx)
            ], capture_output=True, text=True)
            if res_p.returncode != 0:
                raise RuntimeError(
                    f"Erro ao acessar Primary Key no TPM: {res_p.stderr.strip()}. "
                    "Verifique permissões em /dev/tpmrm0 (sudo chmod 666 /dev/tpmrm0 ou sudo usermod -aG tss $USER)."
                )

        if not key_ctx.exists():
            res_l = subprocess.run([
                "tpm2_load", "-C", str(primary_ctx), "-u", str(key_pub), "-r", str(key_priv), "-c", str(key_ctx)
            ], capture_output=True, text=True)
            if res_l.returncode != 0:
                raise RuntimeError(f"Erro ao carregar chave '{key_name}' no TPM: {res_l.stderr.strip()}")

        return key_ctx

    @classmethod
    def _decrypt_with_linux_tpm(cls, key_name: str, cipher_bytes: bytes) -> bytes:
        key_ctx = cls._ensure_linux_tpm_context(key_name)
        primary_ctx = cls._get_tpm_keys_dir() / 'primary.ctx'
        key_pub = cls._get_tpm_keys_dir() / f"{key_name}.pub"
        key_priv = cls._get_tpm_keys_dir() / f"{key_name}.priv"

        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = os.path.join(tmpdir, 'in.bin')
            out_path = os.path.join(tmpdir, 'out.bin')

            with open(in_path, 'wb') as f:
                f.write(cipher_bytes)

            cmd = [
                "tpm2_rsadecrypt",
                "-c", str(key_ctx),
                "-s", "rsaes",
                "-o", out_path,
                in_path
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                # Se o contexto no TPM expirou na memória volátil, recarrega e tenta novamente
                subprocess.run([
                    "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa", "-c", str(primary_ctx)
                ], capture_output=True)
                subprocess.run([
                    "tpm2_load", "-C", str(primary_ctx), "-u", str(key_pub), "-r", str(key_priv), "-c", str(key_ctx)
                ], capture_output=True)
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    raise ValueError(f"Descriptografia rejeitada pelo hardware TPM: {res.stderr.strip()}")

            with open(out_path, 'rb') as f:
                return f.read()

    @classmethod
    def _sign_with_linux_tpm(cls, key_name: str, data: bytes) -> str:
        key_ctx = cls._ensure_linux_tpm_context(key_name)
        primary_ctx = cls._get_tpm_keys_dir() / 'primary.ctx'
        key_pub = cls._get_tpm_keys_dir() / f"{key_name}.pub"
        key_priv = cls._get_tpm_keys_dir() / f"{key_name}.priv"

        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = os.path.join(tmpdir, 'data.bin')
            sig_path = os.path.join(tmpdir, 'sig.bin')

            with open(in_path, 'wb') as f:
                f.write(data)

            cmd = [
                "tpm2_sign",
                "-c", str(key_ctx),
                "-g", "sha256",
                "-s", "rsapss",
                "-f", "plain",
                "-o", sig_path,
                in_path
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                # Se o contexto no TPM expirou na memória volátil, recarrega e tenta novamente
                subprocess.run([
                    "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa", "-c", str(primary_ctx)
                ], capture_output=True)
                subprocess.run([
                    "tpm2_load", "-C", str(primary_ctx), "-u", str(key_pub), "-r", str(key_priv), "-c", str(key_ctx)
                ], capture_output=True)
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    raise RuntimeError(f"Erro na assinatura RSA-PSS com hardware TPM: {res.stderr.strip()}")

            with open(sig_path, 'rb') as f:
                sig_bytes = f.read()

            return base64.b64encode(sig_bytes).decode('utf-8')

    @classmethod
    def export_cng_public_blob(cls, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Exporta a chave pública RSA no formato BCRYPT_RSAKEY_BLOB da Microsoft CNG (RSA1),
        permitindo interoperabilidade completa entre Linux, Windows e clientes de desktop/mobile.
        """
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_numbers.n

        e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

        magic = 0x31415352  # 'RSA1' em little-endian
        bit_len = n.bit_length()
        cb_pub_exp = len(e_bytes)
        cb_modulus = len(n_bytes)
        cb_prime1 = 0
        cb_prime2 = 0

        header = struct.pack('<IIIIII', magic, bit_len, cb_pub_exp, cb_modulus, cb_prime1, cb_prime2)
        return header + e_bytes + n_bytes

    # =========================================================================
    # Operações Principais (Código do Windows preservado na íntegra)
    # =========================================================================
    @staticmethod
    def decrypt_with_tpm(key_name: str, base64_ciphertext: str) -> bytes:
        if sys.platform != "win32":
            cipher_bytes = base64.b64decode(base64_ciphertext)
            return SECryptoService._decrypt_with_linux_tpm(key_name, cipher_bytes)

        """
        Envia o texto cifrado para o Secure Element/TPM usando a API nativa em C do Windows.
        Retorna os bytes descriptografados brutos.
        """
        # 1. Decodifica Base64
        try:
            cipher_bytes = base64.b64decode(base64_ciphertext)
        except Exception as e:
            raise ValueError(f"Ciphertext inválido: não é base64 ({e})")
            
        cipher_arr = (ctypes.c_ubyte * len(cipher_bytes)).from_buffer_copy(cipher_bytes)

        hProv = ctypes.c_void_p()
        hKey = ctypes.c_void_p()

        try:
            # 2. Abre o provedor nativo TPM (Microsoft Platform Crypto Provider)
            status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProv), "Microsoft Platform Crypto Provider", 0)
            if status != 0:
                raise RuntimeError(f"Falha ao abrir TPM Provider: NTSTATUS {hex(status & 0xFFFFFFFF)}")

            # 3. Abre a chave no hardware
            status = ncrypt.NCryptOpenKey(hProv, ctypes.byref(hKey), key_name, 0, 0)
            if status != 0:
                raise RuntimeError(f"Falha ao acessar chave '{key_name}': NTSTATUS {hex(status & 0xFFFFFFFF)}")

            cbResult = wintypes.DWORD(0)

            # 4. Primeira chamada (descobre o tamanho do buffer necessário)
            status = ncrypt.NCryptDecrypt(
                hKey, cipher_arr, len(cipher_bytes), None, None, 0, 
                ctypes.byref(cbResult), NCRYPT_PAD_PKCS1_FLAG
            )
            if status != 0:
                raise RuntimeError(f"Falha ao medir tamanho de descriptografia: NTSTATUS {hex(status & 0xFFFFFFFF)}")

            output_arr = (ctypes.c_ubyte * cbResult.value)()

            # 5. Segunda chamada (faz a descriptografia de fato dentro do TPM)
            status = ncrypt.NCryptDecrypt(
                hKey, cipher_arr, len(cipher_bytes), None, output_arr, 
                cbResult.value, ctypes.byref(cbResult), NCRYPT_PAD_PKCS1_FLAG
            )
            if status != 0:
                raise RuntimeError(f"Descriptografia rejeitada pelo hardware: NTSTATUS {hex(status & 0xFFFFFFFF)}")

            decrypted_bytes = bytes(output_arr[:cbResult.value])
            return decrypted_bytes

        finally:
            # Garante que os ponteiros de memória em C sejam liberados, evitando Memory Leaks
            if hKey:
                ncrypt.NCryptFreeObject(hKey)
            if hProv:
                ncrypt.NCryptFreeObject(hProv)

    @staticmethod
    def sign_with_tpm(key_name: str, data: bytes) -> str:
        if sys.platform != "win32":
            return SECryptoService._sign_with_linux_tpm(key_name, data)

        """
        Assina os dados fornecidos utilizando a chave RSA armazenada no TPM/Secure Element (Windows CNG).
        Retorna a assinatura em Base64.
        """
        hash_val = hashlib.sha256(data).digest()
        hash_arr = (ctypes.c_ubyte * len(hash_val)).from_buffer_copy(hash_val)

        hProv = ctypes.c_void_p()
        hKey = ctypes.c_void_p()

        try:
            status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProv), "Microsoft Platform Crypto Provider", 0)
            if status != 0:
                raise RuntimeError(f"Falha ao abrir TPM Provider: NTSTATUS {hex(status & 0xFFFFFFFF)}")

            status = ncrypt.NCryptOpenKey(hProv, ctypes.byref(hKey), key_name, 0, 0)
            if status != 0:
                raise RuntimeError(f"Falha ao acessar chave '{key_name}': NTSTATUS {hex(status & 0xFFFFFFFF)}")

            pad_info = BCRYPT_PKCS1_PADDING_INFO("SHA256")
            cbResult = wintypes.DWORD(0)

            # 1. Mede o tamanho do buffer necessário
            status = ncrypt.NCryptSignHash(
                hKey,
                ctypes.byref(pad_info),
                hash_arr,
                len(hash_val),
                None,
                0,
                ctypes.byref(cbResult),
                NCRYPT_PAD_PKCS1_FLAG
            )
            if status != 0:
                raise RuntimeError(f"Falha ao medir tamanho da assinatura: NTSTATUS {hex(status & 0xFFFFFFFF)}")

            sig_arr = (ctypes.c_ubyte * cbResult.value)()
            # 2. Executa a assinatura de fato dentro do chip TPM
            status = ncrypt.NCryptSignHash(
                hKey,
                ctypes.byref(pad_info),
                hash_arr,
                len(hash_val),
                sig_arr,
                cbResult.value,
                ctypes.byref(cbResult),
                NCRYPT_PAD_PKCS1_FLAG
            )
            if status != 0:
                raise RuntimeError(f"Assinatura rejeitada pelo hardware TPM: NTSTATUS {hex(status & 0xFFFFFFFF)}")

            sig_bytes = bytes(sig_arr[:cbResult.value])
            return base64.b64encode(sig_bytes).decode('utf-8')

        finally:
            if hKey:
                ncrypt.NCryptFreeObject(hKey)
            if hProv:
                ncrypt.NCryptFreeObject(hProv)

    @classmethod
    def _get_key_file_path(cls, device_type: str = 'desktop') -> Path:
        base_dir = getattr(settings, 'BASE_DIR', Path.cwd())
        return Path(base_dir) / f"{device_type}_public_key.txt"

    @classmethod
    def save_client_public_key(cls, device_type: str, key_data: str) -> None:
        """
        Salva a chave pública do cliente em arquivo de texto.
        """
        file_path = cls._get_key_file_path(device_type)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(key_data.strip())

    @classmethod
    def load_rsa_public_key(cls, key_data: str | bytes):
        """
        Carrega chave pública RSA suportando PEM, DER (Base64) e BCRYPT_RSAKEY_BLOB (CNG).
        """
        if isinstance(key_data, str):
            key_data_str = key_data.strip()
            if key_data_str.startswith('-----BEGIN'):
                return serialization.load_pem_public_key(key_data_str.encode('utf-8'))
            key_bytes = base64.b64decode(key_data_str)
        else:
            key_bytes = key_data

        # Se for formato BCRYPT_RSAKEY_BLOB da Microsoft (começa com RSA1)
        if key_bytes.startswith(b'RSA1'):
            magic, bitlen, cbpubexp, cbmodulus, cbprime1, cbprime2 = struct.unpack('<IIIIII', key_bytes[:24])
            offset = 24
            exp_bytes = key_bytes[offset:offset+cbpubexp]
            offset += cbpubexp
            mod_bytes = key_bytes[offset:offset+cbmodulus]
            e = int.from_bytes(exp_bytes, byteorder='big')
            n = int.from_bytes(mod_bytes, byteorder='big')
            return rsa.RSAPublicNumbers(e, n).public_key()

        # Tenta DER padrão
        return serialization.load_der_public_key(key_bytes)

    @classmethod
    def get_client_public_key(cls, device_type: str = 'desktop'):
        """
        Lê e faz o parse da chave pública do cliente salva no arquivo txt.
        Se não existir em disco, tenta resgatar do banco de dados (User).
        Retorna None se não for encontrada.
        """
        file_path = cls._get_key_file_path(device_type)
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            if content:
                try:
                    return cls.load_rsa_public_key(content)
                except Exception:
                    pass

        # Fallback: busca chave cadastrada no modelo User se for desktop
        if device_type == 'desktop':
            try:
                from Domain.models.schemas.moderation.userSchema import User
                user_with_key = User.objects.filter(machine_public_key__isnull=False, is_active=True).exclude(machine_public_key='').first()
                if user_with_key and user_with_key.machine_public_key:
                    try:
                        cls.save_client_public_key(device_type, user_with_key.machine_public_key)
                    except Exception:
                        pass
                    return cls.load_rsa_public_key(user_with_key.machine_public_key)
            except Exception:
                pass

        return None

    @classmethod
    def encrypt_response_hybrid(cls, public_key, data_bytes: bytes) -> dict:
        """
        Criptografa bytes de resposta com AES-GCM (32 bytes)
        e cifra a chave AES com a chave pública RSA do cliente.
        """
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        aesgcm = AESGCM(aes_key)

        encrypted_data = aesgcm.encrypt(iv, data_bytes, None)
        tag_length = 16
        ciphertext = encrypted_data[:-tag_length]
        tag = encrypted_data[-tag_length:]

        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.PKCS1v15()
        )

        return {
            "encrypted_payload": base64.b64encode(ciphertext).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }

    @classmethod
    def verify_signature(cls, public_key, data: bytes, signature_b64: str) -> bool:
        """
        Verifica a assinatura digital RSA usando a chave pública informada.
        Compatível com RSA-PSS (MAX_LENGTH, DIGEST_LENGTH, AUTO) e PKCS1v15,
        garantindo suporte a hardware TPM, software e clientes multiplataforma.
        """
        try:
            if not isinstance(public_key, rsa.RSAPublicKey):
                public_key = cls.load_rsa_public_key(public_key)

            sig_bytes = base64.b64decode(signature_b64.strip())

            for pad in [
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
                padding.PKCS1v15(),
            ]:
                try:
                    public_key.verify(sig_bytes, data, pad, hashes.SHA256())
                    return True
                except Exception:
                    continue

            return False
        except Exception:
            return False

    @classmethod
    def verify_payload_signature(cls, public_key, payload_dict: dict) -> bool:
        """
        Verifica a assinatura RSA-PSS embutida no payload descriptografado.
        Segue estritamente o padrão do VotaAI Desktop:
        O Desktop serializa o dicionário canônico (sem o campo 'signature', com chaves ordenadas
        e sem espaços) em UTF-8, assina com a chave privada de hardware via RSA-PSS
        e injeta o resultado em Base64 no campo 'signature'.
        """
        signature_b64 = payload_dict.get('signature')
        if not signature_b64:
            return False

        # Modo estrito do Desktop: todo o payload exceto 'signature'
        canonical_dict = {k: v for k, v in payload_dict.items() if k != 'signature'}
        canonical_bytes = json.dumps(
            canonical_dict,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False
        ).encode('utf-8')

        return cls.verify_signature(public_key, canonical_bytes, signature_b64)


