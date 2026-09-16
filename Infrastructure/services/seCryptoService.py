import ctypes
from ctypes import wintypes
import os
import struct
import base64
from pathlib import Path
from django.conf import settings
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes


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
    @staticmethod
    def decrypt_with_tpm(key_name: str, base64_ciphertext: str) -> bytes:
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
        Retorna None se o arquivo não existir.
        """
        file_path = cls._get_key_file_path(device_type)
        if not file_path.exists():
            return None
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        if not content:
            return None
        return cls.load_rsa_public_key(content)

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

    @staticmethod
    def sign_with_tpm(key_name: str, data: bytes) -> str:
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
    def verify_signature(cls, public_key, data: bytes, signature_b64: str) -> bool:
        """
        Verifica a assinatura digital RSA PKCS#1 v1.5 + SHA-256 usando a chave pública informada.
        Suporta instância de RSAPublicKey ou chave em formato PEM/DER/CNG BLOB.
        """
        try:
            if not isinstance(public_key, rsa.RSAPublicKey):
                public_key = cls.load_rsa_public_key(public_key)

            sig_bytes = base64.b64decode(signature_b64.strip())
            public_key.verify(
                sig_bytes,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

