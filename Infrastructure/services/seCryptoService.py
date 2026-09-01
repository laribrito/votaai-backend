import ctypes
from ctypes import wintypes
import base64

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

ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
ncrypt.NCryptFreeObject.restype = wintypes.LONG

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
