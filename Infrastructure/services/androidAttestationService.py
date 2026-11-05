import base64
import hashlib
import logging
from typing import Optional, Dict, Any, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature
from django.conf import settings
from Infrastructure.services.seCryptoService import SECryptoService

logger = logging.getLogger(__name__)

class AndroidAttestationService:
    """
    Serviço para validação de chaves geradas em hardware seguro (TEE ou StrongBox) no Android KeyStore.
    
    Aceita chaves geradas em hardware seguro:
    - Nível 1: TrustedEnvironment (TEE via ARM TrustZone)
    - Nível 2: StrongBox (Secure Element / chip dedicado)
    Chaves em Software (0) são terminantemente rejeitadas.
    """

    ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    # Níveis de segurança conforme a especificação do Android KeyStore Attestation
    SECURITY_LEVEL_MAP = {
        0: "Software",
        1: "TrustedEnvironment",  # TEE (TrustZone)
        2: "StrongBox"             # Secure Element dedicado (Hardware Físico)
    }

    # Fingerprints SHA-256 das chaves públicas do Google Attestation Root CA
    GOOGLE_HARDWARE_ROOT_PUBKEY_SHA256 = "bbaeb3041511110a3f9d99ff74a14c19def43e3d9e383236f6d81081a75d564f"
    GOOGLE_SOFTWARE_ROOT_PUBKEY_SHA256 = "865a7d2b23cb6025bc43ad5d09e53008976bcf608cbb94b79a0cf5b2c2c0352d"

    @classmethod
    def _parse_der_tlv(cls, data: bytes, offset: int = 0) -> tuple[Optional[tuple[int, bytes]], int]:
        """
        Parser DER TLV (Tag-Length-Value) em baixo nível sem dependências externas.
        Suporta comprimentos curtos (< 128 bytes) e comprimentos longos multi-byte.
        """
        if offset >= len(data):
            return None, offset

        tag = data[offset]
        offset += 1

        if offset >= len(data):
            return None, offset

        length_byte = data[offset]
        offset += 1

        if length_byte < 0x80:
            length = length_byte
        else:
            num_len_bytes = length_byte & 0x7F
            if offset + num_len_bytes > len(data):
                raise ValueError("DER TLV: comprimento inválido ou corrompido.")
            length = int.from_bytes(data[offset:offset+num_len_bytes], byteorder='big')
            offset += num_len_bytes

        if offset + length > len(data):
            raise ValueError("DER TLV: tamanho do conteúdo ultrapassa os bytes disponíveis.")

        value = data[offset:offset+length]
        return (tag, value), offset + length

    @classmethod
    def parse_attestation_extension(cls, raw_asn1_bytes: bytes) -> Dict[str, Any]:
        """
        Faz o parse da estrutura ASN.1 Sequence da extensão KeyDescription (OID 1.3.6.1.4.1.11129.2.1.17):
        
        KeyDescription ::= SEQUENCE {
            attestationVersion         INTEGER,
            attestationSecurityLevel   SecurityLevel (ENUMERATED: 0=Software, 1=TEE, 2=StrongBox),
            keymasterVersion           INTEGER,
            keymasterSecurityLevel     SecurityLevel (ENUMERATED),
            attestationChallenge       OCTET STRING,
            uniqueId                   OCTET STRING,
            softwareEnforced           AuthorizationList,
            teeEnforced                AuthorizationList
        }
        """
        (tag, seq_bytes), _ = cls._parse_der_tlv(raw_asn1_bytes, 0)
        if tag != 0x30:  # 0x30 = SEQUENCE
            raise ValueError("A extensão de atestação Android deve iniciar com uma ASN.1 SEQUENCE.")

        offset = 0
        fields = []
        while offset < len(seq_bytes):
            tlv, offset = cls._parse_der_tlv(seq_bytes, offset)
            if tlv:
                fields.append(tlv)

        if len(fields) < 4:
            raise ValueError("Estrutura ASN.1 incompleta na extensão de atestação Android.")

        attestation_version = int.from_bytes(fields[0][1], byteorder='big')
        attestation_sec_level_raw = int.from_bytes(fields[1][1], byteorder='big')
        keymaster_version = int.from_bytes(fields[2][1], byteorder='big')
        keymaster_sec_level_raw = int.from_bytes(fields[3][1], byteorder='big')

        challenge_bytes = b""
        if len(fields) >= 5 and fields[4][0] == 0x04:  # OCTET STRING
            challenge_bytes = fields[4][1]

        att_security_level = cls.SECURITY_LEVEL_MAP.get(attestation_sec_level_raw, f"Unknown({attestation_sec_level_raw})")
        km_security_level = cls.SECURITY_LEVEL_MAP.get(keymaster_sec_level_raw, f"Unknown({keymaster_sec_level_raw})")

        is_strongbox = (attestation_sec_level_raw == 2 or keymaster_sec_level_raw == 2)
        is_hardware = (attestation_sec_level_raw in (1, 2) or keymaster_sec_level_raw in (1, 2))

        return {
            "attestation_version": attestation_version,
            "attestation_security_level_raw": attestation_sec_level_raw,
            "attestation_security_level": att_security_level,
            "keymaster_version": keymaster_version,
            "keymaster_security_level": km_security_level,
            "challenge_bytes": challenge_bytes,
            "is_hardware_backed": is_hardware,
            "is_strongbox": is_strongbox,
        }

    @classmethod
    def load_certificates(cls, certs_data: List[str]) -> List[x509.Certificate]:
        """
        Carrega lista de certificados em formato PEM ou DER Base64.
        """
        certs = []
        for item in certs_data:
            item_clean = item.strip()
            if "-----BEGIN CERTIFICATE-----" in item_clean:
                cert = x509.load_pem_x509_certificate(item_clean.encode('utf-8'), default_backend())
            else:
                raw_bytes = base64.b64decode(item_clean)
                cert = x509.load_der_x509_certificate(raw_bytes, default_backend())
            certs.append(cert)
        return certs

    @classmethod
    def verify_cert_chain(cls, certs: List[x509.Certificate]) -> bool:
        """
        Verifica a cadeia de assinaturas dos certificados (Leaf -> Intermediate -> Root).
        """
        if len(certs) < 2:
            return True

        for i in range(len(certs) - 1):
            child = certs[i]
            parent = certs[i + 1]

            if child.issuer != parent.subject:
                return False

            parent_pubkey = parent.public_key()
            try:
                if isinstance(parent_pubkey, ec.EllipticCurvePublicKey):
                    parent_pubkey.verify(
                        child.signature,
                        child.tbs_certificate_bytes,
                        ec.ECDSA(child.signature_hash_algorithm)
                    )
                elif isinstance(parent_pubkey, rsa.RSAPublicKey):
                    parent_pubkey.verify(
                        child.signature,
                        child.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        child.signature_hash_algorithm
                    )
                else:
                    return False
            except InvalidSignature:
                return False

        return True

    @classmethod
    def validate_hardware_key(
        cls,
        machine_public_key: str,
        attestation_certificates: Optional[List[str]] = None,
        expected_challenge: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executa a validação de hardware seguro (TEE ou StrongBox) para o Android KeyStore.
        
        Exige obrigatoriamente:
        1. Presença da cadeia de certificados X.509 de atestação.
        2. Presença da extensão OID 1.3.6.1.4.1.11129.2.1.17 no certificado folha.
        3. Nível de segurança em hardware seguro: TEE (1) ou StrongBox (2).
        4. Coincidência exata entre a chave pública do certificado folha e a machine_public_key.
        5. Assinaturas válidas na cadeia de certificados.
        """
        if not attestation_certificates or len(attestation_certificates) == 0:
            return {
                "is_hardware_backed": False,
                "is_strongbox": False,
                "security_level": "MissingAttestation",
                "method": "android_key_attestation",
                "verified": False,
                "error": "Cadeia de certificados de atestação Android KeyStore (TEE ou StrongBox) é obrigatória."
            }

        # 1. Valida se a chave pública informada é legível e válida
        try:
            pub_key_obj = SECryptoService.load_rsa_public_key(machine_public_key)
        except Exception:
            try:
                # Tenta carregar chave EC se for curva elíptica
                if isinstance(machine_public_key, str) and machine_public_key.strip().startswith('-----BEGIN'):
                    pub_key_obj = serialization.load_pem_public_key(machine_public_key.encode('utf-8'))
                else:
                    pub_key_bytes = base64.b64decode(machine_public_key)
                    pub_key_obj = serialization.load_der_public_key(pub_key_bytes)
            except Exception as e:
                raise ValueError(f"Formato da chave pública do dispositivo é inválido: {e}")

        # 2. Carrega e valida certificados
        try:
            chain = cls.load_certificates(attestation_certificates)
            if not chain:
                raise ValueError("Cadeia de certificados de atestação vazia.")

            leaf_cert = chain[0]

            # Localiza a extensão OID 1.3.6.1.4.1.11129.2.1.17
            att_ext_bytes = None
            for ext in leaf_cert.extensions:
                if ext.oid.dotted_string == cls.ANDROID_KEY_ATTESTATION_OID:
                    att_ext_bytes = ext.value.value
                    break

            if not att_ext_bytes:
                logger.warning(
                    f"[ATTESTATION_CERT_WARNING] Certificado recebido não contém a extensão Android Key Attestation (OID {cls.ANDROID_KEY_ATTESTATION_OID}). "
                    f"Subject: '{leaf_cert.subject.rfc4514_string()}', Issuer: '{leaf_cert.issuer.rfc4514_string()}'. "
                    f"Total de certificados na cadeia: {len(chain)}."
                )
                if not getattr(settings, 'REQUIRE_HARDWARE_ATTESTATION', True):
                    logger.warning("[ATTESTATION_DEV_BYPASS] Atestação estrita de hardware dispensada via REQUIRE_HARDWARE_ATTESTATION=False no .env.")
                    return {
                        "is_hardware_backed": True,
                        "is_strongbox": False,
                        "security_level": "DevFallback",
                        "method": "android_key_attestation",
                        "verified": True,
                        "details": "Modo de desenvolvimento: validação estrita de hardware dispensada via .env."
                    }
                return {
                    "is_hardware_backed": False,
                    "is_strongbox": False,
                    "security_level": "NoAttestationExtension",
                    "method": "android_key_attestation",
                    "verified": False,
                    "error": "Certificado não contém a extensão Android Key Attestation (OID 1.3.6.1.4.1.11129.2.1.17)."
                }

            # Decodifica os campos ASN.1 da extensão
            parsed_ext = cls.parse_attestation_extension(att_ext_bytes)

            # 3. EXIGÊNCIA DE HARDWARE: Aceita TEE (nível 1) ou StrongBox (nível 2). Rejeita Software (nível 0).
            if not parsed_ext.get("is_hardware_backed"):
                sec_level = parsed_ext.get("attestation_security_level")
                if not getattr(settings, 'REQUIRE_HARDWARE_ATTESTATION', True):
                    logger.warning(f"[ATTESTATION_DEV_BYPASS] Nível {sec_level} aceito via REQUIRE_HARDWARE_ATTESTATION=False no .env.")
                    return {
                        "is_hardware_backed": True,
                        "is_strongbox": False,
                        "security_level": sec_level,
                        "method": "android_key_attestation",
                        "verified": True,
                        "details": f"Modo de desenvolvimento: nível {sec_level} aceito via .env."
                    }
                return {
                    "is_hardware_backed": False,
                    "is_strongbox": False,
                    "security_level": sec_level,
                    "method": "android_key_attestation",
                    "verified": False,
                    "error": f"Nível de segurança rejeitado ({sec_level}). Apenas chaves geradas em hardware seguro (TEE ou StrongBox) são autorizadas."
                }

            # 4. Verifica se a chave pública do certificado folha bate com a chave enviada
            leaf_pub_pem = leaf_cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8').strip()

            sent_pub_pem = pub_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8').strip()

            if leaf_pub_pem != sent_pub_pem:
                return {
                    "is_hardware_backed": False,
                    "is_strongbox": False,
                    "security_level": parsed_ext.get("attestation_security_level"),
                    "method": "android_key_attestation",
                    "verified": False,
                    "error": "A chave pública do certificado de atestação não coincide com a machine_public_key declarada."
                }

            # 5. Valida a cadeia de certificados
            chain_valid = cls.verify_cert_chain(chain)
            if not chain_valid:
                return {
                    "is_hardware_backed": False,
                    "is_strongbox": False,
                    "security_level": parsed_ext.get("attestation_security_level"),
                    "method": "android_key_attestation",
                    "verified": False,
                    "error": "Assinatura da cadeia de certificados X.509 de atestação é inválida."
                }

            # 6. Valida desafio se especificado
            challenge_valid = True
            if expected_challenge:
                challenge_valid = (parsed_ext.get("challenge_bytes") == expected_challenge.encode('utf-8'))

            if not challenge_valid:
                return {
                    "is_hardware_backed": False,
                    "is_strongbox": False,
                    "security_level": parsed_ext.get("attestation_security_level"),
                    "method": "android_key_attestation",
                    "verified": False,
                    "error": "O desafio (challenge) da atestação de hardware não coincide com o token esperado."
                }

            sec_level = parsed_ext.get("attestation_security_level")
            return {
                "is_hardware_backed": True,
                "is_strongbox": parsed_ext.get("is_strongbox", False),
                "security_level": sec_level,
                "keymaster_security_level": parsed_ext.get("keymaster_security_level"),
                "attestation_version": parsed_ext.get("attestation_version"),
                "chain_valid": True,
                "challenge_valid": True,
                "method": "android_key_attestation",
                "verified": True,
                "details": f"Chave gerada e atestada por hardware seguro ({sec_level})."
            }

        except Exception as e:
            logger.warning(f"Falha ao processar atestação StrongBox Android: {e}")
            return {
                "is_hardware_backed": False,
                "is_strongbox": False,
                "security_level": "AttestationError",
                "method": "android_key_attestation",
                "verified": False,
                "error": f"Erro na análise dos certificados de atestação: {str(e)}"
            }
