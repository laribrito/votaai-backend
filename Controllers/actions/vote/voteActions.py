import hashlib
import logging
import uuid
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from Domain.models.schemas.election.votingTokenSchema import VotingToken
from Domain.models.schemas.election.electionSchema import ElectionStatus
from Domain.models.schemas.election.voteSchema import Vote
from Infrastructure.services.votingTokenService import VotingTokenService
from Infrastructure.services.androidAttestationService import AndroidAttestationService
from Infrastructure.services.seCryptoService import SECryptoService

logger = logging.getLogger(__name__)

class VoteActions:
    """
    Business actions for the voting process:
    Orchestrates vote ballot requesting, ballot casting, token validation,
    anti-replay nonces, Android StrongBox hardware attestation, failed attempt tracking,
    device binding, and anonymous ballot deposition.
    """

    MAX_FAILED_ATTEMPTS = getattr(settings, 'VOTING_TOKEN_MAX_FAILED_ATTEMPTS', 3)
    MAX_IP_FAILURES = 10

    @classmethod
    def get_max_failed_attempts(cls) -> int:
        """Returns the maximum failed attempts dynamically from Django settings / .env."""
        return getattr(settings, 'VOTING_TOKEN_MAX_FAILED_ATTEMPTS', cls.MAX_FAILED_ATTEMPTS)

    @classmethod
    def requestVote(cls, data: dict, raw_data: dict | None = None, ip_address: str | None = None) -> dict:
        """
        Validates the voter's single-use token, checks election and voter eligibility,
        evaluates Android hardware key attestation against StrongBox, protects against replay nonces,
        tracks failed invalid attempts (locking out after threshold), and binds the device.
        """
        raw_token = str(data.get('token') or '').strip()
        machine_pub_key = str(data.get('machine_public_key') or '').strip()
        attestation_certs = data.get('attestation_certificates') or []
        nonce = str(data.get('nonce') or '').strip()

        # 0. Proteção contra força bruta no nível de IP
        ip_fail_key = f"vote_ip_failures_{ip_address}" if ip_address else None
        if ip_fail_key:
            current_ip_fails = cache.get(ip_fail_key, 0)
            if current_ip_fails >= cls.MAX_IP_FAILURES:
                raise ValidationError({"error": _("Too many invalid attempts from this IP address. Access temporarily suspended.")})

        if not raw_token:
            raise ValidationError({"token": _("The voting token is required.")})

        if not machine_pub_key:
            raise ValidationError({"machine_public_key": _("The machine public key is required.")})

        if not nonce:
            raise ValidationError({"nonce": _("The client nonce is required.")})

        # 1. Valida o hash do token contra o banco de dados
        token_hash = VotingTokenService._hash_token(raw_token)
        token_obj = VotingToken.objects.select_related('voter', 'election').filter(token_hash=token_hash).first()

        if not token_obj:
            if ip_fail_key:
                cache.set(ip_fail_key, current_ip_fails + 1, timeout=900)
            raise ValidationError({"token": _("Invalid voting token.")})

        # 2. Verifica se o token já está bloqueado por excesso de tentativas inválidas
        if getattr(token_obj, 'is_blocked', False):
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{token_obj.voter.email}': Token já está bloqueado.")
            raise ValidationError({
                "token": _("This voting token has been blocked due to multiple invalid attempts. Contact the election administrator.")
            })

        # 3. Verifica se o token já foi consumido
        if token_obj.is_used:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{token_obj.voter.email}': Token já foi consumido anteriormente.")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({"token": _("This voting token has already been consumed.")})

        # 4. Verifica o estado da eleição
        election = token_obj.election
        if election.status != ElectionStatus.STARTED:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{token_obj.voter.email}': Eleição #{election.id} com status '{election.status}' (esperado STARTED).")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            if election.status == ElectionStatus.CREATED:
                raise ValidationError({"election": _("This election has not started yet.")})
            elif election.status in (ElectionStatus.CLOSED, ElectionStatus.TALLIED):
                raise ValidationError({"election": _("This election has already closed.")})
            else:
                raise ValidationError({"election": _("This election is not open for voting.")})

        # 5. Verifica se o eleitor já votou
        voter = token_obj.voter
        if voter.has_voted:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Eleitor já votou.")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({"voter": _("This voter has already cast their ballot.")})

        # 6. Verifica tentativa de usurpação de token por dispositivo diferente
        if token_obj.machine_public_key and token_obj.machine_public_key.strip() != machine_pub_key:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Chave pública de máquina diferente da vinculada.")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({
                "machine_public_key": _("Access denied: this voting token is already bound to a different device.")
            })

        # 7. Validação anti-replay do Nonce
        nonce_cache_key = f"vote_nonce_used_{nonce}"
        if (token_obj.nonce and token_obj.nonce == nonce) or cache.get(nonce_cache_key):
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Replay de nonce detectado ('{nonce}').")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({"nonce": _("Replay detected: this nonce has already been used.")})

        # 8. Avalia a chave e certificados de hardware via AndroidAttestationService (exige estritamente StrongBox)
        #    O desafio de atestação (challenge) deve coincidir com o nonce para provar atestação em tempo real.
        try:
            attestation_result = AndroidAttestationService.validate_hardware_key(
                machine_public_key=machine_pub_key,
                attestation_certificates=attestation_certs,
                expected_challenge=nonce
            )
        except Exception as e:
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            logger.error(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Erro ao processar chave da máquina: {e}")
            raise ValidationError({"machine_public_key": _("Invalid machine public key: %(error)s") % {'error': str(e)}})

        if not attestation_result.get("verified") or not attestation_result.get("is_hardware_backed"):
            err_msg = attestation_result.get("error") or _("Access denied: only hardware-backed keys (TEE or StrongBox) are accepted.")
            logger.warning(
                f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Rejeitado na atestação de hardware: '{err_msg}'. "
                f"Certificados recebidos: {len(attestation_certs)}. "
                f"Nível de segurança detectado: '{attestation_result.get('security_level')}'."
            )
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({"attestation_certificates": err_msg})

        # 9. Sucesso: registra tentativa bem-sucedida, reseta falhas, amarra chave e nonce
        token_obj.record_successful_attempt(
            machine_public_key=machine_pub_key,
            nonce=nonce,
            ip_address=ip_address
        )
        cache.set(nonce_cache_key, True, timeout=86400)
        if ip_fail_key:
            cache.delete(ip_fail_key)

        # 10. Monta as perguntas e opções da cédula eleitoral
        questions_qs = election.questions.prefetch_related('options').order_by('order', 'id')
        questions_payload = []
        for q in questions_qs:
            options_payload = [
                {"id": opt.id, "label": opt.label}
                for opt in q.options.all().order_by('id')
            ]
            questions_payload.append({
                "id": q.id,
                "question": q.question,
                "order": q.order,
                "options": options_payload
            })

        # 11. Retorno estruturado conforme o contrato estrito
        return {
            "election": {
                "id": election.id,
                "title": election.title,
                "public_key": election.public_key,
                "start_datetime": election.start_datetime,
                "end_datetime": election.end_datetime,
                "questions": questions_payload
            },
            "voter": {
                "id": voter.id,
                "full_name": voter.full_name,
                "nickname": voter.nickname or voter.get_first_name(),
                "email": voter.email
            },
            "attestation": attestation_result,
            "nonce": nonce
        }

    @classmethod
    def castVote(cls, data: dict, raw_data: dict | None = None, ip_address: str | None = None) -> dict:
        """
        Receives an encrypted ballot, validates token authenticity, device binding against
        the StrongBox key that requested the ballot, anti-replay nonces, and records the anonymous
        vote in the ballot box while consuming the single-use token.
        """
        raw_token = str(data.get('token') or '').strip()
        machine_pub_key = str(data.get('machine_public_key') or '').strip()
        content = str(data.get('content') or '').strip()
        nonce = str(data.get('nonce') or '').strip()
        signature = str(data.get('signature') or '').strip()

        # 0. Proteção contra força bruta no nível de IP
        ip_fail_key = f"vote_ip_failures_{ip_address}" if ip_address else None
        if ip_fail_key:
            current_ip_fails = cache.get(ip_fail_key, 0)
            if current_ip_fails >= cls.MAX_IP_FAILURES:
                raise ValidationError({"error": _("Too many invalid attempts from this IP address. Access temporarily suspended.")})

        if not raw_token:
            raise ValidationError({"token": _("The voting token is required.")})

        if not machine_pub_key:
            raise ValidationError({"machine_public_key": _("The machine public key is required.")})

        if not content:
            raise ValidationError({"content": _("The encrypted vote content is required.")})

        if not nonce:
            raise ValidationError({"nonce": _("The client nonce is required.")})

        # 1. Valida o hash do token contra o banco de dados
        token_hash = VotingTokenService._hash_token(raw_token)
        token_obj = VotingToken.objects.select_related('voter', 'election').filter(token_hash=token_hash).first()

        if not token_obj:
            if ip_fail_key:
                cache.set(ip_fail_key, current_ip_fails + 1, timeout=900)
            raise ValidationError({"token": _("Invalid voting token.")})

        # 2. Verifica se o token está bloqueado
        if getattr(token_obj, 'is_blocked', False):
            raise ValidationError({
                "token": _("This voting token has been blocked due to multiple invalid attempts. Contact the election administrator.")
            })

        # 3. Verifica se o token já foi consumido
        if token_obj.is_used:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{token_obj.voter.email}': Token já foi consumido anteriormente.")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({"token": _("This voting token has already been consumed.")})

        # 4. Verifica estado da eleição
        election = token_obj.election
        if election.status != ElectionStatus.STARTED:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{token_obj.voter.email}': Eleição #{election.id} com status '{election.status}' (esperado STARTED).")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            if election.status == ElectionStatus.CREATED:
                raise ValidationError({"election": _("This election has not started yet.")})
            elif election.status in (ElectionStatus.CLOSED, ElectionStatus.TALLIED):
                raise ValidationError({"election": _("This election has already closed.")})
            else:
                raise ValidationError({"election": _("This election is not open for voting.")})

        # 5. Verifica se o eleitor já votou
        voter = token_obj.voter
        if voter.has_voted:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Eleitor já votou.")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({"voter": _("This voter has already cast their ballot.")})

        # 6. Verifica se o dispositivo é o mesmo que solicitou a cédula (binding estrito de hardware)
        saved_key = (token_obj.machine_public_key or '').replace('\r\n', '\n').strip()
        sent_key = machine_pub_key.replace('\r\n', '\n').strip()
        if saved_key and saved_key != sent_key:
            logger.warning(
                f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Chave pública de máquina enviada no depósito "
                f"diferente da vinculada na solicitação da cédula."
            )
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({
                "machine_public_key": _("Access denied: this voting token is bound to a different mobile device.")
            })

        # 7. Validação anti-replay do Nonce
        nonce_cache_key = f"vote_nonce_used_{nonce}"
        if (token_obj.nonce and token_obj.nonce == nonce) or cache.get(nonce_cache_key):
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Replay de nonce detectado ('{nonce}').")
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise ValidationError({"nonce": _("Replay detected: this nonce has already been used.")})

        # 8. Validação da assinatura digital do dispositivo (se fornecida)
        if signature:
            # Testa assinatura no conteúdo ou conteúdo + nonce
            is_valid_sig = SECryptoService.verify_signature(machine_pub_key, content.encode('utf-8'), signature)
            if not is_valid_sig:
                is_valid_sig = SECryptoService.verify_signature(machine_pub_key, f"{content}:{nonce}".encode('utf-8'), signature)
            if not is_valid_sig:
                logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Assinatura digital do voto inválida.")
                token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
                raise ValidationError({"signature": _("Invalid digital signature for the ballot payload.")})

        # 9. Geração do recibo/comprovante anônimo e depósito do voto na urna eleitoral
        now = timezone.now()
        raw_receipt = f"{election.id}:{content}:{uuid.uuid4().hex}:{now.isoformat()}"
        receipt_hash = hashlib.sha256(raw_receipt.encode('utf-8')).hexdigest().upper()
        receipt_id = f"VOTE-{receipt_hash}"

        # Persiste o voto anônimo (Sem relação de chave estrangeira com o eleitor)
        Vote.objects.create(
            id_generated=receipt_id,
            content=content,
            election=election
        )

        # 10. Consome o token de uso único e marca que o eleitor votou
        token_obj.mark_as_used(ip_address=ip_address)
        voter.has_voted = True
        voter.save(update_fields=['has_voted'])

        cache.set(nonce_cache_key, True, timeout=86400)
        if ip_fail_key:
            cache.delete(ip_fail_key)

        logger.info(
            f"[VOTE_CAST_SUCCESS] Cédula eleitoral depositada com sucesso na eleição #{election.id}. "
            f"Comprovante gerado: {receipt_id} (IP: {ip_address or 'desconhecido'})."
        )

        return {
            "receipt": receipt_id,
            "election_id": election.id,
            "deposited_at": now,
            "status": "CONFIRMED",
            "nonce": nonce
        }
