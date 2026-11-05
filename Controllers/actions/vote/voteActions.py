import hashlib
import json
import logging
import re
import secrets
import uuid
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from cryptography.hazmat.primitives import serialization
from Domain.models.schemas.election.votingTokenSchema import VotingToken
from Domain.models.schemas.election.electionSchema import ElectionStatus
from Domain.models.schemas.election.voteSchema import Vote
from Domain.models.schemas.election.ballotTicketSchema import BallotTicket
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

        # 6. Informa e registra quando uma nova sessão de cédula for solicitada antes da finalização
        norm_saved = SECryptoService.to_pem_public_key(token_obj.machine_public_key)
        norm_sent = SECryptoService.to_pem_public_key(machine_pub_key)
        if norm_saved and norm_saved != norm_sent:
            logger.info(
                f"[VOTING_TOKEN_REISSUED] Eleitor '{voter.email}': Votação anterior não finalizada com o id_voto antigo. "
                f"Revinculando chave de máquina de hardware para nova sessão de cédula e emissão de novo id_voto."
            )

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

        # Invalidação opcional de id_voto anterior não consumido se informado pelo cliente
        previous_id_voto = str(data.get('previous_id_voto') or data.get('old_id_voto') or '').strip()
        if previous_id_voto:
            BallotTicket.objects.filter(election=election, id_voto=previous_id_voto, is_used=False).delete()
            logger.info(
                f"[VOTING_TOKEN_PREVIOUS_CLEANED] Eleitor '{voter.email}': id_voto não finalizado '{previous_id_voto}' "
                f"foi invalidado com sucesso."
            )

        # 10. Garante e monta as perguntas e opções da cédula eleitoral (assegurando as opções 'Branco' e 'Nulo')
        election.ensure_default_ballot_options()
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

        # 11. Emite um ID de Voto anônimo (BallotTicket) desvinculado dos dados do eleitor
        id_voto = f"VOTE-{secrets.token_hex(16).upper()}"
        BallotTicket.objects.create(
            election=election,
            id_voto=id_voto,
            is_used=False
        )

        # 12. Retorno estruturado conforme o contrato estrito
        election_pub_key = SECryptoService.to_pem_public_key(election.public_key)

        return {
            "election": {
                "id": election.id,
                "title": election.title,
                "public_key": election_pub_key,
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
            "nonce": nonce,
            "id_voto": id_voto
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
        id_voto = str(data.get('id_voto') or '').strip()

        # Camada 1: Identifica se content traz a estrutura JSON (pacote cifrado com a chave da eleição + ID Voto exposto)
        exposed_id_voto = id_voto
        pacote_cifrado = None
        try:
            content_parsed = json.loads(content)
            if isinstance(content_parsed, dict):
                if 'id_voto' in content_parsed and not exposed_id_voto:
                    exposed_id_voto = str(content_parsed.get('id_voto') or '').strip()
                if 'pacote_cifrado' in content_parsed:
                    pacote_cifrado = str(content_parsed.get('pacote_cifrado') or '').strip()
        except Exception:
            pass

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
        saved_key = SECryptoService.to_pem_public_key(token_obj.machine_public_key)
        sent_key = SECryptoService.to_pem_public_key(machine_pub_key)
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
            # Testa assinatura no conteúdo ou variações suportadas (Camada 2 - TEE com Chave Privada do Eleitor)
            is_valid_sig = SECryptoService.verify_signature(machine_pub_key, content.encode('utf-8'), signature)
            if not is_valid_sig:
                is_valid_sig = SECryptoService.verify_signature(machine_pub_key, f"{content}:{nonce}".encode('utf-8'), signature)
            if not is_valid_sig and pacote_cifrado and exposed_id_voto:
                is_valid_sig = SECryptoService.verify_signature(machine_pub_key, f"{exposed_id_voto}:{pacote_cifrado}".encode('utf-8'), signature)
            if not is_valid_sig and pacote_cifrado:
                is_valid_sig = SECryptoService.verify_signature(machine_pub_key, pacote_cifrado.encode('utf-8'), signature)
            if not is_valid_sig:
                logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Assinatura digital do voto inválida.")
                token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
                raise ValidationError({"signature": _("Invalid digital signature for the ballot payload.")})

        # 8.1. Validação do ticket de cédula anônima (BallotTicket), se id_voto foi fornecido
        ballot_ticket = None
        if exposed_id_voto:
            ballot_ticket = BallotTicket.objects.filter(election=election, id_voto=exposed_id_voto).first()
            if not ballot_ticket:
                logger.warning(
                    f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': id_voto '{exposed_id_voto}' não encontrado na eleição #{election.id}."
                )
                token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
                raise ValidationError({"id_voto": _("Invalid or unrecognized vote ID for this election.")})
            if ballot_ticket.is_used:
                logger.warning(
                    f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': id_voto '{exposed_id_voto}' já foi consumido."
                )
                token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
                raise ValidationError({"id_voto": _("This vote ID has already been consumed.")})

        # 9. Geração do recibo/comprovante anônimo e depósito do voto na urna eleitoral
        now = timezone.now()
        if exposed_id_voto:
            raw_receipt = f"{election.id}:{exposed_id_voto}:{content}:{uuid.uuid4().hex}:{now.isoformat()}"
        else:
            raw_receipt = f"{election.id}:{content}:{uuid.uuid4().hex}:{now.isoformat()}"
        receipt_hash = hashlib.sha256(raw_receipt.encode('utf-8')).hexdigest().upper()
        receipt_id = f"VOTE-{receipt_hash}"

        # Persiste o voto anônimo (Sem relação de chave estrangeira com o eleitor)
        Vote.objects.create(
            id_generated=receipt_id,
            content=content,
            election=election
        )

        # Consome o BallotTicket anônimo com seu timestamp próprio isolado
        if ballot_ticket:
            ballot_ticket.is_used = True
            ballot_ticket.used_at = now
            ballot_ticket.save(update_fields=['is_used', 'used_at'])

        # 10. Consome o token de uso único e marca que o eleitor votou (sem timestamp para evitar correlação)
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
            "id_voto": exposed_id_voto or None,
            "election_id": election.id,
            "deposited_at": now,
            "status": "CONFIRMED",
            "nonce": nonce
        }
