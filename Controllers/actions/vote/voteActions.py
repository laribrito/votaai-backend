import hashlib
import json
import logging
import re
import secrets
import time
import uuid
from django.conf import settings
from django.core.cache import cache
from django.db import DatabaseError, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from cryptography.hazmat.primitives import serialization
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
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
    def _check_ip_rate_limit(cls, ip_address: str | None) -> tuple[str | None, int]:
        """Checks whether the client IP has exceeded the failed-attempt threshold."""
        ip_fail_key = f"vote_ip_failures_{ip_address}" if ip_address else None
        current_ip_fails = cache.get(ip_fail_key, 0) if ip_fail_key else 0
        if ip_fail_key and current_ip_fails >= cls.MAX_IP_FAILURES:
            raise ValidationError({"error": _("Too many invalid attempts from this IP address. Access temporarily suspended.")})
        return ip_fail_key, current_ip_fails

    @classmethod
    def _increment_ip_failure(cls, ip_fail_key: str | None, current_ip_fails: int) -> None:
        """Records a failed IP attempt in cache when an invalid token is submitted."""
        if ip_fail_key:
            cache.set(ip_fail_key, current_ip_fails + 1, timeout=900)

    @classmethod
    def _finalize_nonce_and_ip_cache(cls, nonce_cache_key: str, ip_fail_key: str | None) -> None:
        """Marks the nonce as used and clears any IP failure counter after success."""
        cache.set(nonce_cache_key, True, timeout=86400)
        if ip_fail_key:
            cache.delete(ip_fail_key)

    @classmethod
    def _validate_required_fields(
        cls,
        raw_token: str,
        machine_pub_key: str,
        nonce: str,
        content: str | None = None,
        require_content: bool = False,
    ) -> None:
        """Validates that mandatory request payload fields are present."""
        if not raw_token:
            raise ValidationError({"token": _("The voting token is required.")})

        if not machine_pub_key:
            raise ValidationError({"machine_public_key": _("The machine public key is required.")})

        if require_content and not content:
            raise ValidationError({"content": _("The encrypted vote content is required.")})

        if not nonce:
            raise ValidationError({"nonce": _("The client nonce is required.")})

    @classmethod
    def _invalid_token_error(cls) -> ValidationError:
        """Returns the standardized error for an unrecognized voting token."""
        return ValidationError({"token": _("Invalid voting token.")})

    @classmethod
    def _validate_token_election_and_voter(
        cls,
        token_obj: VotingToken,
        voter: ElectoralCollege,
        election,
    ) -> tuple[ValidationError | None, bool]:
        """
        Validates token state (consumed/blocked), election status, and voter eligibility.
        Returns `(validation_error, should_record_failure)`.
        """
        # Verifica se o token já foi consumido (estado terminal: não incrementa falhas nem bloqueia)
        if token_obj.is_used:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Token já foi consumido anteriormente.")
            return ValidationError({"token": _("This voting token has already been consumed.")}), False

        # Verifica se o token já está bloqueado por excesso de tentativas inválidas
        if getattr(token_obj, 'is_blocked', False):
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Token já está bloqueado.")
            return ValidationError({
                "token": _("This voting token has been blocked due to multiple invalid attempts. Contact the election administrator.")
            }), False

        # Verifica o estado da eleição
        if election.status != ElectionStatus.STARTED:
            logger.warning(
                f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Eleição #{election.id} com status '{election.status}' (esperado STARTED)."
            )
            if election.status == ElectionStatus.CREATED:
                err = ValidationError({"election": _("This election has not started yet.")})
            elif election.status in (ElectionStatus.CLOSED, ElectionStatus.TALLIED):
                err = ValidationError({"election": _("This election has already closed.")})
            else:
                err = ValidationError({"election": _("This election is not open for voting.")})
            return err, True

        # Verifica se o eleitor já votou (sem incrementar falhas após o voto já computado)
        if voter.has_voted:
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Eleitor já votou.")
            return ValidationError({"voter": _("This voter has already cast their ballot.")}), False

        return None, False

    @classmethod
    def _validate_nonce_not_replayed(
        cls,
        token_obj: VotingToken,
        voter: ElectoralCollege,
        nonce: str,
        nonce_cache_key: str,
    ) -> ValidationError | None:
        """Checks whether the nonce was already bound to the token or recorded in cache."""
        if (token_obj.nonce and token_obj.nonce == nonce) or cache.get(nonce_cache_key):
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Replay de nonce detectado ('{nonce}').")
            return ValidationError({"nonce": _("Replay detected: this nonce has already been used.")})
        return None

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

        # 0. Proteção contra força bruta no nível de IP e campos obrigatórios
        ip_fail_key, current_ip_fails = cls._check_ip_rate_limit(ip_address)
        cls._validate_required_fields(raw_token, machine_pub_key, nonce)

        # 1. Valida o hash do token contra o banco de dados
        token_hash = VotingTokenService._hash_token(raw_token)
        token_obj = VotingToken.objects.select_related('voter', 'election').filter(token_hash=token_hash).first()

        if not token_obj:
            cls._increment_ip_failure(ip_fail_key, current_ip_fails)
            raise cls._invalid_token_error()

        voter = token_obj.voter
        election = token_obj.election

        # 2-5. Verifica token consumido/bloqueado, estado da eleição e elegibilidade do eleitor
        validation_err, should_record_failure = cls._validate_token_election_and_voter(token_obj, voter, election)
        if validation_err is not None:
            if should_record_failure:
                token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise validation_err

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
        nonce_err = cls._validate_nonce_not_replayed(token_obj, voter, nonce, nonce_cache_key)
        if nonce_err is not None:
            token_obj.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            raise nonce_err

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
        cls._finalize_nonce_and_ip_cache(nonce_cache_key, ip_fail_key)

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
    def _verify_cast_signature(
        cls,
        machine_pub_key: str,
        content: str,
        nonce: str,
        signature: str,
        exposed_id_voto: str,
        pacote_cifrado: str | None,
    ) -> bool:
        """Verifies the device RSA signature across supported payload formats."""
        candidates = [content.encode('utf-8'), f"{content}:{nonce}".encode('utf-8')]
        if pacote_cifrado and exposed_id_voto:
            candidates.append(f"{exposed_id_voto}:{pacote_cifrado}".encode('utf-8'))
        if pacote_cifrado:
            candidates.append(pacote_cifrado.encode('utf-8'))
        return any(SECryptoService.verify_signature(machine_pub_key, payload, signature) for payload in candidates)

    @classmethod
    def _consume_voter_in_tx1(
        cls,
        token_hash: str,
        machine_pub_key: str,
        content: str,
        nonce: str,
        signature: str,
        exposed_id_voto: str,
        pacote_cifrado: str | None,
        nonce_cache_key: str,
    ) -> tuple[dict | None, uuid.UUID | None, ValidationError | None]:
        """TX1: Locks VotingToken/ElectoralCollege, validates eligibility and marks voter participation."""
        token_obj = VotingToken.objects.select_for_update().filter(token_hash=token_hash).first()
        if not token_obj:
            return None, None, cls._invalid_token_error()

        voter = ElectoralCollege.objects.select_for_update().get(pk=token_obj.voter_id)
        election = token_obj.election

        # 2-5. Verifica token consumido/bloqueado, estado da eleição e elegibilidade do eleitor
        validation_err, should_record_failure = cls._validate_token_election_and_voter(token_obj, voter, election)
        if validation_err is not None:
            return None, (token_obj.id if should_record_failure else None), validation_err

        # 6. Verifica se o dispositivo é o mesmo que solicitou a cédula (binding estrito de hardware)
        saved_key = SECryptoService.to_pem_public_key(token_obj.machine_public_key)
        sent_key = SECryptoService.to_pem_public_key(machine_pub_key)
        if saved_key and saved_key != sent_key:
            logger.warning(
                f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Chave pública de máquina enviada no depósito "
                f"diferente da vinculada na solicitação da cédula."
            )
            return None, token_obj.id, ValidationError({
                "machine_public_key": _("Access denied: this voting token is bound to a different mobile device.")
            })

        # 7. Validação anti-replay do Nonce
        nonce_err = cls._validate_nonce_not_replayed(token_obj, voter, nonce, nonce_cache_key)
        if nonce_err is not None:
            return None, token_obj.id, nonce_err

        # 8. Validação da assinatura digital do dispositivo (se fornecida)
        if signature and not cls._verify_cast_signature(
            machine_pub_key, content, nonce, signature, exposed_id_voto, pacote_cifrado
        ):
            logger.warning(f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': Assinatura digital do voto inválida.")
            return None, token_obj.id, ValidationError({"signature": _("Invalid digital signature for the ballot payload.")})

        # 8.1. Pré-validação somente leitura do ticket anônimo (BallotTicket) antes de consumir o eleitor
        if exposed_id_voto:
            ticket_preview = BallotTicket.objects.filter(
                election=election,
                id_voto=exposed_id_voto
            ).first()
            if not ticket_preview:
                logger.warning(
                    f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': id_voto '{exposed_id_voto}' não encontrado na eleição #{election.id}."
                )
                return None, token_obj.id, ValidationError({"id_voto": _("Invalid or unrecognized vote ID for this election.")})
            if ticket_preview.is_used:
                logger.warning(
                    f"[VOTING_TOKEN_FAILED] Eleitor '{voter.email}': id_voto '{exposed_id_voto}' já foi consumido."
                )
                return None, None, ValidationError({"id_voto": _("This vote ID has already been consumed.")})

        previous_state = {
            "token_id": token_obj.id,
            "voter_id": voter.id,
            "election_id": election.id,
            "previous_nonce": token_obj.nonce,
            "previous_last_attempt_at": token_obj.last_attempt_at,
            "previous_last_attempt_ip": token_obj.last_attempt_ip,
        }

        now = timezone.now()
        token_obj.mark_as_used()
        voter.has_voted = True
        voter.voted_at = now
        voter.save(update_fields=['has_voted', 'voted_at'])

        return {
            "election_id": election.id,
            "now": now,
            "previous_state": previous_state,
        }, None, None

    @classmethod
    def _deposit_ballot_in_tx2(
        cls,
        election_id: int,
        stored_content: str,
        exposed_id_voto: str,
    ) -> None:
        """TX2: Atomically consumes the BallotTicket (if any) and inserts the anonymous Vote in a separate transaction."""
        with transaction.atomic():
            if exposed_id_voto:
                ballot_ticket = BallotTicket.objects.select_for_update().filter(
                    election_id=election_id,
                    id_voto=exposed_id_voto
                ).first()
                if not ballot_ticket:
                    raise ValidationError({"id_voto": _("Invalid or unrecognized vote ID for this election.")})
                if ballot_ticket.is_used:
                    raise ValidationError({"id_voto": _("This vote ID has already been consumed.")})
                ballot_ticket.is_used = True
                ballot_ticket.save(update_fields=['is_used'])

            raw_receipt = f"{election_id}:{stored_content}:{secrets.token_hex(32)}"
            receipt_hash = hashlib.sha256(raw_receipt.encode('utf-8')).hexdigest().upper()
            receipt_id = f"VOTE-{receipt_hash}"

            Vote.objects.create(
                id=uuid.uuid4(),
                id_generated=receipt_id,
                content=stored_content,
                election_id=election_id,
            )

            logger.info(
                f"[VOTE_CAST_SUCCESS] Cédula eleitoral depositada com sucesso na eleição #{election_id}. "
                f"Comprovante gerado: {receipt_id}."
            )

    @classmethod
    def _compensate_voter_consumption(cls, previous_state: dict) -> None:
        """Compensating transaction: reverts token and voter state if TX2 ballot persistence fails."""
        with transaction.atomic():
            VotingToken.objects.filter(pk=previous_state["token_id"]).update(
                is_used=False,
                nonce=previous_state["previous_nonce"],
                last_attempt_at=previous_state["previous_last_attempt_at"],
                last_attempt_ip=previous_state["previous_last_attempt_ip"],
            )
            ElectoralCollege.objects.filter(pk=previous_state["voter_id"]).update(
                has_voted=False,
                voted_at=None,
            )

    @classmethod
    def castVote(cls, data: dict, raw_data: dict | None = None, ip_address: str | None = None) -> dict:
        """
        Receives an encrypted ballot, validates token authenticity, device binding against
        the StrongBox key that requested the ballot, anti-replay nonces, and records the anonymous
        vote in the ballot box in a decoupled Saga transaction while consuming the single-use token.
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

        # Persiste apenas o pacote cifrado na urna, evitando correlação direta com BallotTicket.id_voto
        stored_content = pacote_cifrado if pacote_cifrado else content

        # 0. Proteção contra força bruta no nível de IP e campos obrigatórios
        ip_fail_key, current_ip_fails = cls._check_ip_rate_limit(ip_address)
        cls._validate_required_fields(raw_token, machine_pub_key, nonce, content=content, require_content=True)

        # 1. TX1: Valida e consome o token/eleitor sob transação atômica com lock de linha
        token_hash = VotingTokenService._hash_token(raw_token)
        nonce_cache_key = f"vote_nonce_used_{nonce}"

        with transaction.atomic():
            tx1_result, failed_token_id, validation_error = cls._consume_voter_in_tx1(
                token_hash=token_hash,
                machine_pub_key=machine_pub_key,
                content=content,
                nonce=nonce,
                signature=signature,
                exposed_id_voto=exposed_id_voto,
                pacote_cifrado=pacote_cifrado,
                nonce_cache_key=nonce_cache_key,
            )

        if validation_error is not None:
            if failed_token_id is not None:
                failed_token = VotingToken.objects.select_related('voter').filter(pk=failed_token_id).first()
                if failed_token and not failed_token.is_used:
                    failed_token.record_failed_attempt(ip_address, max_attempts=cls.get_max_failed_attempts())
            elif token_hash and ip_fail_key and not VotingToken.objects.filter(token_hash=token_hash).exists():
                cls._increment_ip_failure(ip_fail_key, current_ip_fails)
            raise validation_error

        # 2. TX2: Deposita a cédula anônima em transação separada com retry curto e compensação Saga
        previous_state = tx1_result["previous_state"]
        election_id = tx1_result["election_id"]
        now = tx1_result["now"]

        max_tx2_attempts = 3
        for attempt in range(max_tx2_attempts):
            try:
                cls._deposit_ballot_in_tx2(
                    election_id=election_id,
                    stored_content=stored_content,
                    exposed_id_voto=exposed_id_voto,
                )
                break
            except ValidationError:
                cls._compensate_voter_consumption(previous_state)
                raise
            except DatabaseError:
                if attempt + 1 < max_tx2_attempts:
                    time.sleep(0.01 * (attempt + 1))
                    continue
                cls._compensate_voter_consumption(previous_state)
                raise
            except Exception:
                cls._compensate_voter_consumption(previous_state)
                raise

        cls._finalize_nonce_and_ip_cache(nonce_cache_key, ip_fail_key)

        return {
            "election_id": election_id,
            "deposited_at": now,
            "status": "CONFIRMED",
            "nonce": nonce
        }
