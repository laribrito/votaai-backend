import json
import logging
from pathlib import Path
from django.conf import settings
from django.db import transaction
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from cryptography.hazmat.primitives import serialization
from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.questionSchema import Question
from Domain.models.schemas.election.optionSchema import Option
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
from Domain.models.schemas.moderation.userSchema import User
from Infrastructure.services.seCryptoService import SECryptoService

logger = logging.getLogger(__name__)

class ElectionActions:
    """
    Orchestrates business logic for Desktop election creation:
    1. Structural validation of the ballot (questions and options).
    2. Validation of the requesting physical machine's digital signature.
    3. Normalized relational persistence: Election, Question, Option, and ElectoralCollege.
    4. Hardware TPM response signature generation (VotaAI_SecureKey_1).
    """

    @staticmethod
    def _extract_questions_and_options(ballot_data) -> tuple[list, int, int]:
        """
        Parses ballot data and returns:
        (questions_list, questions_count, options_count).
        """
        if isinstance(ballot_data, list):
            questions = ballot_data
        elif isinstance(ballot_data, dict):
            questions = ballot_data.get('questions', [])
        else:
            questions = []

        if not isinstance(questions, list) or len(questions) == 0:
            raise ValidationError({"ballot": _("The ballot must contain at least one question.")})

        questions_count = len(questions)
        options_count = 0

        for idx, q in enumerate(questions):
            if not isinstance(q, dict):
                raise ValidationError({"ballot": _("Question at index %(idx)s must be a JSON object.") % {'idx': idx}})

            options = q.get('options')
            if not isinstance(options, list) or len(options) == 0:
                q_name = q.get('question') or str(idx + 1)
                raise ValidationError({
                    "ballot": _("Question '%(q_name)s' must contain at least one option.") % {'q_name': q_name}
                })
            options_count += len(options)

        return questions, questions_count, options_count

    @classmethod
    def criarEleicao(cls, data: dict, raw_data: dict | None = None, user=None, client_pub_key_fallback: str | None = None) -> dict:
        """
        Executes election creation and relational entities persistence:
        - Creates Election
        - Creates each Question and its child Options
        - Creates ElectoralCollege records
        - Signs response payload with server TPM (VotaAI_SecureKey_1)
        """
        title = str(data.get('title') or '').strip()
        ballot = data.get('ballot')
        electoral_college = data.get('electoral_college')
        public_key = str(data.get('public_key') or '').strip()
        key_handle = str(data.get('key_handle') or '').strip()
        machine_signature = str(data.get('signature') or '').strip()
        start_datetime = data.get('start_datetime')
        end_datetime = data.get('end_datetime')

        if not title:
            raise ValidationError({"title": _("The election title is required.")})
        if ballot is None:
            raise ValidationError({"ballot": _("The ballot structure is required.")})
        if electoral_college is None:
            raise ValidationError({"electoral_college": _("The electoral college is required.")})
        if not public_key:
            raise ValidationError({"public_key": _("The election public key is required.")})
        if not key_handle:
            raise ValidationError({"key_handle": _("The keyHandle is required.")})
        if not machine_signature:
            raise ValidationError({"signature": _("The machine digital signature is required.")})

        # 1. Validate ballot structure and compute counts
        questions_raw, questions_count, options_count = cls._extract_questions_and_options(ballot)

        # 2. Locate machine public key for signature validation
        machine_pub_key = None
        if user and getattr(user, 'machine_public_key', None):
            machine_pub_key = user.machine_public_key
        
        if not machine_pub_key:
            machine_pub_key = (
                data.get('machine_public_key')
                or client_pub_key_fallback
            )

        if not machine_pub_key:
            try:
                saved_key = SECryptoService.get_client_public_key('desktop')
                if saved_key:
                    machine_pub_key = saved_key
            except Exception as e:
                logger.warning(f"Erro ao recuperar chave pública salva de desktop: {e}")

        if not machine_pub_key:
            raise ValidationError({
                "signature": _("Physical machine public key not found to validate signature.")
            })

        # 3. Validate digital signature generated by the client machine
        ballot_repr = json.dumps(ballot, sort_keys=True)
        college_repr = json.dumps(electoral_college, sort_keys=True)

        candidate_payloads = [
            f"{title}:{public_key}:{key_handle}".encode('utf-8'),
            f"{title}:{key_handle}".encode('utf-8'),
            f"{title}:{ballot_repr}:{college_repr}:{public_key}:{key_handle}".encode('utf-8'),
            json.dumps({
                "public_key": public_key,
                "electoral_college": electoral_college,
                "ballot": ballot,
                "key_handle": key_handle,
                "title": title
            }, sort_keys=True).encode('utf-8'),
            title.encode('utf-8')
        ]

        full_payload = dict(raw_data if isinstance(raw_data, dict) else data)
        full_payload.pop('machine_user', None)

        is_valid_sig = any(
            SECryptoService.verify_signature(machine_pub_key, cand, machine_signature)
            for cand in candidate_payloads
        ) or SECryptoService.verify_payload_signature(machine_pub_key, full_payload)

        if not is_valid_sig:
            raise ValidationError({
                "signature": _("Physical machine signature is invalid or payload does not match.")
            })

        # Resolve creator user by authentication, machine_public_key, or desktop_public_key.txt
        creator_user = user if (user and user.is_authenticated) else None
        if not creator_user and machine_pub_key:
            if isinstance(machine_pub_key, str):
                creator_user = User.objects.filter(machine_public_key=machine_pub_key.strip()).first()
            elif hasattr(machine_pub_key, 'public_bytes'):
                pem_str = machine_pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8').strip()
                creator_user = User.objects.filter(machine_public_key=pem_str).first()

        if not creator_user:
            pub_key_path = Path(getattr(settings, 'BASE_DIR', Path.cwd())) / 'desktop_public_key.txt'
            if pub_key_path.exists():
                try:
                    with open(pub_key_path, 'r', encoding='utf-8') as f:
                        file_key = f.read().strip()
                    if file_key:
                        creator_user = User.objects.filter(machine_public_key=file_key).first()
                except Exception as e:
                    logger.warning(f"Erro ao ler desktop_public_key.txt para vincular criador: {e}")

        if not creator_user:
            try:
                loaded_key = SECryptoService.get_client_public_key('desktop')
                if loaded_key:
                    if hasattr(loaded_key, 'public_bytes'):
                        pem_str = loaded_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode('utf-8').strip()
                        creator_user = User.objects.filter(machine_public_key=pem_str).first()
                    elif isinstance(loaded_key, str):
                        creator_user = User.objects.filter(machine_public_key=loaded_key.strip()).first()
            except Exception as e:
                logger.warning(f"Erro ao recuperar chave do desktop para creator_user: {e}")

        # 4. Atomic creation in normalized relational tables
        with transaction.atomic():
            if not creator_user:
                raise ValidationError({
                    "creator": _("Could not identify the authenticated user or physical machine owner to create the election.")
                })

            election = Election.objects.create(
                title=title,
                public_key=public_key,
                key_handle=key_handle,
                start_datetime=start_datetime,
                end_datetime=end_datetime,
                machine_signature=machine_signature,
                status=ElectionStatus.CREATED,
                created_by=creator_user
            )

            # Persist Question and child Option records
            for idx, q_data in enumerate(questions_raw):
                question_text = q_data.get('question') or f"Question {idx + 1}"
                order = q_data.get('order') or (idx + 1)

                question_obj = Question.objects.create(
                    election=election,
                    question=question_text,
                    order=order
                )

                options_raw = q_data.get('options') or []
                options_objs = []
                for opt in options_raw:
                    if isinstance(opt, dict):
                        label = opt.get('label') or str(opt)
                    else:
                        label = str(opt)
                    options_objs.append(Option(question=question_obj, label=label))
                
                if options_objs:
                    Option.objects.bulk_create(options_objs)

            # Persist ElectoralCollege records
            college_list = electoral_college if isinstance(electoral_college, list) else [electoral_college]
            voters_objs = []
            for voter in college_list:
                if isinstance(voter, dict):
                    email = (voter.get('email') or '').strip()
                    full_name = (
                        voter.get('full_name')
                        or voter.get('name')
                        or voter.get('nome')
                        or voter.get('nome_completo')
                        or voter.get('fullName')
                        or ''
                    ).strip()

                    if not full_name and email:
                        matched_user = User.objects.filter(email__iexact=email).first()
                        if matched_user:
                            user_full_name = f"{matched_user.first_name} {matched_user.last_name}".strip()
                            if user_full_name:
                                full_name = user_full_name

                    if not full_name and email:
                        full_name = email.split('@')[0]

                    parts = full_name.split()
                    first_name = parts[0] if parts else full_name
                    # O apelido deve ser o primeiro nome do nome completo
                    nickname = first_name

                    raw_pw = voter.get('password') or ''
                    if raw_pw:
                        if str(raw_pw).startswith(('pbkdf2_sha256$', 'argon2', 'bcrypt')):
                            password_hash = str(raw_pw)
                        else:
                            password_hash = make_password(str(raw_pw))
                    else:
                        password_hash = ''
                else:
                    email = str(voter).strip()
                    full_name = ''
                    if email:
                        matched_user = User.objects.filter(email__iexact=email).first()
                        if matched_user:
                            user_full_name = f"{matched_user.first_name} {matched_user.last_name}".strip()
                            if user_full_name:
                                full_name = user_full_name

                    if not full_name and email:
                        full_name = email.split('@')[0]

                    parts = full_name.split()
                    first_name = parts[0] if parts else full_name
                    # O apelido deve ser o primeiro nome do nome completo
                    nickname = first_name
                    password_hash = ''

                if email:
                    voters_objs.append(ElectoralCollege(
                        election=election,
                        full_name=full_name,
                        email=email,
                        nickname=nickname,
                        password=password_hash,
                        has_voted=False
                    ))

            if voters_objs:
                ElectoralCollege.objects.bulk_create(voters_objs, ignore_conflicts=True)

        # 5. Sign response payload with server TPM hardware key (VotaAI_SecureKey_1)
        data_to_sign = f"{election.id}:{questions_count}:{options_count}".encode('utf-8')
        try:
            server_signature = SECryptoService.sign_with_tpm('VotaAI_SecureKey_1', data_to_sign)
        except Exception as e:
            logger.error(f"Erro ao assinar resposta com TPM: {e}")
            raise RuntimeError(_("Error generating server digital signature: %(error)s") % {'error': str(e)})

        return {
            "id": election.id,
            "questions_count": questions_count,
            "options_count": options_count,
            "signature": server_signature
        }
