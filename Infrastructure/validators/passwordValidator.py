import re
from django.core.exceptions import ValidationError as DjangoValidationError
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import ValidationError as DRFValidationError

class PasswordValidator:
    """
    Validador de complexidade de senhas para o VotaAÍ.
    
    Exige:
    - No mínimo 8 caracteres
    - Pelo menos uma letra maiúscula (A-Z)
    - Pelo menos uma letra minúscula (a-z)
    - Pelo menos um número (0-9)
    - Pelo menos um caractere especial (!@#$%^&*...)
    - Validação de regras do Django (não similar ao usuário, não comum, etc.)
    """

    MIN_LENGTH = 8

    def __init__(self, min_length: int = 8):
        self.min_length = min_length

    def validate(self, password: str, user=None):
        """Método compatível com AUTH_PASSWORD_VALIDATORS do Django."""
        errors = self.get_complexity_errors(password)
        if errors:
            raise DjangoValidationError(errors)

    def get_help_text(self):
        return (
            "A senha deve conter no mínimo 8 caracteres, incluindo letras maiúsculas, "
            "letras minúsculas, números e caracteres especiais."
        )

    @classmethod
    def get_complexity_errors(cls, password: str) -> list[str]:
        """Verifica as regras de complexidade e retorna lista com mensagens de erro."""
        errors = []
        if not password or len(password) < cls.MIN_LENGTH:
            errors.append(f"A senha deve conter no mínimo {cls.MIN_LENGTH} caracteres.")

        if not re.search(r'[A-Z]', password or ''):
            errors.append("A senha deve conter pelo menos uma letra maiúscula.")

        if not re.search(r'[a-z]', password or ''):
            errors.append("A senha deve conter pelo menos uma letra minúscula.")

        if not re.search(r'[0-9]', password or ''):
            errors.append("A senha deve conter pelo menos um número.")

        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?~`]', password or ''):
            errors.append("A senha deve conter pelo menos um caractere especial (!@#$%^&*...).")

        return errors

    @classmethod
    def validate_password_complexity(cls, password: str, user=None) -> None:
        """
        Executa a validação de complexidade e as validações nativas do Django.
        Lança DRF ValidationError em caso de inconsistência.
        """
        if not password:
            raise DRFValidationError({"senha": "A senha é obrigatória."})

        errors = cls.get_complexity_errors(password)

        # Executa validações padrão do Django (semelhança com usuário, senhas comuns, etc.)
        try:
            validate_password(password, user=user)
        except DjangoValidationError as e:
            # Adiciona apenas mensagens que ainda não foram capturadas
            for msg in e.messages:
                if msg not in errors:
                    errors.append(msg)

        if errors:
            raise DRFValidationError({"senha": errors})
