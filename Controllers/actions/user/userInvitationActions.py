from Domain.models.schemas.moderation.userSchema import User
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.db import transaction
from rest_framework.exceptions import ValidationError

# Import the decoupled signal instead of the concrete Observer class
from Domain.models.schemas.moderation.userSchema import User
from Domain.signals.invitationSignals import userInvited
from Controllers.querysets.user.userUpdateQueryset import UserUpdateQuerySet



class UserInvitationActions:
    """Orquestra o fluxo de Convite de Usuário."""

    @staticmethod
    def inviteUser(data, acting_user=None):
        """Cria um usuário inativo e dispara o email de convite via Signal."""
        email = data.get('email')
        username = data.get('username')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        roles = data.get('roles')
        status = data.get('status', 'Ativo')

        if roles and 'Administrador' in roles and not UserUpdateQuerySet.is_admin_user(acting_user):
            raise ValidationError({"roles": "Somente Administradores podem atribuir o cargo de Administrador."})

        with transaction.atomic():
            # 1. Validação (Exclusividade)
            if UserUpdateQuerySet.is_username_taken(username):
                raise ValidationError({"username": "Este nome de usuário já está em uso."})

            if UserUpdateQuerySet.is_email_taken(email):
                raise ValidationError({"email": "Este e-mail já está cadastrado."})

            # 2. Cria Usuário com Status Dinâmico
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_active=(status == 'Ativo')
            )

            # 3. Atribui Múltiplos Cargos
            try:
                groups = UserUpdateQuerySet.get_groups_by_names(roles)
                user.groups.set(groups)
            except Exception:
                user.delete()
                raise ValidationError({"roles": "Falha ao atribuir os cargos ao usuário."})

            # 4. Gera Tokens
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # 5. Notifica via Signal (Desacoplado)
            # O email de convite apontará para o endpoint unificado /api/password/reset/confirm/
            userInvited.send(
                sender=UserInvitationActions,
                user=user,
                uid=uid,
                token=token
            )

            return {"message": "User invited successfully. Setup email sent."}

    # NOTA: O método antigo 'complete_setup' foi removido.
    # A configuração de senha para convidados agora é gerenciada pelo método unificado
    # PasswordManagementActions.confirm_reset(), que também ativa o usuário.