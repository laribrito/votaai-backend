from rest_framework import serializers
from django.contrib.auth.models import Group
from Domain.models.schemas.moderation.userSchema import User
from Controllers.querysets.user.userUpdateQueryset import UserUpdateQuerySet

class UserInvitationSerializer(serializers.Serializer):
    """
    API Serializer: Input Validation for User Invitations.
    
    This class ensures strict data integrity for the invitation process.
    It includes custom error messages to guide the frontend developer/user
    precisely on what went wrong.
    """
    
    # 1. First Name Validation
    first_name = serializers.CharField(
        max_length=150, 
        required=True,
        # errorMessages original (EN): { 'required': 'First name is required.', 'blank': 'First name cannot be empty.' }
        error_messages={
            'required': 'O nome é obrigatório.',
            'blank': 'O nome não pode ficar vazio.'
        }
    )

    # 2. Last Name Validation
    last_name = serializers.CharField(
        max_length=150, 
        required=True,
        # errorMessages original (EN): { 'required': 'Last name is required.', 'blank': 'Last name cannot be empty.' }
        error_messages={
            'required': 'O sobrenome é obrigatório.',
            'blank': 'O sobrenome não pode ficar vazio.'
        }
    )

    # 3. Username Validation
    username = serializers.CharField(
        max_length=150, 
        required=True,
        # errorMessages original (EN): { 'required': 'Username is required for system login.', 'blank': 'Username cannot be empty.' }
        error_messages={
            'required': 'O nome de usuário é obrigatório para login no sistema.',
            'blank': 'O nome de usuário não pode ficar vazio.'
        }
    )

    # 4. Email Validation
    email = serializers.EmailField(
        required=True,
        # errorMessages original (EN): { 'required': 'Email address is required...', 'blank': '...', 'invalid': '...' }
        error_messages={
            'required': 'O e-mail é obrigatório para enviar o convite.',
            'blank': 'O e-mail não pode ficar vazio.',
            'invalid': 'Insira um endereço de e-mail válido (ex: usuario@exemplo.com).'
        }
    )

    # 5. Roles (Groups) Validation
    roles = serializers.ListField(
        child=serializers.CharField(),
        required=True,
        allow_empty=False,
        # errorMessages original (EN): { 'required': 'You must select at least one role...', 'empty': 'Roles cannot be empty.' }
        error_messages={
            'required': 'Você deve selecionar pelo menos um cargo para o usuário.',
            'empty': 'Os cargos não podem ficar vazios.'
        }
    )

    # 6. Status Validation (Optional, defaults to Ativo)
    status = serializers.ChoiceField(
        choices=['Ativo', 'Inativo'],
        required=False,
        default='Ativo'
    )

    def validateEmail(self, value):
        """
        Custom Validator: Checks for email duplication.
        """
        email = value.lower()
        if User.objects.filter(email=email).exists():
            # Original (EN): "This email address is already registered in the system."
            raise serializers.ValidationError("Este e-mail já está cadastrado no sistema.")
        return email

    def validateUsername(self, value):
        """
        Custom Validator: Checks for username availability.
        """
        if User.objects.filter(username=value).exists():
            # Original (EN): "This username is already taken. Please choose another one."
            raise serializers.ValidationError("Este nome de usuário já está em uso. Escolha outro.")
        return value

    def validateRoles(self, value):
        """
        Custom Validator: Ensures all submitted Roles actually exist in the database.
        """
        # value is a list of strings, e.g., ["Administrador", "Redator"]
        existingGroups = list(Group.objects.filter(name__in=value).values_list('name', flat=True))
        invalidRoles = [role for role in value if role not in existingGroups]

        requestUser = self.context.get('requestUser')
        
        if invalidRoles:
            # Original (EN): "The following roles are invalid or do not exist: ..."
            raise serializers.ValidationError(
                f"Os seguintes cargos são inválidos ou não existem: {', '.join(invalidRoles)}"
            )

        if 'Administrador' in value:
            if not UserUpdateQuerySet.is_admin_user(requestUser):
                raise serializers.ValidationError("Somente Administradores podem atribuir o cargo de Administrador.")
            value = ['Administrador']

        return value
    