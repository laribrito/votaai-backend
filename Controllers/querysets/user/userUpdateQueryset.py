from Domain.models.schemas.moderation.userSchema import User
from django.contrib.auth.models import Group
from django.shortcuts import get_object_or_404


class UserUpdateQuerySet:
    """
    Camada dedicada para operações de atualização de usuário.
    Encapsula toda a lógica do ORM mantendo a separação estrita de camadas.
    """

    @staticmethod
    def getBaseQueryset():
        """
        Retorna a query base para o model de Usuário.
        """
        return User.objects.all()

    @staticmethod
    def getUserById(user_id: int):
        """
        Recupera uma instância específica pelo ID ou retorna 404.
        """
        return get_object_or_404(User, pk=user_id)

    @staticmethod
    def isEmailTaken(email: str, exclude_user_id: int = None) -> bool:
        """
        Verifica se o e-mail já está associado a outra conta.
        """
        qs = User.objects.filter(email=email)
        if exclude_user_id:
            qs = qs.exclude(pk=exclude_user_id)
        return qs.exists()

    @staticmethod
    def isUsernameTaken(username: str, exclude_user_id: int = None) -> bool:
        """
        Verifica se o username já está em uso.
        """
        qs = User.objects.filter(username=username)
        if exclude_user_id:
            qs = qs.exclude(pk=exclude_user_id)
        return qs.exists()

    @staticmethod
    def userHasGroup(user, group_name: str) -> bool:
        """
        Retorna True se o usuário pertencer ao grupo especificado.
        """
        if not user or not getattr(user, 'is_authenticated', False):
            return False

        return user.groups.filter(name=group_name).exists()

    @staticmethod
    def isAdminUser(user) -> bool:
        """
        Retorna True se o usuário for Administrador.
        """
        return UserUpdateQuerySet.userHasGroup(user, 'Administrador')

    @staticmethod
    def getGroupsByNames(role_names: list) -> list:
        """
        Busca uma lista de objetos Group baseada na lista de nomes.
        """
        return list(Group.objects.filter(name__in=role_names))

    @staticmethod
    def checkAllRolesExist(role_names: list) -> bool:
        """
        Valida se TODOS os nomes de roles informados existem no banco.
        Retorna True apenas se baterem com a quantidade informada.
        """
        count = Group.objects.filter(name__in=role_names).count()
        return count == len(set(role_names))
    