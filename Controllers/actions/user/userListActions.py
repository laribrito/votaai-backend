from Domain.models.schemas.moderation.userSchema import User
from Controllers.querysets.user.userListQueryset import UserListQuerySet

class UserListAction:
    """
    Action responsável por orquestrar a listagem de usuários.
    """

    @staticmethod
    def getBaseQueryset():
        """
        Retorna a query base já com as otimizações e ordenação padrão aplicadas delegando para UserListQuerySet.
        """
        return UserListQuerySet.getBaseQueryset()

    @staticmethod
    def getStatsCounts():
        """
        Retorna as contagens estatísticas de usuários (ativos, inativos, roles).
        Oculta a lógica de montagem dos dados da View.
        """
        baseQs = UserListQuerySet.getBaseQueryset()
        
        return {
            "ativos": baseQs.countActive(),
            "inativos": baseQs.countInactive(),
            "moderadores": baseQs.countByRole('Moderador'),
            "redatores": baseQs.countByRole('Redator'),
            "administradores": baseQs.countByRole('Administrador'),
        }

    get_stats_counts = getStatsCounts
    