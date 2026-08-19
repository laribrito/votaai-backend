from Domain.models.schemas.moderation.userSchema import User
from Controllers.querysets.user.userListQueryset import UserListQuerySet


class UserListAction:
    """
    Action responsável por orquestrar a listagem de usuários.
    """

    @staticmethod
    def getBaseQueryset():
        """
        Retorna a query base já com as otimizações e ordenação padrão aplicadas.
        """
        # Instancia o QuerySet passando o model para não quebrar a arquitetura
        return UserListQuerySet(model=User).with_roles().default_list_order()

    @staticmethod
    def getStatsCounts():
        """
        Retorna as contagens estatísticas de usuários (ativos, inativos, roles).
        Oculta a lógica de montagem dos dados da View.
        """
        baseQs = UserListAction.getBaseQueryset()
        
        return {
            "ativos": baseQs.count_active(),
            "inativos": baseQs.count_inactive(),
            "moderadores": baseQs.count_by_role('Moderador'),
            "redatores": baseQs.count_by_role('Redator'),
            "administradores": baseQs.count_by_role('Administrador'),
        }
    