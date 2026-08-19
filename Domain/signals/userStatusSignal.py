from django.db.models.signals import post_save
from django.dispatch import receiver
from Domain.models.schemas.moderation.userSchema import User
from knox.models import AuthToken


@receiver(post_save, sender=User)
def revokeKnoxTokensOnUserDeactivation(sender, instance, **kwargs):
    """
    Observer triggered after a user is saved.
    If deactivating (is_active=False), all Knox tokens are destroyed for global logout.
    """
    if not instance.is_active:
        AuthToken.objects.filter(user=instance).delete()
        