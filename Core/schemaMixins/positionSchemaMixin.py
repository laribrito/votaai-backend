from django.db import models
from django.utils.translation import gettext_lazy as _

class PositionSchemaMixin(models.Model):
    """
    Core Mixin: PositionSchemaMixin
    
    This mixin provides a standardized manual sorting capability for domain models.
    It centralizes the 'sortOrder' field to ensure a consistent architectural 
    pattern for sequencing items across the system.
    
    By inheriting from this mixin, models automatically gain a sortable field 
    and a default ordering configuration for database queries.
    """

    # Primary field for manual sequence control in the CMS and Frontend
    sortOrder = models.PositiveIntegerField(
        default=0,
        blank=False,
        verbose_name=_('Sort Order'),
        help_text=_('Defines the display sequence for this model. Lower values typically appear first.')
    )

    class Meta:
        """
        Mixin Metadata
        
        Defines this class as abstract to prevent the creation of a dedicated 
        database table and sets the default ordering for all inheriting models.
        """
        abstract = True
        ordering = ['sortOrder']
        