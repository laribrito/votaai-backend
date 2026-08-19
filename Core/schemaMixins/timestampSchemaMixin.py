from django.db import models
from django.utils.translation import gettext_lazy as _

class TimestampSchemaMixin(models.Model):
    """
    Core Mixin: TimestampSchemaMixin
    
    Provides automatic audit fields for tracking the creation and last update 
    times of a model instance. This is a fundamental building block for 
    maintaining a clear audit trail across the domain layers.
    """

    # Automatically set when the object is first created
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At"),
        help_text=_("The date and time when this record was first created.")
    )

    # Automatically updated every time the object is saved
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Updated At"),
        help_text=_("The date and time when this record was last modified.")
    )

    class Meta:
        """
        Mixin Metadata
        
        Defined as abstract to ensure Django incorporates these fields 
        directly into the inheriting model's database table.
        """
        abstract = True
        