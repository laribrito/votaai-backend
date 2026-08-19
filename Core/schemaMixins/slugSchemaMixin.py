from django.db import models
from django.utils.text import slugify
from django.core.validators import validate_slug
from django.utils.translation import gettext_lazy as _

class SlugSchemaMixin(models.Model):
    """
    Core Mixin: SlugSchemaMixin
    
    Fornece geração automática e única de slugs para os modelos de domínio.
    Garante que a entrada manual seja limpa (slugified) e validada,
    enquanto lida com colisões de banco de dados adicionando um contador incremental.

    Configuração:
        slug_source_field (str): O campo do modelo usado para gerar automaticamente o slug.
                                 O padrão é 'name'. Pode ser sobrescrito nas subclasses 
                                 (ex: slug_source_field = 'title').
    """
    
    slug_source_field: str = 'name'

    slug = models.SlugField(
        max_length=300,
        unique=True,
        blank=True,
        validators=[validate_slug],
        verbose_name=_('Slug'),
        help_text=_('URL-friendly identifier. Only letters, numbers, hyphens and underscores are allowed.')
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs) -> None:
        """
        Método save customizado com limpeza forçada e tratamento de colisão.
        
        1. Se o slug estiver vazio: Gera a partir do slug_source_field.
        2. Se o slug for fornecido: Força o slugify() para limpar a entrada manual.
        3. Checagem de colisão: Adiciona um contador se o slug já existir no BD.
        """
        
        # Passo 1 & 2: Obter o slug base
        if not self.slug:
            # Gerar do campo de origem se vazio
            if not hasattr(self, self.slug_source_field):
                raise AttributeError(
                    f"O modelo '{self.__class__.__name__}' não possui o campo '{self.slug_source_field}' "
                    f"especificado em 'slug_source_field'. Por favor, configure-o corretamente."
                )
            sourceValue = getattr(self, self.slug_source_field) or ''
            baseSlug = slugify(str(sourceValue))
        else:
            # Limpar entrada manual para garantir que siga o padrão do slug
            baseSlug = slugify(self.slug)

        # Fallback para valores vazios
        if not baseSlug:
            baseSlug = 'shared-link'

        slug = baseSlug
        counter = 1
        modelClass = self.__class__
        
        # Step 3: Collision Loop
        # We check uniqueness for BOTH auto-generated and manual inputs.
        # .exclude(pk=self.pk) ensures we don't collide with the record itself during updates.
        while modelClass.objects.filter(slug=slug).exclude(pk=self.pk).exists():
            slug = f"{baseSlug}-{counter}"
            counter += 1
        
        self.slug = slug
            
        # Execute the standard save procedure
        super().save(*args, **kwargs)
        