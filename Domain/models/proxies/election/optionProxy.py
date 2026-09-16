class OptionProxy:
    """
    Domain Proxy: Option
    Proxy mixin that adds domain-specific behavior and string representation
    on top of Option without polluting the DB schema.
    """

    def __str__(self) -> str:
        return getattr(self, 'label', '')
