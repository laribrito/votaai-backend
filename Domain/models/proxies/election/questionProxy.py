class QuestionProxy:
    """
    Domain Proxy: Question
    Proxy mixin that adds domain-specific behavior and string representation
    on top of Question without polluting the DB schema.
    """

    def __str__(self) -> str:
        order = getattr(self, 'order', '')
        text = getattr(self, 'question', '')
        return f"{order}. {text[:50]}"
