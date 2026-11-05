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

    def ensure_default_ballot_options(self):
        """
        Garante que a questão contenha as opções padrão de voto ('Branco' e 'Nulo').
        Evita duplicações caso já existam (comparação insensível a maiúsculas/minúsculas).
        """
        from Domain.models.schemas.election.optionSchema import Option

        existing_labels = {
            opt.label.strip().lower()
            for opt in self.options.all()
        }

        if 'branco' not in existing_labels:
            opt = Option.objects.filter(question=self, label__iexact='Branco').first()
            if not opt:
                Option.objects.create(question=self, label='Branco')

        if 'nulo' not in existing_labels:
            opt = Option.objects.filter(question=self, label__iexact='Nulo').first()
            if not opt:
                Option.objects.create(question=self, label='Nulo')

