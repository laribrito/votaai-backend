class ElectionProxy:
    """
    Domain Proxy: Election
    Proxy mixin that adds domain-specific behavior, string representation,
    and business calculations on top of Election without polluting the DB schema.
    """

    def __str__(self) -> str:
        status_display = self.get_status_display() if hasattr(self, 'get_status_display') else getattr(self, 'status', '')
        return f"{self.title} (#{self.id}) - {status_display}"

    @property
    def questions_count(self) -> int:
        """
        Returns the total number of questions for the election.
        """
        if getattr(self, 'pk', None):
            return self.questions.count()
        return 0

    @property
    def options_count(self) -> int:
        """
        Returns the total number of voting options across all questions in the election.
        """
        if getattr(self, 'pk', None):
            from Domain.models.schemas.election.optionSchema import Option
            return Option.objects.filter(question__election=self).count()
        return 0
