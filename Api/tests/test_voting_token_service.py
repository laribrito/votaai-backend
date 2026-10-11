from django.test import TestCase, override_settings
from Infrastructure.services.votingTokenService import VotingTokenService


class VotingTokenServiceLinkTestCase(TestCase):
    """
    Test suite for VotingTokenService decoupled mobile deep link generation.
    """

    @override_settings(MOBILE_VOTING_URL='votaai://votar/?token=')
    def test_default_custom_scheme_query_suffix(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "votaai://votar/?token=token123")

    @override_settings(MOBILE_VOTING_URL='votaai://votar?token=')
    def test_custom_scheme_without_trailing_slash(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "votaai://votar?token=token123")

    @override_settings(MOBILE_VOTING_URL='votaai://vote/{token}')
    def test_custom_scheme_with_template_placeholder(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "votaai://vote/token123")

    @override_settings(MOBILE_VOTING_URL='https://votaai.org/votar/?token=')
    def test_https_universal_link_suffix(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "https://votaai.org/votar/?token=token123")

    @override_settings(MOBILE_VOTING_URL='https://votaai.org/votar')
    def test_https_base_url_appends_token_param(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "https://votaai.org/votar?token=token123")

    @override_settings(MOBILE_VOTING_URL='https://votaai.org/votar?channel=email')
    def test_https_with_existing_query_params(self):
        link = VotingTokenService.build_voting_link("token123")
        self.assertEqual(link, "https://votaai.org/votar?channel=email&token=token123")
