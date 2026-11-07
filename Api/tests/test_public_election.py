from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from rest_framework.test import APITestCase
from rest_framework import status

from Domain.models.schemas.election.electionSchema import Election, ElectionStatus
from Domain.models.schemas.election.electoralCollegeSchema import ElectoralCollege
from Domain.models.schemas.moderation.userSchema import User


class PublicElectionTests(APITestCase):
    def setUp(self):
        # Usuário criador da eleição
        self.creator = User.objects.create_user(
            username='admin.eleicoes@votaai.org',
            email='admin.eleicoes@votaai.org',
            password='AdminPassword123!',
            is_active=True
        )

        # 1. Eleição ABERTA (STARTED)
        self.election_open_1 = Election.objects.create(
            title="Eleição Diretoria Geral 2026",
            public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
            key_handle="0x81010001",
            status=ElectionStatus.STARTED,
            start_datetime=timezone.now() - timedelta(hours=2),
            end_datetime=timezone.now() + timedelta(hours=6),
            created_by=self.creator
        )

        # Eleitores para eleição 1 (3 votantes: 2 votaram, 1 pendente)
        self.voter_1_1 = ElectoralCollege.objects.create(
            election=self.election_open_1,
            full_name="Ana Paula Souza",
            nickname="Ana",
            email="ana.souza@votaai.org",
            has_voted=True
        )
        self.voter_1_2 = ElectoralCollege.objects.create(
            election=self.election_open_1,
            full_name="Carlos Eduardo Lima",
            nickname="Carlos",
            email="carlos.lima@votaai.org",
            has_voted=True
        )
        self.voter_1_3 = ElectoralCollege.objects.create(
            election=self.election_open_1,
            full_name="Beatriz Santos Mendes",
            nickname="Beatriz",
            email="beatriz.mendes@votaai.org",
            has_voted=False
        )

        # 2. Outra Eleição ABERTA (STARTED)
        self.election_open_2 = Election.objects.create(
            title="Consulta Estudantil sobre o Calendário",
            public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8B...\n-----END PUBLIC KEY-----",
            key_handle="0x81010002",
            status=ElectionStatus.STARTED,
            start_datetime=timezone.now() - timedelta(hours=1),
            created_by=self.creator
        )
        self.voter_2_1 = ElectoralCollege.objects.create(
            election=self.election_open_2,
            full_name="Marcos Vinicius",
            nickname="Marcos",
            email="marcos.vinicius@votaai.org",
            has_voted=False
        )

        # 3. Eleição AINDA NÃO INICIADA (CREATED) - Rascunho
        self.election_created = Election.objects.create(
            title="Eleição Conselho Fiscal (Não Iniciada)",
            public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8C...\n-----END PUBLIC KEY-----",
            key_handle="0x81010003",
            status=ElectionStatus.CREATED,
            created_by=self.creator
        )
        ElectoralCollege.objects.create(
            election=self.election_created,
            full_name="Eleitor Rascunho",
            email="rascunho@votaai.org",
            has_voted=False
        )

        # 4. Eleição FINALIZADA (CLOSED)
        self.election_closed = Election.objects.create(
            title="Eleição Colegiado Departamental 2025 (Encerrada)",
            public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8D...\n-----END PUBLIC KEY-----",
            key_handle="0x81010004",
            status=ElectionStatus.CLOSED,
            start_datetime=timezone.now() - timedelta(days=2),
            end_datetime=timezone.now() - timedelta(days=1),
            created_by=self.creator
        )
        ElectoralCollege.objects.create(
            election=self.election_closed,
            full_name="Fernando Rocha",
            nickname="Fernando",
            email="fernando.rocha@votaai.org",
            has_voted=True
        )

    # =========================================================================
    # Testes da Rota Pública de Busca de Eleições em Aberto (List)
    # =========================================================================

    def test_list_open_elections_returns_only_started(self):
        """A listagem pública deve retornar apenas eleições com status STARTED."""
        url = reverse('public-election-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        # Deve conter 2 eleições abertas (open_1 e open_2), e não created nem closed
        self.assertEqual(len(data), 2)
        returned_ids = [item['id'] for item in data]
        self.assertIn(self.election_open_1.id, returned_ids)
        self.assertIn(self.election_open_2.id, returned_ids)
        self.assertNotIn(self.election_created.id, returned_ids)
        self.assertNotIn(self.election_closed.id, returned_ids)

    def test_list_open_elections_alternative_url(self):
        """A rota explícita /api/election/public/open/ deve funcionar identicamente."""
        url = reverse('election-public-open')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(len(data), 2)

    def test_list_open_elections_contains_only_necessary_fields(self):
        """A listagem pública deve conter apenas campos necessários e quórum resumido."""
        url = reverse('public-election-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        item = next(e for e in response.json() if e['id'] == self.election_open_1.id)

        # Campos esperados
        self.assertEqual(item['title'], "Eleição Diretoria Geral 2026")
        self.assertEqual(item['status'], ElectionStatus.STARTED)
        self.assertIn('start_datetime', item)
        self.assertEqual(item['total_voters'], 3)
        self.assertEqual(item['voted_count'], 2)
        self.assertEqual(item['quorum_percentage'], 66.67)

        # Não deve conter dados sensíveis, pesados ou end_datetime
        self.assertNotIn('end_datetime', item)
        self.assertNotIn('public_key', item)
        self.assertNotIn('key_handle', item)
        self.assertNotIn('machine_signature', item)
        self.assertNotIn('created_by', item)
        self.assertNotIn('electoral_college', item)
        self.assertNotIn('password', item)

    def test_list_open_elections_search_filter(self):
        """A busca textual por título deve filtrar as eleições em aberto."""
        url = reverse('public-election-list') + '?search=Diretoria'
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], self.election_open_1.id)

        # Busca por algo inexistente
        url_none = reverse('public-election-list') + '?search=Inexistente123'
        response_none = self.client.get(url_none)
        self.assertEqual(response_none.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_none.json()), 0)

    # =========================================================================
    # Testes da Rota Pública de Acompanhamento da Eleição (Retrieve)
    # =========================================================================

    def test_retrieve_election_quorum_tracking_success(self):
        """O retrieve público deve retornar quórum e colegiado eleitoral com has_voted."""
        url = reverse('public-election-detail', args=[self.election_open_1.id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        # Metadados e Quórum
        self.assertEqual(data['id'], self.election_open_1.id)
        self.assertEqual(data['title'], "Eleição Diretoria Geral 2026")
        self.assertEqual(data['status'], ElectionStatus.STARTED)
        self.assertIn('start_datetime', data)
        self.assertNotIn('end_datetime', data)
        self.assertEqual(data['total_voters'], 3)
        self.assertEqual(data['voted_count'], 2)
        self.assertEqual(data['pending_count'], 1)
        self.assertEqual(data['quorum_percentage'], 66.67)

        # Colegiado eleitoral
        colegiado = data['electoral_college']
        self.assertEqual(len(colegiado), 3)

        # Verifica dados de cada eleitor
        voters_by_email = {v['email']: v for v in colegiado}
        self.assertTrue(voters_by_email['ana.souza@votaai.org']['has_voted'])
        self.assertEqual(voters_by_email['ana.souza@votaai.org']['full_name'], "Ana Paula Souza")
        self.assertTrue(voters_by_email['carlos.lima@votaai.org']['has_voted'])
        self.assertFalse(voters_by_email['beatriz.mendes@votaai.org']['has_voted'])

        # Garante que senhas NUNCA são expostas
        for v in colegiado:
            self.assertNotIn('password', v)
            self.assertNotIn('token', v)
            self.assertNotIn('voting_token', v)

    def test_retrieve_election_alternative_urls(self):
        """As rotas alternativas /api/election/public/<id>/ e /api/election/track/<id>/ devem funcionar."""
        url_pub = reverse('election-public-retrieve', args=[self.election_open_1.id])
        resp_pub = self.client.get(url_pub)
        self.assertEqual(resp_pub.status_code, status.HTTP_200_OK)
        self.assertEqual(resp_pub.json()['id'], self.election_open_1.id)

        url_track = reverse('election-track-retrieve', args=[self.election_open_1.id])
        resp_track = self.client.get(url_track)
        self.assertEqual(resp_track.status_code, status.HTTP_200_OK)
        self.assertEqual(resp_track.json()['id'], self.election_open_1.id)

    def test_retrieve_election_filter_voters_who_voted(self):
        """Parâmetro ?has_voted=true deve retornar apenas eleitores que já votaram."""
        url = reverse('public-election-detail', args=[self.election_open_1.id]) + '?has_voted=true'
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        colegiado = data['electoral_college']

        # Total geral da eleição permanece intacto para quórum
        self.assertEqual(data['total_voters'], 3)
        self.assertEqual(data['voted_count'], 2)

        # Lista de eleitores filtrada
        self.assertEqual(len(colegiado), 2)
        for v in colegiado:
            self.assertTrue(v['has_voted'])

    def test_retrieve_election_filter_voters_pending(self):
        """Parâmetro ?has_voted=false deve retornar apenas eleitores pendentes de votação."""
        url = reverse('public-election-detail', args=[self.election_open_1.id]) + '?has_voted=false'
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        colegiado = data['electoral_college']

        self.assertEqual(len(colegiado), 1)
        self.assertFalse(colegiado[0]['has_voted'])
        self.assertEqual(colegiado[0]['email'], "beatriz.mendes@votaai.org")

    def test_retrieve_election_search_voter_by_name(self):
        """Parâmetro ?search= deve buscar eleitor por nome, apelido ou e-mail."""
        url = reverse('public-election-detail', args=[self.election_open_1.id]) + '?search=Carlos'
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        colegiado = data['electoral_college']

        self.assertEqual(len(colegiado), 1)
        self.assertEqual(colegiado[0]['full_name'], "Carlos Eduardo Lima")

    def test_retrieve_election_created_not_accessible(self):
        """Eleições ainda em status CREATED (rascunho) não são acessíveis publicamente (404)."""
        url = reverse('public-election-detail', args=[self.election_created.id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_non_existent_election_returns_404(self):
        """Eleição com ID inexistente deve retornar 404."""
        url = reverse('public-election-detail', args=[999999])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_closed_election_allows_viewing_final_quorum(self):
        """Eleições encerradas (CLOSED) podem ter seu quórum final visualizado."""
        url = reverse('public-election-detail', args=[self.election_closed.id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data['status'], ElectionStatus.CLOSED)
        self.assertEqual(data['total_voters'], 1)
        self.assertEqual(data['voted_count'], 1)
        self.assertEqual(data['quorum_percentage'], 100.0)
        self.assertEqual(len(data['electoral_college']), 1)
        self.assertTrue(data['electoral_college'][0]['has_voted'])
