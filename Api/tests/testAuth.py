"""
Test: Authentication & User Management

This module contains integration tests for the auth and user management
endpoints that ship with the template. Use these as a reference to write
tests for your own domain modules.

Test classes follow this structure:
    class <Feature>Tests(APITestCase):
        def setUp(self)          : creates test data
        def test_<scenario>(self): validates a single behavior
        def tearDown(self)       : cleanup (optional)

Run with: python manage.py test Api.tests
"""
from django.urls import reverse
from Domain.models.schemas.moderation.userSchema import User
from rest_framework import status
from rest_framework.test import APITestCase
from knox.models import AuthToken



class AuthTests(APITestCase):
    """Tests for the authentication endpoints."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpassword123',
            first_name='Test',
            last_name='User',
        )
        self.loginUrl = reverse('auth-login')

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def testLoginSuccess(self):
        """Authenticated user receives a token on valid credentials."""
        response = self.client.post(self.loginUrl, {
            'username': 'testuser',
            'password': 'testpassword123',
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)

    def testLoginInvalidCredentials(self):
        """Wrong password returns 401."""
        response = self.client.post(self.loginUrl, {
            'username': 'testuser',
            'password': 'wrongpassword',
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def testLoginInactiveUser(self):
        """Inactive accounts are rejected even with valid credentials."""
        self.user.is_active = False
        self.user.save()

        response = self.client.post(self.loginUrl, {
            'username': 'testuser',
            'password': 'testpassword123',
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ------------------------------------------------------------------
    # Me endpoint
    # ------------------------------------------------------------------

    def testMeReturnsCurrentUser(self):
        """Authenticated request to /auth/me/ returns the user's data."""
        _, token = AuthToken.objects.create(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')

        response = self.client.get(reverse('auth-me'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.user.username)

    def testMeRequiresAuthentication(self):
        """Unauthenticated request to /auth/me/ is rejected."""
        response = self.client.get(reverse('auth-me'))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
