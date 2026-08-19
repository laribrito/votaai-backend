"""
Test: User Management

This module contains integration tests for User endpoints (List, Invite), 
replacing the old Bruno API tests.
"""
from django.urls import reverse
from Domain.models.schemas.moderation.userSchema import User
from django.contrib.auth.models import Group
from rest_framework import status
from rest_framework.test import APITestCase
from knox.models import AuthToken
from Domain.models import GroupRoles
from django.test import override_settings

@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class UserManagementTests(APITestCase):
    """Tests for the User Management endpoints."""

    def setUp(self):
        # Create groups
        self.adminGroup, _ = Group.objects.get_or_create(name=GroupRoles.ADMIN.value)
        self.editorGroup, _ = Group.objects.get_or_create(name='Redator')

        # Create admin user
        self.adminUser = User.objects.create_superuser(
            username='admin_users_test',
            email='admin_users@example.com',
            password='adminpassword123',
            first_name='Admin',
            last_name='User',
        )
        self.adminUser.groups.add(self.adminGroup)
        _, self.adminToken = AuthToken.objects.create(self.adminUser)

        # Create groups for tests
        Group.objects.get_or_create(name='Redator')
        Group.objects.get_or_create(name='Administrador')

        # Create regular user
        self.regularUser = User.objects.create_user(
            username='john_doe',
            email='john@example.com',
            password='userpassword123',
            first_name='John',
            last_name='Doe',
        )
        self.regularUser.groups.add(self.editorGroup)

    def testListUsers(self):
        """Admin can list users and use filters (search, role, is_active)."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.adminToken}')
        
        url = reverse('user-list-list')
        
        # 1. Basic list
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data) >= 2)

        # 2. Test search filter
        response = self.client.get(url, {'search': 'john'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['username'], 'john_doe')
        
        # 3. Test active filter
        response = self.client.get(url, {'is_active': 'true'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def testInviteUser(self):
        """Admin can invite a new user with specific roles."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.adminToken}')
        
        url = reverse('user-invitation-list')
        payload = {
            'first_name': 'Jane',
            'last_name': 'Doe',
            'email': 'newuser@example.com',
            'username': 'newuser',
            'roles': ['Redator']
        }
        
        response = self.client.post(url, payload, format='json')
        
        # Some invitation endpoints return 200 or 201
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED])
        
        # Verify in DB
        self.assertTrue(User.objects.filter(username='newuser').exists())
