"""
Test: Group & Permission Management

This module contains integration tests for the GroupViewSet and PermissionViewSet endpoints,
validating full CRUD operations, RBAC enforcement, custom permission registration, and system protection.
"""
from django.urls import reverse
from Domain.models.schemas.moderation.userSchema import User
from django.contrib.auth.models import Group, Permission
from rest_framework import status
from rest_framework.test import APITestCase
from knox.models import AuthToken

from Domain.models import GroupRoles, DomainPermissions



class GroupViewSetTests(APITestCase):
    """Tests for the Group Management endpoints (/groups/)."""

    def setUp(self):
        # Admin / Superuser
        self.adminUser = User.objects.create_superuser(
            username='admin_group_test',
            email='admin_groups@example.com',
            password='adminpassword123',
            first_name='Admin',
            last_name='User',
        )
        _, self.admin_token = AuthToken.objects.create(self.adminUser)

        # Regular user without permissions
        self.regularUser = User.objects.create_user(
            username='regular_group_test',
            email='regular_groups@example.com',
            password='userpassword123',
            first_name='Regular',
            last_name='User',
        )
        _, self.regular_token = AuthToken.objects.create(self.regularUser)

        # Ensure default groups exist for testing
        self.test_group, _ = Group.objects.get_or_create(name='Equipe Teste')
        self.admin_group, _ = Group.objects.get_or_create(name=GroupRoles.ADMIN.value)

    def testListGroupsAsAdmin(self):
        """Admin can list all groups along with user and permission counts."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        response = self.client.get(reverse('group-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(isinstance(response.data, list))
        groupNames = [g['name'] for g in response.data]
        self.assertIn('Equipe Teste', groupNames)
        self.assertIn(GroupRoles.ADMIN.value, groupNames)

    def testListGroupsRegularUserForbidden(self):
        """Regular users without group management permissions receive 403 Forbidden."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.regular_token}')
        response = self.client.get(reverse('group-list'))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def testCreateGroupWithPermissions(self):
        """Admin can create a new group and assign permissions via codenames or IDs."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        
        # Ensure a permission exists to assign
        perm = Permission.objects.first()
        self.assertIsNotNone(perm)

        payload = {
            'name': 'Redatores Seniores',
            'permissions': [perm.codename, DomainPermissions.CAN_MANAGE_USERS]
        }
        response = self.client.post(reverse('group-list'), payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'Redatores Seniores')
        
        # Verify in DB
        newGroup = Group.objects.get(name='Redatores Seniores')
        self.assertTrue(newGroup.permissions.exists())

    def testRetrieveGroupDetails(self):
        """Retrieving a specific group returns user details."""
        self.adminUser.groups.add(self.test_group)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')

        url = reverse('group-detail', kwargs={'pk': self.test_group.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.test_group.pk)
        self.assertIn('users', response.data)
        userIds = [u['id'] for u in response.data['users']]
        self.assertIn(self.adminUser.pk, userIds)

    def testUpdateGroup(self):
        """Admin can update group name and assign new permissions."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        url = reverse('group-detail', kwargs={'pk': self.test_group.pk})

        payload = {
            'name': 'Equipe Teste Atualizada',
            'permissions': []
        }
        response = self.client.patch(url, payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Equipe Teste Atualizada')
        self.test_group.refresh_from_db()
        self.assertEqual(self.test_group.name, 'Equipe Teste Atualizada')

    def testDeleteRegularGroup(self):
        """Admin can delete a regular custom group."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        url = reverse('group-detail', kwargs={'pk': self.test_group.pk})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Group.objects.filter(pk=self.test_group.pk).exists())

    def testDeleteProtectedAdminGroupRejected(self):
        """Attempting to delete system protected groups like Administrador returns 400."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        url = reverse('group-detail', kwargs={'pk': self.admin_group.pk})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(Group.objects.filter(pk=self.admin_group.pk).exists())


class PermissionViewSetTests(APITestCase):
    """Tests for the Custom Permission Management endpoints (/permissions/)."""

    def setUp(self):
        self.adminUser = User.objects.create_superuser(
            username='admin_perm_test',
            email='admin_perms@example.com',
            password='adminpassword123'
        )
        _, self.admin_token = AuthToken.objects.create(self.adminUser)

    def testListPermissions(self):
        """Admin can list available permissions."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        response = self.client.get(reverse('permission-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data) > 0)
        # Check standard fields exist
        firstItem = response.data[0]
        self.assertIn('codename', firstItem)
        self.assertIn('full_codename', firstItem)
        self.assertIn('app_label', firstItem)

    def testCreateCustomPermission(self):
        """Admin can dynamically create and register a custom permission."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        payload = {
            'codename': 'can_moderate_comments',
            'name': 'Can moderate system entities and resources',
            'app_label': 'Domain'
        }
        response = self.client.post(reverse('permission-list'), payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['codename'], 'can_moderate_comments')
        self.assertEqual(response.data['full_codename'], 'Domain.can_moderate_comments')

        # Verify in DB
        self.assertTrue(Permission.objects.filter(codename='can_moderate_comments').exists())

    def testDeleteCustomPermission(self):
        """Admin can delete custom permissions, but cannot delete Django core model permissions."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token}')
        
        # 1. Create a custom permission to delete
        customPerm = Permission.objects.create(
            codename='temporary_custom_perm',
            name='Temporary custom permission',
            contentType=Permission.objects.first().contentType
        )
        url = reverse('permission-detail', kwargs={'pk': customPerm.pk})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Permission.objects.filter(pk=customPerm.pk).exists())

        # 2. Attempt to delete a Django core permission (e.g., add_user)
        corePerm = Permission.objects.filter(codename__startswith='add_').first()
        if corePerm:
            urlCore = reverse('permission-detail', kwargs={'pk': corePerm.pk})
            responseCore = self.client.delete(urlCore)
            self.assertEqual(responseCore.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertTrue(Permission.objects.filter(pk=corePerm.pk).exists())
