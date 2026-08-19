from rest_framework import serializers
from django.contrib.auth.models import Group


class RoleListSerializer(serializers.ModelSerializer):
    """
    Serializer: Exposes Django Groups as selectable 'Roles' for the frontend.
    """

    class Meta:
        model = Group
        fields = ['id', 'name']
