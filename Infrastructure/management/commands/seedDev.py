"""
Management Command: seed_dev

Creates a default superuser for local development.
Usage: python manage.py seed_dev

This command is idempotent — running it multiple times will not create
duplicate users or data.

Customize this command to seed any initial data your application needs
beyond the Groups and Permissions seeded automatically by group_signals.py.
"""
from django.core.management.base import BaseCommand
from Domain.models.schemas.moderation.userSchema import User


class Command(BaseCommand):
    help = "Seeds a default development superuser."

    def handle(self, *args, **options):
        username = 'admin'
        email = 'admin@example.com'
        password = 'admin123'

        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(
                f'⚠️  Superuser "{username}" already exists. Skipping.'
            ))
            return

        User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            first_name='Admin',
            last_name='User',
        )

        self.stdout.write(self.style.SUCCESS(
            f'✅ Superuser created → username: {username} | password: {password}'
        ))
