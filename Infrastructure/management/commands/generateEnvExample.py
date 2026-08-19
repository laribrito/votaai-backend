"""
Management Command: generate_env_example

Automatically generates a sanitized .env.example file from the current .env file.
Preserves comments, empty lines, and structure while sanitizing passwords, secret keys, and tokens.
Usage: python manage.py generate_env_example
"""
from pathlib import Path
from django.core.management.base import BaseCommand
from django.conf import settings


class Command(BaseCommand):
    help = "Generates a sanitized .env.example file from the local .env file."

    def addArguments(self, parser):
        parser.add_argument(
            '--source',
            type=str,
            default='.env',
            help='Path to the source .env file (default: .env)'
        )
        parser.add_argument(
            '--dest',
            type=str,
            default='.env.example',
            help='Path to the destination .env.example file (default: .env.example)'
        )

    def handle(self, *args, **options):
        baseDir = Path(settings.BASE_DIR)
        sourcePath = baseDir / options['source']
        destPath = baseDir / options['dest']

        if not sourcePath.exists():
            self.stdout.write(self.style.ERROR(f"[ERROR] Source file '{sourcePath}' does not exist."))
            return

        # Keywords that indicate sensitive fields whose values should be replaced by safe placeholders
        sensitiveKeywords = ['SECRET', 'PASSWORD', 'TOKEN', 'KEY', 'CREDENTIAL', 'PRIVATE', 'AUTH']

        lines = sourcePath.read_text(encoding='utf-8').splitlines()
        exampleLines = []

        for line in lines:
            stripped = line.strip()
            # Preserve empty lines and comments exactly as they are
            if not stripped or stripped.startswith('#'):
                exampleLines.append(line)
                continue

            # Parse KEY=VALUE assignments
            if '=' in line:
                key, _, value = line.partition('=')
                cleanKey = key.strip()
                upperKey = cleanKey.upper()

                # Check if key contains sensitive terms
                if any(kw in upperKey for kw in sensitiveKeywords):
                    if 'SECRET_KEY' in upperKey:
                        placeholder = 'django-insecure-change-this-in-production'
                    elif 'PASSWORD' in upperKey:
                        placeholder = 'postgres' if 'DB_PASSWORD' in upperKey else 'your_password_here'
                    elif 'HOST_USER' in upperKey:
                        placeholder = ''
                    else:
                        placeholder = f'your_{cleanKey.lower()}_here'
                    exampleLines.append(f"{cleanKey}={placeholder}")
                else:
                    # Keep non-sensitive default configs (DEBUG, DB_HOST, PORT, CORS, etc.)
                    exampleLines.append(f"{cleanKey}={value.strip()}")
            else:
                exampleLines.append(line)

        destPath.write_text('\n'.join(exampleLines) + '\n', encoding='utf-8')
        self.stdout.write(self.style.SUCCESS(
            f"[OK] Successfully generated sanitized '{options['dest']}' from '{options['source']}'!"
        ))
