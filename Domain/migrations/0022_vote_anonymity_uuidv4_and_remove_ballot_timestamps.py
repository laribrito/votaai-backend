import json
import secrets
import uuid

import django.db.models.deletion
from django.db import migrations, models

import Domain.models.proxies.election.voteProxy
import Domain.models.proxies.election.votingTokenProxy

_SNAPSHOT: dict[str, list[dict]] = {
    'votes': [],
    'tickets': [],
    'tokens': [],
}


def _strip_id_voto_from_content(content: str) -> str:
    """Remove exposed id_voto from Vote.content JSON, preserving only pacote_cifrado."""
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict) and 'pacote_cifrado' in parsed:
            pacote = str(parsed.get('pacote_cifrado') or '').strip()
            if pacote:
                return pacote
    except Exception:
        pass
    return content


def snapshot_existing_records(apps, schema_editor):
    Vote = apps.get_model('Domain', 'Vote')
    BallotTicket = apps.get_model('Domain', 'BallotTicket')
    VotingToken = apps.get_model('Domain', 'VotingToken')

    _SNAPSHOT['votes'] = [
        {
            'id_generated': v.id_generated,
            'content': _strip_id_voto_from_content(v.content),
            'election_id': v.election_id,
        }
        for v in Vote.objects.all()
    ]
    _SNAPSHOT['tickets'] = [
        {
            'election_id': t.election_id,
            'id_voto': t.id_voto,
            'is_used': t.is_used,
        }
        for t in BallotTicket.objects.all()
    ]
    _SNAPSHOT['tokens'] = [
        {
            'token_hash': vt.token_hash,
            'voter_id': vt.voter_id,
            'election_id': vt.election_id,
            'is_used': vt.is_used,
            'machine_public_key': vt.machine_public_key,
            'nonce': vt.nonce,
            'failed_attempts': vt.failed_attempts,
            'is_blocked': vt.is_blocked,
            'blocked_at': vt.blocked_at,
            'last_attempt_at': None if vt.is_used else vt.last_attempt_at,
            'last_attempt_ip': None if vt.is_used else vt.last_attempt_ip,
        }
        for vt in VotingToken.objects.all()
    ]


def restore_shuffled_records(apps, schema_editor):
    Vote = apps.get_model('Domain', 'Vote')
    BallotTicket = apps.get_model('Domain', 'BallotTicket')
    VotingToken = apps.get_model('Domain', 'VotingToken')

    rng = secrets.SystemRandom()
    votes = list(_SNAPSHOT['votes'])
    tickets = list(_SNAPSHOT['tickets'])
    tokens = list(_SNAPSHOT['tokens'])

    rng.shuffle(votes)
    rng.shuffle(tickets)
    rng.shuffle(tokens)

    if votes:
        Vote.objects.bulk_create([
            Vote(
                id=uuid.uuid4(),
                id_generated=v['id_generated'],
                content=v['content'],
                election_id=v['election_id'],
            )
            for v in votes
        ])

    if tickets:
        BallotTicket.objects.bulk_create([
            BallotTicket(
                id=uuid.uuid4(),
                election_id=t['election_id'],
                id_voto=t['id_voto'],
                is_used=t['is_used'],
            )
            for t in tickets
        ])

    if tokens:
        VotingToken.objects.bulk_create([
            VotingToken(
                id=uuid.uuid4(),
                token_hash=vt['token_hash'],
                voter_id=vt['voter_id'],
                election_id=vt['election_id'],
                is_used=vt['is_used'],
                machine_public_key=vt['machine_public_key'],
                nonce=vt['nonce'],
                failed_attempts=vt['failed_attempts'],
                is_blocked=vt['is_blocked'],
                blocked_at=vt['blocked_at'],
                last_attempt_at=vt['last_attempt_at'],
                last_attempt_ip=vt['last_attempt_ip'],
            )
            for vt in tokens
        ])

    _SNAPSHOT['votes'].clear()
    _SNAPSHOT['tickets'].clear()
    _SNAPSHOT['tokens'].clear()


class Migration(migrations.Migration):

    dependencies = [
        ('Domain', '0021_user_email_verification'),
    ]

    operations = [
        migrations.RunPython(snapshot_existing_records, reverse_code=migrations.RunPython.noop),
        migrations.DeleteModel(name='Vote'),
        migrations.DeleteModel(name='BallotTicket'),
        migrations.DeleteModel(name='VotingToken'),
        migrations.CreateModel(
            name='Vote',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('id_generated', models.CharField(help_text='Unique identifier for the vote', max_length=255, unique=True, verbose_name='generated ID')),
                ('content', models.TextField(help_text='Encrypted payload of the vote cast by the voter', verbose_name='encrypted content')),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='votes', to='Domain.election', verbose_name='election')),
            ],
            options={
                'verbose_name': 'Vote',
                'verbose_name_plural': 'Votes',
            },
            bases=(Domain.models.proxies.election.voteProxy.VoteProxy, models.Model),
        ),
        migrations.CreateModel(
            name='BallotTicket',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('id_voto', models.CharField(db_index=True, help_text='Randomized ballot ticket identifier issued by the backend.', max_length=64, unique=True, verbose_name='id voto')),
                ('is_used', models.BooleanField(default=False, help_text='True once the ballot ticket has been consumed with a deposited vote.', verbose_name='is used')),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ballot_tickets', to='Domain.election', verbose_name='election')),
            ],
            options={
                'verbose_name': 'Ballot Ticket',
                'verbose_name_plural': 'Ballot Tickets',
            },
        ),
        migrations.CreateModel(
            name='VotingToken',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('token_hash', models.CharField(help_text='SHA-256 hash of the raw token. The raw value is never stored.', max_length=64, unique=True, verbose_name='token hash')),
                ('is_used', models.BooleanField(default=False, help_text='True after the token has been consumed to cast a vote.', verbose_name='is used')),
                ('machine_public_key', models.TextField(blank=True, default='', help_text='Hardware-backed public key of the machine/device that requested this ballot.', verbose_name='machine public key')),
                ('nonce', models.CharField(blank=True, default='', help_text='Latest nonce used for this voting token (anti-replay).', max_length=255, verbose_name='nonce')),
                ('failed_attempts', models.PositiveIntegerField(default=0, help_text='Count of consecutive invalid access attempts.', verbose_name='failed attempts')),
                ('is_blocked', models.BooleanField(default=False, help_text='Indicates whether this token has been blocked due to excessive invalid attempts.', verbose_name='is blocked')),
                ('blocked_at', models.DateTimeField(blank=True, help_text='Timestamp when this token was blocked.', null=True, verbose_name='blocked at')),
                ('last_attempt_at', models.DateTimeField(blank=True, help_text='Timestamp of the most recent access attempt.', null=True, verbose_name='last attempt at')),
                ('last_attempt_ip', models.GenericIPAddressField(blank=True, help_text='IP address of the most recent access attempt.', null=True, verbose_name='last attempt IP')),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='voting_tokens', to='Domain.election', verbose_name='election')),
                ('voter', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='voting_tokens', to='Domain.electoralcollege', verbose_name='voter')),
            ],
            options={
                'verbose_name': 'Voting Token',
                'verbose_name_plural': 'Voting Tokens',
            },
            bases=(Domain.models.proxies.election.votingTokenProxy.VotingTokenProxy, models.Model),
        ),
        migrations.RunPython(restore_shuffled_records, reverse_code=migrations.RunPython.noop),
    ]
