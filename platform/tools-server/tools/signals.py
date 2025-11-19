from django.db.models.signals import post_save, post_delete, m2m_changed
from django.dispatch import receiver
from django.core.cache import cache
from django_redis import get_redis_connection
from tools.models import NormalizedCapability, AccessGrant
import logging


logger = logging.getLogger(__name__)

def _delete_pattern(pattern: str):
    # Works only with django-redis
    try:
        cache.delete_pattern(pattern)
    except Exception:
        # Fallback to direct redis (if available)
        try:
            r = get_redis_connection("default")
            for k in r.scan_iter(pattern):
                r.delete(k)
        except Exception:
            pass

def invalidate_tenant(tenant_id):
    _delete_pattern(f"cap_snapshot:{tenant_id}:*")

def invalidate_team(tenant_id, team_id):
    _delete_pattern(f"cap_snapshot:{tenant_id}:{team_id}:*")

@receiver(post_save, sender=NormalizedCapability)
@receiver(post_delete, sender=NormalizedCapability)
def on_capability_change(sender, instance: NormalizedCapability, **kwargs):
    # Only post_save provides 'created' in kwargs
    created = kwargs.get('created', False)
    if created:
        grant, _ = AccessGrant.objects.get_or_create(
            team=instance.provider.owner_team,
            capability=instance,
            version=instance.version,
            defaults={
                "scopes": NormalizedCapability.DEFAULT_SCOPES,
                "approved_by": instance.created_by,
                "approved_by_type": instance.created_by_type,
                "approved_by_identifier": instance.created_by_identifier,
            },
        )
        logger.info(f"Auto-created AccessGrant {grant.id} for new capability {instance.id}") 
    # Any change to caps affects snapshots tenant-wide
    invalidate_tenant(instance.tenant_id)

@receiver(post_save, sender=AccessGrant)
@receiver(post_delete, sender=AccessGrant)
def on_access_grant_change(sender, instance: AccessGrant, **kwargs):
    # Only that team's snapshot is affected
    team = instance.team
    invalidate_team(team.tenant_id, team.id)
