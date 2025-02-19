from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

# User Profile model to extend User model (for MFA enabled status)
class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile') # One-to-one link to User model
    mfa_enabled = models.BooleanField(default=False) # MFA enabled status

    def __str__(self):
        return f"Profile for {self.user.email} - MFA Enabled: {self.mfa_enabled}"

# Signal to create UserProfile when a new User is created
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()