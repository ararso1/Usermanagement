
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.contrib.auth.signals import user_logged_in, user_logged_out
import uuid
from django.conf import settings

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=500, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    user_email = models.CharField(max_length=300, blank=True)
    photo = models.ImageField(null=True, blank=True)

    def __str__(self):
        return self.user.username




