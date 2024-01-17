
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.contrib.auth.signals import user_logged_in, user_logged_out


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=500, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    user_email = models.CharField(max_length=300, blank=True)
    photo = models.ImageField(null=True, blank=True)

    def __str__(self):
        return self.user.username


class ActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=128)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"

def log_user_activity(user, action):
    ActivityLog.objects.create(user=user, action=action)

def user_logged_in_handler(sender, request, user, **kwargs):
    log_user_activity(user, 'logged in')

def user_logged_out_handler(sender, request, user, **kwargs):
    log_user_activity(user, 'logged out')

#user_logged_in.connect(user_logged_in_handler)
#user_logged_out.connect(user_logged_out_handler)

