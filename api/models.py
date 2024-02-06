from django.db import models
import uuid
from django.contrib.auth.models import User


""" class CustomUser(models.Model):
    # Your user fields here
    is_deleted = models.BooleanField(default=False)
 """

class User_Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=True)
    first_name = models.CharField(max_length=200, blank=True)
    last_name = models.CharField(max_length=200, blank=True)
    email = models.EmailField(max_length=200, blank=True)
    gender = models.CharField(max_length=10, null=True, blank=True)
    phone = models.CharField(max_length=15, null=True, blank=True)
    location = models.CharField(max_length=200, null=True)
    birth_date = models.DateField(null=True)
    photo = models.ImageField(upload_to='images/', null=True, blank=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username
    
