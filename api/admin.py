from django.contrib import admin
from .models import *
from auditlog.registry import auditlog



# Register your models here.

admin.site.register(User_Profile)

auditlog.register(User_Profile)
auditlog.register(User)