from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User 
        fields = ('username', 'password')

class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserProfile 
        fields = ('pk', 'user', 'first_name', 'last_name', 'user_email','photo')

    