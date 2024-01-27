from rest_framework import serializers
from django.contrib.auth.models import User
from login_history.models import LoginHistory
from .models import User_Profile  

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User_Profile
        fields = ['phone','location', 'gender','photo']  # Add the fields you want to include from UserProfile

class UserSerializer(serializers.ModelSerializer):
    userprofile = UserProfileSerializer(source='user_profile', read_only=True)  # Adjust field name if necessary

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'is_active', 'userprofile']


class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginHistory
        fields = ['date_time', 'is_login']  # Replace with actual field names
