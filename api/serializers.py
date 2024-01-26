from rest_framework import serializers
from django.contrib.auth.models import User
from login_history.models import LoginHistory

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'is_active']  # Add other fields you want to include


class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginHistory
        fields = ['date_time', 'is_login']  # Replace with actual field names
