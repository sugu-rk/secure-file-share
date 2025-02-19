from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed 
User = get_user_model()
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from django.conf import settings
from rest_framework.serializers import ErrorDetail

class RegistrationSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'}, min_length=8)
    password2 = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match.")

        password = data['password']
        if not any(char.isdigit() for char in password):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not any(char.isalpha() for char in password):
            raise serializers.ValidationError("Password must contain at least one letter.")
        if not any(not char.isalnum() for char in password):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['username'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user is None:
                raise AuthenticationFailed("Invalid credentials")
            data['user'] = user
        else:
            raise serializers.ValidationError("Must include 'username' and 'password'.")
        return data

class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'is_staff', 'is_superuser', 'date_joined', 'last_login')

class MFAVerifySerializer(serializers.Serializer):
    token = serializers.CharField(required=True, min_length=6, max_length=6)
    username = serializers.CharField(required=True)

class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    refresh = serializers.CharField(required=False) # Make 'refresh' field NOT required

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get(settings.JWT_AUTH_REFRESH_COOKIE)

        if not attrs['refresh']:
            raise serializers.ValidationError(
                {'refresh': [ErrorDetail(string='No valid refresh token found in cookie', code='missing')]}
            )
        
        return super().validate(attrs) # Call original validation with refresh token from cookie