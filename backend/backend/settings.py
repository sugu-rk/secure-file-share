"""
Django settings for backend project.
"""

from pathlib import Path
import os
from datetime import timedelta # Import timedelta for JWT settings
from cryptography.fernet import Fernet # Import Fernet

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-hor_)yza7wenukmhfcc_-uo48s+h1uvaa3@s8c3e(brzuo^m4i') # Use environment variable for production

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', True) # Use environment variable

ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '127.0.0.1,localhost').split(',') # Use environment variable


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Our apps:
    'authentication',
    'files',

    # Django REST Framework:
    'rest_framework',

    #jwt:
    'rest_framework_simplejwt',

    #MFA
    'drf_totp',
    'corsheaders', # CORS

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware', # CORS middleware
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'authentication.authentication.JWTAuthenticationFromCookie', # Custom auth class for refresh token cookie
    )
}

# JWT Settings (configure cookie settings)
JWT_AUTH_REFRESH_COOKIE = 'refresh_token' # Name of the refresh token cookie
JWT_AUTH_COOKIE_SECURE = False  # Send cookies only over HTTPS in production (set to False for local testing if not using HTTPS)
JWT_AUTH_COOKIE_SAMESITE = 'lax' # or 'Strict' - adjust based on your needs and frontend setup  # Changed to lowercase 'lax' for consistency

SIMPLE_JWT = {
    'AUTH_HEADER_TYPES': ('Bearer',), # or ('JWT',) - customize as needed
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15), # Example: 15 minutes access token lifetime
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),   # Example: 7 days refresh token lifetime
    'TOKEN_REFRESH_SERIALIZER': 'authentication.serializers.CustomTokenRefreshSerializer', # <--- Add this line
}

UPLOAD_URL = '/uploads/'  # More generic URL prefix for uploads
UPLOAD_ROOT = os.path.join(BASE_DIR, 'uploads') # More generic directory for uploads

# Master encryption key for files - MUST BE SECURELY STORED IN PRODUCTION (env variable, secret manager)
# MASTER_ENCRYPTION_KEY_FILES = os.environ.get('MASTER_ENCRYPTION_KEY_FILES', Fernet.generate_key().decode()) # Default key for testing
#                                                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Add default key generation for testing
MASTER_ENCRYPTION_KEY_FILES = "t7i6l0y0MEkSkj5brjI6DHSGO8g46OxATEz-LUwjEFg="
# CORS settings - adjust as needed for your frontend origin
CORS_ALLOW_CREDENTIALS = True # Allow cookies to be sent in CORS requests
CORS_ORIGIN_WHITELIST = [ # Replace with your frontend's origin(s) in production
    'http://localhost:3000', # Example for React dev server
    'http://127.0.0.1:3000',
    'https://yourfrontenddomain.com', # Example for production frontend
]


# drf-totp settings (optional - customize issuer name)
TOTP_ISSUER_NAME = "SecureFileShareApp" # Customize issuer name for TOTP QR codes



LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
'handlers': {
'console': {
'class': 'logging.StreamHandler',
},
},
'loggers': {
'files': { # Logger for 'files' app (serializers, views, etc.)
'handlers': ['console'],
'level': 'DEBUG', # Set to DEBUG to see debug logs
'propagate': True,
},
'': { # Root logger for everything else
'handlers': ['console'],
'level': 'INFO', # Default level for other logs
},
},
}

CORS_EXPOSE_HEADERS = ['X-Encryption-Key', 'X-IV']

