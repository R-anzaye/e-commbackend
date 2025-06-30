
from pathlib import Path
from decouple import config
import dj_database_url

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(exist_ok=True)
APPEND_SLASH = True

# Security settings
SECRET_KEY = config('DJANGO_SECRET_KEY')
DEBUG = config('DEBUG', default=True, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1').split(',')

# Static files
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / "frontend/build"]

# Cookie & security settings (for development)
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 1209600
SESSION_COOKIE_NAME = 'sessionid'
CSRF_COOKIE_NAME = 'csrftoken'
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
SECURE_CONTENT_TYPE_NOSNIFF = False
SECURE_BROWSER_XSS_FILTER = False
SECURE_REFERRER_POLICY = 'no-referrer-when-downgrade'

# CSRF & CORS
CSRF_TRUSTED_ORIGINS = ['http://127.0.0.1:8080', 'http://localhost:8000']
CORS_ALLOWED_ORIGINS = ['http://127.0.0.1:8080', 'http://localhost:8000']
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'cache-control',
    'pragma',
    'expires',
]

# Middleware
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'auth_app.middleware.LogRequestMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

# Installed apps
INSTALLED_APPS = [
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'django_filters',
    'auth_app',
]

# URL config
ROOT_URLCONF = 'ecommerce_backend.urls'
WSGI_APPLICATION = 'ecommerce_backend.wsgi.application'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'auth_app.authentication.FirebaseAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'login': '50/hour',
    },
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}

# Database
DATABASES = {
    'default': dj_database_url.config(
        default=config('DATABASE_URL', default='postgresql://ryan_anzaye:%23R11y11a20n05@localhost:5432/ecommerce_db'),
        conn_max_age=600,
    )
}

# Authentication
AUTH_USER_MODEL = 'auth_app.CustomUser'
SESSION_ENGINE = 'django.contrib.sessions.backends.db'

# File uploads
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880
ALLOWED_FILE_TYPES = ['image/jpeg', 'image/png', 'image/gif']

# Email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = config('EMAIL_HOST_USER')
SERVER_EMAIL = config('EMAIL_HOST_USER')

# Firebase Admin Credentials (correct project ID)
FIREBASE_CREDENTIALS = {
    "type": "service_account",
    "project_id": "sillva-styles",
    "private_key_id": config('FIREBASE_PRIVATE_KEY_ID'),
    "private_key": config('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
    "client_email": config('FIREBASE_CLIENT_EMAIL'),
    "client_id": config('FIREBASE_CLIENT_ID'),
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": config('FIREBASE_CLIENT_X509_CERT_URL'),
}

# Templates
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'auth_app' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {'format': '{levelname} {asctime} {module} {message}', 'style': '{'},
    },
    'handlers': {
        'file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': LOG_DIR / 'security.log',
            'formatter': 'verbose',
        },
        'request_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': LOG_DIR / 'requests.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django.security': {
            'handlers': ['file', 'console'],
            'level': 'WARNING',
            'propagate': True,
        },
        'django.request': {
            'handlers': ['console', 'request_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.contrib.sessions': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'auth_app': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
