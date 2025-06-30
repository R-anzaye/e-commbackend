from django.apps import AppConfig
from firebase_admin import credentials, initialize_app
from django.conf import settings
import firebase_admin

class AuthAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'auth_app'

    def ready(self):
        if not firebase_admin._apps:
            cred = credentials.Certificate(settings.FIREBASE_CREDENTIALS)
            