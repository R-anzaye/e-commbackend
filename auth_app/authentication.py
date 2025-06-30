import firebase_admin
from firebase_admin import credentials, auth
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings

User = get_user_model()

# Initialize Firebase Admin SDK
cred = credentials.Certificate(settings.FIREBASE_CREDENTIALS)
firebase_admin.initialize_app(cred)

class FirebaseAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None

        try:
            token = auth_header.split("Bearer ")[1]
            decoded_token = auth.verify_id_token(token)
            uid = decoded_token['uid']
            email = decoded_token.get('email', '')

            user, created = User.objects.get_or_create(
                firebase_uid=uid,
                defaults={'username': email.split('@')[0], 'email': email}
            )
            if not created and user.email != email:
                user.email = email
                user.save()

            return (user, None)
        except (IndexError, ValueError, auth.InvalidIdTokenError, auth.ExpiredIdTokenError):
            raise AuthenticationFailed('Invalid or expired Firebase token')
        except Exception as e:
            raise AuthenticationFailed(f'Authentication error: {str(e)}')