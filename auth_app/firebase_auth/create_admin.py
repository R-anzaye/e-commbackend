from auth_app.models import CustomUser
from uuid import UUID

admin_user = CustomUser.objects.create_superuser(
    email='styles@gmail.com',
    username='styles',
    password='your_secure_password',
    id=UUID('Zz2B52Za42gbNciMHWlFeU5pUlC2'),
    firebase_uid='Zz2B52Za42gbNciMHWlFeU5pUlC2'
)
print("Admin created:", admin_user)
