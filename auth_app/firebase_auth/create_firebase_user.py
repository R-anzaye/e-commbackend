from firebase_admin import auth

auth.create_user(
    uid='Zz2B52Za42gbNciMHWlFeU5pUlC2',
    email='styles@gmail.com',
    email_verified=True,
    display_name='styles'
)
print("Firebase admin user created.")

