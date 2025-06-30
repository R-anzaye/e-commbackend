from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.conf import settings
import bleach
import mimetypes
from .utils import generate_product_id, generate_purchase_id

def validate_file_type(value):
    mime_type, _ = mimetypes.guess_type(value.name)
    if mime_type not in settings.ALLOWED_FILE_TYPES:
        raise ValidationError(f"Invalid file type: {mime_type}. Allowed types: {', '.join(settings.ALLOWED_FILE_TYPES)}")

class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        username = bleach.clean(username)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, username, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=255)
    firebase_uid = models.CharField(max_length=128, unique=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    phone = models.CharField(max_length=20, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    zip = models.CharField(max_length=20, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

class Product(models.Model):
    id = models.CharField(max_length=8, primary_key=True, default=generate_product_id, editable=False)
    name = models.CharField(max_length=255)
    price = models.IntegerField()
    description = models.TextField()
    image = models.ImageField(upload_to='products/', validators=[validate_file_type], null=True, blank=True)
    images = models.JSONField(default=list)
    category = models.CharField(max_length=100)
    stock = models.IntegerField()
    featured = models.BooleanField(default=False)
    sizes = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'products'

    def save(self, *args, **kwargs):
        self.name = bleach.clean(self.name)
        self.description = bleach.clean(self.description)
        self.category = bleach.clean(self.category)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

class Purchase(models.Model):
    id = models.CharField(max_length=8, primary_key=True, default=generate_purchase_id, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    total = models.IntegerField()
    status = models.CharField(max_length=20, default='pending')
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'purchases'

    def save(self, *args, **kwargs):
        self.status = bleach.clean(self.status)
        super().save(*args, **kwargs)

class PurchaseItem(models.Model):
    purchase = models.ForeignKey(Purchase, on_delete=models.CASCADE, to_field='id', related_name='purchaseitem_set')
    product = models.ForeignKey(Product, on_delete=models.CASCADE, to_field='id')
    quantity = models.PositiveIntegerField()
    size = models.CharField(max_length=10, blank=True, null=True)

    class Meta:
        db_table = 'purchase_items'

    def save(self, *args, **kwargs):
        if self.size:
            self.size = bleach.clean(self.size)
        super().save(*args, **kwargs)

class CartItem(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, to_field='id')
    quantity = models.PositiveIntegerField(default=1)
    size = models.CharField(max_length=10, blank=True, null=True)

    class Meta:
        db_table = 'cart_items'
        unique_together = ('user', 'product', 'size')

    def save(self, *args, **kwargs):
        if self.size:
            self.size = bleach.clean(self.size)
        super().save(*args, **kwargs)

class WishlistItem(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, to_field='id')
    size = models.CharField(max_length=10, blank=True, null=True)

    class Meta:
        db_table = 'wishlist_items'
        unique_together = ('user', 'product', 'size')

    def save(self, *args, **kwargs):
        if self.size:
            self.size = bleach.clean(self.size)
        super().save(*args, **kwargs)

class Notification(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)
    type = models.CharField(max_length=20)
    message = models.TextField()
    read = models.BooleanField(default=False)
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notifications'

    def save(self, *args, **kwargs):
        self.type = bleach.clean(self.type)
        self.message = bleach.clean(self.message)
        super().save(*args, **kwargs)

class QuickLink(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255)
    url = models.URLField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'quick_links'

    def save(self, *args, **kwargs):
        self.title = bleach.clean(self.title)
        super().save(*args, **kwargs)

class CustomerInquiry(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    status = models.CharField(max_length=20, choices=[('open', 'Open'), ('resolved', 'Resolved')], default='open')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'customer_inquiries'

    def save(self, *args, **kwargs):
        self.subject = bleach.clean(self.subject)
        self.message = bleach.clean(self.message)
        super().save(*args, **kwargs)