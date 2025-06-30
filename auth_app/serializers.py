from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import CustomUser, Product, Purchase, PurchaseItem, CartItem, WishlistItem, Notification, QuickLink, CustomerInquiry
import bleach

User = get_user_model()

SIZE_OPTIONS = {
    'Shoes': ['36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48'],
    'T-Shirts': ['S', 'M', 'L', 'XL', 'XXL'],
    'Shirts': ['S', 'M', 'L', 'XL', 'XXL'],
    'Sweaters': ['S', 'M', 'L', 'XL', 'XXL'],
    'Hoodies': ['S', 'M', 'L', 'XL', 'XXL'],
    'Trousers': ['28', '30', '32', '34', '36', '38'],
    'Jeans': ['28', '30', '32', '34', '36', '38'],
    'Dresses': ['S', 'M', 'L', 'XL'],
    'Skirts': ['S', 'M', 'L', 'XL'],
    'Blouses': ['S', 'M', 'L', 'XL'],
    'Suits': ['S', 'M', 'L', 'XL'],
    'Sportswear': ['S', 'M', 'L', 'XL'],
    'Underwear': ['S', 'M', 'L', 'XL'],
    'Swimwear': ['S', 'M', 'L', 'XL'],
    'Sleepwear': ['S', 'M', 'L', 'XL'],
    'Formal Wear': ['S', 'M', 'L', 'XL'],
    'Casual Wear': ['S', 'M', 'L', 'XL'],
    'Outerwear': ['S', 'M', 'L', 'XL'],
}

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone', 'address', 'city', 'state', 'zip', 'country']
        read_only_fields = ['id', 'email', 'firebase_uid']

    def validate(self, data):
        for field in ['username', 'phone', 'address', 'city', 'state', 'country']:
            if field in data:
                data[field] = bleach.clean(data[field]) if data[field] else None
        return data

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, data):
        data['username'] = bleach.clean(data['username'])
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user

class ProductSerializer(serializers.ModelSerializer):
    images = serializers.ListField(child=serializers.URLField(), default=[])
    sizes = serializers.ListField(child=serializers.CharField(), default=[])

    class Meta:
        model = Product
        fields = ['id', 'name', 'price', 'description', 'image', 'images', 'category', 'stock', 'featured', 'sizes', 'created_at']

    def validate(self, data):
        category = bleach.clean(data.get('category', ''))
        sizes = data.get('sizes', [])
        data['name'] = bleach.clean(data.get('name', ''))
        data['description'] = bleach.clean(data.get('description', ''))

        if category in SIZE_OPTIONS:
            valid_sizes = SIZE_OPTIONS[category]
            for size in sizes:
                if size not in valid_sizes:
                    raise serializers.ValidationError(
                        f"Invalid size '{size}' for category '{category}'. Valid sizes are: {', '.join(valid_sizes)}"
                    )
        elif sizes and category:
            raise serializers.ValidationError(f"Category '{category}' does not support sizes.")
        return data

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['images'] = instance.images if isinstance(instance.images, list) else []
        representation['sizes'] = instance.sizes if isinstance(instance.sizes, list) else []
        return representation

class PurchaseItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_id = serializers.CharField(write_only=True)
    size = serializers.CharField(max_length=10, required=False, allow_null=True, allow_blank=True)

    class Meta:
        model = PurchaseItem
        fields = ['id', 'product', 'quantity', 'product_id', 'size']
        read_only_fields = ['id', 'product']

    def validate(self, data):
        product_id = bleach.clean(data.get('product_id', ''))
        size = bleach.clean(data.get('size', '')) if data.get('size') else None
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            raise serializers.ValidationError("Product not found")
        if size and product.sizes and size not in product.sizes:
            raise serializers.ValidationError(
                f"Invalid size '{size}' for product '{product.name}'. Valid sizes are: {', '.join(product.sizes)}"
            )
        data['product_id'] = product_id
        data['size'] = size
        return data

class PurchaseSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    items = PurchaseItemSerializer(many=True, read_only=True, source='purchaseitem_set')

    class Meta:
        model = Purchase
        fields = ['id', 'user', 'items', 'total', 'status', 'date']

    def validate(self, data):
        if 'status' in data:
            data['status'] = bleach.clean(data['status'])
        return data

class CartItemSerializer(serializers.ModelSerializer):
    product_id = serializers.CharField(write_only=True, required=True)
    quantity = serializers.IntegerField(min_value=1)
    size = serializers.CharField(max_length=10, required=False, allow_null=True, allow_blank=True)

    class Meta:
        model = CartItem
        fields = ['id', 'product', 'product_id', 'quantity', 'size']
        read_only_fields = ['id', 'product']

    def validate(self, data):
        product_id = bleach.clean(data.get('product_id', ''))
        size = bleach.clean(data.get('size', '')) if data.get('size') else None
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            raise serializers.ValidationError("Product not found")
        if size and product.sizes and size not in product.sizes:
            raise serializers.ValidationError(
                f" NubbinLabs\website\django\ecommerce\auth_app\serializers.py: Invalid size '{size}' for product '{product.name}'. Valid sizes are: {', '.join(product.sizes)}"
            )
        data['product'] = product
        return data

    def create(self, validated_data):
        validated_data.pop('product_id', None)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data.pop('product_id', None)
        return super().update(instance, validated_data)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        product = instance.product
        representation['product'] = {
            'id': product.id,
            'name': bleach.clean(product.name),
            'price': product.price,
            'category': bleach.clean(product.category or 'Uncategorized'),
            'images': product.images if isinstance(product.images, list) else [],
            'sizes': product.sizes if isinstance(product.sizes, list) else [],
        }
        representation['size'] = bleach.clean(instance.size) if instance.size else None
        return representation

class WishlistItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_id = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), source='product', write_only=True
    )
    size = serializers.CharField(max_length=10, required=False, allow_null=True, allow_blank=True)

    class Meta:
        model = WishlistItem
        fields = ['id', 'user', 'product', 'product_id', 'size']
        read_only_fields = ['user']

    def validate(self, data):
        product = data.get('product')
        size = bleach.clean(data.get('size', '')) if data.get('size') else None
        if size and product.sizes and size not in product.sizes:
            raise serializers.ValidationError(
                f"Invalid size '{size}' for product '{product.name}'. Valid sizes are: {', '.join(product.sizes)}"
            )
        return data

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'user', 'type', 'message', 'read', 'date']
        read_only_fields = ['user']

    def validate(self, data):
        data['type'] = bleach.clean(data['type'])
        data['message'] = bleach.clean(data['message'])
        return data

class QuickLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = QuickLink
        fields = ['id', 'title', 'url', 'created_at']

    def validate(self, data):
        data['title'] = bleach.clean(data['title'])
        data['url'] = bleach.clean(data['url'])
        return data

class CustomerInquirySerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerInquiry
        fields = ['id', 'user', 'email', 'subject', 'message', 'status', 'created_at']

    def validate(self, data):
        data['subject'] = bleach.clean(data['subject'])
        data['message'] = bleach.clean(data['message'])
        return data