import requests
from rest_framework import generics, status
from django.db import transaction
from django.shortcuts import redirect
import xml.etree.ElementTree as ET
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from django.db import models
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import ensure_csrf_cookie
from django.conf import settings
from firebase_admin import auth
import logging
import bleach
from .models import Product, CartItem, WishlistItem, Notification, Purchase, PurchaseItem, QuickLink, CustomerInquiry, CustomUser
from .serializers import (
    UserSerializer, RegisterSerializer, ProductSerializer, CartItemSerializer,
    WishlistItemSerializer, NotificationSerializer, PurchaseSerializer,
    QuickLinkSerializer, CustomerInquirySerializer
)
from .utils import generate_unique_id

logger = logging.getLogger('auth_app')
User = get_user_model()

class LoginThrottle(UserRateThrottle):
    rate = '50/hour'

class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.email == 'styles@gmail.com'

class FirebaseAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
            logger.warning("Missing Authorization header")
            return None

        try:
            token = auth_header.split("Bearer ")[1]
            decoded_token = auth.verify_id_token(token)
            uid = decoded_token["uid"]
            user, created = get_user_model().objects.get_or_create(
                firebase_uid=uid,
                defaults={"email": decoded_token.get("email", ""), "username": decoded_token.get("name", uid)}
            )
            return (user, None)
        except (IndexError, auth.InvalidIdTokenError, auth.ExpiredIdTokenError) as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise AuthenticationFailed("Invalid or expired token")
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise AuthenticationFailed(f"Authentication error: {str(e)}")

@ensure_csrf_cookie
def get_csrf_token(request):
    csrf_token = request.META.get('CSRF_COOKIE')
    if not csrf_token:
        logger.warning("CSRF token not found in request")
        return JsonResponse({'csrfToken': None}, status=400)
    logger.info("CSRF token fetched successfully")
    return JsonResponse({'csrfToken': csrf_token})

class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            id_token = request.data.get('id_token')
            try:
                decoded_token = auth.verify_id_token(id_token)
                email = decoded_token.get('email')
                uid = decoded_token['uid']
                username = bleach.clean(serializer.validated_data['username'])

                user = User.objects.filter(firebase_uid=uid).first()
                if user:
                    if user.email != email and User.objects.filter(email=email).exclude(firebase_uid=uid).exists():
                        logger.warning(f"Email {email} already associated with another account")
                        return Response(
                            {'error': f'Email {email} is already associated with another account'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    user.email = email
                    user.username = username
                    user.save()
                else:
                    user = User.objects.create(
                        firebase_uid=uid,
                        email=email,
                        username=username,
                        is_active=True,
                    )
                auth.set_custom_user_claims(uid, {'is_superuser': user.is_superuser})
                logger.info(f"User registered: {email}")
                return Response({
                    'user': UserSerializer(user).data,
                }, status=status.HTTP_201_CREATED)
            except auth.InvalidIdTokenError:
                logger.error("Invalid Firebase token")
                return Response({'error': 'Invalid Firebase token'}, status=status.HTTP_400_BAD_REQUEST)
            except auth.ExpiredIdTokenError:
                logger.error("Expired Firebase token")
                return Response({'error': 'Expired Firebase token'}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"Registration error: {str(e)}")
                return Response({'error': f'Server error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        logger.warning(f"Registration serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ValidateFirebaseTokenView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]

    def post(self, request):
        id_token = request.data.get('id_token')
        username = bleach.clean(request.data.get('username', ''))
        if not id_token:
            logger.warning("Missing ID token")
            return Response({'error': 'ID token is missing'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            decoded_token = auth.verify_id_token(id_token)
            email = decoded_token.get('email')
            uid = decoded_token['uid']
            default_username = username or decoded_token.get('name') or email.split('@')[0]

            user, created = User.objects.get_or_create(
                firebase_uid=uid,
                defaults={'username': default_username, 'email': email}
            )
            if not created and username and username != user.username:
                user.username = username
                try:
                    user.save()
                except Exception as e:
                    logger.error(f"Failed to update user {uid}: {str(e)}")
                    return Response({'error': f'Failed to update user: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Merge session cart with user cart
            session_cart = request.session.get('cart', {})
            if session_cart:
                with transaction.atomic():
                    for product_id, item_data in session_cart.items():
                        try:
                            product = Product.objects.get(id=product_id)
                            cart_item, created = CartItem.objects.get_or_create(
                                user=user,
                                product=product,
                                size=item_data.get('size'),
                                defaults={'quantity': item_data.get('quantity', 1)}
                            )
                            if not created:
                                cart_item.quantity += item_data.get('quantity', 1)
                                cart_item.save()
                        except Product.DoesNotExist:
                            logger.warning(f"Product {product_id} not found during cart merge")
                    request.session['cart'] = {}
                    request.session.modified = True
                    logger.info(f"Session cart merged for user {email}")

            # Merge session wishlist with user wishlist
            session_wishlist = request.session.get('wishlist', {})
            if session_wishlist:
                with transaction.atomic():
                    for product_id, item_data in session_wishlist.items():
                        try:
                            product = Product.objects.get(id=product_id)
                            WishlistItem.objects.get_or_create(
                                user=user,
                                product=product,
                                size=item_data.get('size'),
                                defaults={'size': item_data.get('size')}
                            )
                        except Product.DoesNotExist:
                            logger.warning(f"Product {product_id} not found during wishlist merge")
                    request.session['wishlist'] = {}
                    request.session.modified = True
                    logger.info(f"Session wishlist merged for user {email}")

            logger.info(f"Firebase token validated for user: {email}")
            return Response({
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'username': user.username,
                },
            }, status=status.HTTP_200_OK)
        except auth.InvalidIdTokenError:
            logger.error("Invalid Firebase token")
            return Response({'error': 'Invalid Firebase token'}, status=status.HTTP_400_BAD_REQUEST)
        except auth.ExpiredIdTokenError:
            logger.error("Expired Firebase token")
            return Response({'error': 'Expired Firebase token'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return Response({'error': 'Server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def get(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user)
        logger.info(f"User details fetched for {user.email}")
        return Response(serializer.data)

class UserEditView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        data = request.data.copy()
        if 'email' in data:
            logger.warning(f"Attempt to update email for user {user.id} blocked")
            return Response(
                {'error': 'Email cannot be updated through this endpoint'},
                status=status.HTTP_400_BAD_REQUEST
            )

        for key in ['username', 'phone', 'address', 'city', 'state', 'country']:
            if key in data:
                data[key] = bleach.clean(data[key])

        serializer = UserSerializer(user, data=data, partial=True)
        if serializer.is_valid():
            try:
                serializer.save()
                logger.info(f"User {user.id} updated: {serializer.data}")
                return Response(serializer.data)
            except Exception as e:
                logger.error(f"Failed to update user {user.id}: {str(e)}")
                return Response(
                    {'error': f'Failed to update profile: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        logger.warning(f"User edit serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductListView(generics.ListCreateAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        queryset = Product.objects.all()
        category = self.request.query_params.get('category')
        search = self.request.query_params.get('q')
        min_price = self.request.query_params.get('min_price')
        max_price = self.request.query_params.get('max_price')
        in_stock = self.request.query_params.get('in_stock')

        if category:
            queryset = queryset.filter(category=bleach.clean(category))
        if search:
            search = bleach.clean(search)
            queryset = queryset.filter(
                models.Q(name__icontains=search) |
                models.Q(description__icontains=search)
            )
        if min_price:
            try:
                queryset = queryset.filter(price__gte=float(min_price))
            except ValueError:
                logger.warning(f"Invalid min_price parameter: {min_price}")
                return queryset.none()
        if max_price:
            try:
                queryset = queryset.filter(price__lte=float(max_price))
            except ValueError:
                logger.warning(f"Invalid max_price parameter: {max_price}")
                return queryset.none()
        if in_stock == 'true':
            queryset = queryset.filter(stock__gt=0)

        sort_by = self.request.query_params.get('sort_by')
        if sort_by == 'priceAsc':
            queryset = queryset.order_by('price')
        elif sort_by == 'priceDesc':
            queryset = queryset.order_by('-price')
        elif sort_by == 'newest':
            queryset = queryset.order_by('-created_at')

        return queryset

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_staff:
            logger.warning(f"Unauthorized product creation attempt by {request.user.email if request.user.is_authenticated else 'anonymous'}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        data = request.data.copy()
        data['name'] = bleach.clean(data.get('name', ''))
        data['description'] = bleach.clean(data.get('description', ''))
        data['category'] = bleach.clean(data.get('category', ''))
        serializer = ProductSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Product created by {request.user.email}: {serializer.data['name']}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.warning(f"Product creation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            product = self.get_object()
            serializer = self.get_serializer(product)
            logger.info(f"Product details fetched: {product.name}")
            return Response(serializer.data)
        except Product.DoesNotExist:
            logger.error(f"Product not found: {kwargs.get('pk')}")
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_staff:
            logger.warning(f"Unauthorized product update attempt by {request.user.email if request.user.is_authenticated else 'anonymous'}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        data = request.data.copy()
        data['name'] = bleach.clean(data.get('name', ''))
        data['description'] = bleach.clean(data.get('description', ''))
        data['category'] = bleach.clean(data.get('category', ''))
        serializer = self.get_serializer(self.get_object(), data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Product updated by {request.user.email}: {serializer.data['name']}")
            return Response(serializer.data)
        logger.warning(f"Product update errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_staff:
            logger.warning(f"Unauthorized product deletion attempt by {request.user.email if request.user.is_authenticated else 'anonymous'}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        try:
            product = self.get_object()
            product.delete()
            logger.info(f"Product deleted by {request.user.email}: {product.name}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Product.DoesNotExist:
            logger.error(f"Product not found: {kwargs.get('pk')}")
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

class CartView(APIView):
    permission_classes = [AllowAny]

    def _get_cart_items(self, request):
        if request.user.is_authenticated:
            return CartItem.objects.filter(user=request.user)
        else:
            session_cart = request.session.get('cart', {})
            cart_items = []
            for product_id, item_data in session_cart.items():
                try:
                    product = Product.objects.get(id=product_id)
                    cart_items.append({
                        'product': product,
                        'quantity': item_data.get('quantity', 1),
                        'size': item_data.get('size', None)
                    })
                except Product.DoesNotExist:
                    logger.warning(f"Product {product_id} not found in session cart")
            return cart_items

    def get(self, request):
        logger.debug(f"Fetching cart for {'user ' + request.user.email if request.user.is_authenticated else 'anonymous user'}")
        cart_items = self._get_cart_items(request)
        if request.user.is_authenticated:
            serializer = CartItemSerializer(cart_items, many=True)
        else:
            serializer = CartItemSerializer([{
                'user': None,
                'product': item['product'],
                'quantity': item['quantity'],
                'size': item['size']
            } for item in cart_items], many=True)
        return Response(serializer.data)

    def post(self, request):
        data = request.data
        logger.debug(f"Adding to cart for {'user ' + request.user.email if request.user.is_authenticated else 'anonymous user'}: {data}")
        
        if isinstance(data, list):
            errors = []
            for index, item in enumerate(data):
                item['product_id'] = bleach.clean(item.get('product_id', ''))
                item['size'] = bleach.clean(item.get('size', '')) if item.get('size') else None
                if request.user.is_authenticated:
                    serializer = CartItemSerializer(data=item)
                    if serializer.is_valid():
                        try:
                            cart_item = serializer.save(user=request.user)
                        except Exception as e:
                            errors.append({f"item_{index}": str(e)})
                    else:
                        errors.append({f"item_{index}": serializer.errors})
                else:
                    try:
                        product = Product.objects.get(id=item['product_id'])
                        session_cart = request.session.get('cart', {})
                        session_cart[item['product_id']] = {
                            'quantity': item.get('quantity', 1),
                            'size': item.get('size')
                        }
                        request.session['cart'] = session_cart
                        request.session.modified = True
                    except Product.DoesNotExist:
                        errors.append({f"item_{index}": "Product not found"})
            if errors:
                logger.warning(f"Cart bulk add errors: {errors}")
                return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)
            return Response(self.get(request).data, status=status.HTTP_201_CREATED)
        else:
            data['product_id'] = bleach.clean(data.get('product_id', ''))
            data['size'] = bleach.clean(data.get('size', '')) if data.get('size') else None
            if request.user.is_authenticated:
                serializer = CartItemSerializer(data=data)
                if serializer.is_valid():
                    try:
                        cart_item = serializer.save(user=request.user)
                        logger.info(f"Cart item added for user {request.user.email}: {cart_item.product.name}")
                        return Response(CartItemSerializer(cart_item).data, status=status.HTTP_201_CREATED)
                    except Exception as e:
                        logger.error(f"Cart add error: {str(e)}")
                        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
                logger.warning(f"Cart add serializer errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                try:
                    product = Product.objects.get(id=data['product_id'])
                    session_cart = request.session.get('cart', {})
                    session_cart[data['product_id']] = {
                        'quantity': data.get('quantity', 1),
                        'size': data.get('size')
                    }
                    request.session['cart'] = session_cart
                    request.session.modified = True
                    logger.info(f"Cart item added to session for anonymous user: {product.name}")
                    return Response(self.get(request).data, status=status.HTTP_201_CREATED)
                except Product.DoesNotExist:
                    logger.error(f"Product {data['product_id']} not found")
                    return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, product_id=None, size=None):
        logger.debug(f"Deleting cart item for {'user ' + request.user.email if request.user.is_authenticated else 'anonymous user'}: product_id={product_id}, size={size}")
        product_id = bleach.clean(str(product_id)) if product_id else None
        size = bleach.clean(size) if size else None

        if request.user.is_authenticated:
            if product_id and size:
                cart_item = CartItem.objects.filter(user=request.user, product_id=product_id, size=size).first()
                if cart_item:
                    cart_item.delete()
                    logger.info(f"Cart item deleted for user {request.user.email}: {product_id}, size={size}")
                    return Response(status=status.HTTP_204_NO_CONTENT)
                logger.warning(f"Cart item not found: {product_id}, size={size}")
                return Response({'error': 'Cart item not found'}, status=status.HTTP_404_NOT_FOUND)
            else:
                CartItem.objects.filter(user=request.user).delete()
                logger.info(f"Cart cleared for user {request.user.email}")
                return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            if product_id:
                session_cart = request.session.get('cart', {})
                if product_id in session_cart and (size is None or session_cart[product_id]['size'] == size):
                    del session_cart[product_id]
                    request.session['cart'] = session_cart
                    request.session.modified = True
                    logger.info(f"Cart item deleted from session: {product_id}, size={size}")
                    return Response(status=status.HTTP_204_NO_CONTENT)
                logger.warning(f"Cart item not found in session: {product_id}, size={size}")
                return Response({'error': 'Cart item not found'}, status=status.HTTP_404_NOT_FOUND)
            else:
                request.session['cart'] = {}
                request.session.modified = True
                logger.info(f"Cart cleared for anonymous user")
                return Response(status=status.HTTP_204_NO_CONTENT)

    def put(self, request, product_id, size=None):
        logger.debug(f"Updating cart item for {'user ' + request.user.email if request.user.is_authenticated else 'anonymous user'}: product_id={product_id}, size={size}")
        product_id = bleach.clean(str(product_id))
        size = bleach.clean(size) if size else None

        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            logger.error(f"Product {product_id} not found")
            return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

        data = request.data.copy()
        data['size'] = bleach.clean(data.get('size', '')) if data.get('size') else None

        if request.user.is_authenticated:
            cart_item, created = CartItem.objects.get_or_create(
                user=request.user,
                product=product,
                size=size,
                defaults={'quantity': data.get('quantity', 1), 'size': size}
            )
            serializer = CartItemSerializer(cart_item, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                logger.info(f"Cart item updated for user {request.user.email}: {product_id}, size={size}")
                return Response(serializer.data)
            logger.warning(f"Cart update serializer errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            session_cart = request.session.get('cart', {})
            if product_id in session_cart:
                session_cart[product_id] = {
                    'quantity': data.get('quantity', session_cart[product_id].get('quantity', 1)),
                    'size': data.get('size', session_cart[product_id].get('size'))
                }
                request.session['cart'] = session_cart
                request.session.modified = True
                logger.info(f"Cart item updated in session: {product_id}, size={size}")
                return Response(self.get(request).data)
            logger.warning(f"Cart item not found in session: {product_id}")
            return Response({'error': 'Cart item not found'}, status=status.HTTP_404_NOT_FOUND)

class WishlistView(APIView):
    permission_classes = [AllowAny]

    def _get_wishlist_items(self, request):
        if request.user.is_authenticated:
            return WishlistItem.objects.filter(user=request.user)
        else:
            session_wishlist = request.session.get('wishlist', {})
            wishlist_items = []
            for product_id, item_data in session_wishlist.items():
                try:
                    product = Product.objects.get(id=product_id)
                    wishlist_items.append({
                        'product': product,
                        'size': item_data.get('size', None)
                    })
                except Product.DoesNotExist:
                    logger.warning(f"Product {product_id} not found in session wishlist")
            return wishlist_items

    def get(self, request):
        logger.debug(f"Fetching wishlist for {'user ' + request.user.email if request.user.is_authenticated else 'anonymous user'}")
        wishlist_items = self._get_wishlist_items(request)
        if request.user.is_authenticated:
            serializer = WishlistItemSerializer(wishlist_items, many=True)
        else:
            serializer = WishlistItemSerializer([{
                'user': None,
                'product': item['product'],
                'size': item['size']
            } for item in wishlist_items], many=True)
        return Response(serializer.data)

    def post(self, request):
        data = request.data.copy()
        data['product_id'] = bleach.clean(data.get('product_id', ''))
        data['size'] = bleach.clean(data.get('size', '')) if data.get('size') else None
        if request.user.is_authenticated:
            serializer = WishlistItemSerializer(data=data)
            if serializer.is_valid():
                try:
                    wishlist_item = serializer.save(user=request.user)
                    logger.info(f"Wishlist item added for user {request.user.email}: {wishlist_item.product.name}")
                    return Response(WishlistItemSerializer(wishlist_item).data, status=status.HTTP_201_CREATED)
                except Exception as e:
                    logger.error(f"Wishlist add error: {str(e)}")
                    return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            logger.warning(f"Wishlist serializer errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            try:
                product = Product.objects.get(id=data['product_id'])
                session_wishlist = request.session.get('wishlist', {})
                session_wishlist[data['product_id']] = {'size': data.get('size')}
                request.session['wishlist'] = session_wishlist
                request.session.modified = True
                logger.info(f"Wishlist item added to session for anonymous user: {product.name}")
                return Response(self.get(request).data, status=status.HTTP_201_CREATED)
            except Product.DoesNotExist:
                logger.error(f"Product {data['product_id']} not found")
                return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, product_id, size=None):
        product_id = bleach.clean(str(product_id))
        size = bleach.clean(size) if size else None
        if request.user.is_authenticated:
            try:
                wishlist_item = WishlistItem.objects.get(user=request.user, product_id=product_id, size=size)
                wishlist_item.delete()
                logger.info(f"Wishlist item deleted for user {request.user.email}: {product_id}, size={size}")
                return Response(status=status.HTTP_204_NO_CONTENT)
            except WishlistItem.DoesNotExist:
                logger.warning(f"Wishlist item not found: {product_id}, size={size}")
                return Response({'error': 'Item not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            session_wishlist = request.session.get('wishlist', {})
            if product_id in session_wishlist and (size is None or session_wishlist[product_id]['size'] == size):
                del session_wishlist[product_id]
                request.session['wishlist'] = session_wishlist
                request.session.modified = True
                logger.info(f"Wishlist item deleted from session: {product_id}, size={size}")
                return Response(status=status.HTTP_204_NO_CONTENT)
            logger.warning(f"Wishlist item not found in session: {product_id}, size={size}")
            return Response({'error': 'Item not found'}, status=status.HTTP_404_NOT_FOUND)

class NotificationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logger.debug(f"Fetching notifications for user {request.user.email}")
        notifications = Notification.objects.filter(user=request.user).order_by('-date')
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)

    def put(self, request, id):
        try:
            notification = Notification.objects.get(id=id, user=request.user)
            data = request.data.copy()
            if 'read' in data:
                data['read'] = bleach.clean(str(data['read']))
            serializer = NotificationSerializer(notification, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                logger.info(f"Notification {id} updated for user {request.user.email}")
                return Response(serializer.data)
            logger.warning(f"Notification update errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Notification.DoesNotExist:
            logger.error(f"Notification {id} not found for user {request.user.email}")
            return Response({'error': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)

class QuickLinkView(generics.ListCreateAPIView):
    queryset = QuickLink.objects.all()
    serializer_class = QuickLinkSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_staff:
            logger.warning(f"Unauthorized quick link creation attempt by {request.user.email if request.user.is_authenticated else 'anonymous'}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        data = request.data.copy()
        data['title'] = bleach.clean(data.get('title', ''))
        data['url'] = bleach.clean(data.get('url', ''))
        serializer = QuickLinkSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Quick link created by {request.user.email}: {serializer.data['title']}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.warning(f"Quick link creation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class QuickLinkDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = QuickLink.objects.all()
    serializer_class = QuickLinkSerializer
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        if not request.user.is_staff:
            logger.warning(f"Unauthorized quick link update attempt by {request.user.email}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        data = request.data.copy()
        data['title'] = bleach.clean(data.get('title', ''))
        data['url'] = bleach.clean(data.get('url', ''))
        serializer = self.get_serializer(self.get_object(), data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Quick link updated by {request.user.email}: {serializer.data['title']}")
            return Response(serializer.data)
        logger.warning(f"Quick link update errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        if not request.user.is_staff:
            logger.warning(f"Unauthorized quick link deletion attempt by {request.user.email}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        try:
            quick_link = self.get_object()
            quick_link.delete()
            logger.info(f"Quick link deleted by {request.user.email}: {quick_link.title}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except QuickLink.DoesNotExist:
            logger.error(f"Quick link not found: {kwargs.get('pk')}")
            return Response({'error': 'Quick link not found'}, status=status.HTTP_404_NOT_FOUND)

class CustomerInquiryView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        if not request.user.is_authenticated or not request.user.is_staff:
            logger.warning(f"Unauthorized inquiry access attempt by {request.user.email if request.user.is_authenticated else 'anonymous'}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        inquiries = CustomerInquiry.objects.all().order_by('-created_at')
        serializer = CustomerInquirySerializer(inquiries, many=True)
        logger.info(f"Inquiries fetched by {request.user.email}")
        return Response(serializer.data)

    def post(self, request):
        data = request.data.copy()
        data['subject'] = bleach.clean(data.get('subject', ''))
        data['message'] = bleach.clean(data.get('message', ''))
        data['email'] = bleach.clean(data.get('email', ''))
        if request.user.is_authenticated:
            data['user'] = request.user.id
        serializer = CustomerInquirySerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Customer inquiry created: {serializer.data['subject']}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.warning(f"Customer inquiry creation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomerInquiryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        if not request.user.is_staff:
            logger.warning(f"Unauthorized inquiry detail access by {request.user.email}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        try:
            inquiry = CustomerInquiry.objects.get(id=id)
            serializer = CustomerInquirySerializer(inquiry)
            logger.info(f"Inquiry {id} fetched by {request.user.email}")
            return Response(serializer.data)
        except CustomerInquiry.DoesNotExist:
            logger.error(f"Inquiry {id} not found")
            return Response({'error': 'Inquiry not found'}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, id):
        if not request.user.is_staff:
            logger.warning(f"Unauthorized inquiry update attempt by {request.user.email}")
            return Response({'error': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
        try:
            inquiry = CustomerInquiry.objects.get(id=id)
            data = request.data.copy()
            data['status'] = bleach.clean(data.get('status', ''))
            serializer = CustomerInquirySerializer(inquiry, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                logger.info(f"Inquiry {id} updated by {request.user.email}: {serializer.data['status']}")
                return Response(serializer.data)
            logger.warning(f"Inquiry update errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except CustomerInquiry.DoesNotExist:
            logger.error(f"Inquiry {id} not found")
            return Response({'error': 'Inquiry not found'}, status=status.HTTP_404_NOT_FOUND)

class PurchaseView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logger.debug(f"Fetching purchases for user {request.user.email}")
        purchases = Purchase.objects.filter(user=request.user).order_by('-date')
        serializer = PurchaseSerializer(purchases, many=True)
        return Response(serializer.data)

    def post(self, request):
        logger.debug(f"Creating purchase for user {request.user.email}")
        cart_items = CartItem.objects.filter(user=request.user)
        if not cart_items:
            logger.error(f"Cart is empty for user {request.user.email}")
            return Response({'error': 'Cart is empty'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            total = 0
            purchase_items = []
            line_items = []
            for item in cart_items:
                if item.product.stock < item.quantity:
                    logger.error(f"Insufficient stock for {item.product.name}: Available {item.product.stock}, Requested {item.quantity}")
                    return Response(
                        {'error': f'Insufficient stock for {item.product.name}'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                total += item.product.price * item.quantity
                line_items.append({
                    'unique_id': item.product.id,
                    'particulars': bleach.clean(item.product.name),
                    'quantity': item.quantity,
                    'unitcost': item.product.price,
                    'subtotal': item.product.price * item.quantity
                })
                purchase_items.append({
                    'product_name': bleach.clean(item.product.name),
                    'quantity': item.quantity,
                    'price': item.product.price,
                    'size': bleach.clean(item.size) if item.size else None
                })

            order_id = generate_unique_id(Purchase)
            xml_data = f"""
            <?xml version="1.0" encoding="utf-8"?>
            <PesapalDirectOrderInfo
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                Amount="{total}"
                Description="Order for {bleach.clean(request.user.username)}"
                Type="MERCHANT"
                Reference="{order_id}"
                FirstName="{bleach.clean(request.user.username)}"
                Email="{request.user.email}"
                PhoneNumber="{bleach.clean(request.user.phone or '')}"
                Currency="KES"
                xmlns="http://www.pesapal.com">
                <LineItems>
                    {"".join([f'<LineItem uniqueid="{item["unique_id"]}" particulars="{bleach.clean(item["particulars"])}" quantity="{item["quantity"]}" unitcost="{item["unitcost"]}" subtotal="{item["subtotal"]}" />' for item in line_items])}
                </LineItems>
            </PesapalDirectOrderInfo>
            """

            auth_url = f"{settings.PESAPAL_API_URL}/api/Auth/RequestToken"
            auth_data = {
                'consumer_key': settings.PESAPAL_CONSUMER_KEY,
                'consumer_secret': settings.PESAPAL_CONSUMER_SECRET
            }
            try:
                auth_response = requests.post(auth_url, data=auth_data, timeout=10)
            except requests.exceptions.RequestException as e:
                logger.error(f"PesaPal auth request failed: {str(e)}")
                return Response({'error': f'Failed to connect to PesaPal: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            if auth_response.status_code != 200:
                logger.error(f"PesaPal auth failed: {auth_response.text}")
                return Response(
                    {'error': f'PesaPal authentication failed: {auth_response.text}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            try:
                auth_json = auth_response.json()
                token = auth_json.get('token')
                if not token:
                    logger.error("No token received from PesaPal")
                    return Response({'error': 'Authentication failed: No token received'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except ValueError as e:
                logger.error(f"Failed to parse PesaPal auth response: {auth_response.text}, Error: {str(e)}")
                return Response({'error': 'Invalid response from PesaPal'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            order_url = f"{settings.PESAPAL_API_URL}/api/Transactions/SubmitOrderRequest"
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/xml',
                'Accept': 'application/xml'
            }
            params = {
                'callbackurl': settings.PESAPAL_CALLBACK_URL,
                'ipnurl': settings.PESAPAL_IPN_URL
            }
            try:
                response = requests.post(order_url, headers=headers, params=params, data=xml_data, timeout=10)
            except requests.exceptions.RequestException as e:
                logger.error(f"PesaPal order submission failed: {str(e)}")
                return Response({'error': f'Failed to submit order to PesaPal: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    payment_url = root.text
                    if not payment_url:
                        logger.error("No payment URL returned by PesaPal")
                        return Response({'error': 'Failed to initiate payment: No payment URL'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                except ET.ParseError as e:
                    logger.error(f"Failed to parse PesaPal XML response: {response.text}, Error: {str(e)}")
                    return Response({'error': 'Invalid XML response from PesaPal'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                with transaction.atomic():
                    request.session['pesapal_order_id'] = order_id
                    request.session['pesapal_purchase_items'] = purchase_items
                    request.session['pesapal_total'] = float(total)
                    request.session['pesapal_user_id'] = str(request.user.id)
                    request.session.modified = True
                    logger.info(f"Payment initiated for order {order_id}, user {request.user.email}")
                    return Response({
                        'payment_url': payment_url,
                        'order_id': order_id
                    }, status=status.HTTP_200_OK)
            else:
                logger.error(f"PesaPal order submission failed: {response.text}")
                return Response({'error': f'Failed to initiate payment: {response.text}'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"PesaPal payment error: {str(e)}")
            return Response({'error': f'Failed to create payment session: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AdminPurchaseView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        try:
            purchases = Purchase.objects.all().order_by('-date')
            logger.info(f"Admin fetched {purchases.count()} purchases")
            serializer = PurchaseSerializer(purchases, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error fetching purchases: {str(e)}")
            return Response({'error': 'Server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, id):
        try:
            purchase = Purchase.objects.get(id=id)
            data = request.data.copy()
            if 'status' in data:
                data['status'] = bleach.clean(data['status'])
            serializer = PurchaseSerializer(purchase, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                if 'status' in data:
                    Notification.objects.create(
                        user=purchase.user,
                        type='order',
                        message=bleach.clean(f"Your order (ID: {purchase.id}) has been updated to '{data['status']}'")
                    )
                    logger.info(f"Purchase {id} status updated to {data['status']} by {request.user.email}")
                return Response(serializer.data)
            logger.warning(f"Purchase update errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Purchase.DoesNotExist:
            logger.error(f"Purchase {id} not found")
            return Response({'error': 'Purchase not found'}, status=status.HTTP_404_NOT_FOUND)

@csrf_exempt
def payment_callback(request):
    order_id = bleach.clean(request.GET.get('OrderMerchantReference', ''))
    tracking_id = bleach.clean(request.GET.get('OrderTrackingId', ''))
    notification_type = bleach.clean(request.GET.get('OrderNotificationType', ''))

    if not order_id or not tracking_id:
        logger.error("Missing callback parameters")
        return redirect(settings.PESAPAL_CANCEL_URL)

    try:
        auth_url = f"{settings.PESAPAL_API_URL}/api/Auth/RequestToken"
        auth_data = {
            'consumer_key': settings.PESAPAL_CONSUMER_KEY,
            'consumer_secret': settings.PESAPAL_CONSUMER_SECRET
        }
        auth_response = requests.post(auth_url, data=auth_data, timeout=10)
        if auth_response.status_code != 200:
            logger.error(f"PesaPal auth failed: {auth_response.text}")
            return redirect(settings.PESAPAL_CANCEL_URL)

        token = auth_response.json().get('token')
        if not token:
            logger.error("No token received from PesaPal")
            return redirect(settings.PESAPAL_CANCEL_URL)

        status_url = f"{settings.PESAPAL_API_URL}/api/Transactions/GetTransactionStatus"
        headers = {'Authorization': f'Bearer ${token}'}
        params = {'orderTrackingId': tracking_id}
        status_response = requests.get(status_url, headers=headers, params=params, timeout=10)

        if status_response.status_code == 200:
            status_data = status_response.json()
            payment_status = status_data.get('payment_status_description').lower()
            if payment_status in ['completed', 'paid']:
                logger.info(f"Payment completed for order {order_id}")
                return redirect(settings.PESAPAL_SUCCESS_URL)
            logger.info(f"Payment not completed for order {order_id}: {payment_status}")
            return redirect(settings.PESAPAL_CANCEL_URL)
        logger.error(f"Transaction status check failed: {status_response.text}")
        return redirect(settings.PESAPAL_CANCEL_URL)
    except Exception as e:
        logger.error(f"Payment callback error: {str(e)}")
        return redirect(settings.PESAPAL_CANCEL_URL)

@csrf_exempt
def pesapal_ipn(request):
    if request.method != 'GET':
        logger.error("Invalid IPN request method")
        return HttpResponse(status=405)

    order_id = bleach.clean(request.GET.get('OrderMerchantReference', ''))
    tracking_id = bleach.clean(request.GET.get('OrderTrackingId', ''))
    notification_type = bleach.clean(request.GET.get('OrderNotificationType', ''))

    if not order_id or not tracking_id:
        logger.error("Missing IPN parameters")
        return HttpResponse(status=400)

    try:
        auth_url = f"{settings.PESAPAL_API_URL}/api/Auth/RequestToken"
        auth_data = {
            'consumer_key': settings.PESAPAL_CONSUMER_KEY,
            'consumer_secret': settings.PESAPAL_CONSUMER_SECRET
        }
        auth_response = requests.post(auth_url, data=auth_data, timeout=10)
        if auth_response.status_code != 200:
            logger.error(f"PesaPal IPN auth failed: {auth_response.text}")
            return HttpResponse(status=401)

        token = auth_response.json().get('token')
        if not token:
            logger.error("No token received from PesaPal")
            return HttpResponse(status=401)

        status_url = f"{settings.PESAPAL_API_URL}/api/Transactions/GetTransactionStatus"
        headers = {'Authorization': f'Bearer ${token}'}
        params = {'orderTrackingId': tracking_id}
        status_response = requests.get(status_url, headers=headers, params=params, timeout=10)

        if status_response.status_code == 200:
            status_data = status_response.json()
            payment_status = status_data.get('payment_status_description').lower()

            if payment_status in ['completed', 'paid']:
                user_id = request.session.get('pesapal_user_id')
                purchase_items = request.session.get('pesapal_purchase_items', [])
                total = float(request.session.get('pesapal_total', 0))

                try:
                    user = CustomUser.objects.get(id=user_id)
                except CustomUser.DoesNotExist:
                    logger.error(f"User {user_id} not found for order {order_id}")
                    return HttpResponse(status=400)

                cart_items = CartItem.objects.filter(user=user)

                with transaction.atomic():
                    purchase = Purchase.objects.create(
                        user=user,
                        id=generate_unique_id(Purchase),
                        total=total,
                        status='paid'
                    )
                    for item in cart_items:
                        PurchaseItem.objects.create(
                            purchase=purchase,
                            product=item.product,
                            quantity=item.quantity,
                            size=bleach.clean(item.size) if item.size else None
                        )
                        item.product.stock -= item.quantity
                        item.product.save()
                    cart_items.delete()

                    order_details = '\n'.join(
                        [f"- {bleach.clean(item['product_name'])}: {item['quantity']} x KSH {item['price']}" + (f" (Size: {bleach.clean(item['size'])})" if item['size'] else "") for item in purchase_items]
                    )
                    notification_message = (
                        f"Order placed successfully!\n"
                        f"Order ID: {purchase.id}\n"
                        f"Items ({len(purchase_items)}):\n{order_details}\n"
                        f"Total: KSH {total}\n"
                        f"Date: {purchase.date.strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"Status: {purchase.status}"
                    )
                    Notification.objects.create(
                        user=user,
                        type='order',
                        message=bleach.clean(notification_message)
                    )
                    Notification.objects.create(
                        user=None,
                        type='order',
                        message=bleach.clean(
                            f"New order placed by {user.username} (Order ID: {purchase.id})\n"
                            f"Items ({len(purchase_items)}):\n{order_details}\n"
                            f"Total: KSH {total}\n"
                            f"Date: {purchase.date.strftime('%Y-%m-%d %H:%M:%S')}"
                        )
                    )
                    logger.info(f"IPN purchase created: Order ID {purchase.id}, User {user.email}")

                    request.session.pop('pesapal_order_id', None)
                    request.session.pop('pesapal_purchase_items', None)
                    request.session.pop('pesapal_total', None)
                    request.session.pop('pesapal_user_id', None)
                    request.session.modified = True

                    return HttpResponse(status=200)
            logger.info(f"IPN payment not completed for order {order_id}: {payment_status}")
            return HttpResponse(status=200)
        logger.error(f"IPN transaction status check failed: {status_response.text}")
        return HttpResponse(status=400)
    except Exception as e:
        logger.error(f"IPN processing error: {str(e)}")
        return HttpResponse(status=400)

class AdminNotificationView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        notifications = Notification.objects.all()
        serializer = NotificationSerializer(notifications, many=True)
        logger.info(f"Admin notifications fetched by {request.user.email}")
        return Response(serializer.data)

    def post(self, request):
        serializer = NotificationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=None)  # System-wide notification
            logger.info(f"Admin notification created by {request.user.email}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PurchaseDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        try:
            purchase = Purchase.objects.get(id=id, user=request.user)
            serializer = PurchaseSerializer(purchase)
            return Response(serializer.data)
        except Purchase.DoesNotExist:
            return Response({'error': 'Purchase not found'}, status=status.HTTP_404_NOT_FOUND)

class TrackPackageView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        try:
            purchase = Purchase.objects.get(id=id, user=request.user)
            tracking_info = {'status': purchase.status, 'last_updated': purchase.date}
            return Response(tracking_info)
        except Purchase.DoesNotExist:
            return Response({'error': 'Purchase not found'}, status=status.HTTP_404_NOT_FOUND)

class BuyAgainView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            purchase = Purchase.objects.get(id=id, user=request.user)
            for item in purchase.purchaseitem_set.all():
                CartItem.objects.get_or_create(
                    user=request.user,
                    product=item.product,
                    size=item.size,
                    defaults={'quantity': item.quantity, 'size': item.size}
                )
            return Response({'message': 'Items added to cart'}, status=status.HTTP_200_OK)
        except Purchase.DoesNotExist:
            return Response({'error': 'Purchase not found'}, status=status.HTTP_404_NOT_FOUND)