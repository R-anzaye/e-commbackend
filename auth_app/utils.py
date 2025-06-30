import string
import random

def generate_unique_id(model_class, length=8):
    while True:
        new_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
        if not model_class.objects.filter(id=new_id).exists():
            return new_id

# Named functions to avoid lambda issues
def generate_product_id():
    from .models import Product
    return generate_unique_id(Product)

def generate_purchase_id():
    from .models import Purchase
    return generate_unique_id(Purchase)
