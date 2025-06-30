from django.utils.timezone import now

class LogRequestMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print(f"[{now()}] {request.method} {request.get_full_path()}")
        response = self.get_response(request)
        print(f"[{now()}] Response {response.status_code}")
        return response
