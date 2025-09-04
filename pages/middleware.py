from django.shortcuts import redirect
from django.urls import reverse


class AdminOnlyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Allow through for unauthenticated users
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Only apply to superusers (treat them as admin-only)
        if request.user.is_superuser:
            dashboard_url = reverse('admin_dashboard')
            allowed_prefixes = [
                dashboard_url,
                reverse('logout'),
                '/static/',
                '/media/',
            ]

            path = request.path
            if not any(path.startswith(prefix) for prefix in allowed_prefixes):
                return redirect('admin_dashboard')

        return self.get_response(request)


