from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', lambda request: redirect('login')),  # Redirect root to login
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),  # Include under /accounts/
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
