from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('send_otp/', views.send_otp, name='send_otp'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('dashboard/', views.dashboard, name='dashboard'),

    path('forgot_password/', views.forgot_password_view, name='forgot_password'),
    path('verify_reset_otp/', views.verify_reset_otp, name='verify_reset_otp'),
    path('reset_password/', views.reset_password_view, name='reset_password'),

    path('logout/', views.logout_view, name='logout'),

    # Existing decrypt route
    path('decrypt/<int:file_id>/', views.decrypt_file, name='decrypt_file'),
    
    # Updated download-stego route
    path('download-stego/<int:file_id>/', views.download_stego, name='download_stego'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)