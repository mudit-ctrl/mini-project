import datetime
import random
import uuid
import os
from django.shortcuts import render, redirect
from django.http import HttpResponse, FileResponse, JsonResponse
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.contrib import messages
from django.utils.text import slugify
from cryptography.fernet import Fernet
from stegano import lsb

from .forms import (
    SignUpForm,
    OTPForm,
    ForgotPasswordForm,
    ResetPasswordForm,
    FileUploadForm,
)
from .models import UploadedFile


# ----------------- SIGNUP -----------------
def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            request.session['username'] = user.username
            return redirect('send_otp')
    else:
        form = SignUpForm()
    return render(request, 'accounts/signup.html', {'form': form})


# ----------------- LOGIN -----------------
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            request.session['username'] = username
            return redirect('send_otp')
        else:
            return render(request, 'accounts/login.html', {'error': 'Invalid credentials'})
    return render(request, 'accounts/login.html')


# ----------------- SEND OTP -----------------
def send_otp(request):
    username = request.session.get('username')
    if not username:
        return redirect('login')

    user = User.objects.get(username=username)
    otp = str(random.randint(100000, 999999))
    request.session['otp'] = otp

    send_mail(
        'Your SecureVault OTP',
        f'Hi {user.username},\nYour OTP is: {otp}',
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )
    return redirect('verify_otp')


# ----------------- VERIFY OTP -----------------
def verify_otp(request):
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['otp'] == request.session.get('otp'):
                user = User.objects.get(username=request.session.get('username'))
                login(request, user)
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid OTP')
    else:
        form = OTPForm()
    return render(request, 'accounts/otp_verify.html', {'form': form})


# ----------------- DASHBOARD -----------------
@login_required
def dashboard(request):
    user = request.user
    upload_form = FileUploadForm()

    if request.method == 'POST':
        upload_form = FileUploadForm(request.POST, request.FILES)
        if upload_form.is_valid():
            uploaded_file = request.FILES.get('encrypted_file')
            stego_img = request.FILES.get('stegano_image')

            if not uploaded_file or not stego_img:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Both file and stego image are required.'
                    })
                messages.error(request, 'Both file and stego image are required.')
                return redirect('dashboard')

            try:
                # Generate key and encrypt file
                key = Fernet.generate_key()
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(uploaded_file.read())

                # Generate unique filenames with timestamp
                timestamp = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                unique_filename = f"{timestamp}_{uuid.uuid4().hex[:8]}_{slugify(uploaded_file.name)}"
                unique_stego_name = f"{timestamp}_{uuid.uuid4().hex[:8]}_{slugify(stego_img.name)}"

                # Save encrypted file
                encrypted_dir = os.path.join(settings.MEDIA_ROOT, 'user_files')
                os.makedirs(encrypted_dir, exist_ok=True)
                encrypted_path = os.path.join(encrypted_dir, unique_filename)
                with open(encrypted_path, 'wb') as f:
                    f.write(encrypted_data)

                # Save original stego image temporarily
                stego_dir = os.path.join(settings.MEDIA_ROOT, 'stego_images')
                os.makedirs(stego_dir, exist_ok=True)
                stego_path = os.path.join(stego_dir, unique_stego_name)
                with open(stego_path, 'wb+') as f:
                    for chunk in stego_img.chunks():
                        f.write(chunk)

                # Hide key in the image
                secret_img = lsb.hide(stego_path, key.decode())

                if not stego_path.lower().endswith(('.png', '.bmp')):
                    stego_path += '.png'
                    unique_stego_name += '.png'

                secret_img.save(stego_path)

                # Save to DB
                new_file = UploadedFile.objects.create(
                    user=user,
                    original_filename=uploaded_file.name,
                    encrypted_file=f'user_files/{unique_filename}',
                    stegano_image=f'stego_images/{unique_stego_name}',
                    is_decrypted=False,
                    uploaded_at=datetime.datetime.utcnow()
                )

                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'success',
                        'message': 'File encrypted and image saved successfully.',
                        'file_data': {
                            'id': new_file.id,
                            'name': unique_filename,
                            'original_name': uploaded_file.name,
                            'uploaded_at': new_file.uploaded_at.strftime("%b %d, %Y %H:%M"),
                        },
                        'download_url': f'/accounts/download-stego/{new_file.id}/'  # Updated URL path
                    })

                messages.success(request, 'File encrypted and image saved. Download the image containing the key below.')
                return FileResponse(open(stego_path, 'rb'), as_attachment=True, filename=unique_stego_name)

            except Exception as e:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'error',
                        'message': f'Encryption failed: {str(e)}'
                    })
                messages.error(request, f'Encryption failed: {str(e)}')
                return redirect('dashboard')

    user_files = UploadedFile.objects.filter(user=user).order_by('-uploaded_at')
    return render(request, 'accounts/dashboard.html', {
        'user': user,
        'upload_form': upload_form,
        'user_files': user_files,
    })

# Add this new view for downloading stego images
@login_required
def download_stego(request, file_id):
    try:
        file_obj = UploadedFile.objects.get(id=file_id, user=request.user)
        stego_path = os.path.join(settings.MEDIA_ROOT, file_obj.stegano_image.name)
        if os.path.exists(stego_path):
            response = FileResponse(
                open(stego_path, 'rb'),
                as_attachment=True,
                filename=os.path.basename(file_obj.stegano_image.name)
            )
            # Add headers to prevent caching
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
            return response
        else:
            messages.error(request, 'Stego image file not found.')
    except UploadedFile.DoesNotExist:
        messages.error(request, 'File not found.')
    except Exception as e:
        messages.error(request, f'Download failed: {str(e)}')
    return redirect('dashboard')
# ----------------- DECRYPT FILE -----------------
@login_required
def decrypt_file(request, file_id):
    if request.method == 'POST':
        try:
            file_obj = UploadedFile.objects.get(id=file_id, user=request.user)
            user_stego_image = request.FILES.get("stego_image")

            if not user_stego_image:
                messages.error(request, "Please upload a stego image containing the encryption key.")
                return redirect('dashboard')

            # Save stego image temporarily
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, f"{uuid.uuid4().hex}.png")
            with open(temp_path, 'wb+') as f:
                for chunk in user_stego_image.chunks():
                    f.write(chunk)

            # Extract key from stego image
            extracted_key = lsb.reveal(temp_path)

            if not extracted_key:
                messages.error(request, "No key found in the image.")
                return redirect('dashboard')

            # Decrypt the file
            fernet = Fernet(extracted_key.encode())
            file_path = os.path.join(settings.MEDIA_ROOT, file_obj.encrypted_file.name)
            with open(file_path, 'rb') as ef:
                decrypted_data = fernet.decrypt(ef.read())

            # Delete temp stego image
            if os.path.exists(temp_path):
                os.remove(temp_path)

            # Return decrypted file
            response = HttpResponse(decrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file_obj.original_filename}"'
            return response

        except UploadedFile.DoesNotExist:
            messages.error(request, "Encrypted file not found.")
        except Exception as e:
            messages.error(request, f"Decryption failed: {str(e)}")

    return redirect('dashboard')


# ----------------- FORGOT PASSWORD -----------------
def forgot_password_view(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                request.session['reset_email'] = user.email

                otp = str(random.randint(100000, 999999))
                request.session['reset_otp'] = otp

                send_mail(
                    'SecureVault Password Reset OTP',
                    f'Hi {user.username},\nYour password reset OTP is: {otp}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                )
                return redirect('verify_reset_otp')
            except User.DoesNotExist:
                messages.error(request, 'Email not registered.')
    else:
        form = ForgotPasswordForm()
    return render(request, 'accounts/forgot_password.html', {'form': form})


# ----------------- VERIFY RESET OTP -----------------
def verify_reset_otp(request):
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['otp'] == request.session.get('reset_otp'):
                return redirect('reset_password')
            else:
                messages.error(request, 'Invalid OTP')
    else:
        form = OTPForm()
    return render(request, 'accounts/verify_reset_otp.html', {'form': form})


# ----------------- RESET PASSWORD -----------------
def reset_password_view(request):
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            email = request.session.get('reset_email')
            try:
                user = User.objects.get(email=email)
                user.set_password(form.cleaned_data['new_password'])
                user.save()
                request.session.pop('reset_email', None)
                request.session.pop('reset_otp', None)
                messages.success(request, 'Password reset successful.')
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, 'Something went wrong.')
    else:
        form = ResetPasswordForm()
    return render(request, 'accounts/reset_password.html', {'form': form})


# ----------------- LOGOUT -----------------
def logout_view(request):
    logout(request)
    return redirect('login')