from django import forms
from django.contrib.auth.models import User
from .models import UploadedFile


# ----------------- SignUp Form -----------------
class SignUpForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter Password'}),
        min_length=6,
        label="Password"
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Enter Username'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Enter Email'}),
        }


# ----------------- OTP Form -----------------
class OTPForm(forms.Form):
    otp = forms.CharField(
        label="Enter OTP",
        max_length=6,
        widget=forms.TextInput(attrs={'placeholder': '6-digit OTP'})
    )


# ----------------- Forgot Password -----------------
class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        label="Enter your registered email",
        widget=forms.EmailInput(attrs={'placeholder': 'user@example.com'})
    )


# ----------------- Reset Password -----------------
class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'New Password'}),
        label="New Password",
        min_length=6
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}),
        label="Confirm Password"
    )

    def clean(self):
        cleaned_data = super().clean()
        pwd = cleaned_data.get("new_password")
        confirm = cleaned_data.get("confirm_password")

        if pwd != confirm:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data


# ----------------- File Upload Form (Encryption) -----------------
class FileUploadForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['encrypted_file', 'stegano_image']
        labels = {
            'encrypted_file': "File to Encrypt",
            'stegano_image': "Carrier Image (JPEG or PNG)",
        }

    def clean_encrypted_file(self):
        file = self.cleaned_data.get('encrypted_file')
        if file:
            if file.size > 5 * 1024 * 1024:
                raise forms.ValidationError("Encrypted file size exceeds 5MB.")
            if file.content_type not in ['application/pdf', 'application/zip', 'image/jpeg', 'image/png']:
                raise forms.ValidationError("Only PDF, ZIP, JPEG, and PNG files are allowed.")
        return file

    def clean_stegano_image(self):
        image = self.cleaned_data.get('stegano_image')
        if image:
            if image.size > 5 * 1024 * 1024:
                raise forms.ValidationError("Image size exceeds 5MB.")
            if image.content_type not in ['image/jpeg', 'image/png']:
                raise forms.ValidationError("Only JPEG and PNG images are allowed.")
        return image


# ----------------- Stego Image Upload Form (Decryption) -----------------
class StegoImageUploadForm(forms.Form):
    stegano_image = forms.ImageField(
        label="Upload Key Image (JPEG or PNG)",
        widget=forms.FileInput(attrs={'accept': 'image/jpeg,image/png'})
    )

    def clean_stegano_image(self):
        image = self.cleaned_data.get('stegano_image')
        if image:
            if image.size > 5 * 1024 * 1024:
                raise forms.ValidationError("Image size exceeds 5MB.")
            if image.content_type not in ['image/jpeg', 'image/png']:
                raise forms.ValidationError("Only JPEG and PNG images are allowed.")
        return image
