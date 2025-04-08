from django.db import models
from django.contrib.auth.models import User


class UploadedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_filename = models.CharField(max_length=255, blank=True)
    
    # Stores encrypted file
    encrypted_file = models.FileField(upload_to='user_files/', blank=True, null=True)

    # Stores stego image which contains the key
    stegano_image = models.ImageField(upload_to='stego_images/', blank=True, null=True)

    # Optionally store decrypted output file (if needed later)
    decrypted_file = models.FileField(upload_to='decrypted_files/', blank=True, null=True)

    is_decrypted = models.BooleanField(default=False)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.original_filename or self.encrypted_file.name}"
