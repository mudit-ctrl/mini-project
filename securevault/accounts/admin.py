from django.contrib import admin
from .models import UploadedFile

# Register the UploadedFile model to make it accessible in the Django admin
admin.site.register(UploadedFile)
