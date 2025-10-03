from django.db import models
from django.contrib.auth.models import User

class UploadedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.CharField(max_length=500) # Stores the URL to the Supabase file
    file_title = models.CharField(max_length=200, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    file_type = models.CharField(max_length=10, blank=True, null=True) # e.g., 'csv', 'pdf', 'excel'
    FILE_CATEGORIES = [
        ('documents', 'Documents'),
        ('images', 'Images'),
        ('videos', 'Videos'),
        ('audio', 'Audio'),
        ('other', 'Other'),
    ]
    file_category = models.CharField(max_length=50, choices=FILE_CATEGORIES, default='other')

    def __str__(self):
        return f"{self.user.username} - {self.file.name}"

class ActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.action} at {self.timestamp}"

class FileAccessLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_path = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} accessed {self.file_path} at {self.timestamp}"

class UserProfile(models.Model):
    USER_STATUS_CHOICES = [
        ('user', 'User'),
        ('admin', 'Admin'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    location = models.CharField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    status = models.CharField(max_length=10, choices=USER_STATUS_CHOICES, default='user')

    def __str__(self):
        return self.user.username
