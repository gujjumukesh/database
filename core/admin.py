from django.contrib import admin
from .models import UserProfile, UploadedFile, ActivityLog, FileAccessLog

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'status', 'location', 'phone_number')
    list_filter = ('status',)
    search_fields = ('user__username', 'location', 'phone_number')

class UploadedFileAdmin(admin.ModelAdmin):
    list_display = ('user', 'file_title', 'file_category', 'uploaded_at')
    list_filter = ('file_category', 'uploaded_at')
    search_fields = ('user__username', 'file_title')

class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'timestamp')
    list_filter = ('action', 'timestamp')
    search_fields = ('user__username', 'action')

class FileAccessLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'file_path', 'timestamp')
    list_filter = ('timestamp',)
    search_fields = ('user__username', 'file_path')

admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(UploadedFile, UploadedFileAdmin)
admin.site.register(ActivityLog, ActivityLogAdmin)
admin.site.register(FileAccessLog, FileAccessLogAdmin)
