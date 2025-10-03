from django.urls import path
from . import views

urlpatterns = [
    path("", views.user_login, name="login"),
    path("register/", views.register, name="register"),
    path("logout/", views.user_logout, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("user-dashboard/", views.user_dashboard_view, name="user_dashboard_view"), # New user dashboard URL
    path("user-files/", views.user_files, name="user_files"),
    path("user-files/view/<int:file_id>/", views.user_view_file, name="user_view_file"),
    path("user-files/download/<int:file_id>/", views.user_download, name="user_download"),
    path("data/", views.data_view, name="data_view"),
    path("visualize/", views.visualize_data, name="visualize_data"),
    path("download/<str:file_type>/", views.download_data, name="download_data"),
    # Admin URLs
    path("app-admin/users/", views.user_list, name="user_list"),
    path("app-admin/users/add/", views.add_user, name="add_user"),
    path("app-admin/users/edit/<int:user_id>/", views.edit_user, name="edit_user"),
    path("app-admin/users/delete/<int:user_id>/", views.delete_user, name="delete_user"),
    path("app-admin/bulk-upload/", views.admin_bulk_upload, name="admin_bulk_upload"),
    path("app-admin/activity-logs/", views.admin_activity_logs, name="admin_activity_logs"),
    path("app-admin/activity-logs/json/", views.get_activity_logs_json, name="get_activity_logs_json"),
    path("app-admin/logs/<str:log_type>/<int:log_id>/", views.get_log_details, name="get_log_details"),
    path("app-admin/file-access-logs/", views.file_access_logs, name="file_access_logs"),
    path("app-admin/data-crud/", views.admin_data_crud, name="admin_data_crud"),
    path("app-admin/dashboard/", views.admin_dashboard, name="admin_dashboard"), # Updated admin dashboard URL
    path("app-admin/files/", views.files_view, name="files_view"), # Files view with upload form
    path("app-admin/files/view/<int:file_id>/", views.view_file, name="view_file"), # View file content
]
