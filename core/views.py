from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponse, JsonResponse, FileResponse, Http404
from django.db.models import Q # Added for complex queries
import pandas as pd
import io
import matplotlib.pyplot as plt
import seaborn as sns
import base64
import csv # Added this import
from .forms import BulkUploadForm, UserForm, UserProfileForm, FileUploadForm
from .models import UploadedFile, ActivityLog, UserProfile, FileAccessLog
from django.contrib.auth.models import User
import datetime # Added for date/time filtering
from django.conf import settings
from supabase import create_client, Client
import httpx # For fetching file content from URL
from .supabase_storage import supabase_storage

# Initialize Supabase client
supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

def register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            UserProfile.objects.create(user=user, status='user') # Ensure UserProfile is created with default 'user' status
            login(request, user)
            return redirect("user_dashboard_view") # Directly redirect to user dashboard after registration
    else:
        form = UserCreationForm()
    return render(request, "core/register.html", {"form": form})

def user_login(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                user_profile, created = UserProfile.objects.get_or_create(user=user)
                ActivityLog.objects.create(user=user, action="logged in")
                if user_profile.status == 'admin':
                    return redirect("admin_dashboard")
                else:
                    return redirect("user_dashboard_view")
            else:
                # Handle invalid login
                pass
    else:
        form = AuthenticationForm()
    return render(request, "core/login.html", {"form": form})

@login_required
def user_logout(request):
    ActivityLog.objects.create(user=request.user, action="logged out")
    logout(request)
    return redirect("login")

@login_required
def dashboard(request):
    if is_admin(request.user):
        return redirect("admin_dashboard")
    else:
        return redirect("user_dashboard_view")

@login_required
def user_dashboard_view(request):
    if is_admin(request.user):
        return redirect("admin_dashboard")
    files = UploadedFile.objects.filter(user=request.user).order_by('-uploaded_at')

    # Filtering logic
    date_filter = request.GET.get('date_filter')
    time_filter = request.GET.get('time_filter')
    category_filter = request.GET.get('category_filter')
    search_query = request.GET.get('search_query')

    if date_filter:
        try:
            filter_date = datetime.datetime.strptime(date_filter, '%Y-%m-%d').date()
            files = files.filter(uploaded_at__date=filter_date)
        except ValueError:
            pass # Handle invalid date format

    if time_filter:
        try:
            filter_time = datetime.datetime.strptime(time_filter, '%H:%M').time()
            # This will filter by exact time, which might be too restrictive.
            # A more flexible approach might involve time ranges.
            files = files.filter(uploaded_at__time__hour=filter_time.hour,
                                 uploaded_at__time__minute=filter_time.minute)
        except ValueError:
            pass # Handle invalid time format

    if category_filter:
        files = files.filter(file_category=category_filter) # Assuming a 'file_category' field in UploadedFile model

    if search_query:
        files = files.filter(Q(file__icontains=search_query) | Q(description__icontains=search_query)) # Assuming 'file' is the filename and 'description' is another field

    context = {
        "files": files,
        "date_filter": date_filter,
        "time_filter": time_filter,
        "category_filter": category_filter,
        "search_query": search_query,
        "file_categories": UploadedFile.FILE_CATEGORIES, # Pass categories to template
    }
    return render(request, "core/user_dashboard.html", context)

@login_required
def data_view(request):
    if is_admin(request.user):
        return redirect("admin_dashboard")
    files = UploadedFile.objects.filter(user=request.user)
    context = {"files": files}
    return render(request, "core/data_view.html", context)

@login_required
def visualize_data(request):
    if is_admin(request.user):
        return redirect("admin_dashboard")
    if request.method == "POST":
        file_id = request.POST.get("file_id")
        uploaded_file = UploadedFile.objects.get(id=file_id, user=request.user)
        
        # Log file access
        FileAccessLog.objects.create(user=request.user, file_path=uploaded_file.file.name)

        df = None
        if uploaded_file.file.name.endswith(".csv"):
            df = pd.read_csv(uploaded_file.file)
        elif uploaded_file.file.name.endswith((".xls", ".xlsx")):
            df = pd.read_excel(uploaded_file.file)
        elif uploaded_file.file.name.endswith(".pdf"):
            # PDF visualization is complex, for now, we'll just show a message
            return render(request, "core/visualize_data.html", {"message": "PDF visualization is not directly supported for plotting."})

        if df is not None:
            # Generate a simple plot (e.g., histogram of the first numeric column)
            numeric_cols = df.select_dtypes(include=['number']).columns
            if not numeric_cols.empty:
                plt.figure(figsize=(10, 6))
                sns.histplot(df[numeric_cols[0]], kde=True)
                plt.title(f"Histogram of {numeric_cols[0]}")
                plt.xlabel(numeric_cols[0])
                plt.ylabel("Frequency")
                
                buffer = io.BytesIO()
                plt.savefig(buffer, format="png")
                buffer.seek(0)
                image_png = buffer.getvalue()
                buffer.close()
                
                graphic = base64.b64encode(image_png)
                graphic = graphic.decode("utf-8")
                
                return render(request, "core/visualize_data.html", {"graphic": graphic})
            else:
                return render(request, "core/visualize_data.html", {"message": "No numeric data to visualize."})
    
    files = UploadedFile.objects.filter(user=request.user)
    context = {"files": files}
    return render(request, "core/visualize_data.html", context)

@login_required
def download_data(request, file_type):
    if is_admin(request.user):
        return redirect("admin_dashboard")
    if file_type == "csv":
        # Example: Create a dummy CSV for download
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="sample.csv"'
        writer = csv.writer(response)
        writer.writerow(["Header1", "Header2"])
        writer.writerow(["Value1", "Value2"])
        return response
    # Add more file types as needed
    return HttpResponse("Invalid file type", status=400)

# Admin views
def is_admin(user):
    # Ensure user has a UserProfile before checking status
    if not hasattr(user, 'userprofile'):
        return False
    return user.userprofile.status == 'admin'

@login_required
@user_passes_test(is_admin)
def user_list(request):
    users = User.objects.all().select_related('userprofile')
    context = {"users": users}
    return render(request, "core/user_list.html", context)

@login_required
@user_passes_test(is_admin)
def add_user(request):
    if request.method == 'POST':
        user_form = UserForm(request.POST)
        profile_form = UserProfileForm(request.POST)
        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)
            user.set_password(user_form.cleaned_data['password'])
            user.save()
            profile = profile_form.save(commit=False)
            profile.user = user
            profile.save()
            return redirect('user_list')
    else:
        user_form = UserForm()
        profile_form = UserProfileForm()
    return render(request, 'core/add_user.html', {'user_form': user_form, 'profile_form': profile_form})

@login_required
@user_passes_test(is_admin)
def edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    try:
        profile = user.userprofile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=user)
    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=user)
        profile_form = UserProfileForm(request.POST, instance=profile)
        if user_form.is_valid() and profile_form.is_valid():
            # Only update password if it's provided in the form
            if user_form.cleaned_data['password']:
                user.set_password(user_form.cleaned_data['password'])
                user.save()
            else:
                user_form.save() # Save other user fields
            profile_form.save()
            return redirect('user_list')
    else:
        user_form = UserForm(instance=user)
        profile_form = UserProfileForm(instance=profile)
    return render(request, 'core/add_user.html', {'user_form': user_form, 'profile_form': profile_form})

@login_required
@user_passes_test(is_admin)
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.delete()
    return redirect('user_list')

@login_required
@user_passes_test(is_admin)
def admin_bulk_upload(request):
    if request.method == "POST":
        form = BulkUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.save(commit=False)
            uploaded_file.user = request.user
            uploaded_file.save()
            ActivityLog.objects.create(user=request.user, action=f"uploaded file: {uploaded_file.file.name}")
            return redirect("admin_bulk_upload")
    else:
        form = BulkUploadForm()
    files = UploadedFile.objects.all()
    context = {"form": form, "files": files}
    return render(request, "core/admin_bulk_upload.html", context)

@login_required
@user_passes_test(is_admin)
def admin_activity_logs(request):
    # Get filter parameters
    log_type = request.GET.get('log_type', 'all')  # 'all', 'activity', 'file_access'
    user_filter = request.GET.get('user_filter', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    search_query = request.GET.get('search', '')
    
    # Get pagination parameters
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 50))
    
    # Initialize logs querysets
    activity_logs = ActivityLog.objects.select_related('user').all()
    file_access_logs = FileAccessLog.objects.select_related('user').all()
    
    # Apply filters
    if user_filter:
        activity_logs = activity_logs.filter(user__username__icontains=user_filter)
        file_access_logs = file_access_logs.filter(user__username__icontains=user_filter)
    
    if date_from:
        try:
            from_date = datetime.datetime.strptime(date_from, '%Y-%m-%d').date()
            activity_logs = activity_logs.filter(timestamp__date__gte=from_date)
            file_access_logs = file_access_logs.filter(timestamp__date__gte=from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.datetime.strptime(date_to, '%Y-%m-%d').date()
            activity_logs = activity_logs.filter(timestamp__date__lte=to_date)
            file_access_logs = file_access_logs.filter(timestamp__date__lte=to_date)
        except ValueError:
            pass
    
    if search_query:
        activity_logs = activity_logs.filter(action__icontains=search_query)
        file_access_logs = file_access_logs.filter(file_path__icontains=search_query)
    
    # Combine and format logs
    combined_logs = []
    
    if log_type in ['all', 'activity']:
        for log in activity_logs.order_by('-timestamp'):
            combined_logs.append({
                'type': 'activity',
                'id': log.id,
                'user': log.user,
                'action': log.action,
                'timestamp': log.timestamp,
                'details': f"User {log.user.username} performed action: {log.action}"
            })
    
    if log_type in ['all', 'file_access']:
        for log in file_access_logs.order_by('-timestamp'):
            combined_logs.append({
                'type': 'file_access',
                'id': log.id,
                'user': log.user,
                'action': f"Accessed file: {log.file_path}",
                'timestamp': log.timestamp,
                'details': f"User {log.user.username} accessed file: {log.file_path}",
                'file_path': log.file_path
            })
    
    # Sort combined logs by timestamp
    combined_logs.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Calculate pagination
    total_logs = len(combined_logs)
    total_pages = (total_logs + per_page - 1) // per_page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    # Get paginated logs
    paginated_logs = combined_logs[start_idx:end_idx]
    
    # Create page range for pagination
    page_range = list(range(1, total_pages + 1)) if total_pages > 0 else []
    
    # Get all users for filter dropdown
    all_users = User.objects.all().order_by('username')
    
    context = {
        'logs': paginated_logs,
        'log_type': log_type,
        'user_filter': user_filter,
        'date_from': date_from,
        'date_to': date_to,
        'search_query': search_query,
        'current_page': page,
        'total_pages': total_pages,
        'per_page': per_page,
        'total_logs': total_logs,
        'displayed_logs': len(paginated_logs),
        'has_previous': page > 1,
        'has_next': page < total_pages,
        'previous_page': page - 1 if page > 1 else None,
        'next_page': page + 1 if page < total_pages else None,
        'page_range': page_range,
        'all_users': all_users,
    }
    
    return render(request, "core/admin_activity_logs.html", context)


@login_required
@user_passes_test(is_admin)
def get_activity_logs_json(request):
    # Get filter parameters
    log_type = request.GET.get('log_type', 'all')
    user_filter = request.GET.get('user_filter', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    search_query = request.GET.get('search', '')
    
    # Get pagination parameters
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 50))
    
    # Initialize logs querysets
    activity_logs = ActivityLog.objects.select_related('user').all()
    file_access_logs = FileAccessLog.objects.select_related('user').all()
    
    # Apply filters
    if user_filter:
        activity_logs = activity_logs.filter(user__username__icontains=user_filter)
        file_access_logs = file_access_logs.filter(user__username__icontains=user_filter)
    
    if date_from:
        try:
            from_date = datetime.datetime.strptime(date_from, '%Y-%m-%d').date()
            activity_logs = activity_logs.filter(timestamp__date__gte=from_date)
            file_access_logs = file_access_logs.filter(timestamp__date__gte=from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.datetime.strptime(date_to, '%Y-%m-%d').date()
            activity_logs = activity_logs.filter(timestamp__date__lte=to_date)
            file_access_logs = file_access_logs.filter(timestamp__date__lte=to_date)
        except ValueError:
            pass
    
    if search_query:
        activity_logs = activity_logs.filter(action__icontains=search_query)
        file_access_logs = file_access_logs.filter(file_path__icontains=search_query)
    
    # Combine and format logs
    combined_logs = []
    
    if log_type in ['all', 'activity']:
        for log in activity_logs.order_by('-timestamp'):
            combined_logs.append({
                'type': 'activity',
                'id': log.id,
                'user': {
                    'username': log.user.username,
                    'email': log.user.email,
                },
                'action': log.action,
                'timestamp': log.timestamp.isoformat(),
            })
    
    if log_type in ['all', 'file_access']:
        for log in file_access_logs.order_by('-timestamp'):
            combined_logs.append({
                'type': 'file_access',
                'id': log.id,
                'user': {
                    'username': log.user.username,
                    'email': log.user.email,
                },
                'action': f"Accessed file: {log.file_path}",
                'timestamp': log.timestamp.isoformat(),
            })
    
    # Sort combined logs by timestamp
    combined_logs.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Calculate pagination
    total_logs = len(combined_logs)
    total_pages = (total_logs + per_page - 1) // per_page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    # Get paginated logs
    paginated_logs = combined_logs[start_idx:end_idx]
    
    data = {
        'logs': paginated_logs,
        'current_page': page,
        'total_pages': total_pages,
        'total_logs': total_logs,
        'displayed_logs': len(paginated_logs),
    }
    
    return JsonResponse(data)


@login_required
@user_passes_test(is_admin)
def get_log_details(request, log_type, log_id):
    try:
        if log_type == 'activity':
            log = ActivityLog.objects.get(id=log_id)
            details = {
                'ID': log.id,
                'User': log.user.username,
                'Action': log.action,
                'Timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
        elif log_type == 'file_access':
            log = FileAccessLog.objects.get(id=log_id)
            details = {
                'ID': log.id,
                'User': log.user.username,
                'File Path': log.file_path,
                'Timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            }
        else:
            return JsonResponse({'error': 'Invalid log type'}, status=400)
        
        return JsonResponse(details)
    except (ActivityLog.DoesNotExist, FileAccessLog.DoesNotExist):
        return JsonResponse({'error': 'Log not found'}, status=404)


@login_required
@user_passes_test(is_admin)
def file_access_logs(request):
    logs = FileAccessLog.objects.all().order_by("-timestamp")
    context = {"logs": logs}
    return render(request, "core/logs.html", context)

@login_required
@user_passes_test(is_admin)
def admin_data_crud(request):
    files = UploadedFile.objects.all()
    context = {"files": files}
    return render(request, "core/admin_data_crud.html", context)

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    # User statistics
    total_users = User.objects.count()
    
    # Active users in the last 30 minutes
    thirty_minutes_ago = datetime.datetime.now() - datetime.timedelta(minutes=30)
    active_users_count = ActivityLog.objects.filter(timestamp__gte=thirty_minutes_ago).values('user').distinct().count()

    # File filtering and search logic (similar to user_dashboard_view)
    files = UploadedFile.objects.all().order_by('-uploaded_at')

    date_filter = request.GET.get('date_filter')
    time_filter = request.GET.get('time_filter')
    category_filter = request.GET.get('category_filter')
    search_query = request.GET.get('search_query')

    if date_filter:
        try:
            filter_date = datetime.datetime.strptime(date_filter, '%Y-%m-%d').date()
            files = files.filter(uploaded_at__date=filter_date)
        except ValueError:
            pass

    if time_filter:
        try:
            filter_time = datetime.datetime.strptime(time_filter, '%H:%M').time()
            files = files.filter(uploaded_at__time__hour=filter_time.hour,
                                 uploaded_at__time__minute=filter_time.minute)
        except ValueError:
            pass

    if category_filter:
        files = files.filter(file_category=category_filter)

    if search_query:
        files = files.filter(Q(file__icontains=search_query) | Q(file_title__icontains=search_query))

    context = {
        "total_users": total_users,
        "active_users": active_users_count,
        "files": files,
        "date_filter": date_filter,
        "time_filter": time_filter,
        "category_filter": category_filter,
        "search_query": search_query,
        "file_categories": UploadedFile.FILE_CATEGORIES, # Pass categories to template
    }
    return render(request, "core/admin_dashboard.html", context)

@login_required
@user_passes_test(is_admin)
def files_view(request):
    # Handle file upload
    if request.method == "POST":
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file_instance = form.cleaned_data['file']
            file_category = form.cleaned_data['file_category']
            
            try:
                # Use our Supabase storage utility
                result = supabase_storage.upload_file(
                    uploaded_file_instance, 
                    request.user.id,
                    file_category
                )
                
                # Create the UploadedFile record
                uploaded_file = UploadedFile()
                uploaded_file.user = request.user
                uploaded_file.file = result['file_url']  # Store the public URL
                uploaded_file.file_title = form.cleaned_data['file_title']
                uploaded_file.file_type = result['file_type']
                uploaded_file.file_category = file_category
                uploaded_file.save()
                
                ActivityLog.objects.create(user=request.user, action=f"uploaded file to Supabase: {uploaded_file_instance.name}")
                return redirect("files_view")
            except Exception as e:
                # Handle Supabase upload error
                print(f"Supabase upload error: {e}")
                form.add_error(None, f"Error uploading file to Supabase: {e}")
    else:
        form = FileUploadForm()


    # File filtering and search logic
    files = UploadedFile.objects.all().order_by('-uploaded_at')

    date_filter = request.GET.get('date_filter')
    time_filter = request.GET.get('time_filter')
    category_filter = request.GET.get('category_filter')
    title_filter = request.GET.get('title_filter')
    filename_filter = request.GET.get('filename_filter')

    if date_filter:
        try:
            filter_date = datetime.datetime.strptime(date_filter, '%Y-%m-%d').date()
            files = files.filter(uploaded_at__date=filter_date)
        except ValueError:
            pass

    if time_filter:
        try:
            filter_time = datetime.datetime.strptime(time_filter, '%H:%M').time()
            files = files.filter(uploaded_at__time__hour=filter_time.hour,
                                 uploaded_at__time__minute=filter_time.minute)
        except ValueError:
            pass

    if category_filter:
        files = files.filter(file_category=category_filter)

    if title_filter:
        files = files.filter(file_title__icontains=title_filter)

    if filename_filter:
        files = files.filter(file__icontains=filename_filter)

    context = {
        "form": form,
        "files": files,
        "date_filter": date_filter,
        "time_filter": time_filter,
        "category_filter": category_filter,
        "title_filter": title_filter,
        "filename_filter": filename_filter,
        "file_categories": UploadedFile.FILE_CATEGORIES,
    }
    return render(request, "core/files.html", context)

@login_required
def user_files(request):
    # Show user's own files plus files uploaded by admins
    files = UploadedFile.objects.filter(
        Q(user=request.user) | Q(user__is_staff=True) | Q(user__userprofile__status='admin')
    ).order_by('-uploaded_at').distinct()

    date_filter = request.GET.get('date_filter')
    time_filter = request.GET.get('time_filter')
    category_filter = request.GET.get('category_filter')
    title_filter = request.GET.get('title_filter')
    filename_filter = request.GET.get('filename_filter')

    if date_filter:
        try:
            filter_date = datetime.datetime.strptime(date_filter, '%Y-%m-%d').date()
            files = files.filter(uploaded_at__date=filter_date)
        except ValueError:
            pass

    if time_filter:
        try:
            filter_time = datetime.datetime.strptime(time_filter, '%H:%M').time()
            files = files.filter(uploaded_at__time__hour=filter_time.hour,
                                 uploaded_at__time__minute=filter_time.minute)
        except ValueError:
            pass

    if category_filter:
        files = files.filter(file_category=category_filter)

    if title_filter:
        files = files.filter(file_title__icontains=title_filter)

    if filename_filter:
        files = files.filter(Q(file__icontains=filename_filter) | Q(file_title__icontains=filename_filter))

    context = {
        "files": files,
        "date_filter": date_filter,
        "time_filter": time_filter,
        "category_filter": category_filter,
        "title_filter": title_filter,
        "filename_filter": filename_filter,
        "file_categories": UploadedFile.FILE_CATEGORIES,
    }
    return render(request, "core/user_files.html", context)

@login_required
def user_download(request, file_id):
    try:
        uploaded_file = UploadedFile.objects.select_related('user').get(id=file_id)
    except UploadedFile.DoesNotExist:
        raise Http404("File not found")

    # Permission: owner or file uploaded by an admin
    is_owner = uploaded_file.user_id == request.user.id
    is_admin_uploader = getattr(uploaded_file.user, 'is_staff', False)
    if not (is_owner or is_admin_uploader):
        return HttpResponse("Forbidden", status=403)

    # Log access
    FileAccessLog.objects.create(user=request.user, file_path=uploaded_file.file.name)

    # Serve file securely from Supabase URL
    try:
        response_from_supabase = httpx.get(uploaded_file.file)
        response_from_supabase.raise_for_status() # Raise an exception for 4xx or 5xx status codes
        
        file_content = response_from_supabase.content
        file_name = uploaded_file.file.split('/')[-1] # Extract filename from URL
        
        response = HttpResponse(file_content, content_type=response_from_supabase.headers['content-type'])
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        return response
    except httpx.RequestError as e:
        raise Http404(f"Error fetching file from Supabase: {e}")
    except httpx.HTTPStatusError as e:
        raise Http404(f"File not found or access denied on Supabase: {e}")

@login_required
def user_view_file(request, file_id):
    try:
        uploaded_file = UploadedFile.objects.get(id=file_id)
    except UploadedFile.DoesNotExist:
        return render(request, "core/view_file.html", {'error': 'File not found'})

    # Permission: owner or file uploaded by an admin
    is_owner = uploaded_file.user_id == request.user.id
    is_admin_uploader = getattr(uploaded_file.user, 'is_staff', False) or (
        hasattr(uploaded_file.user, 'userprofile') and uploaded_file.user.userprofile.status == 'admin'
    )
    if not (is_owner or is_admin_uploader):
        return HttpResponse("Forbidden", status=403)
        
    # Ensure the file URL is up-to-date
    if not uploaded_file.file.startswith('http'):
        # Extract file path from URL or use the file field directly
        file_path = uploaded_file.file.split('/')[-1] if '/' in uploaded_file.file else uploaded_file.file
        # Update the URL using our Supabase storage utility
        uploaded_file.file = supabase_storage.get_file_url(file_path)
        uploaded_file.save()
        
    # Get file content from Supabase if needed
    file_content = None
    if uploaded_file.file.startswith(settings.SUPABASE_URL):
        try:
            # Extract bucket name and path from URL if possible
            if '/storage/v1/object/public/' in uploaded_file.file:
                parts = uploaded_file.file.split('/storage/v1/object/public/')[1].split('/', 1)
                bucket_name = parts[0]
                file_path = parts[1] if len(parts) > 1 else ''
                # Use supabase_storage utility to get file content
                file_bytes = supabase_storage.get_file_content(file_path, bucket_name)
            else:
                # Fallback to direct HTTP request
                response = httpx.get(uploaded_file.file)
                response.raise_for_status()
                file_bytes = io.BytesIO(response.content)
        except Exception as e:
            print(f"Error fetching file from Supabase: {e}")
            # Will continue with regular processing

    # Log file access
    FileAccessLog.objects.create(user=request.user, file_path=uploaded_file.file)

    # Reuse same rendering logic as admin view, but without admin-only restriction
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 50))
    search_query = request.GET.get('search', '')

    file_extension = uploaded_file.file.name.split('.')[-1].lower()
    file_content = None
    file_type = 'unknown'
    data_table = None
    columns = []
    rows = []
    total_rows = 0
    filtered_rows = 0
    total_pages = 0

    try:
        if file_extension in ['csv', 'xlsx', 'xls', 'json', 'txt', 'xml', 'html', 'css', 'js', 'py', 'md', 'pdf']:
            # Fetch file content from Supabase URL
            try:
                response_from_supabase = httpx.get(uploaded_file.file)
                response_from_supabase.raise_for_status()
                file_bytes = io.BytesIO(response_from_supabase.content)
            except httpx.RequestError as e:
                file_type = 'error'
                file_content = f"Error fetching file from Supabase: {e}"
            except httpx.HTTPStatusError as e:
                file_type = 'error'
                file_content = f"File not found or access denied on Supabase: {e}"
            
            if file_type != 'error': # Only proceed if file fetch was successful
                if file_extension == 'csv':
                    import pandas as pd
                    df = pd.read_csv(file_bytes)
                    file_type = 'data_table'
                    columns = []
                    for col in df.columns.tolist():
                        clean_col = str(col).strip().replace('_', ' ').title()
                        columns.append(clean_col)
                    total_rows = len(df)
                    if search_query:
                        mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False, na=False)).any(axis=1)
                        df = df[mask]
                        filtered_rows = len(df)
                    else:
                        filtered_rows = total_rows
                    total_pages = (filtered_rows + per_page - 1) // per_page
                    start_idx = (page - 1) * per_page
                    end_idx = start_idx + per_page
                    rows = []
                    for _, row in df.iloc[start_idx:end_idx].iterrows():
                        formatted_row = []
                        for value in row:
                            if getattr(pd, 'isna')(value) or str(value).lower() in ['nan', 'none', 'null']:
                                formatted_row.append('')
                            else:
                                formatted_row.append(str(value))
                        rows.append(formatted_row)
                elif file_extension in ['xlsx', 'xls']:
                    import pandas as pd
                    df = pd.read_excel(file_bytes)
                    file_type = 'data_table'
                    columns = [str(col).strip().replace('_', ' ').title() for col in df.columns.tolist()]
                    total_rows = len(df)
                    if search_query:
                        mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False, na=False)).any(axis=1)
                        df = df[mask]
                        filtered_rows = len(df)
                    else:
                        filtered_rows = total_rows
                    total_pages = (filtered_rows + per_page - 1) // per_page
                    start_idx = (page - 1) * per_page
                    end_idx = start_idx + per_page
                    rows = []
                    for _, row in df.iloc[start_idx:end_idx].iterrows():
                        rows.append([str(value) if value is not None else '' for value in row])
                elif file_extension == 'json':
                    import json
                    data = json.load(file_bytes)
                    file_type = 'json'
                    file_content = json.dumps(data, indent=2)
                elif file_extension in ['txt', 'xml', 'html', 'css', 'js', 'py', 'md']:
                    try:
                        file_content = file_bytes.getvalue().decode('utf-8')
                        file_type = 'text'
                    except Exception:
                        try:
                            file_content = file_bytes.getvalue().decode('latin-1')
                            file_type = 'text'
                        except Exception:
                            file_content = "Unable to read file content"
                            file_type = 'error'
                elif file_extension == 'pdf':
                    file_type = 'pdf'
                    file_content = "PDF files cannot be displayed directly in the browser. Please download to view."
        elif file_extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg']:
            file_type = 'image'
        else:
            file_type = 'other'
            file_content = f"This file type (.{file_extension}) cannot be displayed. Please download to view."
    except Exception as e:
        file_type = 'error'
        file_content = f"Error reading file: {str(e)}"

    page_range = list(range(1, total_pages + 1)) if total_pages > 0 else []
    context = {
        'file': uploaded_file,
        'file_content': file_content,
        'file_type': file_type,
        'file_extension': file_extension,
        'data_table': data_table,
        'columns': columns,
        'rows': rows,
        'total_rows': total_rows,
        'filtered_rows': filtered_rows,
        'displayed_rows': len(rows) if rows else 0,
        'current_page': page,
        'total_pages': total_pages,
        'per_page': per_page,
        'search_query': search_query,
        'has_previous': page > 1,
        'has_next': page < total_pages,
        'previous_page': page - 1 if page > 1 else None,
        'next_page': page + 1 if page < total_pages else None,
        'page_range': page_range
    }
    return render(request, "core/view_file.html", context)

@login_required
@user_passes_test(is_admin)
def view_file(request, file_id):
    try:
        uploaded_file = UploadedFile.objects.get(id=file_id)
        
        # Log file access
        FileAccessLog.objects.create(user=request.user, file_path=uploaded_file.file)
        
        # Get pagination parameters
        page = int(request.GET.get('page', 1))
        per_page = int(request.GET.get('per_page', 50))
        search_query = request.GET.get('search', '')
        
        # Determine file type and prepare content for viewing
        file_extension = uploaded_file.file_type # Use file_type from model
        file_content = None
        file_type = 'unknown'
        data_table = None
        columns = []
        rows = []
        total_rows = 0
        filtered_rows = 0
        total_pages = 0
        
        if file_extension in ['csv', 'xlsx', 'xls', 'json', 'txt', 'xml', 'html', 'css', 'js', 'py', 'md', 'pdf']:
            # Fetch file content from Supabase URL
            try:
                response_from_supabase = httpx.get(uploaded_file.file)
                response_from_supabase.raise_for_status()
                file_bytes = io.BytesIO(response_from_supabase.content)
            except httpx.RequestError as e:
                file_type = 'error'
                file_content = f"Error fetching file from Supabase: {e}"
            except httpx.HTTPStatusError as e:
                file_type = 'error'
                file_content = f"File not found or access denied on Supabase: {e}"
            
            if file_type != 'error': # Only proceed if file fetch was successful
                if file_extension == 'csv':
                    import pandas as pd
                    df = pd.read_csv(file_bytes)
                    file_type = 'data_table'
                    
                    # Clean and format column names
                    columns = []
                    for col in df.columns.tolist():
                        # Clean column names - remove special characters and make readable
                        clean_col = str(col).strip()
                        if clean_col.startswith('C-'):
                            clean_col = clean_col.replace('C-', 'Candidate ').replace('_', ' ').title()
                        elif clean_col.startswith('opd-'):
                            clean_col = clean_col.replace('opd-', '').replace('_', ' ').title()
                        elif clean_col.startswith('dropdown-'):
                            clean_col = clean_col.replace('dropdown-', '').replace('_', ' ').title()
                        elif clean_col.startswith('icon-'):
                            clean_col = clean_col.replace('icon-', '').replace('_', ' ').title()
                        elif clean_col.startswith('origin-'):
                            clean_col = clean_col.replace('origin-', '').replace('_', ' ').title()
                        else:
                            clean_col = clean_col.replace('_', ' ').title()
                        columns.append(clean_col)
                    
                    total_rows = len(df)
                    
                    # Apply search filter if provided
                    if search_query:
                        mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False, na=False)).any(axis=1)
                        df = df[mask]
                        filtered_rows = len(df)
                    else:
                        filtered_rows = total_rows
                    
                    # Calculate pagination
                    total_pages = (filtered_rows + per_page - 1) // per_page
                    start_idx = (page - 1) * per_page
                    end_idx = start_idx + per_page
                    
                    # Get paginated data and format it
                    rows = []
                    for _, row in df.iloc[start_idx:end_idx].iterrows():
                        formatted_row = []
                        for value in row:
                            if pd.isna(value) or str(value).lower() in ['nan', 'none', 'null']:
                                formatted_row.append('')
                            elif isinstance(value, str) and value.startswith('http'):
                                # Handle URLs - truncate for display but keep full URL
                                if len(value) > 50:
                                    formatted_row.append({
                                        'type': 'url',
                                        'display': value[:47] + '...',
                                        'full_url': value
                                    })
                                else:
                                    formatted_row.append({
                                        'type': 'url',
                                        'display': value,
                                        'full_url': value
                                    })
                            elif isinstance(value, str) and len(value) > 100:
                                # Truncate very long text
                                formatted_row.append({
                                    'type': 'long_text',
                                    'display': value[:97] + '...',
                                    'full_text': value
                                })
                            else:
                                formatted_row.append(str(value))
                        rows.append(formatted_row)
                    
                elif file_extension in ['xlsx', 'xls']:
                    import pandas as pd
                    df = pd.read_excel(file_bytes)
                    file_type = 'data_table'
                    
                    # Clean and format column names
                    columns = []
                    for col in df.columns.tolist():
                        # Clean column names - remove special characters and make readable
                        clean_col = str(col).strip()
                        if clean_col.startswith('C-'):
                            clean_col = clean_col.replace('C-', 'Candidate ').replace('_', ' ').title()
                        elif clean_col.startswith('opd-'):
                            clean_col = clean_col.replace('opd-', '').replace('_', ' ').title()
                        elif clean_col.startswith('dropdown-'):
                            clean_col = clean_col.replace('dropdown-', '').replace('_', ' ').title()
                        elif clean_col.startswith('icon-'):
                            clean_col = clean_col.replace('icon-', '').replace('_', ' ').title()
                        elif clean_col.startswith('origin-'):
                            clean_col = clean_col.replace('origin-', '').replace('_', ' ').title()
                        else:
                            clean_col = clean_col.replace('_', ' ').title()
                        columns.append(clean_col)
                    
                    total_rows = len(df)
                    
                    # Apply search filter if provided
                    if search_query:
                        mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False, na=False)).any(axis=1)
                        df = df[mask]
                        filtered_rows = len(df)
                    else:
                        filtered_rows = total_rows
                    
                    # Calculate pagination
                    total_pages = (filtered_rows + per_page - 1) // per_page
                    start_idx = (page - 1) * per_page
                    end_idx = start_idx + per_page
                    
                    # Get paginated data and format it
                    rows = []
                    for _, row in df.iloc[start_idx:end_idx].iterrows():
                        formatted_row = []
                        for value in row:
                            if pd.isna(value) or str(value).lower() in ['nan', 'none', 'null']:
                                formatted_row.append('')
                            elif isinstance(value, str) and value.startswith('http'):
                                # Handle URLs - truncate for display but keep full URL
                                if len(value) > 50:
                                    formatted_row.append({
                                        'type': 'url',
                                        'display': value[:47] + '...',
                                        'full_url': value
                                    })
                                else:
                                    formatted_row.append({
                                        'type': 'url',
                                        'display': value,
                                        'full_url': value
                                    })
                            elif isinstance(value, str) and len(value) > 100:
                                # Truncate very long text
                                formatted_row.append({
                                    'type': 'long_text',
                                    'display': value[:97] + '...',
                                    'full_text': value
                                })
                            else:
                                formatted_row.append(str(value))
                        rows.append(formatted_row)
                    
                except Exception as e:
                    file_type = 'error'
                    file_content = f"Error reading Excel file: {str(e)}"
                    
                elif file_extension == 'json':
                    import json
                    data = json.load(file_bytes)
                    file_type = 'json'
                    file_content = json.dumps(data, indent=2)
                elif file_extension in ['txt', 'xml', 'html', 'css', 'js', 'py', 'md']:
                    try:
                        file_content = file_bytes.getvalue().decode('utf-8')
                        file_type = 'text'
                    except Exception:
                        try:
                            file_content = file_bytes.getvalue().decode('latin-1')
                            file_type = 'text'
                        except Exception:
                            file_content = "Unable to read file content"
                            file_type = 'error'
                elif file_extension == 'pdf':
                    file_type = 'pdf'
                    file_content = "PDF files cannot be displayed directly in the browser. Please download to view."
        elif file_extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg']:
            file_type = 'image'
        else:
            file_type = 'other'
            file_content = f"This file type (.{file_extension}) cannot be displayed in the browser. Please download to view."
        
        # Create page range for pagination
        page_range = list(range(1, total_pages + 1)) if total_pages > 0 else []
        
        context = {
            'file': uploaded_file,
            'file_content': file_content,
            'file_type': file_type,
            'file_extension': file_extension,
            'data_table': data_table,
            'columns': columns,
            'rows': rows,
            'total_rows': total_rows,
            'filtered_rows': filtered_rows,
            'displayed_rows': len(rows) if rows else 0,
            'current_page': page,
            'total_pages': total_pages,
            'per_page': per_page,
            'search_query': search_query,
            'has_previous': page > 1,
            'has_next': page < total_pages,
            'previous_page': page - 1 if page > 1 else None,
            'next_page': page + 1 if page < total_pages else None,
            'page_range': page_range
        }
        
        return render(request, "core/view_file.html", context)
        
    except UploadedFile.DoesNotExist:
        return render(request, "core/view_file.html", {'error': 'File not found'})
