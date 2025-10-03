import os
import uuid
import magic
from django.conf import settings
from supabase import create_client, Client

def get_supabase_client() -> Client:
    """Get a Supabase client instance."""
    url = settings.SUPABASE_URL
    key = settings.SUPABASE_KEY
    
    if not url or not key:
        raise ValueError("Supabase URL and key must be set in environment variables")
    
    return create_client(url, key)

def upload_file_to_supabase(file, file_category, user_id):
    """
    Upload a file to Supabase storage.
    
    Args:
        file: The file object from the request
        file_category: The category of the file (documents, images, etc.)
        user_id: The ID of the user uploading the file
        
    Returns:
        tuple: (file_url, file_type)
    """
    supabase = get_supabase_client()
    
    # Generate a unique filename
    file_extension = os.path.splitext(file.name)[1]
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    
    # Determine the file type using python-magic
    file_type = magic.from_buffer(file.read(1024), mime=True).split('/')[1]
    file.seek(0)  # Reset file pointer after reading
    
    # Upload to the appropriate bucket based on category
    bucket_name = file_category
    
    # Upload the file
    response = supabase.storage.from_(bucket_name).upload(
        f"{user_id}/{unique_filename}",
        file.read(),
        {"content-type": magic.from_buffer(file.read(1024), mime=True)}
    )
    file.seek(0)  # Reset file pointer after reading
    
    # Get the public URL
    file_url = supabase.storage.from_(bucket_name).get_public_url(f"{user_id}/{unique_filename}")
    
    return file_url, file_type

def delete_file_from_supabase(file_url):
    """
    Delete a file from Supabase storage.
    
    Args:
        file_url: The URL of the file to delete
    """
    supabase = get_supabase_client()
    
    # Extract bucket name and path from URL
    # URL format: https://<supabase_url>/storage/v1/object/public/<bucket_name>/<path>
    parts = file_url.split('/storage/v1/object/public/')[1].split('/', 1)
    bucket_name = parts[0]
    file_path = parts[1]
    
    # Delete the file
    supabase.storage.from_(bucket_name).remove(file_path)

def get_file_from_supabase(file_url):
    """
    Get a file from Supabase storage.
    
    Args:
        file_url: The URL of the file to get
        
    Returns:
        bytes: The file content
    """
    supabase = get_supabase_client()
    
    # Extract bucket name and path from URL
    parts = file_url.split('/storage/v1/object/public/')[1].split('/', 1)
    bucket_name = parts[0]
    file_path = parts[1]
    
    # Get the file
    response = supabase.storage.from_(bucket_name).download(file_path)
    
    return response