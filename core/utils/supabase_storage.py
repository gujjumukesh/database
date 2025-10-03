import os
import uuid
import magic
from supabase import create_client
from django.conf import settings

# Initialize Supabase client
supabase_url = settings.SUPABASE_URL
supabase_key = settings.SUPABASE_KEY
supabase = create_client(supabase_url, supabase_key)

# Define bucket name
BUCKET_NAME = "file_uploads"

def initialize_bucket():
    """Ensure the bucket exists in Supabase"""
    try:
        # Check if bucket exists
        buckets = supabase.storage.list_buckets()
        bucket_exists = any(bucket.name == BUCKET_NAME for bucket in buckets)
        
        if not bucket_exists:
            # Create bucket if it doesn't exist
            supabase.storage.create_bucket(BUCKET_NAME, {"public": False})
        
        return True
    except Exception as e:
        print(f"Error initializing bucket: {str(e)}")
        return False

def upload_file(file_obj, user_id, file_category="other"):
    """
    Upload a file to Supabase storage
    
    Args:
        file_obj: The file object from request.FILES
        user_id: The ID of the user uploading the file
        file_category: Category of the file (documents, images, etc.)
        
    Returns:
        dict: Contains file URL, file type, and other metadata
    """
    try:
        # Initialize bucket if needed
        initialize_bucket()
        
        # Generate a unique filename
        file_extension = os.path.splitext(file_obj.name)[1]
        unique_filename = f"{user_id}_{uuid.uuid4()}{file_extension}"
        
        # Determine file path based on category
        file_path = f"{file_category}/{unique_filename}"
        
        # Read file content
        file_content = file_obj.read()
        
        # Detect file type using python-magic
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(file_content)
        
        # Upload to Supabase
        response = supabase.storage.from_(BUCKET_NAME).upload(
            file_path,
            file_content,
            {"content-type": file_type}
        )
        
        # Get public URL
        file_url = supabase.storage.from_(BUCKET_NAME).get_public_url(file_path)
        
        return {
            "success": True,
            "file_url": file_url,
            "file_path": file_path,
            "file_type": file_type,
            "file_extension": file_extension.lstrip('.'),
            "original_name": file_obj.name
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def get_file_url(file_path):
    """Get the public URL for a file"""
    try:
        return supabase.storage.from_(BUCKET_NAME).get_public_url(file_path)
    except Exception as e:
        print(f"Error getting file URL: {str(e)}")
        return None

def delete_file(file_path):
    """Delete a file from Supabase storage"""
    try:
        supabase.storage.from_(BUCKET_NAME).remove([file_path])
        return True
    except Exception as e:
        print(f"Error deleting file: {str(e)}")
        return False

def list_files(path=""):
    """List files in a specific path"""
    try:
        return supabase.storage.from_(BUCKET_NAME).list(path)
    except Exception as e:
        print(f"Error listing files: {str(e)}")
        return []