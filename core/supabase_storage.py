import os
import uuid
from django.conf import settings
from supabase import create_client, Client
from storage3.utils import StorageException

class SupabaseStorage:
    def __init__(self):
        self.supabase_url = settings.SUPABASE_URL
        self.supabase_key = settings.SUPABASE_KEY
        self.supabase: Client = create_client(self.supabase_url, self.supabase_key)
        self.bucket_name = "file-uploads"
        
        # Ensure bucket exists
        self._ensure_bucket_exists()
    
    def _ensure_bucket_exists(self):
        """Ensure the bucket exists, create it if it doesn't"""
        try:
            buckets = self.supabase.storage.list_buckets()
            bucket_exists = any(bucket['name'] == self.bucket_name for bucket in buckets)
            
            if not bucket_exists:
                self.supabase.storage.create_bucket(self.bucket_name, {'public': False})
        except Exception as e:
            print(f"Error ensuring bucket exists: {e}")
    
    def upload_file(self, file, user_id, file_category="other"):
        """
        Upload a file to Supabase storage
        
        Args:
            file: The file object to upload
            user_id: The ID of the user uploading the file
            file_category: The category of the file (documents, images, etc.)
            
        Returns:
            dict: A dictionary containing the file URL and metadata
        """
        try:
            # Generate a unique file path
            file_extension = os.path.splitext(file.name)[1]
            unique_filename = f"{user_id}/{file_category}/{uuid.uuid4()}{file_extension}"
            
            # Upload the file
            response = self.supabase.storage.from_(self.bucket_name).upload(
                unique_filename,
                file.read(),
                {"content-type": file.content_type}
            )
            
            # Get the public URL
            file_url = self.supabase.storage.from_(self.bucket_name).get_public_url(unique_filename)
            
            return {
                "file_url": file_url,
                "file_path": unique_filename,
                "file_type": file_extension.lstrip('.'),
                "file_category": file_category
            }
        except StorageException as e:
            print(f"Supabase storage error: {e}")
            raise
        except Exception as e:
            print(f"Error uploading file: {e}")
            raise
    
    def get_file_url(self, file_path):
        """
        Get the URL for a file in Supabase storage
        
        Args:
            file_path: The path of the file in storage
            
        Returns:
            str: The URL of the file
        """
        try:
            return self.supabase.storage.from_(self.bucket_name).get_public_url(file_path)
        except Exception as e:
            print(f"Error getting file URL: {e}")
            return None
    
    def delete_file(self, file_path):
        """
        Delete a file from Supabase storage
        
        Args:
            file_path: The path of the file in storage
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.supabase.storage.from_(self.bucket_name).remove([file_path])
            return True
        except Exception as e:
            print(f"Error deleting file: {e}")
            return False
    
    def list_files(self, prefix=""):
        """
        List files in the bucket with an optional prefix
        
        Args:
            prefix: The prefix to filter files by
            
        Returns:
            list: A list of files
        """
        try:
            return self.supabase.storage.from_(self.bucket_name).list(prefix)
        except Exception as e:
            print(f"Error listing files: {e}")
            return []

# Create a singleton instance
supabase_storage = SupabaseStorage()