from django import forms
from django.contrib.auth.models import User
from .models import UploadedFile, UserProfile

class BulkUploadForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ["file"]

class FileUploadForm(forms.Form):
    file = forms.FileField(label='Select File', required=True, widget=forms.FileInput(attrs={'accept': '*'})) 
    file_title = forms.CharField(label='File Title', max_length=200, required=True)
    file_category = forms.ChoiceField(label='File Category', choices=UploadedFile.FILE_CATEGORIES, required=True)

class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

class UserEditForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['location', 'phone_number', 'status']
