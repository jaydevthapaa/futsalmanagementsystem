# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import FutsalGround


class SignupForm(UserCreationForm):
    first_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your first name'})
    )
    last_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your last name'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'})
    )
    phone_number = forms.CharField(
        required=True,
        max_length=10,
        help_text='Enter your phone number example: 9700000001, 9800000002',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': '9700000001'})
    )
    address = forms.CharField(
        required=False,
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your address '})
    )

    class Meta:
        model = User
        fields = ("first_name", "last_name", "username", "email", "phone_number", "address", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add CSS classes to username and password fields
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Choose a username'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Enter password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm password'
        })

    def clean_email(self):
        email = self.cleaned_data.get("email", "").strip()
        if not email:
            raise forms.ValidationError("Email is required")
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists")
        return email

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get("phone_number", "").strip()
        if not phone_number:
            raise forms.ValidationError("Phone number is required")
        
        # Validate phone number format (only digits)
        if not phone_number.isdigit():
            raise forms.ValidationError("Phone number must contain only digits")
        
        # Validate length
        if len(phone_number) != 10:
            raise forms.ValidationError("Phone number must be exactly 10 digits")
        
        return phone_number

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"].strip()
        user.first_name = self.cleaned_data.get("first_name", "").strip()
        user.last_name = self.cleaned_data.get("last_name", "").strip()
        if commit:
            user.save()
        return user


class FutsalGroundForm(forms.ModelForm):
    class Meta:
        model = FutsalGround
        fields = [
            "groundName",
            "location",
            "description",
            "price_per_hour",
            "image",
            "is_available",
            'contact_number',
        ]
        widgets = {
            'groundName': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ground Name'}),
            'location': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Location'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4, 'placeholder': 'Description'}),
            'price_per_hour': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Price per hour'}),
            'image': forms.FileInput(attrs={'class': 'form-control'}),
            'is_available': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'contact_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Contact Number'}),
        }


class UserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["username", "email", "is_staff", "is_superuser"]
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'is_staff': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_superuser': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }