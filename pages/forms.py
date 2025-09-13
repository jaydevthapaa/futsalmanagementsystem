from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import FutsalGround


class SignupForm(UserCreationForm):
    email = forms.EmailField(required=True)
    address = forms.CharField(required=False, max_length=25)
    phone_number= forms.CharField(
        required=True,
        max_length=10,
        help_text='enter your phone number example==9700000001,9800000002')

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_email(self):
        email = self.cleaned_data.get("email", "").strip()
        if not email:
            raise forms.ValidationError("Email is required")
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists")
        return email
    
    def clean_phone_number(self):
        phone_number=self.cleaned_data.get("phone_number","").strip()
        if not phone_number:
            raise forms.ValidationError("phone number is required")
            
        return phone_number

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"].strip()
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


class UserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["username", "email", "is_staff", "is_superuser"]


