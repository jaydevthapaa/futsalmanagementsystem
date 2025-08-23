from django.shortcuts import render
from django.http import HttpResponse


# Create your views here.
def home_page_view(request):
    return render(request,"home.html")

def signin_view(request):
    return render(request, 'signin.html')

def signup_view(request):
    return render(request,'signup.html')
