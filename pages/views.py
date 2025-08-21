from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.
def home_page_view(request):
    return render(request,"home.html")

# def about_page(request):
#     context={"name":"jaydev",
#              "age":20,
#              "address":"Kathmandu"
#              }
#     return render(request,"about.html",context)