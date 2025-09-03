from django.urls import path
from .views import home_page_view,signin_view,signup_view,about_view,logout_view

urlpatterns=[
    path("",home_page_view, name='home'),    
    path('signin/',signin_view,name="signin"),
    path('signup/', signup_view, name='signup'),
    path('about/', about_view, name='about'),
    path('logout/',logout_view, name='logout')
   
]