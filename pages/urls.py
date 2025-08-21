from django.urls import path
from .views import home_page_view
# from .views import about_page
urlpatterns=[
    path("",home_page_view),    
]