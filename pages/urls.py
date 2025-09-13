from django.urls import path
from .views import (
    home_page_view,
    signin_view,
    signup_view,
    logout_view,
    about_view,
    admin_dashboard_view,
    grounds_list_view,
    grounds_create_view,
    grounds_edit_view,
    grounds_delete_view,
    users_list_view,
    admin_profile_view,
    user_edit_view,
    user_delete_view,
    user_grounds_view,
    grounds_detail_view,
    all_grounds_view,
    book_ground_view,
    initiate_payment_view,
    verify_payment_view,
)

urlpatterns = [
    # Public / general
    path('', home_page_view, name='home'),
    path('signin/', signin_view, name='signin'),
    path('signup/', signup_view, name='signup'),
    path('logout/', logout_view, name='logout'),
    path('about/', about_view, name='about'),

    # Admin dashboard & management
    path('dashboard/', admin_dashboard_view, name='admin_dashboard'),
    path('dashboard/grounds/', grounds_list_view, name='grounds_list'),
    path('dashboard/grounds/new/', grounds_create_view, name='grounds_create'),
    path('dashboard/grounds/<int:pk>/edit/', grounds_edit_view, name='grounds_edit'),
    path('dashboard/grounds/<int:pk>/delete/', grounds_delete_view, name='grounds_delete'),
    path('dashboard/users/', users_list_view, name='users_list'),
    path('dashboard/profile/', admin_profile_view, name='admin_profile'),
    path('dashboard/users/<int:pk>/edit/', user_edit_view, name='user_edit'),
    path('dashboard/users/<int:pk>/delete/', user_delete_view, name='user_delete'),

    # User-facing ground views
    path('user/grounds/', user_grounds_view, name='users_grounds'),
    path('ground/<int:pk>/', grounds_detail_view, name='ground_detail'),
    path('grounds/', all_grounds_view, name='all_grounds'),

    #booking url
    path('book/<int:ground_id>/', book_ground_view, name='book_ground'),

    #khalti url
    path('initiate', initiate_payment_view, name="initate"),
    path('verify', verify_payment_view,name='verify'),
]
