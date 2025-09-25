from django.urls import path
from .views import (
    # public/genral
    home_page_view,
    signin_view,
    signup_view,
    logout_view,
    about_view,
    # admin
    admin_dashboard_view,
    grounds_list_view,
    grounds_create_view,
    grounds_edit_view,
    grounds_delete_view,
    users_list_view,
    admin_profile_view,
    user_edit_view,
    user_delete_view,
    #User    
    user_grounds_view,
    grounds_detail_view,
    all_grounds_view,
    book_ground_view,
    user_bookings_view,
    cancel_booking_view,
    
    # payments
    initiate_payment_view,
    payment_successview,
    payment_success_page_view,
    verify_payment_view,
    
    # Notification views
    get_notifications_view,
    mark_notification_read_view,
    get_admin_notifications_view,
    mark_admin_notification_read_view,
    get_notification_count_view,
    
    # admin bookings
    admin_bookings_view,
    admin_booking_detail_view,
    update_booking_status_view,
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

    # Admin booking management
    path('dashboard/bookings/', admin_bookings_view, name='admin_bookings'),
    path('dashboard/bookings/<int:booking_id>/', admin_booking_detail_view, name='admin_booking_detail'),
    path('dashboard/bookings/<int:booking_id>/update-status/', update_booking_status_view, name='update_booking_status'),

    # User grounds
    path('user/grounds/', user_grounds_view, name='user_grounds'),
    path('ground/<int:pk>/', grounds_detail_view, name='ground_detail'),
    path('grounds/', all_grounds_view, name='all_grounds'),
    # Booking 
    path('book/<int:ground_id>/', book_ground_view, name='book_ground'),
    path('bookings/', user_bookings_view, name='user_bookings'),
    path('bookings/cancel/<int:booking_id>/', cancel_booking_view, name='cancel_booking'),

    # Payments
    path('esewa/success/', payment_successview, name='esewa_success'),
    path('khalti/success/', payment_successview, name='khalti_success'),
    path('payment/success/', payment_success_page_view, name='payment_success_page'),
    path('initiate/', initiate_payment_view, name='initiate'),
    path('verify/', verify_payment_view,name="verify_payment"),
    #  notification URLs
    path('admin/notifications/', get_admin_notifications_view, name='get_admin_notifications'),
    path('admin/notifications/<int:notification_id>/mark-read/', mark_admin_notification_read_view, name='mark_admin_notification_read'),
    path('api/notification-count/', get_notification_count_view, name='get_notification_count'),
    path('notifications/', get_notifications_view, name='get_notifications'),
    path('notifications/<int:notification_id>/read/', mark_notification_read_view, name='mark_notification_read'),
]