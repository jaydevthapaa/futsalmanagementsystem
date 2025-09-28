from django.shortcuts import render,redirect,get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate,login, logout
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .forms import SignupForm, FutsalGroundForm, UserEditForm
from django.contrib.auth.decorators import login_required
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta
from .models import UserProfile, FutsalGround, Booking, Notification
from django.urls import reverse
# esewaa intergration
import hmac, hashlib, base64,uuid

#khaltii

import requests
import json

# Create your views here.
def home_page_view(request):
    nearby_grounds = []
    user_location = None
    if request.user.is_authenticated:
        try:
            profile = UserProfile.objects.get(user=request.user)
            user_address = (profile.address or '').strip()
            if user_address:
                user_location = user_address
                # First try exact match - show ALL grounds in the same location
                nearby_grounds = list(
                    FutsalGround.objects.filter(location__iexact=user_address)
                )
                
                # If no exact match, try partial match - show up to 10 grounds
                if not nearby_grounds:
                    nearby_grounds = list(
                        FutsalGround.objects.filter(location__icontains=user_address)[:10]
                    )
        except UserProfile.DoesNotExist:
            pass
    
    context = {
        "nearby_grounds": nearby_grounds,
        "user_location": user_location
    }
    return render(request, "home.html", context)


# signin view
def signin_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        if username and password:
            # Try username first
            user = authenticate(request, username=username, password=password)

            # If failed, try resolving username by email
            if user is None and '@' in username:
                try:
                    matched_user = User.objects.get(email__iexact=username)
                    user = authenticate(request, username=matched_user.username, password=password)
                except User.DoesNotExist:
                    user = None

            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back to FutsalThings, {user.username}!')
                if user.is_staff:
                    return redirect('admin_dashboard')  # This will go to /dashboard/
                return redirect('home')
            else:
                messages.error(request, "Invalid username or password. Please try again.")
        else:
            messages.error(request, "Please fill in all fields")
    return render(request, 'signin.html')

# signup view
def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            address = form.cleaned_data.get('address', '').strip()
            if address:
                UserProfile.objects.update_or_create(
                    user=user,
                    defaults={"address": address}
                )
            messages.success(request, f'Account created successfully for {username}! You can log in now')
            return redirect('signin')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = SignupForm()

    return render(request, 'signup.html', {'form': form})


def logout_view(request):
    logout(request)
    messages.success(request,"you have been logged out successfully.")
    return redirect('home')

def about_view(request):
    return render(request, 'about.html')


@login_required
def grounds_list_view(request):
    
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    
    grounds = FutsalGround.objects.all().order_by('-created_at')
    total_grounds = grounds.count()  
    
    context = {
        'grounds': grounds,  
        'total_grounds': total_grounds,
        'grounds_list_url': reverse('grounds_list')
    }
    
    return render(request, 'admin/grounds_list.html', context)



@login_required
def grounds_create_view(request):
    
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    
    if request.method == 'POST':
        form = FutsalGroundForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Ground created successfully.')
            return redirect('grounds_list')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = FutsalGroundForm()
    
    return render(request, 'admin/grounds_form.html', {'form': form, 'is_edit': False})

@login_required
def admin_dashboard_view(request):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access the dashboard.")
        return redirect('home')
    
    # Dashboard data to show
    total_users = User.objects.count()
    total_grounds = FutsalGround.objects.count()
    recent_grounds = FutsalGround.objects.order_by('-created_at')[:5]  
    total_bookings = Booking.objects.count()
    
    # Recent bookings that need attention
    pending_bookings = Booking.objects.filter(status='pending').order_by('-created_at')[:5]

    # notifications for admin - 
    notification_queryset = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_count = notification_queryset.filter(status='unread').count()
    notifications = notification_queryset[:10]
    
    # Handle ground creation form
    if request.method == 'POST':
        form = FutsalGroundForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Ground created successfully.')
            return redirect('admin_dashboard')  
        else:
            messages.error(request, 'Please correct the errors in the ground form.')
    else:
        form = FutsalGroundForm()
    
    context = {
        'total_users': total_users,
        'total_grounds': total_grounds,
        'recent_grounds': recent_grounds,
        'total_bookings': total_bookings,
        'pending_bookings': pending_bookings,
        'admin_user': request.user,
        'form': form,
        'is_edit': False,
        'notifications': notifications,
        'unread_count': unread_count,
        'grounds_list_url': reverse('grounds_list'), 
        'users_list_url': reverse('users_list'),
    }
    
    return render(request, 'admin/dashboard.html', context)

@login_required
def get_admin_notifications_view(request):
    print(f"Logged in user: {request.user.username}")

    all_notifications = Notification.objects.all().order_by('-created_at')
    print(f"All notifications: {all_notifications}")

    user_notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    print(f"User notifications: {user_notifications}")

    unread_count = user_notifications.filter(status="unread").count()
    print(f"Unread count: {unread_count}")

    context = {
        'notifications': user_notifications,
        'unread_count': unread_count,
    }

    return render(request, 'admin/notifications.html', context)



@login_required
def mark_admin_notification_read_view(request, notification_id):
    
    if not request.user.is_staff:
        return JsonResponse({'success': False, 'error': 'Permission denied'})
    
    if request.method == 'POST':
        try:
            notification = Notification.objects.get(id=notification_id, user=request.user)
            notification.status = 'read'
            notification.save()
            return JsonResponse({'success': True})
        except Notification.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Notification not found'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})


@login_required
def get_notification_count_view(request):
    
    if request.user.is_staff:
        count = Notification.objects.filter(user=request.user, status='unread').count()
    else:
        count = Notification.objects.filter(user=request.user, status='unread').count()
    
    return JsonResponse({'count': count})
    


@login_required
def grounds_edit_view(request, pk):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    ground = FutsalGround.objects.get(pk=pk)
    if request.method == 'POST':
        form = FutsalGroundForm(request.POST, request.FILES, instance=ground)
        if form.is_valid():
            form.save()
            messages.success(request, 'Ground updated successfully.')
            return redirect('grounds_list')
    else:
        form = FutsalGroundForm(instance=ground)
    return render(request, 'admin/grounds_form.html', { 'form': form, 'is_edit': True })


@login_required
def grounds_delete_view(request, pk):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    ground = FutsalGround.objects.get(pk=pk)
    if request.method == 'POST':
        ground.delete()
        messages.success(request, 'Ground deleted successfully.')
        return redirect('grounds_list')
    return render(request, 'admin/grounds_confirm_delete.html', { 'ground': ground })


@login_required
def users_list_view(request):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    users = User.objects.all().order_by('username')
    total_users = users.count()  # Calculat total users
    
    context = {
        'users': users,  
        'total_users': total_users,
        'users_list_url': reverse('users_list'), 
    }
    
    return render(request, 'admin/users_list.html', context)


@login_required
def admin_profile_view(request):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    return render(request, 'admin/profile.html', { 'admin_user': request.user })


@login_required
def user_edit_view(request, pk):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    user_obj = User.objects.get(pk=pk)
    if request.method == 'POST':
        form = UserEditForm(request.POST, instance=user_obj)
        if form.is_valid():
            form.save()
            messages.success(request, 'User updated successfully.')
            return redirect('users_list')
    else:
        form = UserEditForm(instance=user_obj)
    return render(request, 'admin/user_form.html', { 'form': form, 'user_obj': user_obj })


@login_required
def user_delete_view(request, pk):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    user_obj = User.objects.get(pk=pk)
    if request.method == 'POST':
        if user_obj == request.user:
            messages.error(request, 'You cannot delete your own account while logged in.')
            return redirect('users_list')
        user_obj.delete()
        messages.success(request, 'User deleted successfully.')
        return redirect('users_list')
    return render(request, 'admin/user_confirm_delete.html', { 'user_obj': user_obj })

@login_required
# user ground view
def user_grounds_view(request):
    # to see all avilable futsal grounds  
    grounds= FutsalGround.objects.all().order_by('groundName')
    # filter by location if user has address

    location_filter= request.GET.get('location','').strip()
    if location_filter:
        grounds= grounds.filter(location__icontains=location_filter)

    context={
        'grounds':grounds,
        'location_filter': location_filter
    }
    return render(request,'user/ground_list.html', context)

@login_required
def grounds_detail_view(request,pk):
    #to see  detailed information about a specific grond
    try:
        ground= FutsalGround.objects.get(pk=pk)
    except FutsalGround.DoesNotExist:
        messages.error(request,"ground not found sorry")
        return redirect('users_grounds')

    context={
        'ground':ground,
    }
    return render(request,'user/ground_detail.html',context)

#all_grounds_view
def all_grounds_view(request):
    grounds= FutsalGround.objects.all().order_by('groundName')
    
    #adding search functionallity 
    
    search_query= request.GET.get('search','').strip()
    location_filter= request.GET.get('location','').strip()

    if search_query:
        grounds= grounds.filter(groundName__icontains=search_query)

    if location_filter:
        grounds= grounds.filter(location__icontains=location_filter)

    #unique location for filter dropdown
    
    all_locations= FutsalGround.objects.values_list('location',flat=True).distinct()

    context={
        'grounds':grounds,
        'search_query':search_query,
        'all_locations':all_locations,
    }
    return render(request,'ground_list.html', context)

#booking ground

def generate_esewa_signature(secret_key, params, signed_fields):
    signing_string = ','.join(f"{field}={params[field]}" for field in signed_fields.split(','))
    digest = hmac.new(secret_key.encode('utf-8'), signing_string.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(digest).decode('utf-8')


@login_required
def book_ground_view(request, ground_id):
    ground = get_object_or_404(FutsalGround, id=ground_id)
    show_payment = False
    pending_date = None
    pending_time = None
    advance_amount = None
    transaction_id = None
    esewa_signature = None
    signed_fields = "total_amount,transaction_uuid,product_code"
    success_url = None
    failure_url = None

    if request.method == "POST":
        date = request.POST.get("date")
        time = request.POST.get("time")

        # Save session
        request.session["pending_booking"] = {
            "ground_id": ground.id,
            "date": date,
            "time": time,
        }

        # Calculate advance
        advance_amount = (ground.price_per_hour * Decimal("0.4")).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        transaction_id = str(uuid.uuid4())
        product_code = "EPAYTEST"
        secret_key = "8gBm/:&EnhH.1/q"

        # Build proper URLs with protocol
        if request.is_secure():
            protocol = 'https'
        else:
            protocol = 'http'

        host = request.get_host()

        success_url = f"{protocol}://{host}/esewa/success/"
        failure_url = f"{protocol}://{host}/esewa/failure/"
       
        print(f"Manual URLs - Success: {success_url}, Failure: {failure_url}")
        #  Print the URLs being generated
        print(f"DEBUG - Success URL: {success_url}")
        print(f"DEBUG - Failure URL: {failure_url}")
        print(f"DEBUG - Request is_secure: {request.is_secure()}")
        print(f"DEBUG - Request get_host: {request.get_host()}")

        params = {
            "total_amount": str(advance_amount),
            "transaction_uuid": transaction_id,
            "product_code": product_code,
        }

        esewa_signature = generate_esewa_signature(secret_key, params, signed_fields)

        show_payment = True
        pending_date = date
        pending_time = time

    context = {
        "ground": ground,
        "show_payment": show_payment,
        "pending_date": pending_date,
        "pending_time": pending_time,
        "advance_amount": advance_amount,
        "transaction_id": transaction_id,
        "esewa_signature": esewa_signature,
        "signed_fields": signed_fields,
        "success_url": success_url,
        "failure_url": failure_url,
    }

    return render(request, "booking/book_ground.html", context)


#khalti integration view

def verify_payment_view(request):
    pidx = request.GET.get("pidx")
    if not pidx:
        messages.error(request, "Missing payment ID.")
        return redirect("home")

    url = "https://dev.khalti.com/api/v2/epayment/lookup/"
    headers = {
        "Authorization": "key 9a4a719c4a044bd09710344117cd5f55",
        "Content-Type": "application/json",
    }
    payload = json.dumps({"pidx": pidx})

    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()
        khalti_response = response.json()

        if khalti_response.get("status") != "Completed":
            messages.error(request, "Khalti payment verification failed.")
            return redirect("home")

        transaction_id = khalti_response.get("transaction_id") or pidx
        amount_paid = str(khalti_response.get("total_amount", 0) / 100)  # paisa → Rs
        reference_id = pidx

        # Booking Details from Session 
        pending_booking = request.session.get("pending_booking")
        ground = None
        ground_name = "Unknown Ground"
        ground_image = None
        booking_date = "N/A"
        booking_time = "N/A"
        booking_obj = None

        if pending_booking:
            try:
                ground = FutsalGround.objects.get(id=pending_booking["ground_id"])
                ground_name = ground.groundName
                ground_image = ground.image.url if ground.image else None
                booking_date = pending_booking.get("date", "N/A")
                booking_time = pending_booking.get("time", "N/A")

                # Create Booking object
                start_time = datetime.strptime(booking_time, "%H:%M").time()
                end_time = (datetime.combine(datetime.today(), start_time) + timedelta(hours=1)).time()
                total_hours = Decimal("1.0")  # Assuming 1 hour booking
                total_amount = ground.price_per_hour * total_hours

                booking_obj = Booking.objects.create(
                    user=request.user,
                    ground=ground,
                    booking_date=booking_date,
                    start_time=start_time,
                    end_time=end_time,
                    total_hours=total_hours,
                    total_amount=total_amount,
                    status='pending'
                )

                # Create notification for user
                Notification.objects.create(
                    user=request.user,
                    booking=booking_obj,
                    message=f"Your booking for {ground.groundName} on {booking_date} at {booking_time} is pending confirmation."
                )

                # Create notification for admin
                admin_users = User.objects.filter(is_staff=True)
                for admin in admin_users:
                    Notification.objects.create(
                        user=admin,
                        booking=booking_obj,
                        message=f"New booking by {request.user.username} for {ground.groundName} on {booking_date} at {booking_time}. Payment: Khalti, Transaction ID: {transaction_id}"
                    )

                if booking_time != "N/A":
                    try:
                        dt = datetime.strptime(booking_time, "%H:%M")
                        booking_time = dt.strftime("%I:%M %p")
                    except ValueError:
                        pass
            except FutsalGround.DoesNotExist:
                pass
            # clear session
            del request.session["pending_booking"]

        context = {
            "transaction_id": transaction_id,
            "amount_paid": amount_paid,
            "reference_id": reference_id,
            "payment_done_through": "Khalti",
            "ground_name": ground_name,
            "ground_image": ground_image,
            "booking_date": booking_date,
            "booking_time": booking_time,
            "user_name": request.user.username if request.user.is_authenticated else "Guest",
        }

        # Store context in session and redirect to success page
        request.session['payment_success_context'] = context
        return redirect('payment_success_page')

    except (requests.exceptions.RequestException, json.JSONDecodeError):
        messages.error(request, "Khalti verification error.")
        return redirect("home")


def initiate_payment_view(request):
    url = "https://dev.khalti.com/api/v2/epayment/initiate/"
    return_url = request.POST.get('return_url', '').strip()   
    purchase_order_id = request.POST.get('purchase_order_id', '').strip()
    amount = request.POST.get('amount', '0').strip()
    user = request.user

    try:
        # Convert to paisa (Khalti expects integer)
        amount_paisa = int(float(amount) * 100)
    except ValueError:
        return JsonResponse({'error': 'Invalid amount'}, status=400)

    payload = json.dumps({
        "return_url": return_url,
        "website_url": "http://127.0.0.1:8000",
        "amount": amount_paisa,
        "purchase_order_id": purchase_order_id or str(uuid.uuid4()),  
        "purchase_order_name": "Ground Booking",
        "customer_info": {
            "name": user.username,
            "email": user.email,
            "phone": getattr(user.userprofile, 'phone_number', '')
        }
    })

    headers = {
        'Authorization': 'key 9a4a719c4a044bd09710344117cd5f55',
        'Content-Type': 'application/json',
    }

    response = requests.post(url, headers=headers, data=payload)
    new_response = response.json()

    print("Khalti response:", new_response)  
    if 'payment_url' in new_response:
        return redirect(new_response['payment_url'])
    else:
        return JsonResponse(new_response, status=400)  #actual error


# payment success view for both eSewa and Khalti
def payment_successview(request):
    # eSewa V2 parameters
    transaction_uuid = request.GET.get("transaction_uuid")
    total_amount = request.GET.get("total_amount")
    refId = request.GET.get("refId")

    # Khalti parameters
    pidx = request.GET.get("pidx")
    purchase_order_id = request.GET.get("purchase_order_id")

    payment_method = None
    transaction_id = None
    amount_paid = None
    reference_id = None

    # eSewa V2 
    if transaction_uuid and total_amount and refId:
        payment_method = "eSewa"
        transaction_id = transaction_uuid
        amount_paid = total_amount
        reference_id = refId

        # Verify with eSewa V2 API
        url = "https://rc-epay.esewa.com.np/api/epay/transaction"
        payload = {
            "amount": total_amount,
            "product_code": "EPAYTEST", 
            "transaction_uuid": transaction_uuid,
            "reference_id": refId,
        }
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "COMPLETE":
                messages.error(request, "eSewa payment verification failed.")
                return redirect("home")
        except requests.exceptions.RequestException:
            messages.error(request, "eSewa verification error.")
            return redirect("home")

    #Khalti 
    elif pidx:
        payment_method = "Khalti"
        url = "https://dev.khalti.com/api/v2/epayment/lookup/"
        headers = {
            "Authorization": "key 9a4a719c4a044bd09710344117cd5f55",
            "Content-Type": "application/json",
        }
        payload = json.dumps({"pidx": pidx})

        try:
            response = requests.post(url, headers=headers, data=payload)
            response.raise_for_status()
            khalti_response = response.json()

            if khalti_response.get("status") != "Completed":
                messages.error(request, "Khalti payment verification failed.")
                return redirect("home")

            transaction_id = khalti_response.get("transaction_id") or pidx
            amount_paid = str(khalti_response.get("total_amount", 0) / 100)  # paisa → Rs
            reference_id = pidx
        except (requests.exceptions.RequestException, json.JSONDecodeError):
            messages.error(request, "Khalti verification error.")
            return redirect("home")

    else:
        # Check for eSewa V1 parameters
        oid = request.GET.get("oid")
        amt = request.GET.get("amt")
        refId_v1 = request.GET.get("refId")

        if oid and amt and refId_v1:
            payment_method = "eSewa"
            transaction_id = oid
            amount_paid = amt
            reference_id = refId_v1

            # Verify with eSewa V1 API
            url = "https://uat.esewa.com.np/epay/transrec"
            payload = {
                "amt": amt,
                "scd": "EPAYTEST",
                "rid": refId_v1,
                "pid": oid,
            }

            try:
                response = requests.post(url, data=payload)
                if "Success" not in response.text:
                    messages.error(request, "eSewa payment verification failed.")
                    return redirect("home")
            except requests.exceptions.RequestException:
                messages.error(request, "eSewa verification error.")
                return redirect("home")
        else:
            messages.error(request, "Missing payment parameters.")
            return redirect("home")

    #  Booking Details from Session 
    pending_booking = request.session.get("pending_booking")
    ground = None
    ground_name = "Unknown Ground"
    ground_image = None
    booking_date = "N/A"
    booking_time = "N/A"

    if pending_booking:
        try:
            ground = FutsalGround.objects.get(id=pending_booking["ground_id"])
            ground_name = ground.groundName
            ground_image = ground.image.url if ground.image else None
            booking_date = pending_booking.get("date", "N/A")
            booking_time = pending_booking.get("time", "N/A")

            # Create Booking object
            start_time = datetime.strptime(booking_time, "%H:%M").time()
            end_time = (datetime.combine(datetime.today(), start_time) + timedelta(hours=1)).time()
            total_hours = Decimal("1.0")  #  1 hour booking
            total_amount = ground.price_per_hour * total_hours

            booking_obj = Booking.objects.create(
                user=request.user,
                ground=ground,
                booking_date=booking_date,
                start_time=start_time,
                end_time=end_time,
                total_hours=total_hours,
                total_amount=total_amount,
                status='pending'
            )

            # Create notification for user
            Notification.objects.create(
                user=request.user,
                booking=booking_obj,
                message=f"Your booking for {ground.groundName} on {booking_date} at {booking_time} is pending confirmation."
            )

            # Create notification for admin
            admin_users = User.objects.filter(is_staff=True)
            for admin in admin_users:
                Notification.objects.create(
                    user=admin,
                    booking=booking_obj,
                    message=f"New booking by {request.user.username} for {ground.groundName} on {booking_date} at {booking_time}. Payment: {payment_method}, Transaction ID: {transaction_id}"
                )

            if booking_time != "N/A":
                try:
                    dt = datetime.strptime(booking_time, "%H:%M")
                    booking_time = dt.strftime("%I:%M %p")
                except ValueError:
                    pass
        except FutsalGround.DoesNotExist:
            pass
        # clear session
        del request.session["pending_booking"]

    context = {
        "transaction_id": transaction_id,
        "amount_paid": amount_paid,
        "reference_id": reference_id,
        "payment_done_through": payment_method,
        "ground_name": ground_name,
        "ground_image": ground_image,
        "booking_date": booking_date,
        "booking_time": booking_time,
        "user_name": request.user.username if request.user.is_authenticated else "Guest",
    }

    # Store context in session and redirect to success page
    request.session['payment_success_context'] = context
    return redirect('payment_success_page')


def payment_success_page_view(request):
    context = request.session.get('payment_success_context', {})
    if not context:
        messages.error(request, "No payment information found.")
        return redirect('home')
    del request.session['payment_success_context']
    return render(request, "booking/payment_success.html", context)


# Notification Views
@login_required
def get_notifications_view(request):
    # View to fetch notifications for logged-in user
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[:10]
    notifications_data = []

    for notification in notifications:
        notifications_data.append({
            'id': notification.id,
            'message': notification.message,
            'status': notification.status,
            'created_at': notification.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'booking_id': notification.booking.id if notification.booking else None,
            'booking_status': notification.booking.status if notification.booking else None,
        })

    return JsonResponse({'notifications': notifications_data})


@login_required
def mark_notification_read_view(request, notification_id):
    
    if request.method == 'POST':
        try:
            notification = Notification.objects.get(id=notification_id, user=request.user)
            notification.status = 'read'
            notification.save()
            return JsonResponse({'success': True})
        except Notification.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Notification not found'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})


@login_required
def admin_confirm_booking(request, booking_id):
    """Admin view to confirm a booking - similar to user confirm but for admin"""
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    
    try:
        booking = Booking.objects.get(id=booking_id)
        
        # Only allow confirmation if booking is pending
        if booking.status != 'pending':
            messages.error(request, "This booking cannot be confirmed.")
            return redirect('admin_bookings')
        
        if request.method == 'POST':
            action = request.POST.get('action')
            
            if action == 'confirm':
                booking.status = 'confirmed'
                booking.save()
                
                # Create notification for user
                Notification.objects.create(
                    user=booking.user,
                    booking=booking,
                    message=f"Your booking for {booking.ground.groundName} on {booking.booking_date} at {booking.start_time.strftime('%I:%M %p')} has been confirmed by admin."
                )
                
                # Create notification for admin
                Notification.objects.create(
                    user=request.user,
                    booking=booking,
                    message=f"You confirmed booking by {booking.user.username} for {booking.ground.groundName} on {booking.booking_date} at {booking.start_time.strftime('%I:%M %p')}."
                )
                
                messages.success(request, "Booking confirmed successfully.")
                return redirect('admin_bookings')
            
            elif action == 'cancel':
                booking.status = 'cancelled'
                booking.save()
                
                # Create notification for user about cancellation and refund
                Notification.objects.create(
                    user=booking.user,
                    booking=booking,
                    message=f"Your booking for {booking.ground.groundName} on {booking.booking_date} has been cancelled by admin. Your advance payment will be refunded within 3-5 business days."
                )
                
                # Create notification for admin
                Notification.objects.create(
                    user=request.user,
                    booking=booking,
                    message=f"You cancelled booking by {booking.user.username} for {booking.ground.groundName}. Refund process initiated."
                )
                
                messages.success(request, "Booking cancelled successfully. User has been notified about the refund.")
                return redirect('admin_bookings')
        
        return render(request, 'admin/admin_confirm_booking.html', {'booking': booking})
        
    except Booking.DoesNotExist:
        messages.error(request, "Booking not found.")
        return redirect('admin_bookings')
# cancle ground view
@login_required
def cancel_booking_view(request, booking_id):
    try:
        booking = Booking.objects.get(id=booking_id, user=request.user)
        
        # Only allow cancellation if booking is pending or confirmed
        if booking.status not in ['pending', 'confirmed']:
            messages.error(request, "This booking cannot be cancelled.")
            return redirect('user_bookings')
        
        if request.method == 'POST':
            booking.status = 'cancelled'
            booking.save()
            
            # Create notification for user
            Notification.objects.create(
                user=request.user,
                booking=booking,
                message=f"You cancelled your booking for {booking.ground.groundName} on {booking.booking_date} at {booking.start_time.strftime('%I:%M %p')}."
            )
            
            # Create notification for admin
            admin_users = User.objects.filter(is_staff=True)
            for admin in admin_users:
                Notification.objects.create(
                    user=admin,
                    booking=booking,
                    message=f"Booking cancelled by {request.user.username} for {booking.ground.groundName} on {booking.booking_date} at {booking.start_time.strftime('%I:%M %p')}."
                )
            
            messages.success(request, "Booking cancelled successfully.")
            return redirect('user_bookings')
        
        return render(request, 'user/cancel_booking.html', {'booking': booking})
        
    except Booking.DoesNotExist:
        messages.error(request, "Booking not found.")
        return redirect('user_bookings')


@login_required
def admin_booking_detail_view(request, booking_id):
   
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')
    
    try:
        booking = Booking.objects.get(id=booking_id)
        return render(request, 'admin/booking_detail.html', {'booking': booking})
    except Booking.DoesNotExist:
        messages.error(request, "Booking not found.")
        return redirect('admin_bookings')



# Admin Booking Management Views
@login_required
def admin_bookings_view(request):
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to access this page.")
        return redirect('home')

    bookings = Booking.objects.all().order_by('-created_at')
    return render(request, 'admin/admin_bookings.html', {'bookings': bookings})  


@login_required
def update_booking_status_view(request, booking_id):
 
    if not request.user.is_staff:
        return JsonResponse({'success': False, 'error': 'Permission denied'})

    if request.method == 'POST':
        try:
            booking = Booking.objects.get(id=booking_id)
            new_status = request.POST.get('status')

            if new_status not in ['confirmed', 'cancelled', 'completed']:
                return JsonResponse({'success': False, 'error': 'Invalid status'})

            old_status = booking.status
            booking.status = new_status
            booking.save()

          
            status_messages = {
                'confirmed': f"Your booking for {booking.ground.groundName} on {booking.booking_date} has been confirmed.",
                'cancelled': f"Your booking for {booking.ground.groundName} on {booking.booking_date} has been cancelled.",
                'completed': f"Your booking for {booking.ground.groundName} on {booking.booking_date} has been completed."
            }

            Notification.objects.create(
                user=booking.user,
                booking=booking,
                message=status_messages[new_status]
            )

            return JsonResponse({'success': True, 'new_status': new_status})

        except Booking.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Booking not found'})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})


@login_required
def user_bookings_view(request):
    # View for users to see their bookings
    bookings = Booking.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'user/bookings.html', {'bookings': bookings})