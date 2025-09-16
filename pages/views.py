from django.shortcuts import render,redirect,get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate,login, logout
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .forms import SignupForm, FutsalGroundForm, UserEditForm
from django.contrib.auth.decorators import login_required
from decimal import Decimal, ROUND_HALF_UP
from .models import UserProfile, FutsalGround
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
    return render(request, 'admin/grounds_list.html', {'grounds': grounds})



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
    
    # Handle ground creation form
    if request.method == 'POST':
        form = FutsalGroundForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Ground created successfully.')
            return redirect('admin_dashboard')  # Stay on dashboard
        else:
            messages.error(request, 'Please correct the errors in the ground form.')
    else:
        form = FutsalGroundForm()
    
    context = {
        'total_users': total_users,
        'total_grounds': total_grounds,
        'recent_grounds': recent_grounds,
        'admin_user': request.user,
        'form': form,
        'is_edit': False,
    }
    return render(request, 'admin/dashboard.html', context)
    


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
    return render(request, 'admin/users_list.html', { 'users': users })


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

    #unique location for filter dropdown#
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
    }

    return render(request, "booking/book_ground.html", context)


#khalti integration view

def initiate_payment_view(request):


    url = "https://dev.khalti.com/api/v2/epayment/initiate/"
    return_url=request.POST.get('return_url')
    purchase_order_id = request.POST.get('purchase_order_id')
    amount= request.POST.get('amount')

    print("return_url",return_url)
    print("purchase_order_id",purchase_order_id)
    print("amount",amount)
    user= request.user


    payload = json.dumps({
        "return_url": return_url,
        "website_url": "http://127.0.0.1:8000",
        "amount": amount,
        "purchase_order_id": purchase_order_id,
        "purchase_order_name": "Ground Booking",
        "customer_info": {
        "name":user.username,
        "email": user.email,
        "phone": user.userprofile.phone_number,
        }
    })
    headers = {
        'Authorization': 'key 9a4a719c4a044bd09710344117cd5f55',
        'Content-Type': 'application/json',
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    print(response.text)
    new_response= json.loads(response.text)
    print(new_response)
    return redirect(new_response['payment_url'])
    

def verify_payment_view(request):
    url = "https://dev.khalti.com/api/v2/epayment/lookup/",  
    pidx= request.GET.get('pidx')
    if not pidx:
        return JsonResponse({'error':'pidx parameter is required'},status=400)
    headers={
        'Authorization': 'key 9a4a719c4a044bd09710344117cd5f55',
        'Content-Type': 'application/json',   
    }
    payload=json.dumps({
        'pidx':pidx,   
    })
    
    try:
        response = requests.post(url, headers=headers, data=payload)  
        print(response.text)
        response.raise_for_status()
        new_response = json.loads(response.text)
        print(new_response)
        return redirect('home')
        
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return JsonResponse({'error': 'Payment verification failed'}, status=500)
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return JsonResponse({'error': 'Invalid response format'}, status=500)
    

#esewa 
def payment_success_view(request):
    # Here you can mark the booking as paid
    messages.success(request, "Payment successful! Your booking is confirmed.")
    return redirect('users_grounds')  # Redirect to your grounds list or booking page

def  payment_faliure_view(request):  # Fixed: "failure" not "faliure"
    # Here you can show a failure message
    messages.error(request, "Payment failed! Please try again.")
    return redirect('book_ground', ground_id=request.session.get('pending_booking', {}).get('ground_id'))
