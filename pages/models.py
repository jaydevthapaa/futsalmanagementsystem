from django.db import models
from django.contrib.auth.models import User

class FutsalGround(models.Model):
    groundName = models.CharField(max_length=100)
    location = models.CharField(max_length=100)
    description = models.TextField()
    price_per_hour = models.DecimalField(max_digits=6, decimal_places=2)  
    image = models.ImageField(upload_to='grounds/', null=True, blank=True)
    is_available = models.BooleanField(default=True)
    contact_number = models.CharField(max_length=10, blank=True, null=True)  
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.groundName
    
    class Meta:
        ordering = ['groundName']

class Booking(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('canceled', 'Canceled'),
        ('completed', 'Completed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ground = models.ForeignKey(FutsalGround, on_delete=models.CASCADE)
    booking_date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    total_hours = models.DecimalField(max_digits=4, decimal_places=2)
    total_amount = models.DecimalField(max_digits=8, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return f"{self.user.username} - {self.ground.groundName} on {self.booking_date}"
    
    class Meta:
        ordering = ['-created_at']
        # Prevent double booking for same time slot
        unique_together = ['ground', 'booking_date', 'start_time']

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=10, blank=True)  #
    address = models.TextField(blank=True)


    def __str__(self):
        return f"{self.user.username}'s Profile"

    @property
    def full_name(self):
        first_name = self.user.first_name or ""
        last_name = self.user.last_name or ""
        full_name = f"{first_name} {last_name}".strip()
        return full_name if full_name else self.user.username

class Notification(models.Model):
    STATUS_CHOICES = [
        ('unread', 'Unread'),
        ('read', 'Read'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, null=True, blank=True)
    message = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='unread')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message[:50]}"

    class Meta:
        ordering = ['-created_at']
