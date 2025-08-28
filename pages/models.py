from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class FutsalGround(models.Model):
    groundName=models.CharField(max_length=20)
    location=models.CharField(max_length=20)
    description=models.TextField()
    price_per_hour = models.DecimalField(max_digits=4, decimal_places=0)
    image=models.ImageField(upload_to='grounds', null=True , blank= True)
    is_available=models.BooleanField(default=True)
    created_at=models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.groundName
    
class Booking(models.Model):
    Status_Choices=[
            ('pending','Pending'),
            ('confirmed','Confirmed'),
            ('canceled','Canceled'),
            ('completed','Completed'),
        ]

    user= models.ForeignKey(User,on_delete=models.CASCADE)
    ground= models.ForeignKey(FutsalGround,on_delete=models.CASCADE)
    booking_date= models.DateField()
    start_time= models.TimeField()
    end_time= models.TimeField()
    total_hours=models.DecimalField(max_digits=4, decimal_places=2)
    total_amount= models.DecimalField(max_digits=8, decimal_places=2)
    status= models.CharField(max_length=20, choices=Status_Choices, default='pending')
    created_at= models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.ground.groundName} on {self.booking_date}"

class UserProfile(models.Model):
    user= models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number= models.CharField(max_length=10,blank=True)
    address=models.TextField(blank=True)
    
    def __str__(self):
        return self.user.username


