from django.db import models
from django.contrib.auth.models import user
# Create your models here.

class FutsalGround(models.Model):
    groundName=models.CharField(max_length=20)
    location=models.CharField(max_length=20)
    description=models.TextField
    price_per_hour=models.IntegerField(max_digits=4)
    image=models.ImageField(upload_to='grounds', null=True , blank= True)
    is_available=models.BooleanField(default=True)
    created_at=models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
    
    class Booking(models.Model):
        Status_CChoices=[
            ('pending','Pending')
            ('confirmed','Conformed')
            ('canceled','Canceled')
            ('completed','Completed')
        ]

    