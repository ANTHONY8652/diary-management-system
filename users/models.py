from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db.models.signals import post_save
from django.dispatch import receiver 
from django.utils import timezone

class User(models.Model):
    ADMIN = 'admin'
    MEMBER = 'member'

    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (MEMBER, 'Member'),
    ]

    class Meta:
        ordering = ['user']

    def validate_role(self):
        if self.role not in ['admin', 'member']:
            raise ValidationError("Role must be either 'admin' or 'member'. Try again sorry")
            
    def save(self, *args, **kwargs):
        self.validate_role
        super().save(*args, **kwargs)

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    date_of_membership = models.DateField(auto_now_add=True)
    active_status = models.BooleanField(default=True)
    role = models.CharField(max_length=8, choices=ROLE_CHOICES, default='member', validators=[validate_role])

    def is_admin(self):
        return self.role == 'admin'
    
    def __str__(self):
        return self.user.username

@receiver(post_save, sender=User)
def create_or_save_profile(sender, instance, created, **kwargs):
    if created:
        User.objects.create(user=instance)
    else:
        instance.user.date_of_membership = timezone.now()
        instance.user.save()

class PasswordResetCode(models.Model):
    #Model to store OTP codes for password reset
    User = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['code', 'email', 'used']),
        ]
    
    def is_valid(self):
        #CHEck if code is still valid (not used and not expired that is)
        from django.utils import timezone
        return not self.used and timezone.now() < self.expires_at
    
    def __str__(self):
        return f"Code {self.code} for {self.email} (expires: {self.expires_at})"



# Create your models here.
