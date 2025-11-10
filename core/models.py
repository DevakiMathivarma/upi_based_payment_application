from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import datetime

# Custom User model
class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    is_phone_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username


# Model to store OTPs for registration/login
class MobileOTP(models.Model):
    PURPOSE_CHOICES = [
        ('REGISTER', 'Register'),
        ('LOGIN', 'Login'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    purpose = models.CharField(max_length=10, choices=PURPOSE_CHOICES)
    attempts = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.user.username} - {self.otp} ({self.purpose})"

    def is_expired(self):
        return timezone.now() > self.expires_at

    def mark_used(self):
        self.used = True
        self.save()

    @classmethod
    def create_otp(cls, user, otp, purpose):
        expiry = timezone.now() + datetime.timedelta(minutes=5)
        return cls.objects.create(user=user, otp=otp, expires_at=expiry, purpose=purpose)


# 
# core/models.py
from django.db import models
from django.conf import settings


User = settings.AUTH_USER_MODEL

class BankAccount(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bank_accounts')
    bank_name = models.CharField(max_length=120)
    account_number = models.CharField(max_length=64)
    ifsc = models.CharField(max_length=32, blank=True, null=True)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.bank_name} ({self.account_number[-4:]})"


class Transaction(models.Model):
    STATUS_PENDING = 'PENDING'
    STATUS_SUCCESS = 'SUCCESS'
    STATUS_FAILED = 'FAILED'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_SUCCESS, 'Success'),
        (STATUS_FAILED, 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    to_upi = models.CharField(max_length=128, blank=True, null=True)      # recipient UPI ID or phone
    provider = models.CharField(max_length=32, blank=True, null=True)      # 'gpay','phonepe','razorpay','bank'
    razorpay_order_id = models.CharField(max_length=128, blank=True, null=True)
    razorpay_payment_id = models.CharField(max_length=128, blank=True, null=True)
    razorpay_signature = models.CharField(max_length=256, blank=True, null=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def mark_success(self, payment_id=None, signature=None):
        if payment_id:
            self.razorpay_payment_id = payment_id
        if signature:
            self.razorpay_signature = signature
        self.status = self.STATUS_SUCCESS
        self.save(update_fields=['razorpay_payment_id', 'razorpay_signature', 'status', 'updated_at'])

    def mark_failed(self, reason=None):
        if reason:
            self.notes = (self.notes or '') + f"\nFailed: {reason}"
        self.status = self.STATUS_FAILED
        self.save(update_fields=['notes', 'status', 'updated_at'])

    def __str__(self):
        return f"{self.user} — ₹{self.amount} — {self.status}"


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} — {self.message[:40]}"
