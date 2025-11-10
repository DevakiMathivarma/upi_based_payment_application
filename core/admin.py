# core/admin.py
from django.contrib import admin
from .models import BankAccount, Transaction, Notification

@admin.register(BankAccount)
class BankAccountAdmin(admin.ModelAdmin):
    list_display = ('user', 'bank_name', 'account_number', 'is_default', 'created_at')
    search_fields = ('user__username', 'bank_name', 'account_number')

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'amount', 'provider', 'status', 'created_at')
    search_fields = ('user__username', 'razorpay_order_id', 'razorpay_payment_id')
    list_filter = ('status', 'provider', 'created_at')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'is_read', 'created_at')
    list_filter = ('is_read','created_at')
