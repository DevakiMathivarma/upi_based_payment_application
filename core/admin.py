# # core/admin.py
# from django.contrib import admin
# from .models import BankAccount, Transaction, Notification

# @admin.register(BankAccount)
# class BankAccountAdmin(admin.ModelAdmin):
#     list_display = ('user', 'bank_name', 'account_number', 'is_default', 'created_at')
#     search_fields = ('user__username', 'bank_name', 'account_number')
# from django.contrib import admin
# from .models import Transaction

# from django.contrib import admin
# from .models import Transaction
# from django.utils.html import format_html
# @admin.register(Transaction)
# class TransactionAdmin(admin.ModelAdmin):
#     # Columns shown in the main list view
#     list_display = (
#         'txn_num', 'user', 'amount', 'provider', 'status', 'created_at', 'updated_at'
#     )
#     # Fields that can be searched
#     search_fields = (
#         'txn_num', 'user__username', 'provider', 'to_upi', 'razorpay_payment_id'
#     )
#     # Filters shown on the right-hand side
#     list_filter = (
#         'status', 'provider', 'created_at'
#     )
#     # Fields that cannot be edited manually in the admin form
#     readonly_fields = (
#         'txn_num', 'created_at', 'updated_at', 'razorpay_order_id',
#         'razorpay_payment_id', 'razorpay_signature'
#     )

#     # Optional: field grouping in the edit form for better layout
#     fieldsets = (
#         ("Transaction Info", {
#             "fields": (
#                 'txn_num', 'user', 'amount', 'to_upi', 'provider', 'status'
#             )
#         }),
#         ("Razorpay Details", {
#             "fields": (
#                 'razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature'
#             ),
#             "classes": ("collapse",),  # collapsible section
#         }),
#         ("Notes & Timestamps", {
#             "fields": ('notes', 'created_at', 'updated_at')
#         }),
#     )

#     # Default ordering (latest first)
#     ordering = ('-created_at',)

#     # Display color-coded statuses (optional enhancement)
#     def colored_status(self, obj):
#         color_map = {
#             'PENDING': 'orange',
#             'SUCCESS': 'green',
#             'FAILED': 'red'
#         }
#         color = color_map.get(obj.status, 'black')
#         return format_html(f'<b style="color:{color}">{obj.status}</b>')
#     colored_status.short_description = 'Status'


# @admin.register(Notification)
# class NotificationAdmin(admin.ModelAdmin):
#     list_display = ('user', 'message', 'is_read', 'created_at')
#     list_filter = ('is_read','created_at')


# core/admin.py
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.html import format_html
from django.http import HttpResponse
import csv

from .models import (
    BankAccount,
    Transaction,
    Notification,
    Operator,
    RechargePlan,
    RechargeOrder,
)

User = get_user_model()


# --- Inline for Transactions on User page ---
class TransactionInline(admin.TabularInline):
    model = Transaction
    fields = ('txn_num', 'amount', 'to_upi', 'provider', 'status', 'created_at')
    readonly_fields = ('txn_num', 'amount', 'to_upi', 'provider', 'status', 'created_at')
    extra = 0
    show_change_link = True
    can_delete = False  # typically don't delete transactions from user page


# --- Inline for BankAccount on User page ---
class BankAccountInline(admin.TabularInline):
    model = BankAccount
    fields = ('bank_name', 'account_number', 'ifsc', 'is_default', 'created_at')
    readonly_fields = ('created_at',)
    extra = 0


# --- Admin actions ---
def export_transactions_csv(modeladmin, request, queryset):
    """Admin action to export selected transactions as CSV."""
    meta = modeladmin.model._meta
    field_names = ['txn_num', 'user', 'amount', 'to_upi', 'provider', 'status', 'created_at', 'updated_at']

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename=transactions_export.csv'
    writer = csv.writer(response)

    writer.writerow(field_names)
    for obj in queryset.select_related('user'):
        writer.writerow([
            getattr(obj, 'txn_num', ''),
            str(obj.user),
            getattr(obj, 'amount', ''),
            getattr(obj, 'to_upi', ''),
            getattr(obj, 'provider', ''),
            getattr(obj, 'status', ''),
            getattr(obj, 'created_at', ''),
            getattr(obj, 'updated_at', ''),
        ])
    return response

export_transactions_csv.short_description = "Export selected transactions to CSV"


# --- TransactionAdmin ---
# core/admin.py (TransactionAdmin portion)
from django.contrib import admin
from django.contrib.admin import DateFieldListFilter
from django.utils.html import format_html
from .models import Transaction

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('txn_num', 'user', 'amount', 'provider', 'colored_status', 'created_at', 'updated_at')
    search_fields = ('txn_num', 'user__username', 'user__email', 'provider', 'to_upi', 'razorpay_payment_id')
    # Use explicit DateFieldListFilter for created_at so date ranges behave correctly
    list_filter = ('status', 'provider', ('created_at', DateFieldListFilter), 'user')
    readonly_fields = (
        'txn_num', 'created_at', 'updated_at', 'razorpay_order_id',
        'razorpay_payment_id', 'razorpay_signature'
    )
    fieldsets = (
        ("Transaction Info", {
            "fields": ('txn_num', 'user', 'amount', 'to_upi', 'provider', 'status')
        }),
        ("Razorpay Details", {
            "fields": ('razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature'),
            "classes": ("collapse",),
        }),
        ("Notes & Timestamps", {
            "fields": ('notes', 'created_at', 'updated_at')
        }),
    )
    ordering = ('-created_at',)
    actions = []  # keep or add export action if you want
    date_hierarchy = 'created_at'
    list_select_related = ('user',)
    raw_id_fields = ('user',)

    def colored_status(self, obj):
        color_map = {
            Transaction.STATUS_PENDING: 'orange',
            Transaction.STATUS_SUCCESS: 'green',
            Transaction.STATUS_FAILED: 'red'
        }
        color = color_map.get(obj.status, 'black')
        return format_html(f'<b style="color:{color}">{obj.status}</b>')
    colored_status.short_description = 'Status'



# --- NotificationAdmin ---
@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'short_message', 'is_read', 'created_at')
    list_filter = ('is_read', 'created_at')
    search_fields = ('user__username', 'message')
    readonly_fields = ('created_at',)

    def short_message(self, obj):
        return obj.message[:60]
    short_message.short_description = 'Message (first 60 chars)'


# --- BankAccount admin ---
@admin.register(BankAccount)
class BankAccountAdmin(admin.ModelAdmin):
    list_display = ('user', 'bank_name', 'account_number_masked', 'is_default', 'created_at')
    search_fields = ('user__username', 'bank_name', 'account_number')
    list_filter = ('is_default', 'created_at')
    raw_id_fields = ('user',)
    readonly_fields = ('created_at',)

    def account_number_masked(self, obj):
        if obj.account_number and len(obj.account_number) > 4:
            return f"****{obj.account_number[-4:]}"
        return obj.account_number
    account_number_masked.short_description = 'Account'


# --- Optionally register recharge models if you want them in admin ---
@admin.register(Operator)
class OperatorAdmin(admin.ModelAdmin):
    list_display = ('name', 'code', 'circle')
    search_fields = ('name', 'code', 'circle')


@admin.register(RechargePlan)
class RechargePlanAdmin(admin.ModelAdmin):
    list_display = ('title', 'operator', 'amount', 'validity')
    search_fields = ('title', 'operator__name')
    list_filter = ('operator',)


@admin.register(RechargeOrder)
class RechargeOrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'mobile', 'amount', 'status', 'created_at')
    list_filter = ('status', 'created_at', 'operator')
    search_fields = ('mobile', 'user__username', 'id')
    date_hierarchy = 'created_at'
    raw_id_fields = ('user', 'operator', 'plan')


# --- Register User with inlines ---
@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    # keep Django's default UserAdmin configuration but add inlines
    inlines = (BankAccountInline, TransactionInline)
    list_display = ('username', 'email', 'phone_number', 'is_staff', 'is_phone_verified', 'is_active', 'date_joined')
    search_fields = ('username', 'email', 'phone_number',)
    readonly_fields = ('date_joined',)
    # optionally add list_filter or fieldsets adjustments if needed
