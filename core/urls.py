from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('', views.home_view, name='home'),                     # optional homepage
    path('register/', views.register_view, name='register'),    # registration form (GET/POST)
    path('login/', views.login_view, name='login'),             # login form (username + otp) (GET/POST)
    path('resend-otp/', views.resend_otp_view, name='resend_otp'),  # resend otp (POST)
    path('dashboard/', views.dashboard_view, name='dashboard'), # user dashboard (login required)
    path('logout/', views.logout_view, name='logout'),  
            
    path('payments/create-order/', views.create_order_view, name='create_order'),
    path('payments/verify/', views.verify_payment_view, name='verify_payment'),
    path('payments/webhook/razorpay/', views.razorpay_webhook, name='razorpay_webhook'),

    path("recharge/", views.recharge_view, name="recharge"),
    path("recharge/create/", views.create_recharge, name="create_recharge"),
    path("recharge/upi/<uuid:order_id>/", views.recharge_upi_page, name="recharge_upi_page"),
    path("recharge/submit-txn/<uuid:order_id>/", views.submit_upi_tid, name="submit_upi_tid"),
    path("api/plans/<str:operator_code>/", views.api_get_plans, name="api_get_plans"),
    # path('create-order/', views.create_order, name='create_order'),
    path('i-paid/', views.i_paid, name='i_paid'),
    path('transaction/', views.transactions_view, name='transactions_view'),

]
