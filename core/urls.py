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
]
