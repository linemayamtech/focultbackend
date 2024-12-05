from django.urls import path
from backendapis.views import Org_register,verify_otp,login_organization,resend_otp


urlpatterns = [
    path('register/', Org_register),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('login/', login_organization, name='login'),
    path('resend_otp/', resend_otp, name='resend_otp'),

    
    
]
