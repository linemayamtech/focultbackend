from django.urls import path
from backendapis.views import Org_register,verify_otp,login_organization


urlpatterns = [
    path('register/', Org_register),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('login/', login_organization, name='login'),
    
]
