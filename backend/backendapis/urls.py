from django.urls import path
from backendapis.views import Org_register,verify_otp,login_organization,resend_otp,AddOrganizationAPIView,EditDataAPIView,DeleteDataAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


urlpatterns = [
    path('register/', Org_register),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('login/', login_organization, name='login'),
    path('resend_otp/', resend_otp, name='resend_otp'),
    path('add_organization/', AddOrganizationAPIView.as_view(),name='add'),
    path('edit-data/<int:data_id>/', EditDataAPIView.as_view(), name='edit-data'),
    path('delete-data/<int:data_id>/', DeleteDataAPIView.as_view(), name='delete-data'),


    
    
]
