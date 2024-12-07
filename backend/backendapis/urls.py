from django.urls import path
from backendapis.views import Org_register,verify_otp,login_organization,resend_otp,AddProductivityAPIView,EditProductivityAPIView,DeleteProductivityAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


urlpatterns = [
    path('register/', Org_register),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('login/', login_organization, name='login'),
    path('resend_otp/', resend_otp, name='resend_otp'),
    path('add_productivity/', AddProductivityAPIView.as_view(),name='add'),
    path('edit-productivity/<int:data_id>/', EditProductivityAPIView.as_view(), name='edit-data'),
    path('delete-productivity/<int:data_id>/', DeleteProductivityAPIView.as_view(), name='delete-data'),


    
    
]
