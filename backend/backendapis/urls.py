from django.urls import path
from backendapis.views import Org_register,verify_otp,login_organization,resend_otp,AddAppProductivityAPIView,EditAppProductivityAPIView,DeleteAppProductivityAPIView,GetAppProductivityAPIView


urlpatterns = [
    path('register/', Org_register),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('login/', login_organization, name='login'),
    path('resend_otp/', resend_otp, name='resend_otp'),
    path('add_productivity/', AddAppProductivityAPIView.as_view(),name='add'),
    path('display_productivity/', GetAppProductivityAPIView.as_view(),name='display'),
    path('edit-productivity/<int:data_id>/', EditAppProductivityAPIView.as_view(), name='edit-data'),
    path('delete-productivity/<int:data_id>/', DeleteAppProductivityAPIView.as_view(), name='delete-data'),


    
    
]
