from django.urls import path
from backendapis.views import Org_register,verify_otp,login_organization,resend_otp,AddAppProductivityAPIView,EditAppProductivityAPIView,DeleteAppProductivityAPIView,GetAppProductivityAPIView,AddActivityProductivityAPIView,EditActivityProductivityAPIView,DeleteActivityProductivityAPIView,DisplayActivityProductivityAPIView


urlpatterns = [
    path('register/', Org_register),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('login/', login_organization, name='login'),
    path('resend_otp/', resend_otp, name='resend_otp'),
    path('add_productivity/', AddAppProductivityAPIView.as_view(),name='add'),
    path('display_productivity/', GetAppProductivityAPIView.as_view(),name='display'),
    path('edit-productivity/<int:data_id>/', EditAppProductivityAPIView.as_view(), name='edit-data'),
    path('delete-productivity/<int:data_id>/', DeleteAppProductivityAPIView.as_view(), name='delete-data'),

#ActivityProductivity
    path('display_ActivityProductivity/', DisplayActivityProductivityAPIView.as_view(),name='display_Activity_Productivity'),
    path('add_activity_productivity/', AddActivityProductivityAPIView.as_view(),name='add_activity_productivity'),
    path('edit_activity_productivity/<int:pk>/', EditActivityProductivityAPIView.as_view(), name='edit_activity_productivity'),
    path('delete_activity_productivity/<int:pk>/', DeleteActivityProductivityAPIView.as_view(), name='delete_activity_productivity'),

]




    
    
