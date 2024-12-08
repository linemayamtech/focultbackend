from django.urls import path
from backendapis.views import Org_register,verify_otp,login_organization,resend_otp,AddAppProductivityAPIView,EditAppProductivityAPIView,DeleteAppProductivityAPIView,GetAppProductivityAPIView,AddActivityProductivityAPIView,EditActivityProductivityAPIView,DeleteActivityProductivityAPIView,DisplayActivityProductivityAPIView
from .views import *

urlpatterns = [
    path('register/', Org_register),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('login/', login_organization, name='login'),
    path('resend_otp/', resend_otp, name='resend_otp'),

    #App Productivity

    path('add_productivity/', AddAppProductivityAPIView.as_view(),name='add'),
    path('display_productivity/', GetAppProductivityAPIView.as_view(),name='display'),
    path('edit_productivity/<int:data_id>/', EditAppProductivityAPIView.as_view(), name='edit-data'),
    path('delete_productivity/<int:data_id>/', DeleteAppProductivityAPIView.as_view(), name='delete-data'),

#ActivityProductivity
    path('display_ActivityProductivity/', DisplayActivityProductivityAPIView.as_view(),name='display_Activity_Productivity'),
    path('add_activity_productivity/', AddActivityProductivityAPIView.as_view(),name='add_activity_productivity'),
    path('edit_activity_productivity/<int:pk>/', EditActivityProductivityAPIView.as_view(), name='edit_activity_productivity'),
    path('delete_activity_productivity/<int:pk>/', DeleteActivityProductivityAPIView.as_view(), name='delete_activity_productivity'),
# OfflineData section
    path('start_Offline_data/', StartOfflineDataAPIView.as_view(),name='start_Offline_data'),
    path('end_Offline_data/<int:pk>/', EndOfflineDataAPIView.as_view(),name='end_Offline_data'),
    path('get_offline_data/', OfflineDataAPIView.as_view(), name='get_offline_data'),


#Notice section

    path('add_notices/', NoticeAPIView.as_view(), name='create-notice'),  # For creating new notice
    path('display_notices/', NoticeAPIView.as_view(), name='get-notices'),  # For getting the list of notices
    path('update_notices/<int:id>/', NoticeAPIView.as_view(), name='update-notice'),  # For updating a specific notice
    path('delete_notices/<int:id>/', NoticeAPIView.as_view(), name='delete-notice'),  # For deleting a specific notice

]




    
    
