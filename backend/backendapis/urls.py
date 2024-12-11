from django.urls import path
from backendapis.views import Org_register,verify_otp,login_organization,resend_otp
from .views import *

urlpatterns = [

    #Authentication section

    path('register/', Org_register),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('login/', login_organization, name='login'),
    path('resend_otp/', resend_otp, name='resend_otp'),

    #App Productivity

    path('add_display_app_productivity/', AppProductivityAPIView.as_view(), name='app-productivity-list-add'),
    path('edit_delete_app_productivity/<int:id>/', AppProductivityAPIView.as_view(), name='app-productivity-edit-delete'),

    #ActivityProductivity
    path('add_display_activity_productivity/', ActivityProductivityAPIView.as_view(), name='activity-productivity-list-create'),
    path('edit_delete_activity_productivity/<int:pk>/', ActivityProductivityAPIView.as_view(), name='activity-productivity-edit-delete'),
    # OfflineData section
    path('add_display_offline_data/', OfflineDataAPIView.as_view(), name='offline-data'),  # For displaying and adding
    path('end_manage_offline_data/<int:id>/', ManageOfflineDataAPIView.as_view(), name='manage-offline-data'),  # For end


    #Notice section

    path('add_display_notices/', NoticeAPIView.as_view(), name='get-notices'),  # For getting the list of notices
    path('delete_update_notices/<int:id>/', NoticeAPIView.as_view(), name='update-notice'),  # For updating a specific notice


    # Keystroke  section
    
    path('display_keystrokes/', KeystrokeDataView.as_view(), name='keystroke_list'),


    #Monitoring section
    path('display_monitoring_data/', MonitoringEmployeeView.as_view(), name='display_monitoring_data'),



]




    
    
