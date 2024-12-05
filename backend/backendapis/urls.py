from django.urls import path
from backendapis.views import Org_register  

urlpatterns = [
    path('register/', Org_register),
]
