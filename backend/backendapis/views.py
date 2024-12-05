from .serializers import OrganizationSerializer
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from .models import Location
import random
import math
from rest_framework.permissions import AllowAny

@api_view(['POST', 'GET'])
@permission_classes([AllowAny])
def Org_register(request):
    if request.method == 'GET':
        locations = Location.objects.values('country_id', 'country_name').distinct()
        return JsonResponse({'locations': list(locations)}, status=200)

    if request.method == 'POST':
        data = request.data
        serializer = OrganizationSerializer(data=data)
        
        if serializer.is_valid():
            o_name = data.get('o_name')
            o_email = data.get('o_email')
            o_password = data.get('password1')
            o_website = data.get('o_website')
            contact_no = data.get('o_contact')
            o_address = data.get('o_address')
            o_country = data.get('o_country')
            o_state = data.get('o_state')
            o_city = data.get('o_city')
            o_pin_no = data.get('o_pin_no')

            otp = generateOTP()
            request.session['tempOTP'] = otp
            subject = 'Focult - OTP Verification'
            message = f"Hi {o_name}, thank you for registering in Focult. Your OTP for verification is {otp}."
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [o_email]
            send_mail(subject, message, email_from, recipient_list)

            return JsonResponse({'success': 'OTP sent successfully. Please verify.'}, status=200)
        else:
            return JsonResponse({'error': serializer.errors}, status=400)

    return JsonResponse({'error': 'Invalid HTTP method.'}, status=405)

def generateOTP():
    digits = "0123456789"
    OTP = ""
    for i in range(5):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP
