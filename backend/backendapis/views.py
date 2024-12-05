from .serializers import OrganizationSerializer,OrganizationLoginSerializer
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from .models import Location
import random
import math
from rest_framework.permissions import AllowAny
from .models import *
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
from .models import Organization

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
            request.session['user_data'] = {
                'o_name': o_name,
                'o_email': o_email,
                'o_website': o_website,
                'o_contact': contact_no,
                'o_address': o_address,
                'o_country': o_country,
                'o_state': o_state,
                'o_city': o_city,
                'o_pin_no': o_pin_no,
                'o_password': o_password,

            }

            subject = 'Focult - OTP Verification'
            message = f"Hi {o_name}, thank you for registering in Focult. Your OTP for verification is {otp}."
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [o_email]
            send_mail(subject, message, email_from, recipient_list)

            return JsonResponse({'success': 'OTP sent successfully. Please verify.', 'redirect_url': '/api/verify_otp/'}, status=200)
        else:
            return JsonResponse({'error': serializer.errors}, status=400)

    return JsonResponse({'error': 'Invalid HTTP method.'}, status=405)


def generateOTP():
    digits = "0123456789"
    OTP = ""
    for i in range(5):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    # Get the user data from the session
    user_data = request.session.get('user_data')

    if not user_data:
        return Response({"message": "No user data found in session."}, status=400)

    # Retrieve the OTP from the request data
    otp = request.data.get('otp')
    stored_otp = request.session.get('tempOTP')

    # Check if the OTP matches
    if otp == stored_otp:
        # OTP is valid, now we need to remove the password from user_data
        # (if the password is not part of the Organization model)
        if 'password' in user_data:
            del user_data['password']  # Remove the password field from user_data

        # Encrypt the password using make_password before saving
        if 'o_password' in user_data:
            user_data['o_password'] = make_password(user_data['o_password'])  # Hash the password

        try:
            # Create the user directly in the database (now with hashed password)
            new_user = Organization.objects.create(
                o_name=user_data.get('o_name'),
                o_email=user_data.get('o_email'),
                o_website=user_data.get('o_website'),
                o_contact=user_data.get('o_contact'),
                o_address=user_data.get('o_address'),
                o_country=user_data.get('o_country'),
                o_state=user_data.get('o_state'),
                o_city=user_data.get('o_city'),
                o_pin_no=user_data.get('o_pin_no'),
                o_password=user_data.get('o_password'),  # Save the hashed password
            )

            # Clear session data after successful verification
            del request.session['tempOTP']
            del request.session['user_data']

            return Response({"message": "Registered successfully!", "user_id": new_user.id}, status=200)

        except Exception as e:
            return Response({"message": f"Error occurred while creating the user: {str(e)}"}, status=500)
    else:
        return Response({"message": "OTP is invalid."}, status=400)



@api_view(['POST'])
@permission_classes([AllowAny])
def login_organization(request):
    if request.method == 'POST':
        
        serializer = OrganizationLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            # Print the validated data after serializer validation
            print("Validated Data: ", serializer.validated_data)  # This will show the data after validation
            
            organization = serializer.validated_data['organization']
            
            # Generate JWT token for the user (organization)
            refresh = RefreshToken.for_user(organization)
            access_token = str(refresh.access_token)
            
            return Response({
                "message": "Login successful",
                "access_token": access_token,
                "organization_id": organization.id,
                "organization_name": organization.o_name,
            }, status=200)
        
        # Print errors if validation fails
        print("Validation Errors: ", serializer.errors)
        
        return Response(serializer.errors, status=400)

