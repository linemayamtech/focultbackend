from .serializers import OrganizationSerializer, OrganizationLoginSerializer, ProductivitySerializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from .models import Location, Organization, Productivity
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.authentication import get_authorization_header
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from .serializers import OrganizationLoginSerializer, ProductivitySerializers



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

            
            # Save OTP in cache with a timeout of 30 seconds
            cache.set(f"otp_{o_email}", otp, timeout=30)  # Key is based on email
            
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

            return JsonResponse({'success': 'OTP sent successfully. Please verify.'}, status=200)
        else:
            return JsonResponse({'error': serializer.errors}, status=400)

    return JsonResponse({'error': 'Invalid HTTP method.'}, status=405)



def generateOTP():
    import random  # Ensure import for random
    digits = "0123456789"
    OTP = "".join(random.choice(digits) for _ in range(5))
    return OTP

@api_view(['POST'])
@permission_classes([AllowAny])
def resend_otp(request):
    # Check if user data exists in the session
    user_data = request.session.get('user_data')

    if not user_data:
        return Response({"message": "Session expired. Please fill out the form again."}, status=400)

    o_name = user_data.get('o_name')
    o_email = user_data.get('o_email')

    # Generate a new OTP
    otp = generateOTP()
    
    # Save the new OTP in the cache with a 30-second timeout
    cache.set(f"otp_{o_email}", otp, timeout=30)

    # Send the OTP to the user's email
    subject = 'Focult - Resend OTP Verification'
    message = f"Hi {o_name}, here is your new OTP for verification: {otp}."
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [o_email]
    send_mail(subject, message, email_from, recipient_list)

    return Response({"message": "New OTP sent successfully. Please check your email."}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    # Get the user data from the session
    user_data = request.session.get('user_data')

    if not user_data:
        return Response({"message": "No user data found in session."}, status=400)

    # Retrieve the OTP from the request data
    otp = request.data.get('otp')
    o_email = user_data.get('o_email')

    # Get the OTP from the cache
    stored_otp = cache.get(f"otp_{o_email}")

    if not stored_otp:
        return Response({"message": "OTP has expired. Please request a new one."}, status=400)

    # Check if the OTP matches
    if otp == stored_otp:
        # Encrypt the password using make_password before saving
        user_data['o_password'] = make_password(user_data['o_password'])

        try:
            # Create the user directly in the database
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
                o_password=user_data.get('o_password'),
            )

            # Clear session data and cache after successful verification
            cache.delete(f"otp_{o_email}")
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
        # Deserialize the login data
        serializer = OrganizationLoginSerializer(data=request.data)

        # Check if the serializer is valid
        if serializer.is_valid():
            # Extract the organization from the validated data
            organization = serializer.validated_data['organization']

            # Generate a refresh token for the organization
            refresh = RefreshToken.for_user(organization)

            access_token = str(refresh.access_token)

            # Return the response with the generated access token
            return Response({
                "message": "Login successful",
                "access_token": access_token,
                "organization_id": organization.id,
                "organization_name": organization.o_name,
            }, status=200)

        # If the serializer is not valid, return the errors
        return Response(serializer.errors, status=400)



#Productivity Section


class AddProductivityAPIView(APIView):
    permission_classes = [AllowAny]
    
    def initial(self, request, *args, **kwargs):
        """
        This method is executed before the actual view logic (such as post()).
        It's a good place to validate the token.
        """
        # Get the Authorization header
        auth_header = get_authorization_header(request).decode('utf-8')
        
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Extract token from "Bearer <token>"
            token = auth_header.split(" ")[1]  # [1] contains the token part
            
            # Verify and decode the token
            access_token = AccessToken(token)
            
            # Optionally, you can print or check claims here for debugging
            print(f"Decoded token claims: {access_token.payload}")

            # Extract information, e.g., organization_id
            self.organization_id = access_token.get('organization_id')
            
            if not self.organization_id:
                return Response({"error": "Organization ID not found in token."}, status=status.HTTP_401_UNAUTHORIZED)
        
        except IndexError:
            return Response({"error": "Invalid token format. Please provide a valid 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"error": f"Token error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Call the parent class's initial() method to continue the request processing
        super().initial(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        # After token verification, the request enters the post method

        # Make sure the organization ID is provided in the request data
        organization_id_from_data = request.data.get('organization')
        
        if not organization_id_from_data:
            return Response({"error": "Organization ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if str(self.organization_id) != str(organization_id_from_data):
            return Response({"error": "Organization ID mismatch with token."}, status=status.HTTP_400_BAD_REQUEST)

        # Continue with your organization and productivity logic
        try:
            organization = Organization.objects.get(id=self.organization_id)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)

        # Continue with serializer logic to save organization data
        serializer = ProductivitySerializers(data=request.data)
        if serializer.is_valid():
            serializer.save(organization=organization)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class EditProductivityAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Token validation and data ID extraction happens here.
        """
        auth_header = get_authorization_header(request).decode('utf-8')

        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Extract token from "Bearer <token>"
            token = auth_header.split(" ")[1]  # [1] contains the token part
            access_token = AccessToken(token)

            # Extract organization_id from the token (if needed)
            self.organization_id = access_token.get('organization_id')

            if not self.organization_id:
                return Response({"error": "Organization ID not found in token."}, status=status.HTTP_401_UNAUTHORIZED)

        except IndexError:
            return Response({"error": "Invalid token format. Please provide a valid 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"error": f"Token error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

        super().initial(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        """
        Handle data editing (based on data ID)
        """
        # If token is invalid, `initial` method would already have returned a response,
        # so the code execution should never reach here if validation failed.

        data_id_from_url = kwargs.get('data_id')  # Get the data ID from the URL
        organization_id_from_request = self.organization_id  # Organization ID from the token

        try:
            # Retrieve the data item by the ID passed in the URL
            data = Productivity.objects.get(id=data_id_from_url)

            # Ensure the data belongs to the organization from the token
            if data.organization_id != organization_id_from_request:
                return Response({"error": "You are not authorized to edit this data."}, status=status.HTTP_403_FORBIDDEN)

            # Perform the update with the new data from the request
            data.app_name = request.data.get('app_name', data.app_name)
            data.app_state = request.data.get('app_state', data.app_state)
            data.save()

            return Response({"message": "Data updated successfully."}, status=status.HTTP_200_OK)

        except Productivity.DoesNotExist:
            return Response({"error": "Data not found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)




class DeleteProductivityAPIView(APIView):
    permission_classes = [AllowAny]
    
    def initial(self, request, *args, **kwargs):
        """
        Token validation and data ID extraction happens here.
        """
        auth_header = get_authorization_header(request).decode('utf-8')
        
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Extract token from "Bearer <token>"
            token = auth_header.split(" ")[1]  # [1] contains the token part
            access_token = AccessToken(token)
            
            # Extract organization_id from the token (if needed)
            self.organization_id = access_token.get('organization_id')
            
            if not self.organization_id:
                return Response({"error": "Organization ID not found in token."}, status=status.HTTP_401_UNAUTHORIZED)
        
        except IndexError:
            return Response({"error": "Invalid token format. Please provide a valid 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"error": f"Token error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        
        super().initial(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        """
        Handle data deletion (based on data ID and organization ID)
        """
        data_id_from_url = kwargs.get('data_id')  # Get the data ID from the URL
        
        try:
            # Retrieve the data item by the ID passed in the URL
            data = Productivity.objects.get(id=data_id_from_url)
            
            # Check if the organization_id from the token matches the organization_id of the data
            if data.organization.id != self.organization_id:
                return Response({"error": "Organization ID mismatch."}, status=status.HTTP_403_FORBIDDEN)
            
            # Proceed to delete the data
            data.delete()

            return Response({"message": "Data deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        
        except Productivity.DoesNotExist:
            return Response({"error": "Data not found."}, status=status.HTTP_404_NOT_FOUND)











