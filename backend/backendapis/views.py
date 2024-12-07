from .serializers import OrganizationSerializer, OrganizationLoginSerializer, AppProductivitySerializers,ActivityProductivitySerializers
from .serializers import *
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from .models import Location, Organization, AppProductivity,Employee,ActivityProductivity
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
from .serializers import OrganizationLoginSerializer, AppProductivitySerializers
from django.utils import timezone



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
            refresh.payload['organization_id'] = organization.id  # Add the organization_id to the token


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



#AppProductivity Section
class GetAppProductivityAPIView(APIView):
    permission_classes = [AllowAny]
    
    def initial(self, request, *args, **kwargs):
        """
        This method is executed before the actual view logic (such as get()).
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

    def get(self, request, *args, **kwargs):
        """
        Retrieve and display the data related to the organization_id from the token.
        """
        # Get the Organization from the token's organization_id
        try:
            organization = Organization.objects.get(id=self.organization_id)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve all the productivity records associated with the organization
        productivity_data = AppProductivity.objects.filter(organization=organization)

        # Use the ProductivitySerializers to serialize the data
        serializer = AppProductivitySerializers(productivity_data, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)



class AddAppProductivityAPIView(APIView):
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
        serializer = AppProductivitySerializers(data=request.data)
        if serializer.is_valid():
            serializer.save(organization=organization)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class EditAppProductivityAPIView(APIView):
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
            data = AppProductivity.objects.get(id=data_id_from_url)

            # Ensure the data belongs to the organization from the token
            if data.organization_id != organization_id_from_request:
                return Response({"error": "You are not authorized to edit this data."}, status=status.HTTP_403_FORBIDDEN)

            # Perform the update with the new data from the request
            data.app_name = request.data.get('app_name', data.app_name)
            data.app_state = request.data.get('app_state', data.app_state)
            data.save()

            return Response({"message": "Data updated successfully."}, status=status.HTTP_200_OK)

        except AppProductivity.DoesNotExist:
            return Response({"error": "Data not found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)




class DeleteAppProductivityAPIView(APIView):
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
            data = AppProductivity.objects.get(id=data_id_from_url)
            
            # Check if the organization_id from the token matches the organization_id of the data
            if data.organization.id != self.organization_id:
                return Response({"error": "Organization ID mismatch."}, status=status.HTTP_403_FORBIDDEN)
            
            # Proceed to delete the data
            data.delete()

            return Response({"message": "Data deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        
        except AppProductivity.DoesNotExist:
            return Response({"error": "Data not found."}, status=status.HTTP_404_NOT_FOUND)



#Activity Productivity section

class DisplayActivityProductivityAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Validate the token and extract the organization_id.
        """
        auth_header = get_authorization_header(request).decode('utf-8')
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token = auth_header.split(" ")[1]
            access_token = AccessToken(token)
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

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests to list activity productivity data for the organization.
        """
        organization_id_from_token = self.organization_id

        # Fetch employees belonging to the organization
        employees = Employee.objects.filter(o_id=organization_id_from_token)
        if not employees.exists():
            return Response({"error": "No employees found for the organization."}, status=status.HTTP_404_NOT_FOUND)

        # Fetch all activity productivity data for the employees
        activity_productivity_data = ActivityProductivity.objects.filter(employee__in=employees)

        # Serialize the data
        serializer = ActivityProductivitySerializers(activity_productivity_data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



class AddActivityProductivityAPIView(APIView):
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

            # Extract organization_id from token payload
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
        """
        Handles POST requests to add activity productivity data.
        """
        # Use the organization ID extracted from the token
        organization_id_from_token = self.organization_id

        # Ensure the employee exists in the specified organization
        employee_id = request.data.get('employee')
        if not employee_id:
            return Response({"error": "Employee ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            employee = Employee.objects.get(id=employee_id, o_id=organization_id_from_token)
        except Employee.DoesNotExist:
            return Response({"error": "Employee not found or does not belong to the organization."}, status=status.HTTP_404_NOT_FOUND)

        # Validate and save activity productivity data
        serializer = ActivityProductivitySerializers(data=request.data)
        if serializer.is_valid():
            # Save with the referenced employee
            serializer.save(employee=employee)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class EditActivityProductivityAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Validate the token and extract the organization_id.
        """
        auth_header = get_authorization_header(request).decode('utf-8')
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token = auth_header.split(" ")[1]
            access_token = AccessToken(token)
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

    def put(self, request, *args, **kwargs):
        """
        Handles PUT requests to edit an activity productivity record.
        """
        organization_id_from_token = self.organization_id

        # Get the productivity record ID
        productivity_id = kwargs.get('pk')
        if not productivity_id:
            return Response({"error": "Productivity record ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            productivity = ActivityProductivity.objects.get(id=productivity_id, employee__o_id=organization_id_from_token)
        except ActivityProductivity.DoesNotExist:
            return Response({"error": "Productivity record not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)

        # Validate and update the record
        serializer = ActivityProductivitySerializers(productivity, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class DeleteActivityProductivityAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Validate the token and extract the organization_id.
        """
        auth_header = get_authorization_header(request).decode('utf-8')
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token = auth_header.split(" ")[1]
            access_token = AccessToken(token)
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
        Handles DELETE requests to remove an activity productivity record.
        """
        organization_id_from_token = self.organization_id

        # Get the productivity record ID
        productivity_id = kwargs.get('pk')
        if not productivity_id:
            return Response({"error": "Productivity record ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            productivity = ActivityProductivity.objects.get(id=productivity_id, employee__o_id=organization_id_from_token)
        except ActivityProductivity.DoesNotExist:
            return Response({"error": "Productivity record not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)

        # Delete the record
        productivity.delete()
        return Response({"success": "Productivity record deleted successfully."}, status=status.HTTP_200_OK)




# OfflineData section

class StartOfflineDataAPIView(APIView):
    permission_classes = [AllowAny]
    
    def initial(self, request, *args, **kwargs):
        auth_header = get_authorization_header(request).decode('utf-8')
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token = auth_header.split(" ")[1]
            access_token = AccessToken(token)
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

    def post(self, request, *args, **kwargs):
        organization_id_from_token = self.organization_id

        employee_id = request.data.get('employee')
        if not employee_id:
            return Response({"error": "Employee ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            employee = Employee.objects.get(id=employee_id, o_id=organization_id_from_token)
        except Employee.DoesNotExist:
            return Response({"error": "Employee not found or does not belong to the organization."}, status=status.HTTP_404_NOT_FOUND)

        # Validate and save the new offline data
        serializer = OfflineDataSerializers(data=request.data)
        if serializer.is_valid():
            serializer.save(employee=employee)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EndOfflineDataAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        # Extract the organization ID from the token
        auth_header = get_authorization_header(request).decode('utf-8')
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = auth_header.split(" ")[1]
            access_token = AccessToken(token)
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

    def put(self, request, *args, **kwargs):
        # Ensure `organization_id` is properly set
        organization_id_from_token = self.organization_id

        # Extract offline data ID from request data
        offline_data_id = request.data.get('id')
        if not offline_data_id:
            return Response({"error": "Offline data ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the OfflineData instance
        try:
            offline_data = OfflineData.objects.get(id=offline_data_id, employee__o_id=organization_id_from_token)
        except OfflineData.DoesNotExist:
            return Response({"error": "Offline data record not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)

        # Debugging: Check current values
        print(f"Existing Offline Data: {offline_data.starting_approved_by}, {offline_data.ending_approved_by}")

        # Update the `ending_approved_by` and `end_time` fields
        ending_approved_by = request.data.get('ending_approved_by')

        # If `ending_approved_by` is not provided, use `starting_approved_by`
        if not ending_approved_by:
            print("No ending_approved_by provided. Using starting_approved_by instead.")
            offline_data.ending_approved_by = offline_data.starting_approved_by
        else:
            print(f"Provided ending_approved_by: {ending_approved_by}")
            offline_data.ending_approved_by = ending_approved_by

        offline_data.end_time = timezone.now()
        offline_data.save()

        # Debugging: Check values after update
        print(f"Updated Offline Data: {offline_data.starting_approved_by}, {offline_data.ending_approved_by}")

        return Response({"success": "Offline data updated successfully."}, status=status.HTTP_200_OK)
    



    from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from django.utils import timezone
from .models import OfflineData
from .serializers import OfflineDataSerializers
from datetime import datetime

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.authentication import get_authorization_header
from .models import OfflineData
from .serializers import OfflineDataSerializers
from rest_framework.pagination import PageNumberPagination
from django.utils import timezone
from datetime import datetime

# Pagination class
class OfflineDataPagination(PageNumberPagination):
    page_size = 6  # Display 6 records per page
    page_size_query_param = 'page_size'
    max_page_size = 100

class OfflineDataAPIView(APIView):
    pagination_class = OfflineDataPagination
    print("sdfsdfsdfsdf",pagination_class)

    def initial(self, request, *args, **kwargs):
        print("dddddddddddddddddddddddddddddddddd")
        """
        Override the initial method to extract and verify the token
        before processing the request.
        """
        auth_header = get_authorization_header(request).decode('utf-8')
        print("WWWWww",auth_header)
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Extract the token from the authorization header
            token = auth_header.split(" ")[1]
            print("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR",token)
            access_token = AccessToken(token)
            # Extract the organization_id from the token
            self.organization_id = access_token.get('organization_id')
            if not self.organization_id:
                return Response({"error": "Organization ID not found in token."}, status=status.HTTP_401_UNAUTHORIZED)
        except IndexError:
            return Response({"error": "Invalid token format. Please provide a valid 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"error": f"Token error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

        # Continue processing the request after successful token validation
        super().initial(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        """
        Get the offline data based on the filter date and apply pagination.
        """
        # Ensure `organization_id` is properly set after validation
        organization_id_from_token = self.organization_id

        # Get the date filter from query parameters (default to today's date)
        date_str = request.query_params.get('date', None)
        if date_str:
            # If a date is provided, parse it
            try:
                filter_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                return Response({"error": "Invalid date format. Use 'YYYY-MM-DD'."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Default to today's date if no date filter is provided
            filter_date = timezone.now().date()

        # Filter offline data by the date (today's data if no date is provided)
        offline_data = OfflineData.objects.filter(starting_time__date=filter_date)

        # Paginate the data
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(offline_data, request)
        if result_page is not None:
            # Return paginated response with serialized data
            return paginator.get_paginated_response(OfflineDataSerializers(result_page, many=True).data)

        # If pagination isn't needed, return all data
        return Response(OfflineDataSerializers(offline_data, many=True).data, status=status.HTTP_200_OK)





# #Notice section

# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework.permissions import AllowAny
# from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_204_NO_CONTENT
# from rest_framework_simplejwt.authentication import JWTAuthentication
# from rest_framework_simplejwt.tokens import AccessToken
# from .models import Notice, Organization
# from .serializers import NoticeSerializer
# from rest_framework import status  # Importing status here

# class NoticeAPIView(APIView):
#     permission_classes = [AllowAny]  # Adjust to the needed permission class

#     def initial(self, request, *args, **kwargs):
#         """
#         Override the initial method to extract and verify the token
#         before processing the request.
#         """
#         # Get the Authorization header
#         auth_header = get_authorization_header(request).decode('utf-8')

#         if not auth_header:
#             return Response({"error": "Authorization token is required."}, status=HTTP_400_BAD_REQUEST)

#         try:
#             # Extract token from "Bearer <token>"
#             token = auth_header.split(" ")[1]  # [1] contains the token part
            
#             # Decode and verify the token using Simple JWT AccessToken
#             access_token = AccessToken(token)
            
#             # Extract the organization_id from the token
#             self.organization_id = access_token.get('organization_id')
#             if not self.organization_id:
#                 return Response({"error": "Organization ID not found in token."}, status=HTTP_400_BAD_REQUEST)
        
#         except IndexError:
#             return Response({"error": "Invalid token format. Please provide a valid 'Bearer <token>'."}, status=HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({"error": f"Token decoding error: {str(e)}"}, status=HTTP_400_BAD_REQUEST)

#         # Continue with the parent class's initial() method
#         super().initial(request, *args, **kwargs)

#     def post(self, request, *args, **kwargs):
#          """ Create a new notice """
#          # Ensure the organization ID from token matches the request data
#          organization_id_from_data = request.data.get('organization', self.organization_id)
#          print("PPPPPPPPPPPPPPPPPPPPP",organization_id_from_data)
     
#          if not organization_id_from_data:
#              # Add the organization ID from the token to the request data
#              request.data['organization'] = self.organization_id
     
#          if str(self.organization_id) != str(organization_id_from_data):
#              return Response({"error": "Organization ID mismatch with token."}, status=HTTP_400_BAD_REQUEST)
     
#          # Check if the organization exists
#          try:
#              organization = Organization.objects.get(id=self.organization_id)
#          except Organization.DoesNotExist:
#              return Response({"error": "Organization not found."}, status=HTTP_404_NOT_FOUND)
     
#          # Proceed with creating the notice and associate it with the organization
#          serializer = NoticeSerializer(data=request.data)
#          if serializer.is_valid():
#              notice = serializer.save(organization=organization)  # Save the notice with the organization
#              return Response(serializer.data, status=HTTP_201_CREATED)
#          return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


#     def get(self, request, *args, **kwargs):
#         """ Get a list of all notices for the organization """
#         notices = Notice.objects.filter(organization_id=self.organization_id)  # Filter by organization_id
#         serializer = NoticeSerializer(notices, many=True)
#         return Response(serializer.data, status=HTTP_200_OK)

#     def put(self, request, *args, **kwargs):
#         """ Update an existing notice """
#         try:
#             notice = Notice.objects.get(id=kwargs['id'], organization_id=self.organization_id)
#         except Notice.DoesNotExist:
#             return Response({'error': 'Notice not found'}, status=HTTP_404_NOT_FOUND)

#         serializer = NoticeSerializer(notice, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=HTTP_200_OK)
#         return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

#     def delete(self, request, *args, **kwargs):
#         """ Delete a notice """
#         try:
#             notice = Notice.objects.get(id=kwargs['id'], organization_id=self.organization_id)
#         except Notice.DoesNotExist:
#             return Response({'error': 'Notice not found'}, status=HTTP_404_NOT_FOUND)

#         notice.delete()
#         return Response(status=HTTP_204_NO_CONTENT)

