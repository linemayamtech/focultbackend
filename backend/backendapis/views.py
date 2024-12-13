from .serializers import *
from rest_framework.decorators import api_view, permission_classes
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from .models import *
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.authentication import get_authorization_header
from rest_framework.decorators import api_view, permission_classes
from .serializers import OrganizationLoginSerializer, AppProductivitySerializers
from django.db.models import Q
from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_204_NO_CONTENT
from .models import Notice, Organization
from .serializers import NoticeSerializer
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.authentication import get_authorization_header
from .models import OfflineData
from .serializers import OfflineDataSerializers
from rest_framework.pagination import PageNumberPagination
from datetime import datetime
from django.utils.timezone import now
from rest_framework.authentication import get_authorization_header
from django.conf import settings
from datetime import datetime
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.authentication import get_authorization_header
from django.utils import timezone
from rest_framework.views import APIView
from datetime import timedelta
from django.db.models import Max, Min
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from datetime import datetime, timedelta
from django.db.models import Min, Max
from django.utils.timezone import make_aware
from pytz import timezone
import threading
from django.core.mail import send_mail
from django.db.models import DateField
from django.db.models.functions import Cast
from django.utils import timezone
from datetime import datetime, timedelta
import logging
from collections import defaultdict
from django.db.models import Sum, F, Value
from django.db.models.functions import Cast, Coalesce
from datetime import datetime
import pytz
from django.db.models import Sum, F
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from datetime import datetime, timedelta
from rest_framework.exceptions import AuthenticationFailed



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

class Pagination_AppProductivity(PageNumberPagination):
    page_size = 10  # Default page size
    page_size_query_param = 'page_size'  # Allows client to specify page size
    max_page_size = 100  # Maximum page size limit

class AppProductivityAPIView(APIView):
    permission_classes = [AllowAny]
    
    def initial(self, request, *args, **kwargs):
        """
        Validates the token and extracts the organization_id.
        """
        auth_header = get_authorization_header(request).decode('utf-8')
        
        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Extract token from "Bearer <token>"
            token = auth_header.split(" ")[1]
            access_token = AccessToken(token)
            
            # Extract organization_id
            self.organization_id = access_token.get('organization_id')
            
            if not self.organization_id:
                return Response({"error": "Organization ID not found in token."}, status=status.HTTP_401_UNAUTHORIZED)
        
        except IndexError:
            return Response({"error": "Invalid token format. Please provide a valid 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)
        
        super().initial(request, *args, **kwargs)
    
    def get(self, request, *args, **kwargs):
        """
        Retrieve productivity data for the authenticated organization.
        """
        try:
            organization = Organization.objects.get(id=self.organization_id)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)
        
        # Fetch productivity data for the organization
        app_productivity_data = AppProductivity.objects.filter(department__o_id=organization)

        
        paginator = Pagination_AppProductivity()
        result_page = paginator.paginate_queryset(app_productivity_data, request)
        serializer = AppProductivitySerializers(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)
     
    
    def post(self, request, *args, **kwargs):
        """
        Add productivity data for the authenticated organization via department.
        """
        try:
            # Get the department object from the request data
            department_id = request.data.get('department')
            department = Departments.objects.get(id=department_id)
    
            # Retrieve the organization from the department
            organization = department.o_id
        except Departments.DoesNotExist:
            return Response({"error": "Department not found."}, status=status.HTTP_404_NOT_FOUND)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)
    
        # Check for duplicate app name in the same department
        app_name = request.data.get('app_name')
        if AppProductivity.objects.filter(department=department, app_name=app_name).exists():
            return Response({"error": "App name already exists in this department."}, status=status.HTTP_400_BAD_REQUEST)
    
        # Pass the department, not the organization, to the serializer
        serializer = AppProductivitySerializers(data=request.data)
        
        if serializer.is_valid():
            serializer.save(department=department)  # Save with the correct field
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    
    def patch(self, request, *args, **kwargs):
        """
        Edit productivity data by its ID.
        """
        data_id = kwargs.get('id')
        
        try:
            data = AppProductivity.objects.get(id=data_id)
    
            # Ensure the data belongs to the authenticated organization
            if data.department.o_id.id != self.organization_id:
                return Response({"error": "You are not authorized to edit this data."}, status=status.HTTP_403_FORBIDDEN)
    
            # Check for duplicate app name in the same department, excluding the current record
            new_app_name = request.data.get('app_name', data.app_name)
            if (
                new_app_name != data.app_name and 
                AppProductivity.objects.filter(department=data.department, app_name=new_app_name).exclude(id=data_id).exists()
            ):
                return Response({"error": "App name already exists in this department."}, status=status.HTTP_400_BAD_REQUEST)
    
            # Update fields
            data.app_name = new_app_name
            data.app_state = request.data.get('app_state', data.app_state)
            data.save()
            
            return Response({"message": "Data updated successfully."}, status=status.HTTP_200_OK)
        
        except AppProductivity.DoesNotExist:
            return Response({"error": "Data not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
    
    
    def delete(self, request, *args, **kwargs):
        """
        Delete productivity data by its ID.
        """
        data_id = kwargs.get('id')
        
        try:
            data = AppProductivity.objects.get(id=data_id)
            
            # Ensure the data belongs to the authenticated organization
            if data.department.o_id.id != self.organization_id:
                return Response({"error": "You are not authorized to delete this data."}, status=status.HTTP_403_FORBIDDEN)
            
            data.delete()
            return Response({"message": "Data deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        
        except AppProductivity.DoesNotExist:
            return Response({"error": "Data not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)


#Activity Productivity section




class Pagination_activityProductivity(PageNumberPagination):
    page_size = 10  # Default page size
    page_size_query_param = 'page_size'  # Allows client to specify page size
    max_page_size = 100  # Maximum page size limit

class ActivityProductivityAPIView(APIView):
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
        Display the list of activity productivity data for the organization.
        """
        search_query = request.query_params.get('search', '').strip()
        departments = Departments.objects.filter(o_id=self.organization_id)
        
        if not departments.exists():
            return Response({"error": "No departments found for the organization."}, status=status.HTTP_404_NOT_FOUND)
        
        activity_productivity_data = ActivityProductivity.objects.filter(department__in=departments)
        
        if search_query:
            if search_query.isdigit():
                activity_productivity_data = activity_productivity_data.filter(
                    Q(no_of_key_press__contains=search_query) |
                    Q(no_of_mouse_press__contains=search_query) |
                    Q(no_of_mouse_scroll__contains=search_query)
                )
            else:
                activity_productivity_data = activity_productivity_data.filter(
                    department__department_name__icontains=search_query
                )
        
        activity_productivity_data = activity_productivity_data.order_by('department__department_name')
        paginator = Pagination_activityProductivity()
        result_page = paginator.paginate_queryset(activity_productivity_data, request)
        serializer = ActivityProductivitySerializers(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Add a new activity productivity record for the organization.
        """
        department_id = request.data.get('department')
        if not department_id:
            return Response({"error": "Department ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            department = Departments.objects.get(id=department_id, o_id=self.organization_id)
        except Departments.DoesNotExist:
            return Response({"error": "Department not found or does not belong to the organization."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = ActivityProductivitySerializers(data=request.data)
        if serializer.is_valid():
            serializer.save(department=department)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def patch(self, request, *args, **kwargs):
        """
        Partially update an existing activity productivity record.
        """
        productivity_id = kwargs.get('pk')
        if not productivity_id:
            return Response({"error": "Productivity record ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            productivity = ActivityProductivity.objects.get(id=productivity_id, department__o_id=self.organization_id)
        except ActivityProductivity.DoesNotExist:
            return Response({"error": "Productivity record not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)
        
        # Partial update with partial=True
        serializer = ActivityProductivitySerializers(productivity, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    def delete(self, request, *args, **kwargs):
        """
        Delete an existing activity productivity record.
        """
        productivity_id = kwargs.get('pk')
        if not productivity_id:
            return Response({"error": "Productivity record ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            productivity = ActivityProductivity.objects.get(id=productivity_id, department__o_id=self.organization_id)
        except ActivityProductivity.DoesNotExist:
            return Response({"error": "Productivity record not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)
        
        productivity.delete()
        return Response({"success": "Productivity record deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


# OfflineData section


# Pagination class
class OfflineDataPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


class OfflineDataAPIView(APIView):
    permission_classes = [AllowAny]
    pagination_class = OfflineDataPagination

    def initial(self, request, *args, **kwargs):
        """
        Extract and verify the token to get the organization_id.
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
            return Response({"error": "Invalid token format. Use 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

        super().initial(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        """
        Display offline data for the logged-in organization, filtered by date or date range.
        """
        organization_id = self.organization_id

        # Get date filters
        start_date_str = request.query_params.get('start_date', None)
        end_date_str = request.query_params.get('end_date', None)

        try:
            start_date = datetime.strptime(start_date_str.strip(), "%Y-%m-%d").date() if start_date_str else None
            end_date = datetime.strptime(end_date_str.strip(), "%Y-%m-%d").date() if end_date_str else None
        except ValueError:
            return Response({"error": "Invalid date format. Use 'YYYY-MM-DD'."}, status=status.HTTP_400_BAD_REQUEST)

        # Filter data
        if start_date and end_date:
            offline_data_queryset = OfflineData.objects.filter(
                employee__o_id=organization_id,
                starting_time__date__range=(start_date, end_date)
            )
        elif start_date:
            offline_data_queryset = OfflineData.objects.filter(
                employee__o_id=organization_id,
                starting_time__date=start_date
            )
        elif end_date:
            offline_data_queryset = OfflineData.objects.filter(
                employee__o_id=organization_id,
                starting_time__date=end_date
            )
        else:
            filter_date = timezone.now().date()
            offline_data_queryset = OfflineData.objects.filter(
                employee__o_id=organization_id,
                starting_time__date=filter_date
            )

        # Paginate and serialize
        paginator = self.pagination_class()
        paginated_data = paginator.paginate_queryset(offline_data_queryset, request)
        serialized_data = OfflineDataSerializers(paginated_data, many=True)

        return paginator.get_paginated_response(serialized_data.data)

    def post(self, request, *args, **kwargs):
        """
        Add new offline data.
        """
        organization_id = self.organization_id
        employee_id = request.data.get('employee')

        if not employee_id:
            return Response({"error": "Employee ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            employee = Employee.objects.get(id=employee_id, o_id=organization_id)
        except Employee.DoesNotExist:
            return Response({"error": "Employee not found or does not belong to the organization."}, status=status.HTTP_404_NOT_FOUND)

        serializer = OfflineDataSerializers(data=request.data)
        if serializer.is_valid():
            serializer.save(employee=employee)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ManageOfflineDataAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Validate and extract organization_id from token.
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
            return Response({"error": "Invalid token format. Use 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

        super().initial(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        """
        Partially update an existing offline data record.
        """
        organization_id = self.organization_id
        offline_data_id = kwargs.get('id')
        
        try:
            offline_data = OfflineData.objects.get(id=offline_data_id, employee__o_id=organization_id)
        except OfflineData.DoesNotExist:
            return Response({"error": "Offline data not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)
        
        # Check if 'ending_approved_by' is null and set it to the same value as 'starting_approved_by'
        if not request.data.get('ending_approved_by') and offline_data.starting_approved_by:
            request.data['ending_approved_by'] = offline_data.starting_approved_by
        
        # Proceed with the serializer to validate and save the data
        serializer = OfflineDataSerializers(offline_data, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    

    def delete(self, request, *args, **kwargs):
        """
        Delete an offline data record.
        """
        organization_id = self.organization_id
        offline_data_id = kwargs.get('id')

        try:
            offline_data = OfflineData.objects.get(id=offline_data_id, employee__o_id=organization_id)
        except OfflineData.DoesNotExist:
            return Response({"error": "Offline data not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)

        offline_data.delete()
        return Response({"success": "Offline data deleted successfully."}, status=status.HTTP_200_OK)


#Notice section

def send_email_thread(employee, subject, personalized_message, from_email):
        send_mail(
            subject,
            personalized_message,
            from_email,  # Display sender as: Organization Name <otp@focult.com>
            [employee.e_email],
            fail_silently=False,
        )
    

class NoticePagination(PageNumberPagination):
    page_size = 10   # Number of notices per page
    page_size_query_param = 'page_size'  # Optional: Allow the client to specify the page size
    max_page_size = 100  # Max limit on page size

class NoticeAPIView(APIView):
    permission_classes = [AllowAny]  # Adjust to the needed permission class

    def initial(self, request, *args, **kwargs):
        """
        Override the initial method to extract and verify the token
        before processing the request.
        """
        # Get the Authorization header
        auth_header = get_authorization_header(request).decode('utf-8')

        if not auth_header:
            return Response({"error": "Authorization token is required."}, status=HTTP_400_BAD_REQUEST)

        try:
            # Extract token from "Bearer <token>"
            token = auth_header.split(" ")[1]  # [1] contains the token part
            
            # Decode and verify the token using Simple JWT AccessToken
            access_token = AccessToken(token)
            
            # Extract the organization_id from the token
            self.organization_id = access_token.get('organization_id')
            if not self.organization_id:
                return Response({"error": "Organization ID not found in token."}, status=HTTP_400_BAD_REQUEST)
        
        except IndexError:
            return Response({"error": "Invalid token format. Please provide a valid 'Bearer <token>'."}, status=HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=HTTP_400_BAD_REQUEST)

        # Continue with the parent class's initial() method
        super().initial(request, *args, **kwargs)

    

    def post(self, request, *args, **kwargs):
        """Create a new notice"""
        organization_id_from_token = self.organization_id
    
        if not organization_id_from_token:
            return Response({"error": "Organization ID not found in token."}, status=status.HTTP_400_BAD_REQUEST)
    
        # Check if the organization exists
        try:
            organization = Organization.objects.get(id=organization_id_from_token)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)
    
        # Add the organization instance to the request data
        data = request.data.copy()
        data['organization'] = organization.id
    
        # Serialize and validate the data
        serializer = NoticeSerializer(data=data)
        if serializer.is_valid():
            # Save the notice and associate it with the organization
            notice = serializer.save(organization=organization)
    
            # Get all employees in the organization
            employees = Employee.objects.filter(o_id=organization)
    
            # Prepare the email content
            subject = notice.title
            message_template = notice.description  # The original message template
            
            # Fixed sender email address
            sender_email = 'otp@focult.com'
            # Set the sender's display name as the organization name
            from_email = f"{organization.o_name} <{sender_email}>"
    
            # Send email to all employees in parallel using threads
            threads = []
            for employee in employees:
                # Create a personalized message by inserting the employee's name
                personalized_message = f"Dear {employee.e_name},\n\n {subject} \n\n  {message_template}"
    
                # Create and start a new thread for each email to be sent in parallel
                thread = threading.Thread(target=send_email_thread, args=(employee, subject, personalized_message, from_email))
                threads.append(thread)
                thread.start()
    
            # Wait for all threads to finish
            for thread in threads:
                thread.join()
    
            return Response(serializer.data, status=status.HTTP_201_CREATED)
    
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    def get(self, request, *args, **kwargs):
        """ Get a paginated list of all notices for the organization """
        # Fetch the notices filtered by organization ID and order by 'added_time'
        notices = Notice.objects.filter(organization_id=self.organization_id).order_by('-added_time')
        
        # Apply pagination
        paginator = NoticePagination()  # NoticePagination is your custom pagination class
        paginated_notices = paginator.paginate_queryset(notices, request)  # Apply pagination on the queryset
        
        # Serialize the paginated data
        serializer = NoticeSerializer(paginated_notices, many=True)
        
        # Return the paginated response
        return paginator.get_paginated_response(serializer.data)


    def patch(self, request, *args, **kwargs):
        """ Partially update an existing notice """
        try:
            notice = Notice.objects.get(id=kwargs['id'], organization_id=self.organization_id)
        except Notice.DoesNotExist:
            return Response({'error': 'Notice not found'}, status=HTTP_404_NOT_FOUND)
    
        # Use partial=True to allow partial updates
        serializer = NoticeSerializer(notice, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=HTTP_200_OK)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        """ Delete a notice """
        try:
            notice = Notice.objects.get(id=kwargs['id'], organization_id=self.organization_id)
        except Notice.DoesNotExist:
            return Response({'error': 'Notice not found'}, status=HTTP_404_NOT_FOUND)

        notice.delete()
        return Response({"message":"Deleted Succesfully"},status=HTTP_204_NO_CONTENT)



# Keystroke  section

class KeystrokePagination(PageNumberPagination):
    page_size = 10   # Number of notices per page
    page_size_query_param = 'page_size'  # Optional: Allow the client to specify the page size
    max_page_size = 100  # Max limit on page size

class KeystrokeDataView(APIView):
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
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

        super().initial(request, *args, **kwargs)

   
    def get_session_time(self, employee_keystrokes):
        """
        Calculate the total session time across multiple days.
        """
        # First, get the first and last entry timestamps across all keystrokes for the employee
        first_entry = employee_keystrokes.aggregate(Min('activity_timestamp'))['activity_timestamp__min']
        last_entry = employee_keystrokes.aggregate(Max('activity_timestamp'))['activity_timestamp__max']
        
        # If no entries exist, return zero session time
        if not first_entry or not last_entry:
            return timedelta()
    
        # Initialize total session time
        total_session_time = timedelta()
    
        # Iterate through each day's keystrokes and calculate session time for that day
        current_day_start = first_entry.replace(hour=0, minute=0, second=0, microsecond=0)  # Start of the first day
        current_day_end = current_day_start.replace(hour=23, minute=59, second=59, microsecond=999999)  # End of the first day
        
        while current_day_start <= last_entry:
            # Get the keystrokes for the current day
            daily_keystrokes = employee_keystrokes.filter(
                activity_timestamp__gte=current_day_start,
                activity_timestamp__lte=current_day_end
            )
            
            if daily_keystrokes.exists():
                first_entry_for_day = daily_keystrokes.aggregate(Min('activity_timestamp'))['activity_timestamp__min']
                last_entry_for_day = daily_keystrokes.aggregate(Max('activity_timestamp'))['activity_timestamp__max']
                
                # Calculate session time for the current day
                if first_entry_for_day and last_entry_for_day:
                    session_time_for_day = last_entry_for_day - first_entry_for_day
                    total_session_time += session_time_for_day
    
            # Move to the next day
            current_day_start += timedelta(days=1)
            current_day_end += timedelta(days=1)
    
        return total_session_time
    
    def get(self, request):
        """
        Retrieve keystroke data based on date filters.
        """
        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')
        
        try:
            # Determine the date range
            today = datetime.now().date()
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date() if start_date_str else today
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date() if end_date_str else start_date
            
            # Ensure end_date is not before start_date
            if end_date < start_date:
                return Response({"error": "End date cannot be before start date."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Fetch employees in the organization
            employees = Employee.objects.filter(o_id=self.organization_id)
            employee_ids = employees.values_list('id', flat=True)
            
            # Containers for results
            daily_avg_productivity = []
            response_data = []
    
            # Iterate over each day in the range
            current_date = start_date
            while current_date <= end_date:
                # Daily time range
                start_datetime = make_aware(datetime.combine(current_date, datetime.min.time()), timezone=pytz.UTC)
                end_datetime = make_aware(datetime.combine(current_date, datetime.max.time()), timezone=pytz.UTC)
    
                # Query keystrokes for the day
                keystrokes = Keystroke.objects.filter(
                    e_id__in=employee_ids,
                    activity_timestamp__range=(start_datetime, end_datetime)
                ).exclude(activity_timestamp__isnull=True)
    
                # Calculate daily average productivity
                daily_productivity = [
                    self.calculate_productivity(keystrokes.filter(e_id=employee))
                    for employee in employees if keystrokes.filter(e_id=employee).exists()
                ]
                avg_productivity = sum(daily_productivity) / len(daily_productivity) if daily_productivity else 0
    
                daily_avg_productivity.append({
                    "date": current_date.strftime("%Y-%m-%d"),
                    "average_productivity": round(avg_productivity, 2)
                })
    
                # Add employee-wise productivity
                for employee in employees:
                    employee_keystrokes = keystrokes.filter(e_id=employee)
                    if not employee_keystrokes.exists():
                        response_data.append({
                            "employee_name": employee.e_name,
                            "date": current_date.strftime("%Y-%m-%d"),
                            "session_time": "00:00:00",
                            "work_time": "00:00:00",
                            "idle_time": "00:00:00",
                            "activity": 0
                        })
                        continue
    
                    # Calculate session and productivity details
                    session_time = self.get_session_time(employee_keystrokes)
                    idle_minutes = employee_keystrokes.filter(
                        total_keys_pressed=0, total_mouse_clicks=0, total_mouse_movements=0
                    ).count()
                    idle_time = timedelta(minutes=idle_minutes)
                    work_time = max(session_time - idle_time, timedelta(0))
    
                    productivity = self.calculate_productivity(employee_keystrokes)
    
                    response_data.append({
                        "employee_name": employee.e_name,
                        "date": current_date.strftime("%Y-%m-%d"),
                        "session_time": self.format_time(session_time),
                        "work_time": self.format_time(work_time),
                        "idle_time": self.format_time(idle_time),
                        "activity": round(productivity, 2)
                    })
    
                # Move to the next day
                current_date += timedelta(days=1)
                # Paginate employee_productivity
                productivity_paginator = KeystrokePagination()
                paginated_productivity = productivity_paginator.paginate_queryset(response_data, request)
                # Paginate graph_daily_avg_productivity
                avg_productivity_paginator = KeystrokePagination()
                paginated_avg_productivity = avg_productivity_paginator.paginate_queryset(daily_avg_productivity, request)

            # Final response
            return Response({
                "employee_productivity": productivity_paginator.get_paginated_response(paginated_productivity).data,
                "graph_daily_avg_productivity": avg_productivity_paginator.get_paginated_response(paginated_avg_productivity).data
            })
    
        except Exception as e:
            # Log error for debugging
            logging.error(f"Error in get method: {str(e)}", exc_info=True)
            return Response({"error": "An unexpected error occurred. Please try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       
    def format_time(self, time_delta):
        """
        Formats a timedelta object into a string in the format 'HH:MM:SS'.
        """
        if isinstance(time_delta, timedelta):
            total_seconds = int(time_delta.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            return f"{hours:02}:{minutes:02}:{seconds:02}"
        else:
            return "00:00:00"
    
    

    def calculate_productivity(self, keystrokes):
       print("Starting productivity calculation...")
       
       # Cache thresholds for departments
       department_thresholds = {}
       default_thresholds = {"key_threshold": 40, "mouse_threshold": 40, "scroll_threshold": 40}
       print(f"Default thresholds: {default_thresholds}")
       
       # Query department-specific thresholds and store in a dictionary
       for activity_productivity in ActivityProductivity.objects.select_related('department').all():
           department_thresholds[activity_productivity.department] = {
               "key_threshold": activity_productivity.no_of_key_press,
               "mouse_threshold": activity_productivity.no_of_mouse_press,
               "scroll_threshold": activity_productivity.no_of_mouse_scroll,
           }
   
       # Initialize list to hold productivity values
       productivity_values = []
       print(f"Initialized productivity values: {productivity_values}")
   
       for keystroke in keystrokes:
           print(f"Processing keystroke for employee: {keystroke.e_id}")
           employee = keystroke.e_id  # Assuming keystrokes have e_id as a ForeignKey to Employee
           departments = Departments.objects.filter(employees=employee)  # Many-to-Many relationship
   
           # Check if departments exist
           if not departments.exists():
               print(f"Employee {employee.e_name} has no department, skipping.")
               continue  # Skip employees with no assigned departments
           
           # Use the first department's thresholds
           department = departments.first()
           thresholds = department_thresholds.get(department.id, default_thresholds)
   
           # Debugging: Print department thresholds
           print(f"Employee {employee.e_name} - Department {department.department_name}: {thresholds}")
   
           # Get the keystroke values
           total_keys = keystroke.total_keys_pressed
           total_clicks = keystroke.total_mouse_clicks
           total_movements = keystroke.total_mouse_movements
   
           # Debugging: Check keystroke values
           print(f"Keystrokes - Keys: {total_keys}, Clicks: {total_clicks}, Movements: {total_movements}")
   
           productivity = 0
           if (
               total_keys >= thresholds["key_threshold"]
               or total_clicks >= thresholds["mouse_threshold"]
               or total_movements >= thresholds["scroll_threshold"]
           ):
               productivity = 100
           else:
               if thresholds["key_threshold"] > 0:
                   productivity += (total_keys / thresholds["key_threshold"]) * 100
               if thresholds["mouse_threshold"] > 0:
                   productivity += (total_clicks / thresholds["mouse_threshold"]) * 100
               if thresholds["scroll_threshold"] > 0:
                   productivity += (total_movements / thresholds["scroll_threshold"]) * 100
   
               # Normalize productivity to a maximum of 100
               productivity = min(productivity, 100)
   
           # Append productivity for this record
           productivity_values.append(productivity)
   
       # Debugging: Print all calculated productivity values
       print(f"Calculated productivity values: {productivity_values}")
   
       # Calculate average productivity
       average_productivity = sum(productivity_values) / len(productivity_values) if productivity_values else 0
       print(f"Average productivity: {average_productivity}")
       
       return average_productivity


# Monitoring section 
from django.db.models import F
from django.db.models import Q
class MonitoringEmployeePagination(PageNumberPagination):
    page_size = 10   # Number of notices per page
    page_size_query_param = 'page_size'  # Optional: Allow the client to specify the page size
    max_page_size = 100  # Max limit on page size

class MonitoringEmployeeView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Extract and verify the token to get the organization_id.
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
            return Response({"error": "Invalid token format. Use 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

        super().initial(request, *args, **kwargs)


    def get(self, request, *args, **kwargs):
        """
        Display offline data for the logged-in organization, filtered by date or date range.
        Compare the data with the AppProductivity model to categorize app usage as productive, unproductive, or neutral.
        Calculate idle time and active hours for employees from the Keystroke model.
        """
        organization_id = self.organization_id
        monitoring_data = Monitoring.objects.filter(e_id__o_id=organization_id)
        
        # Get date filters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        
        try:
            start_date = datetime.strptime(start_date.strip(), "%Y-%m-%d").date() if start_date else None
            end_date = datetime.strptime(end_date.strip(), "%Y-%m-%d").date() if end_date else None
        except ValueError:
            return Response({"error": "Invalid date format. Use 'YYYY-MM-DD'."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Filter monitoring data
        monitoring_data = monitoring_data.annotate(m_log_date=Cast('m_log_ts', DateField()))
        
        if start_date and end_date:
            monitoring_data_queryset = monitoring_data.filter(
                m_log_date__range=(start_date, end_date)
            )
        elif start_date:
            monitoring_data_queryset = monitoring_data.filter(
                m_log_date__gte=start_date
            )
        elif end_date:
            monitoring_data_queryset = monitoring_data.filter(
                m_log_date__lte=end_date
            )
        else:
            filter_date = timezone.now().date()
            monitoring_data_queryset = monitoring_data.filter(
                m_log_date=filter_date
            )
        
        # Serialize the filtered data
        serializer = MonitoringSerializer(monitoring_data_queryset, many=True)
        
        # Additional processing for productivity states
        employee_app_usage = {}  # Dictionary to store employee aggregated data
        
        for record in monitoring_data_queryset:
            employee_id = record.e_id.id
            app_name = record.m_title
            
            # Safely handle total_time_seconds
            if record.m_total_time_seconds is not None:
                try:
                    time_parts = list(map(int, record.m_total_time_seconds.split(":")))
                    total_time_seconds = timedelta(
                        hours=time_parts[0], minutes=time_parts[1], seconds=time_parts[2]
                    ).total_seconds()
                except (ValueError, IndexError):
                    total_time_seconds = 0
            else:
                total_time_seconds = 0
            
            # Initialize employee data
            if employee_id not in employee_app_usage:
                employee_app_usage[employee_id] = {
                    'employee_name': record.e_id.e_name,
                    'productive_time': 0,
                    'unproductive_time': 0,
                    'neutral_time': 0,
                    'idle_time': 0,  # Initialize idle time
                    'active_hours': "0:00:00"  # Initialize active hours
                }
            
            # Check app productivity state
            employee = Employee.objects.get(id=record.e_id.id, o_id=organization_id)
            departments = Departments.objects.filter(employees=employee)
            
            app_productivity = AppProductivity.objects.filter(
                app_name=app_name, department__in=departments
            ).first()
            
            if app_productivity:
                app_state = app_productivity.app_state
            else:
                app_state = AppProductivity.NEUTRAL
            
            # Aggregate time spent on the app
            if app_state == AppProductivity.PRODUCTIVE:
                employee_app_usage[employee_id]['productive_time'] += total_time_seconds
            elif app_state == AppProductivity.UNPRODUCTIVE:
                employee_app_usage[employee_id]['unproductive_time'] += total_time_seconds
            elif app_state == AppProductivity.NEUTRAL:
                employee_app_usage[employee_id]['neutral_time'] += total_time_seconds
        
        # Calculate idle time and active hours for each employee
        for employee_id in employee_app_usage.keys():
            idle_time_seconds = 0
            
            # Fetch keystroke records for the employee
            keystroke_records = Keystroke.objects.filter(
                e_id__id=employee_id,
                e_id__o_id=organization_id,
                activity_timestamp__date__range=(start_date, end_date) if start_date and end_date else Q()
            )
            
            # Iterate through keystroke records to calculate idle time
            for record in keystroke_records:
                if (
                    record.total_keys_pressed == 0 or record.total_keys_pressed is None
                ) and (
                    record.total_mouse_clicks == 0 or record.total_mouse_clicks is None
                ) and (
                    record.total_mouse_movements == 0 or record.total_mouse_movements is None
                ):
                    idle_time_seconds += 60  # Assume 1 minute of idle time per record meeting the condition
            
            # Convert idle time from seconds to hours, minutes, seconds format
            hours, remainder = divmod(idle_time_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            idle_time = f"{hours}:{minutes:02}:{seconds:02}"
            employee_app_usage[employee_id]['idle_time'] = idle_time
            
            # Calculate active hours
            productive_seconds = employee_app_usage[employee_id]['productive_time']
            print("productive hours", productive_seconds)
            unproductive_seconds = employee_app_usage[employee_id]['unproductive_time']
            print("unproductive_seconds",unproductive_seconds)
            print("idle_seconds",idle_time_seconds)
            neutral_seconds = employee_app_usage[employee_id]['neutral_time']  # Include neutral_time

            active_seconds = productive_seconds + unproductive_seconds + neutral_seconds - idle_time_seconds
            
            print("active hours",active_seconds)
            
            if active_seconds < 0:
                active_seconds = 0  # Ensure active time is not negative
            
            # Convert active time to hours, minutes, seconds format
            hours, remainder = divmod(active_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            employee_app_usage[employee_id]['active_hours'] = f"{hours}:{minutes:02}:{seconds:02}"
        
        # Convert time from seconds to hours, minutes, seconds format for other fields
        for employee_id, usage_data in employee_app_usage.items():
            for key in ['productive_time', 'unproductive_time', 'neutral_time']:
                total_seconds = usage_data[key]
                hours, remainder = divmod(total_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                usage_data[key] = f"{hours}:{minutes:02}:{seconds:02}"
        
        # Return the aggregated employee data
        employee_app_usage_list = list(employee_app_usage.values())  # Convert dict to list for pagination
        paginator = MonitoringEmployeePagination()
        paginated_data = paginator.paginate_queryset(employee_app_usage_list, request)

        # Return paginated response
        return paginator.get_paginated_response(paginated_data) 
    




#Screenshot section
class Pagination_ScreenShotsMonitoring(PageNumberPagination):
    page_size = 10  # Default page size
    page_size_query_param = 'page_size'  # Allows client to specify page size
    max_page_size = 100  # Maximum page size limit    

class ScreenShotsMonitoringAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Validate the token and extract the organization_id.
        """
        auth_header = request.headers.get('Authorization', '')
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


    def get(self, request):
        """
        Retrieve screenshots based on date filters and include computer username.
        """
        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')
        employee_id = request.query_params.get('employee_id')  # Optional employee filter
        computer_id = request.query_params.get('computer_id')  # Optional computer filter
    
        # Debugging: Print the received query parameters
        print("Received start_date:", start_date_str)
        print("Received end_date:", end_date_str)
    
        # Calculate date range with time adjustment
        today = datetime.now().date()
        if start_date_str:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
        else:
            start_date = datetime.combine(today, datetime.min.time())
        
        if end_date_str:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)
        else:
            end_date = start_date + timedelta(days=1) - timedelta(seconds=1)
    
        # Debugging: Print the calculated date range
        print("Start date (with time):", start_date)
        print("End date (with time):", end_date)
    
        # Filter screenshots and annotate with computer username
        screenshots = ScreenShotsMonitoring.objects.filter(
            e_id__o_id=self.organization_id,
            ssm_log_ts__range=[start_date, end_date]
        ).annotate(
            computer_username=F('c_id__c_username')  # Assumes a reverse relation from Employee to Computer
        ).order_by('-ssm_log_ts')
        if employee_id:
             screenshots = screenshots.filter(e_id=employee_id)
    
        if computer_id:
            screenshots = screenshots.filter(c_id=computer_id)
    
        # Debugging: Print the queryset
        print("Screenshots QuerySet:", screenshots)
    
        # Apply pagination
        paginator = Pagination_ScreenShotsMonitoring()
        paginated_screenshots = paginator.paginate_queryset(screenshots, request)
    
        # Serialize the paginated data
        serializer = ScreenShotsMonitoringSerializer(paginated_screenshots, many=True)
    
        # Return the paginated response
        return paginator.get_paginated_response(serializer.data)
    
        
    
# webpage and applications section 


def parse_time_to_seconds(time_str):
    if not time_str or ":" not in time_str:
        return 0
    h, m, s = map(int, time_str.split(":"))
    return h * 3600 + m * 60 + s

       
class Pagination_Webpage_and_applications(PageNumberPagination):
    page_size = 10  # Default page size
    page_size_query_param = 'page_size'  # Allows client to specify page size
    max_page_size = 100  # Maximum page size limit    

class Webpage_and_applicationsAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Validate the token and extract the organization_id.
        Ensure the token is not expired.
        """
        auth_header = request.headers.get('Authorization', '')
        if not auth_header:
            raise AuthenticationFailed("Authorization token is required.")

        try:
            token = auth_header.split(" ")[1]
            access_token = AccessToken(token)
            self.organization_id = access_token.get('organization_id')

            if not self.organization_id:
                raise AuthenticationFailed("Organization ID not found in token.")

            # Check token expiration
            exp_timestamp = access_token.get('exp')
            if not exp_timestamp:
                raise AuthenticationFailed("Token expiration time not found.")

            current_timestamp = datetime.now(pytz.UTC).timestamp()
            if current_timestamp > exp_timestamp:
                raise AuthenticationFailed("Token has expired. Please log in again.")

        except IndexError:
            raise AuthenticationFailed("Invalid token format. Please provide a valid 'Bearer <token>'.")
        except TokenError as e:
            raise AuthenticationFailed(f"Token error: {str(e)}")
        except Exception as e:
            raise AuthenticationFailed(f"Token decoding error: {str(e)}")

        super().initial(request, *args, **kwargs)

    def get(self, request):
        """
        Retrieve data based on date filters, aggregated employee-wise and app-wise.
        Restrict data to the organization specified in the token.
        """
        # Ensure the `initial` method has set the organization_id
        organization_id = getattr(self, 'organization_id', None)
        if not organization_id:
            return Response({"error": "Unauthorized access."}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Get query parameters
        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')
        employee_id = request.query_params.get('employee_id')  # Optional employee filter
        computer_id = request.query_params.get('computer_id')  # Optional computer filter
        app_or_webpage_id = request.query_params.get('app_or_webpage_id')  # Optional app/webpage filter
        
        # Parse dates
        today = datetime.now().date()
        if start_date_str:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
        else:
            start_date = datetime.combine(today, datetime.min.time())
    
        if end_date_str:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)
        else:
            end_date = start_date + timedelta(days=1) - timedelta(seconds=1)
    
        # Filter Monitoring data by date range, organization, and optional filters
        monitoring_queryset = Monitoring.objects.filter(
            m_log_ts__range=(start_date, end_date),
            e_id__o_id=organization_id  # Restrict to the organization in the token
        )
    
        if employee_id:
            monitoring_queryset = monitoring_queryset.filter(e_id=employee_id)
    
        if computer_id:
            monitoring_queryset = monitoring_queryset.filter(e_id__computer__id=computer_id)
    
        if app_or_webpage_id:
            monitoring_queryset = monitoring_queryset.filter(
                m_title__in=AppProductivity.objects.filter(id=app_or_webpage_id).values_list('app_name', flat=True)
            )
    
        # Fetch data and calculate total duration in seconds
        response_data = []
        employee_data = monitoring_queryset.select_related('e_id').values(
            'e_id__e_name',  # Employee name
            'm_title',  # App/Webpage
            'm_url',  # URL
            'e_id__computer__c_username',  # Computer name
            'm_total_time_seconds',  # Include total time
            'm_log_ts'  # Include the log timestamp
        )
    
        # Get the total time for the employee across all apps/webpages
        total_employee_time_seconds = sum(
            parse_time_to_seconds(entry['m_total_time_seconds']) for entry in employee_data
        )
    
        # Graph response to aggregate app/webpage usage time
        graph_response = []
    
        # Calculate total time spent per app/webpage
        app_data = {}
        for entry in employee_data:
            app_name = entry['m_title']
            total_seconds = parse_time_to_seconds(entry['m_total_time_seconds'])
    
            if app_name not in app_data:
                app_data[app_name] = 0
            app_data[app_name] += total_seconds
    
        # Add aggregated app usage time to graph response
        for app_name, total_seconds in app_data.items():
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            formatted_duration = f"{hours}h {minutes}m {seconds}s"
    
            graph_response.append({
                'app_name': app_name,
                'used_time': formatted_duration
            })
    
        # Create employee-specific data
        for entry in employee_data:
            # Calculate total seconds for the current app/webpage for the current employee
            durations = monitoring_queryset.filter(
                e_id__e_name=entry['e_id__e_name'],
                m_title=entry['m_title']  # Filter by the app/webpage title
            ).values_list('m_total_time_seconds', flat=True)
    
            total_seconds = sum(parse_time_to_seconds(duration) for duration in durations)
    
            # Calculate percentage of time spent on this app/webpage
            percentage = (total_seconds / total_employee_time_seconds) * 100 if total_employee_time_seconds > 0 else 0
    
            # Convert total seconds to HH:MM:SS format
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            formatted_duration = f"{hours}h {minutes}m {seconds}s"
    
            # Convert m_log_ts to a readable datetime format
            log_datetime = datetime.strptime(entry['m_log_ts'], "%Y-%m-%d %H:%M:%S")  # Adjust format if needed
            formatted_log_ts = log_datetime.strftime("%Y-%m-%d %H:%M:%S")
    
            response_data.append({
                'employee_name': entry['e_id__e_name'],
                'computer_name': entry.get('e_id__computer__c_username', 'N/A'),
                'app_webpage': entry['m_title'],
                'process_url': entry['m_url'],
                'duration': formatted_duration,
                'percentage': f"{percentage:.2f}%",  # Add percentage to the response
                'log_timestamp': formatted_log_ts  # Add log timestamp to the response
            })
    
        # Paginate response
        paginator = Pagination_Webpage_and_applications()
        paginated_data = paginator.paginate_queryset(response_data, request)
        
        # Return both the paginated employee data and the aggregated app usage data (graph response)
        return Response({
            'employee_data': paginator.get_paginated_response(paginated_data).data,
            'graph_data': graph_response
        })
     



#Screen vdo monitoring section

class Pagination_ScreenVideoMonitoring(PageNumberPagination):
    page_size = 10  # Default page size
    page_size_query_param = 'page_size'  # Allows client to specify page size
    max_page_size = 100  # Maximum page size limit    

class ScreenVideoMonitoringAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Validate the token and extract the organization_id.
        """
        auth_header = request.headers.get('Authorization', '')
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


    def get(self, request):
        """
        Retrieve screenshots based on date filters and include computer username.
        """
        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')
        employee_id = request.query_params.get('employee_id')  # Optional employee filter
        computer_id = request.query_params.get('computer_id')  # Optional computer filter
    
        # Debugging: Print the received query parameters
        print("Received start_date:", start_date_str)
        print("Received end_date:", end_date_str)
    
        # Calculate date range with time adjustment
        today = datetime.now().date()
        if start_date_str:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
        else:
            start_date = datetime.combine(today, datetime.min.time())
        
        if end_date_str:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)
        else:
            end_date = start_date + timedelta(days=1) - timedelta(seconds=1)
    
        # Debugging: Print the calculated date range
        print("Start date (with time):", start_date)
        print("End date (with time):", end_date)
    
        # Filter screenvideo and annotate with computer username
        screen_videos = ScreenVideoMonitoring.objects.filter(
            e_id__o_id=self.organization_id,
            svm_log_ts__range=[start_date, end_date]
        ).annotate(
            computer_username=F('c_id__c_username')  
        ).order_by('-svm_log_ts')

        if employee_id:
             screen_videos = screen_videos.filter(e_id=employee_id)
    
        if computer_id:
            screen_videos = screen_videos.filter(c_id=computer_id)
    
        # Debugging: Print the queryset
        print("Screen video QuerySet:", screen_videos)
    
        # Apply pagination
        paginator = Pagination_ScreenVideoMonitoring()
        paginated_screenshots = paginator.paginate_queryset(screen_videos, request)
    
        # Serialize the paginated data
        serializer = ScreenVideoMonitoringSerializer(paginated_screenshots, many=True)
    
        # Return the paginated response
        return paginator.get_paginated_response(serializer.data)
    


#Keystrokes
class Pagination_Keystrokes(PageNumberPagination):
    page_size = 10  # Default page size
    page_size_query_param = 'page_size'  # Allows client to specify page size
    max_page_size = 100  # Maximum page size limit    

class KeyStrokesAPIView(APIView):
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        """
        Validate the token and extract the organization_id.
        """
        auth_header = request.headers.get('Authorization', '')
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


    def get(self, request):
        """
        Retrieve screenshots based on date filters and include computer username.
        """
        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')
        employee_id = request.query_params.get('employee_id')  # Optional employee filter
        computer_id = request.query_params.get('computer_id')  # Optional computer filter
    
        # Debugging: Print the received query parameters
        print("Received start_date:", start_date_str)
        print("Received end_date:", end_date_str)
    
        # Calculate date range with time adjustment
        today = datetime.now().date()
        if start_date_str:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
        else:
            start_date = datetime.combine(today, datetime.min.time())
        
        if end_date_str:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)
        else:
            end_date = start_date + timedelta(days=1) - timedelta(seconds=1)
    
        # Debugging: Print the calculated date range
        print("Start date (with time):", start_date)
        print("End date (with time):", end_date)
    
        # Filter screenvideo and annotate with computer username
        all_strokes = Keystroke.objects.filter(
            e_id__o_id=self.organization_id,
            activity_timestamp__range=[start_date, end_date]
        ).annotate(
            computer_username=F('c_id__c_username')  
        ).order_by('-svm_log_ts')

        if employee_id:
             screen_videos = screen_videos.filter(e_id=employee_id)
    
        if computer_id:
            screen_videos = screen_videos.filter(c_id=computer_id)
    
        # Debugging: Print the queryset
        print("Screen video QuerySet:", screen_videos)
    
        # Apply pagination
        paginator = Pagination_ScreenVideoMonitoring()
        paginated_screenshots = paginator.paginate_queryset(screen_videos, request)
    
        # Serialize the paginated data
        serializer = ScreenVideoMonitoringSerializer(paginated_screenshots, many=True)
    
        # Return the paginated response
        return paginator.get_paginated_response(serializer.data)