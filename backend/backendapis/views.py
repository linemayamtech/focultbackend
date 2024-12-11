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
        productivity_data = AppProductivity.objects.filter(organization=organization)
        serializer = AppProductivitySerializers(productivity_data, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request, *args, **kwargs):
        """
        Add productivity data for the authenticated organization.
        """
        try:
            organization = Organization.objects.get(id=self.organization_id)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = AppProductivitySerializers(data=request.data)
        
        if serializer.is_valid():
            serializer.save(organization=organization)
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
            if data.organization.id != self.organization_id:
                return Response({"error": "You are not authorized to edit this data."}, status=status.HTTP_403_FORBIDDEN)
            
            # Update fields
            data.app_name = request.data.get('app_name', data.app_name)
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
            if data.organization.id != self.organization_id:
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


    def put(self, request, *args, **kwargs):
        """
        Edit an existing activity productivity record.
        """
        productivity_id = kwargs.get('pk')
        if not productivity_id:
            return Response({"error": "Productivity record ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            productivity = ActivityProductivity.objects.get(id=productivity_id, department__o_id=self.organization_id)
        except ActivityProductivity.DoesNotExist:
            return Response({"error": "Productivity record not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)
        
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

    def put(self, request, *args, **kwargs):
        """
        Update an existing offline data record.
        """
        organization_id = self.organization_id
        offline_data_id = kwargs.get('id')

        try:
            offline_data = OfflineData.objects.get(id=offline_data_id, employee__o_id=organization_id)
        except OfflineData.DoesNotExist:
            return Response({"error": "Offline data not found or not associated with the organization."}, status=status.HTTP_404_NOT_FOUND)

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


class NoticePagination(PageNumberPagination):
    page_size = 10  # Number of notices per page
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
        """ Create a new notice """
        # Ensure the organization ID from the token is used
        organization_id_from_token = self.organization_id
    
        if not organization_id_from_token:
            return Response({"error": "Organization ID not found in token."}, status=HTTP_400_BAD_REQUEST)
    
        # Check if the organization exists
        try:
            organization = Organization.objects.get(id=organization_id_from_token)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found."}, status=HTTP_404_NOT_FOUND)
    
        # Add the organization instance to the request data
        data = request.data.copy()
        data['organization'] = organization.id
    
        # Serialize and validate the data
        serializer = NoticeSerializer(data=data)
        if serializer.is_valid():
            # Save the notice and associate it with the organization
            serializer.save(organization=organization)
            return Response(serializer.data, status=HTTP_201_CREATED)
    
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)



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


    def put(self, request, *args, **kwargs):
        """ Update an existing notice """
        try:
            notice = Notice.objects.get(id=kwargs['id'], organization_id=self.organization_id)
        except Notice.DoesNotExist:
            return Response({'error': 'Notice not found'}, status=HTTP_404_NOT_FOUND)

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
from collections import defaultdict


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
        print("start_date:", start_date_str)
        print("end_date:", end_date_str)
    
        try:
            # Calculate date range
            today = datetime.now().date()  # Get today's date
            if start_date_str:
                start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
            else:
                start_date = today  # Default to today if no start_date is provided
    
            # If only start_date is provided, we assume the same for end_date
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date() if end_date_str else start_date
    
            # Query employees belonging to the same organization
            employees = Employee.objects.filter(o_id=self.organization_id)
            employee_ids = employees.values_list('id', flat=True)  # Get a list of employee IDs
    
            # Initialize a list to store average productivity for each day
            daily_avg_productivity = []
    
            # Iterate over each day in the date range
            current_date = start_date
            while current_date <= end_date:
                # Start and end datetime for the current day
                start_datetime = make_aware(datetime.combine(current_date, datetime.min.time()))
                end_datetime = make_aware(datetime.combine(current_date, datetime.max.time()))
    
                # Query keystrokes for the current day and organization ID
                keystrokes = Keystroke.objects.filter(
                    e_id__in=employee_ids,  # Filter by employee IDs
                    activity_timestamp__range=(start_datetime, end_datetime)
                ).exclude(activity_timestamp__isnull=True)
    
                # Calculate total productivity for the day
                total_productivity = []
                for employee in employees:
                    # Filter keystrokes for the current employee on the current day
                    employee_keystrokes = keystrokes.filter(e_id=employee)
                    
                    # If no keystrokes for this employee on this day, skip to next employee
                    if not employee_keystrokes.exists():
                        continue
    
                    # Calculate productivity for the employee on this day
                    productivity = self.calculate_productivity(employee_keystrokes)
                    total_productivity.append(productivity)
    
                # Calculate the average productivity for the day
                avg_productivity = sum(total_productivity) / len(total_productivity) if total_productivity else 0
                daily_avg_productivity.append({
                    "date": current_date.strftime("%Y-%m-%d"),
                    "average_productivity": avg_productivity
                })
    
                # Move to the next day
                current_date += timedelta(days=1)
    
            # Prepare the response data for the given date range
            response_data = []
            for employee in employees:
                # Filter keystrokes for the current employee over the full date range
                employee_keystrokes = keystrokes.filter(e_id=employee)
                if not employee_keystrokes.exists():
                    continue
    
                # Calculate session time across multiple days
                session_time = self.get_session_time(employee_keystrokes)
    
                # Calculate idle time (no keys pressed, no clicks, no movements)
                idle_minutes = employee_keystrokes.filter(
                    total_keys_pressed=0,
                    total_mouse_clicks=0,
                    total_mouse_movements=0
                ).count()
                idle_time = timedelta(minutes=idle_minutes)
    
                # Work time (session time minus idle time)
                work_time = session_time - idle_time
                if work_time < timedelta():
                    work_time = timedelta()
    
                # Calculate productivity
                productivity = self.calculate_productivity(employee_keystrokes)
    
                # Prepare the response data for this employee
                response_data.append({
                    "employee_name": employee.e_name,
                    "session_time": self.format_time(session_time),
                    "work_time": self.format_time(work_time),
                    "idle_time": self.format_time(idle_time),
                    "activity": productivity
                })
    
            # Prepare final response including employee-wise productivity and daily avg productivity
            response = {
                "employee_productivity": response_data,
                "daily_avg_productivity": daily_avg_productivity
            }
    
            return Response(response, status=status.HTTP_200_OK)
    
        except Exception as e:
            # Log and handle any errors during the processing
            print("Error:", str(e))
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)     
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


# class MonitoringEmployeeView(APIView):
#     permission_classes = [AllowAny]

#     def initial(self, request, *args, **kwargs):
#         """
#         Extract and verify the token to get the organization_id.
#         """
#         auth_header = get_authorization_header(request).decode('utf-8')
#         if not auth_header:
#             return Response({"error": "Authorization token is required."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             token = auth_header.split(" ")[1]
#             access_token = AccessToken(token)
#             self.organization_id = access_token.get('organization_id')
#             if not self.organization_id:
#                 return Response({"error": "Organization ID not found in token."}, status=status.HTTP_401_UNAUTHORIZED)
#         except IndexError:
#             return Response({"error": "Invalid token format. Use 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

#         super().initial(request, *args, **kwargs)

#     def get(self, request, *args, **kwargs):
#         """
#         Display offline data for the logged-in organization, filtered by date or date range.
#         Compare the data with the AppProductivity model to categorize app usage as productive, unproductive, or neutral.
#         """
#         organization_id = self.organization_id
#         monitoring_data = Monitoring.objects.filter(e_id__o_id=organization_id)

#         # Get date filters
#         start_date_str = request.query_params.get('start_date', None)
#         end_date_str = request.query_params.get('end_date', None)

#         try:
#             start_date = datetime.strptime(start_date_str.strip(), "%Y-%m-%d").date() if start_date_str else None
#             end_date = datetime.strptime(end_date_str.strip(), "%Y-%m-%d").date() if end_date_str else None
#         except ValueError:
#             return Response({"error": "Invalid date format. Use 'YYYY-MM-DD'."}, status=status.HTTP_400_BAD_REQUEST)

#         # Filter data
#         if start_date and end_date:
#             monitoring_data_queryset = monitoring_data.filter(
#                 starting_time__date__range=(start_date, end_date)
#             )
#         elif start_date:
#             monitoring_data_queryset = monitoring_data.filter(
#                 starting_time__date=start_date
#             )
#         elif end_date:
#             monitoring_data_queryset = monitoring_data.filter(
#                 starting_time__date=end_date
#             )
#         else:
#             filter_date = timezone.now().date()
#             monitoring_data_queryset = monitoring_data.filter(
#                 starting_time__date=filter_date
#             )

#         # Initialize result dictionary
#         employee_app_usage = {}

#         for record in monitoring_data_queryset:
#             employee_id = record.e_id.id
#             app_name = record.m_title
#             total_time_seconds = record.m_total_time_seconds

#             # Check if employee data exists in result dictionary
#             if employee_id not in employee_app_usage:
#                 employee_app_usage[employee_id] = {
#                     'employee_name': record.e_id.name,
#                     'productive_time': 0,
#                     'unproductive_time': 0,
#                     'neutral_time': 0
#                 }

#             # Check app productivity state
#             app_productivity = AppProductivity.objects.filter(app_name=app_name, department=record.e_id.department).first()
#             if app_productivity:
#                 app_state = app_productivity.app_state
#             else:
#                 app_state = AppProductivity.NEUTRAL

#             # Categorize time spent on the app
#             if app_state == AppProductivity.PRODUCTIVE:
#                 employee_app_usage[employee_id]['productive_time'] += total_time_seconds
#             elif app_state == AppProductivity.UNPRODUCTIVE:
#                 employee_app_usage[employee_id]['unproductive_time'] += total_time_seconds
#             elif app_state == AppProductivity.NEUTRAL:
#                 employee_app_usage[employee_id]['neutral_time'] += total_time_seconds

#         # Convert time from seconds to hours, minutes, seconds format for better readability
#         for employee_id, usage_data in employee_app_usage.items():
#             for key in ['productive_time', 'unproductive_time', 'neutral_time']:
#                 total_seconds = usage_data[key]
#                 hours, remainder = divmod(total_seconds, 3600)
#                 minutes, seconds = divmod(remainder, 60)
#                 usage_data[key] = f"{hours}:{minutes:02}:{seconds:02}"

#         return Response(employee_app_usage)




