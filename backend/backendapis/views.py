from .serializers import *
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from .models import *
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.authentication import get_authorization_header
from rest_framework.decorators import api_view, permission_classes
from .serializers import OrganizationLoginSerializer, AppProductivitySerializers
from rest_framework import status
from django.db.models import Q
from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_204_NO_CONTENT
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Notice, Organization
from .serializers import NoticeSerializer
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.authentication import get_authorization_header
from .models import OfflineData
from .serializers import OfflineDataSerializers
from rest_framework.pagination import PageNumberPagination
from django.utils import timezone
from datetime import datetime
from django.utils.timezone import now






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
        employees = Employee.objects.filter(o_id=self.organization_id)
        
        if not employees.exists():
            return Response({"error": "No employees found for the organization."}, status=status.HTTP_404_NOT_FOUND)
        
        activity_productivity_data = ActivityProductivity.objects.filter(employee__in=employees)
        
        if search_query:
            if search_query.isdigit():
                activity_productivity_data = activity_productivity_data.filter(
                    Q(no_of_key_press__contains=search_query) |
                    Q(no_of_mouse_press__contains=search_query) |
                    Q(no_of_mouse_scroll__contains=search_query)
                )
            else:
                activity_productivity_data = activity_productivity_data.filter(
                    employee__e_name__icontains=search_query
                )
        
        activity_productivity_data = activity_productivity_data.order_by('employee__e_name')
        paginator = Pagination_activityProductivity()
        result_page = paginator.paginate_queryset(activity_productivity_data, request)
        serializer = ActivityProductivitySerializers(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Add a new activity productivity record for the organization.
        """
        employee_id = request.data.get('employee')
        if not employee_id:
            return Response({"error": "Employee ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            employee = Employee.objects.get(id=employee_id, o_id=self.organization_id)
        except Employee.DoesNotExist:
            return Response({"error": "Employee not found or does not belong to the organization."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = ActivityProductivitySerializers(data=request.data)
        if serializer.is_valid():
            serializer.save(employee=employee)
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
            productivity = ActivityProductivity.objects.get(id=productivity_id, employee__o_id=self.organization_id)
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
            productivity = ActivityProductivity.objects.get(id=productivity_id, employee__o_id=self.organization_id)
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
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.authentication import get_authorization_header
# from rest_framework import status
# from rest_framework.exceptions import AuthenticationFailed
# from rest_framework.permissions import IsAuthenticated
# from django.conf import settings
# from datetime import datetime
# from rest_framework_simplejwt.tokens import AccessToken
# from backendapis.models import Keystroke, Employee
# from .serializers import KeystrokeSerializer
# from rest_framework.authentication import TokenAuthentication


# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.authentication import get_authorization_header
# from rest_framework import status
# from rest_framework_simplejwt.tokens import AccessToken
# from backendapis.models import Keystroke
# from .serializers import KeystrokeSerializer

# from datetime import datetime
# from django.utils import timezone
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework.permissions import AllowAny
# from datetime import timedelta

# from datetime import timedelta

# from django.db.models import Max, Min

# from datetime import timedelta
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework.permissions import AllowAny
# from django.utils import timezone
# from datetime import datetime

# from datetime import datetime, timedelta
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework.permissions import AllowAny
# from rest_framework import status
# from django.utils import timezone

# class KeystrokeView(APIView):
#     permission_classes = [AllowAny]

#     def initial(self, request, *args, **kwargs):
#         """
#         Validate the token and extract the organization_id.
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
#             return Response({"error": "Invalid token format. Please provide a valid 'Bearer <token>'."}, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({"error": f"Token decoding error: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

#         super().initial(request, *args, **kwargs)

#     def get(self, request):
#         """
#         Handle the GET request to fetch aggregated keystroke data for the organization.
#         """
#         if not hasattr(self, 'organization_id'):
#             return Response({"error": "Organization ID is missing."}, status=status.HTTP_400_BAD_REQUEST)

#         # Get the date(s) from the query parameters or use today's date if not specified
#         date_str = request.query_params.get('date', None)
#         from_date_str = request.query_params.get('from_date', None)
#         to_date_str = request.query_params.get('to_date', None)

#         if date_str:
#             # If a specific date is provided
#             date_filter = datetime.strptime(date_str, '%Y-%m-%d').date()
#         elif from_date_str and to_date_str:
#             # If both from_date and to_date are provided, filter based on the range
#             from_date = datetime.strptime(from_date_str, '%Y-%m-%d').date()
#             to_date = datetime.strptime(to_date_str, '%Y-%m-%d').date()
#             date_filter = (from_date, to_date)
#         else:
#             # Default to today's date if no date or range is provided
#             date_filter = timezone.localdate()

#         # Filter keystrokes based on the date(s) and organization
#         if isinstance(date_filter, tuple):  # If it's a range (from_date, to_date)
#             keystrokes = Keystroke.objects.filter(
#                 e_id__o_id=self.organization_id,
#                 activity_timestamp__date__range=date_filter
#             )
#         else:
#             keystrokes = Keystroke.objects.filter(
#                 e_id__o_id=self.organization_id,
#                 activity_timestamp__date=date_filter
#             )

#         # Initialize aggregates
#         total_keys_pressed = 0
#         total_mouse_clicks = 0
#         total_mouse_movements = 0
#         total_idle_time = timedelta()
#         total_productivity = 0
#         count = 0
#         employee_data = {}  # Dictionary to store session time data for each employee

#         # Iterate through the filtered keystrokes and group by employee
#         for keystroke in keystrokes:
#             e_id = keystroke.e_id  # Get employee ID
            
#             # Initialize employee data if not already present
#             if e_id not in employee_data:
#                 employee_data[e_id] = {
#                     'total_keys_pressed': 0,
#                     'total_mouse_clicks': 0,
#                     'total_mouse_movements': 0,
#                     'total_idle_time': timedelta(),
#                     'total_productivity': 0,
#                     'count': 0,
#                     'first_entry': None,
#                     'last_entry': None,
#                     'first_time_range': None,  # Track first time_range
#                     'last_time_range': None,  # Track first time_range
#                 }
            
#             # Access the employee's data dictionary
#             employee = employee_data[e_id]
            
#             # Aggregate data for the employee
#             employee['total_keys_pressed'] += keystroke.total_keys_pressed
#             employee['total_mouse_clicks'] += keystroke.total_mouse_clicks
#             employee['total_mouse_movements'] += keystroke.total_mouse_movements

#             # Calculate idle time (1 minute if all fields are 0)
#             if keystroke.total_keys_pressed == 0 and keystroke.total_mouse_clicks == 0 and keystroke.total_mouse_movements == 0:
#                 employee['total_idle_time'] += timedelta(minutes=1)  # Add 1 minute of idle time
#             else:
#                 employee['total_idle_time'] += timedelta(minutes=0)  # Not idle

#             # Update first and last entries for session time calculation
#             if not employee['first_entry'] or keystroke.activity_timestamp < employee['first_entry']:
#                 employee['first_entry'] = keystroke.activity_timestamp
#                 if not employee['first_time_range']:  # Set the first time range
#                     employee['first_time_range'] = keystroke.time_range  # Use the time range associated with the first entry
            
#             # Correct last entry to include time range of the latest activity
#             if not employee['last_entry'] or keystroke.activity_timestamp > employee['last_entry']:
#                 employee['last_entry'] = keystroke.activity_timestamp
#                 employee['last_time_range'] = keystroke.time_range  # Use the latest time range
            

#             # Calculate productivity for this keystroke
#             employee['total_productivity'] += calculate_productivity(
#                 keystroke.total_keys_pressed, 
#                 keystroke.total_mouse_clicks, 
#                 keystroke.total_mouse_movements
#             )
#             employee['count'] += 1  # Count the number of entries to calculate average productivity

#         # Prepare the aggregated response data for all employees
#         employee_session_data = []
        
#         for e_id, data in employee_data.items():
#             # Calculate average productivity (if count > 0 to avoid division by 0)
#             avg_productivity = data['total_productivity'] / data['count'] if data['count'] > 0 else 0
        
#             # Calculate session time (time difference between first and last entry)
#             session_time = timedelta()
#             if data['first_entry'] and data['last_entry']:
#                 session_time = data['last_entry'] - data['first_entry']
        
#             # Calculate work time (session time minus idle time)
#             work_time = session_time - data['total_idle_time']
#             print('work_time',work_time)
        
#             # Ensure work_time and session_time are not negative
#             if work_time < timedelta():
#                 work_time = timedelta()
#             if session_time < timedelta():
#                 session_time = timedelta()
        
#             # Format the times
#             def format_time(time_delta):
#                 """
#                 Formats a datetime object into a string in the format 'HH:MM:SS'.
#                 """
#                 total_seconds = int(time_delta.total_seconds())
#                 hours = total_seconds // 3600
#                 minutes = (total_seconds % 3600) // 60
#                 return f"{hours:02}:{minutes:02}"
                
        
#             formatted_session_time = format_time(session_time)
#             formatted_work_time = format_time(work_time)
#             formatted_idle_time = format_time(data['total_idle_time'])
            
#             formatted_first_time_range = data['first_time_range'] if data['first_time_range'] else "No Time Range"
#             formatted_last_time_range = data['last_time_range'] if data['last_time_range'] else "No Time Range"
            
#             employee_session_data.append({
#                 "employee_id": e_id.id,  # Ensure e_id is serializable
#                 "total_keys_pressed": data['total_keys_pressed'],
#                 "total_mouse_clicks": data['total_mouse_clicks'],
#                 "total_mouse_movements": data['total_mouse_movements'],
#                 "avg_productivity": avg_productivity,
#                 "total_idle_time": formatted_idle_time,  # Display idle time in HH:MM format
#                 "work_time": formatted_work_time,  # Working time excluding idle
#                 "session_time": formatted_session_time,  # Total session time including idle
#                 "first_time": formatted_first_time_range,
#                 "last_time": formatted_last_time_range,
#                 "date": date_filter,
#             })


        
#         return Response(employee_session_data)






