from rest_framework import serializers
from .models import Location, Organization,AppProductivity,ActivityProductivity
from rest_framework import serializers
from django.contrib.auth.hashers import check_password
from .models import Organization
from .models import *

class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ['id', 'country_id', 'country_name', 'state_id', 'state_name', 'name']

class OrganizationSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    o_country = serializers.CharField(required=True)
    o_state = serializers.CharField(required=True)
    o_city = serializers.CharField(required=True)
    o_pin_no = serializers.CharField(required=True)

    class Meta:
        model = Organization
        fields = [
            'o_name', 'o_email', 'password1', 'password2', 'o_contact', 'o_website',
            'o_address', 'o_country', 'o_state', 'o_city', 'o_pin_no',
            'created_at', 'updated_at'
        ]

    def validate(self, data):
        """
        Custom validation to ensure the password match and location validation.
        """
        password1 = data.get('password1')
        password2 = data.get('password2')

        if password1 != password2:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        """
        Custom create method to handle object creation after validation.
        """
        # Remove the temporary password fields, which are not part of the model
        validated_data.pop('password1')
        validated_data.pop('password2')

        # Use the remaining validated data to create the Organization object
        organization = Organization.objects.create(
            o_name=validated_data['o_name'],
            o_email=validated_data['o_email'],
            o_password=validated_data['password1'],  # Store password1 as o_password
            o_contact=validated_data.get('o_contact', ''),
            o_website=validated_data['o_website'],
            o_address=validated_data['o_address'],
            o_country=validated_data['o_country'],
            o_state=validated_data['o_state'],
            o_city=validated_data['o_city'],
            o_pin_no=validated_data['o_pin_no']
        )
        return organization



class OrganizationLoginSerializer(serializers.Serializer):
    o_email = serializers.EmailField()
    o_password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('o_email')
        password = data.get('o_password')

        # Check if email exists in the database
        try:
            organization = Organization.objects.get(o_email=email)
        except Organization.DoesNotExist:
            raise serializers.ValidationError("Invalid email .")

        # Verify password
        if not check_password(password, organization.o_password):
            raise serializers.ValidationError("password.")

        data['organization'] = organization  # Store organization data to return in view
        return data


from rest_framework import serializers
from .models import AppProductivity, Organization

# class ProductivitySerializers(serializers.ModelSerializer):
#     # Adding an extra field to the serializer
#     productivity_info = serializers.SerializerMethodField()

#     class Meta:
#         model = Productivity
#         fields = ['id', 'organization', 'app_name', 'app_state', 'productivity_info']  # include your extra field here

#     def get_productivity_info(self, obj):  
#         # This method provides additional data to the serialized output
#         return "extra field"

#     def validate(self, data):
#         # Validation logic can be placed here
#         # If you want to check for special characters in app_name or another field, you can modify it
#         spl_chars = "!@#$%&*_-=+?><:;/\\|"
#         if any(c in spl_chars for c in data['app_name']):
#             raise serializers.ValidationError("App name should not contain special characters")
        
#         return data

#     def create(self, validated_data):
#         # Handle the 'organization' field properly
#         organization_id = validated_data.get('organization', None)
#         if not organization_id:
#             raise serializers.ValidationError("Organization is required.")

#         # Ensure the organization exists
#         try:
#             organization = Organization.objects.get(id=organization_id)
#         except Organization.DoesNotExist:
#             raise serializers.ValidationError("Organization not found.")
        
#         # Create the Productivity object
#         return Productivity.objects.create(organization=organization, **validated_data)


class AppProductivitySerializers(serializers.ModelSerializer):
    organization_name = serializers.ReadOnlyField(source='organization.o_name')

    class Meta:
        model = AppProductivity    
        fields = ['id', 'organization', 'organization_name', 'app_name', 'app_state']


from rest_framework import serializers

class ActivityProductivitySerializers(serializers.ModelSerializer):
    organization_name = serializers.SerializerMethodField()  # Custom field for organization name
    department_name = serializers.CharField(source='department.department_name', read_only=True)

    class Meta:
        model = ActivityProductivity
        fields = ['id', 'department', 'no_of_key_press', 'no_of_mouse_press', 'no_of_mouse_scroll', 'organization_name', 'department_name']

    def get_organization_name(self, obj):
        # Access organization name via the department's related organization
        return obj.department.o_id.o_name


class OfflineDataSerializers(serializers.ModelSerializer):
    organization_name = serializers.SerializerMethodField()  # Custom field for organization name

    class Meta:
        model = OfflineData
        fields = [
            'id', 
            'employee', 
            'purpose_of_offline', 
            'starting_approved_by', 
            'ending_approved_by', 
            'starting_time', 
            'end_time', 
            'organization_name'
        ]

    def get_organization_name(self, obj):
        # Access organization name via the employee's related organization
        return obj.employee.o_id.o_name



    def validate_end_time(self, value):
        # Optional: Prevent setting `end_time` during creation if needed
        if not self.instance and value is not None:
            raise serializers.ValidationError("end_time cannot be set during creation.")
        return value



#Notice section


class NoticeSerializer(serializers.ModelSerializer):
    organization_name = serializers.SerializerMethodField()  # Custom field for organization name

    class Meta:
        model = Notice
        fields = ['id', 'organization', 'title', 'description', 'added_time', 'organization_name']

    def get_organization_name(self, obj):
        # Access organization name from the 'organization' field in the Notice model
        return obj.organization.o_name    # Assuming 'Organization' model has a 'name' field
    


# Keystroke  section


from rest_framework import serializers
from datetime import timedelta

from backendapis.models import Keystroke

def calculate_productivity(keys_pressed, mouse_clicks, mouse_movements):
    if keys_pressed >= 40 or mouse_clicks >= 40 or mouse_movements >= 40:
        return 100  # Maximum productivity if any of the fields is >= 40
    productivity = 0
    if keys_pressed < 40:
        productivity += (keys_pressed / 40) * 100
    if mouse_clicks < 40:
        productivity += (mouse_clicks / 40) * 100
    if mouse_movements < 40:
        productivity += (mouse_movements / 40) * 100
    return min(productivity, 100)  # Ensure productivity does not exceed 100

class KeystrokeSerializer(serializers.ModelSerializer):
    productivity = serializers.SerializerMethodField()
    idle_time = serializers.SerializerMethodField()
    employee_name = serializers.SerializerMethodField()  # New field for employee name

    class Meta:
        model = Keystroke
        fields = ['id', 'activity_timestamp', 'time_range', 'captured_events', 'total_keys_pressed', 
                  'total_mouse_clicks', 'total_mouse_movements', 'productivity','idle_time', 'employee_name']

    def get_productivity(self, obj):
        return calculate_productivity(
            obj.total_keys_pressed, 
            obj.total_mouse_clicks, 
            obj.total_mouse_movements
        )
        
    def get_idle_time(self, obj):
            """
            Calculate idle time: if all three fields (keys_pressed, mouse_clicks, mouse_movements) are 0,
            that time period is considered idle.
            """
            if (
                obj.total_keys_pressed == 0 and
                obj.total_mouse_clicks == 0 and
                obj.total_mouse_movements == 0
            ):
                return 1  # 1 minute idle time
            return 0  # Not idle
    
    def get_employee_name(self, obj):
            """
            Retrieve the employee name (e_name) from the Employee model.
            """
            return obj.e_id.e_name
    def get_session_time(self, obj):
        """
        Calculate the session time (time difference between the first and last entry).
        """
        first_entry = obj.activity_timestamp  # Assuming first entry is the current keystroke timestamp
        last_entry = obj.activity_timestamp  # Similarly for last entry, it can be the current timestamp

        # You may need to fetch the first and last entries from the database based on the e_id and date
        # For now, I will calculate it directly based on the current keystroke

        session_time = last_entry - first_entry
        return self.format_time(session_time)

    def get_work_time(self, obj):
        """
        Calculate work time: session time minus idle time.
        """
        session_time = self.get_session_time(obj)
        idle_time = timedelta(minutes=self.get_idle_time(obj))  # Idle time is already in minutes
        
        work_time = session_time - idle_time
        return self.format_time(work_time)

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

