from rest_framework import serializers
from .models import Location, Organization

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
