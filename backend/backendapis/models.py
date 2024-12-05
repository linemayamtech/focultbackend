from django.db import models
from django.core.validators import RegexValidator

class Location(models.Model):
    name = models.CharField(max_length=255)
    state_id = models.IntegerField()
    state_code = models.CharField(max_length=10)
    state_name = models.CharField(max_length=255)
    country_id = models.IntegerField()
    country_code = models.CharField(max_length=10)
    country_name = models.CharField(max_length=255)
    latitude = models.DecimalField(max_digits=10, decimal_places=8)
    longitude = models.DecimalField(max_digits=11, decimal_places=8)
    wikiDataId = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.name
    
    class Meta:
        db_table = "Location"

class Organization(models.Model):
    o_name = models.CharField(max_length=100)
    o_email = models.EmailField(unique=True)
    o_password = models.CharField(max_length=250)
    o_contact = models.CharField(
        max_length=15,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$')],
        null=True,
        blank=True,
        unique=True
    )
    o_website = models.CharField(max_length=100)
    o_address = models.CharField(max_length=150)
    o_country = models.CharField(max_length=100, null=True, blank=True)
    o_state = models.CharField(max_length=100, null=True, blank=True)
    o_city = models.CharField(max_length=100, null=True, blank=True)
    o_pin_no = models.CharField(max_length=20, null=True, unique=True)

    # New fields for logging date and time
    created_at = models.DateTimeField(null=True, blank=True,auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)

    def __str__(self):
        return f'{self.o_email} {self.o_password}'
    
    class Meta:
        db_table = "organization"
