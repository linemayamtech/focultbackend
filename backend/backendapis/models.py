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
    o_pin_no = models.CharField(max_length=20, null=True, blank=True)

    # New fields for logging date and time
    created_at = models.DateTimeField(null=True, blank=True,auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)

    def __str__(self):
        return f'{self.o_email} {self.o_password}'
    
    class Meta:
        db_table = "organization"

class AppProductivity(models.Model):
    PRODUCTIVE = 'productive'
    UNPRODUCTIVE = 'unproductive'
    NEUTRAL = 'neutral'

    APP_STATE_CHOICES = [
        (PRODUCTIVE, 'Productive'),
        (UNPRODUCTIVE, 'Un Productive'),  
        (NEUTRAL, 'Neutral'),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE,null=True)
    app_name = models.CharField(max_length=100)
    app_state = models.CharField(
        max_length=20,
        choices=APP_STATE_CHOICES,
        default=NEUTRAL,
    )

    def __str__(self):
        return f"{self.app_name} ({self.get_app_state_display()})"
    


class Employee(models.Model):
        o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)
        e_name = models.CharField(max_length=100)
        e_email = models.EmailField()
        e_password = models.CharField(max_length=255)
        e_gender = models.CharField(max_length=25)
        e_contact = models.CharField(max_length=100)
        e_address = models.CharField(max_length=150)
        e_role = models.CharField(max_length=150, default='Employee')
        monitored = models.IntegerField(default=0) 
        def __str__(self):
            return f'{self.id} {self.e_email} {self.e_password} {self.e_address} {self.e_contact} {self.e_gender} {self.e_role}'
    
        class Meta:
         db_table = "employee"


class ActivityProductivity(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    no_of_key_press = models.IntegerField(default=0)
    no_of_mouse_press = models.IntegerField(default=0)
    no_of_mouse_scroll = models.IntegerField(default=0)

    def __str__(self):
        return f'Employee: {self.employee.e_name}, Key Presses: {self.no_of_key_press}, Mouse Presses: {self.no_of_mouse_press}, Mouse Scrolls: {self.no_of_mouse_scroll}'

    class Meta:
        db_table = "activity_productivity"

class OfflineData(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    purpose_of_offline = models.CharField(max_length=250)
    starting_approved_by = models.CharField(max_length=50)
    ending_approved_by = models.CharField(max_length=50,null=True)
    starting_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)  


class Notice(models.Model):
    organization=models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="notices")
    title=models.CharField(max_length=70)
    description=models.CharField(max_length=300)
    added_time=models.DateTimeField(auto_now_add=True)


class Keystroke(models.Model):
    activity_timestamp = models.DateTimeField(auto_now_add=True)
    time_range = models.CharField(max_length=20)
    captured_events = models.TextField()
    total_keys_pressed = models.IntegerField()
    total_mouse_clicks = models.IntegerField()
    total_mouse_movements = models.IntegerField()
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE,null=True)
    
    class Meta:
       db_table = "keystrokes" 