import csv
from django.core.management.base import BaseCommand
from backendapis.models import Computer, Employee, Organization  # Import the Organization model as well

class Command(BaseCommand):
    help = 'Imports computers data from CSV file'

    def handle(self, *args, **kwargs):
        file_path = r'C:\EMAYAM WORK\FOCULT BACKEND\backend\imports\computers.csv'

        try:
            with open(file_path, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    # Skip the 'o_id' and 'e_id' columns for importing
                    o_id = row.pop('o_id', None)  # Remove 'o_id' from the row if it exists
                    e_id = row.pop('e_id', None)  # Remove 'e_id' from the row if it exists

                    # Get Employee object based on e_id from CSV (if provided)
                    employee = None
                    if e_id:  # If e_id is present
                        try:
                            employee = Employee.objects.get(id=e_id)
                        except Employee.DoesNotExist:
                            self.stdout.write(self.style.ERROR(f'Employee with ID {e_id} not found'))
                            continue  # Skip this row if employee not found

                    # Get Organization object based on o_id from CSV (if provided)
                    organization = None
                    if o_id:  # If o_id is present
                        try:
                            organization = Organization.objects.get(id=o_id)
                        except Organization.DoesNotExist:
                            self.stdout.write(self.style.ERROR(f'Organization with ID {o_id} not found'))
                            continue  # Skip this row if organization not found

                    # Create a new Computer instance, excluding 'o_id' and 'e_id' from row
                    Computer.objects.create(
                        c_log_ts=row['c_log_ts'],
                        c_ip_address=row['c_ip_address'],
                        c_system_status=row['c_system_status'],
                        c_operating_system=row['c_operating_system'],
                        c_username=row['c_username'],
                        c_host_name=row['c_host_name'],
                        uuid=row['uuid'],
                        o_id=organization,  # Assign Organization (nullable)
                        e_id=employee,  # Assign Employee object
                    )

            self.stdout.write(self.style.SUCCESS('Successfully imported computers data'))
        except FileNotFoundError:
            self.stdout.write(self.style.ERROR(f'File not found: {file_path}'))
    