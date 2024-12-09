import csv
from django.core.management.base import BaseCommand
from backendapis.models import Keystroke, Employee, Organization  # Replace `your_app` with your app's name

class Command(BaseCommand):
    help = 'Import keystrokes from a CSV file'

    def add_arguments(self, parser):
        parser.add_argument('file_path', type=str, help='The file path of the CSV to import')

    def handle(self, *args, **kwargs):
        file_path = kwargs['file_path']
        try:
         with open(file_path, mode='r', encoding='utf-8') as file:
             reader = csv.DictReader(file)
             for row in reader:
                 try:
                     # Fetch related Employee and Organization objects
                     employee = Employee.objects.get(id=row['e_id_id'])  # Use 'e_id_id'
                     organization = Organization.objects.get(id=row['o_id_id'])  # Use 'o_id_id'
         
                     # Create Keystroke object
                     Keystroke.objects.create(
                         activity_timestamp=row['activity_timestamp'],
                         time_range=row['time_range'],
                         captured_events=row['captured_events'],
                         total_keys_pressed=row['total_keys_pressed'],
                         total_mouse_clicks=row['total_mouse_clicks'],
                         total_mouse_movements=row['total_mouse_movements'],
                         e_id=employee,  # Use the Employee object
                         o_id=organization,  # Use the Organization object
                     )
                     self.stdout.write(self.style.SUCCESS(f"Successfully imported row: {row}"))
                 except Exception as e:
                     self.stdout.write(self.style.ERROR(f"Error importing row: {row} - {e}"))


        except FileNotFoundError:
            self.stdout.write(self.style.ERROR(f"File {file_path} not found!"))
