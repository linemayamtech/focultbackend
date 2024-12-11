import csv
from django.core.management.base import BaseCommand
from backendapis.models import Monitoring

class Command(BaseCommand):
    help = 'Import data from CSV into the Monitoring table'

    def handle(self, *args, **kwargs):
        file_path = 'C:/EMAYAM WORK/FOCULT BACKEND/backend/imports/data2.csv'
        
        # Open the CSV file
        with open(file_path, mode='r') as file:
            csv_reader = csv.DictReader(file)
            
            # Check the headers to see what's available in the CSV
            headers = csv_reader.fieldnames
            print("CSV Headers:", headers)  # This will print the column names in the CSV

            # Loop through each row in the CSV
            for row in csv_reader:
                print(row)  # To check the data in each row
                # Adjust the field names according to your CSV headers
                Monitoring.objects.create(
                    id=row['id'],  # Adjust this to match the CSV column names
                    m_title=row['m_title'],
                    m_log_ts=row['m_log_ts'],
                    e_id_id=row['e_id_id'],
                    o_id_id=row['o_id_id'],
                    m_total_time_seconds=row['m_total_time_seconds'] if row['m_total_time_seconds'] != 'NULL' else None,  # Handle 'NULL' values
                    m_url=row['m_url'],
                    m_process=row['m_process'],
                    # If needed, adjust for any other fields
                )

        self.stdout.write(self.style.SUCCESS('Data imported successfully'))
