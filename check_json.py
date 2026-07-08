import json
import csv

# Define the input JSON file and output CSV file paths
input_json_file = 'file_analysis.json'
output_csv_file = 'file_analysis.csv'

# Load data from the JSON file
with open(input_json_file, 'r') as json_file:
    data = json.load(json_file)

# Open the CSV file for writing
with open(output_csv_file, 'w', newline='') as csv_file:
    # Define the CSV fieldnames based on the JSON structure
    fieldnames = [
        'old_name',
        'new_name',
        'original_hash',
        'file_type',
        'magic_number_hex',
        'magic_number_offset_hex',
        'magic_number_ascii',
        'metadata.size',
        'metadata.created',
        'metadata.modified',
        'metadata.accessed'
    ]
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    # Write the header row
    writer.writeheader()

    # Write each entry from the JSON data to the CSV file
    for entry in data:
        # Flatten the nested metadata dictionary
        flat_entry = {
            'old_name': entry.get('original_name', ''),
            'new_name': entry.get('new_name', ''),
            'original_hash': entry.get('original_hash', ''),
            'file_type': entry.get('file_type', ''),
            'magic_number_hex': entry.get('magic_number_hex', ''),
            'magic_number_offset_hex': entry.get('magic_number_offset_hex', ''),
            'magic_number_ascii': entry.get('magic_number_ascii', ''),
            'metadata.size': entry.get('metadata', {}).get('size', ''),
            'metadata.created': entry.get('metadata', {}).get('created', ''),
            'metadata.modified': entry.get('metadata', {}).get('modified', ''),
            'metadata.accessed': entry.get('metadata', {}).get('accessed', '')
        }
        writer.writerow(flat_entry)

print(f"Data has been successfully converted from {input_json_file} to {output_csv_file}.")
