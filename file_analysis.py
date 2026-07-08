import os
import hashlib
import zipfile
import json
import shutil
import struct
from datetime import datetime

# Define magic numbers and their corresponding file types
MAGIC_NUMBERS = {
    b'\x50\x4B\x03\x04': 'zip',                   # ZIP files
    b'\x25\x50\x44\x46': 'pdf',                   # PDF files
    b'\xEF\xBB\xBF\x3C': 'ps1',                   # PowerShell scripts
    b'\x4D\x5A': 'exe',                           # EXE files (initially)
    b'\x4D\x5A\x90\x00': 'dll',                   # DLL files (initially)
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'png',   # PNG files
    b'\xFF\xD8': 'jpg',                           # JPG files
    b'\x40\x65\x63\x68\x6F': 'bat',               # Batch files
}

# Function to calculate SHA256 hash
def sha256_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# Function to get file metadata
def get_file_metadata(file_path):
    stat = os.stat(file_path)
    return {
        'size': stat.st_size,
        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),  # Convert to ISO format
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),  # Convert to ISO format
        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),  # Convert to ISO format
    }

# Function to identify file type based on magic numbers
def identify_file_type(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)  # Read the first 8 bytes
            for magic, file_type in MAGIC_NUMBERS.items():
                if header.startswith(magic):
                    return file_type, magic
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return None, None

# Function to determine the file type from the contents of a ZIP file
def determine_zip_file_type(zip_path, temp_dir):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)  # Extract to the temporary directory
            # Check for specific folders to determine the file type
            if os.path.exists(os.path.join(temp_dir, 'word')):
                return 'docx'
            elif os.path.exists(os.path.join(temp_dir, 'ppt')):
                return 'pptx'
            elif os.path.exists(os.path.join(temp_dir, 'xl')):
                return 'xlsx'
    except Exception as e:
        print(f"Error reading zip file {zip_path}: {e}")
    return None  # Return None if type cannot be determined

# Function to determine if a PE file is a DLL or EXE
def determine_pe_type(file_path):
    try:
        with open(file_path, "rb") as f:
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]

            f.seek(pe_offset + 0x16)
            characteristics = struct.unpack('<H', f.read(2))[0]

            if characteristics & 0x2000:  # Check if the DLL characteristic is set
                return 'dll'
            return 'exe'
    except Exception as e:
        print(f"Error determining PE type for {file_path}: {e}")
    return None

# Function to process files in the directory
def process_files(input_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    log_data = []  # List to hold log information

    for filename in os.listdir(input_dir):
        file_path = os.path.join(input_dir, filename)
        if os.path.isfile(file_path):
            try:
                original_hash = sha256_hash(file_path)
                file_type, magic_number = identify_file_type(file_path)
                metadata = get_file_metadata(file_path)

                # Prepare to log information
                log_info = {
                    'original_name': filename,
                    'original_hash': original_hash,
                    'file_type': file_type if file_type else 'txt',  # Default to txt
                    'metadata': metadata,
                }

                # Handle ZIP files specifically
                if file_type == 'zip':
                    temp_dir = os.path.join(output_dir, 'zip')  # Temporary extraction directory
                    os.makedirs(temp_dir, exist_ok=True)  # Create the temp directory if it doesn't exist

                    determined_type = determine_zip_file_type(file_path, temp_dir)
                    if determined_type:
                        new_filename = f"{os.path.splitext(filename)[0]}.{determined_type}"
                        new_file_path = os.path.join(output_dir, new_filename)
                        # Copy the zip file to the new file with the determined type
                        shutil.copy(file_path, new_file_path)
                        log_info['new_name'] = new_filename
                        log_info['recovered_hash'] = sha256_hash(new_file_path)
                        log_info['magic_number_hex'] = magic_number.hex() if magic_number else None
                        log_info['magic_number_ascii'] = magic_number.decode(errors='ignore') if magic_number else None
                        log_info['magic_number_offset'] = '0'  # Offset is 0 for the header
                    else:
                        print(f"Could not determine the file type of ZIP: {filename}")
                    shutil.rmtree(temp_dir)  # Clean up the temporary directory

                # Handle EXE and DLL files
                elif file_type in ['exe', 'dll']:
                    pe_type = determine_pe_type(file_path)
                    if pe_type:
                        new_filename = f"{os.path.splitext(filename)[0]}.{pe_type}"
                        new_file_path = os.path.join(output_dir, new_filename)
                        shutil.copy(file_path, new_file_path)
                        log_info['new_name'] = new_filename
                        log_info['recovered_hash'] = sha256_hash(new_file_path)
                        log_info['magic_number_hex'] = magic_number.hex() if magic_number else None
                        log_info['magic_number_ascii'] = magic_number.decode(errors='ignore') if magic_number else None
                        log_info['magic_number_offset'] = '0'  # Offset is 0 for the header
                    else:
                        print(f"Could not determine the PE type for {filename}")

                else:
                    # Handle other file types
                    if file_type:
                        new_filename = f"{filename}.{file_type}"
                        new_file_path = os.path.join(output_dir, new_filename)
                        shutil.copy(file_path, new_file_path)
                        log_info['new_name'] = new_filename
                        log_info['recovered_hash'] = sha256_hash(new_file_path)
                        if file_type == "bat":
                            log_info['magic_number_hex'] = None
                            log_info['magic_number_ascii'] = None
                            log_info['magic_number_offset'] = None
                        else:
                            log_info['magic_number_hex'] = magic_number.hex() if magic_number else None
                            log_info['magic_number_ascii'] = magic_number.decode(errors='ignore') if magic_number else None
                            log_info['magic_number_offset'] = '0'  # Offset is 0 for the header
                    else:
                        # If the file type is unknown, treat it as a text file
                        new_filename = f"{filename}.txt"
                        new_file_path = os.path.join(output_dir, new_filename)
                        shutil.copy(file_path, new_file_path)
                        log_info['new_name'] = new_filename
                        log_info['recovered_hash'] = sha256_hash(new_file_path)
                        log_info['magic_number_hex'] = None
                        log_info['magic_number_ascii'] = None
                        log_info['magic_number_offset'] = None

                log_data.append(log_info)  # Append log information to the list

            except Exception as e:
                print(f"Error processing file {file_path}: {e}")

    # Save log information to a JSON file
    with open('file_analysis.json', 'w') as json_file:
        json.dump(log_data, json_file, indent=4)

# Main execution
if __name__ == "__main__":
    input_directory = 'salvaged_files'
    output_directory = 'recovered_files'
    process_files(input_directory, output_directory)