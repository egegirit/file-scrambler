from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import json
import random
import string
import hashlib


chunk_dir = "chunks"
join_folder = chunk_dir
encrypted_folder_path = "encrypted"
decrypted_folder_path = "decrypted"
original_file_path = "example-image.png"
chunk_amount = 5
random_chunk_names = True
random_chunk_sizes = True
encrypt_files = True
key_storage = {}


def generate_unique_filename(existing_names, length=10):
    while True:
        name = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        if name not in existing_names:
            return name


def split_file(file_path, num_chunks, random_size_for_each_chunk, random_name_for_each_chunk):
    # Get the file size
    file_size = os.path.getsize(file_path)

    # Calculate the size of each chunk
    chunk_size, remainder = divmod(file_size, num_chunks)

    # List to store metadata
    metadata = []

    # Create a directory for chunks if it doesn't exist
    os.makedirs(chunk_dir, exist_ok=True)

    # Set to keep track of generated file names
    generated_names = set()

    # Open the input file in binary read mode
    with open(file_path, 'rb') as f:
        remaining_size = file_size
        for i in range(num_chunks):
            # Add remainder to the first few chunks
            current_chunk_size = chunk_size + (1 if i < remainder else 0)

            # Generate a random chunk size if necessary, but make sure the remaining size is enough
            if random_size_for_each_chunk:
                current_chunk_size = random.randint(1, remaining_size - (num_chunks - i - 1))

            # Reduce the remaining size
            remaining_size -= current_chunk_size

            # Generate random chunk name if necessary
            if random_name_for_each_chunk:
                chunk_name = generate_unique_filename(generated_names)
                generated_names.add(chunk_name)
            else:
                chunk_name = f"{file_path.split('.')[0]}.part{i + 1}"

            chunk_path = os.path.join(chunk_dir, chunk_name)

            # Append metadata
            metadata.append((chunk_name, current_chunk_size))

            # Write the current chunk to file
            with open(chunk_path, 'wb') as chunk_file:
                chunk_file.write(f.read(current_chunk_size))

    # Create the metadata file
    with open("metadata.txt", 'w') as m:
        for chunk_name, current_chunk_size in metadata:
            hash_value = hash_metadata_text(chunk_name, current_chunk_size)
            m.write(f"{hash_value}\n")


def join_file(metadata_path, output_file_name="original_file"):
    # Initialize an empty list to hold the hash values
    hash_metadata = []

    # Read the metadata file to get the hash values
    with open(metadata_path, 'r') as m:
        lines = m.readlines()
        for line in lines:
            hash_value = line.strip()
            hash_metadata.append(hash_value)

    # Create a directory for chunks if it doesn't exist
    # Initialize a list to store the chunks in their correct order
    ordered_chunk_files = [None] * len(hash_metadata)

    # Iterate through all chunks and hash them
    for chunk_name in os.listdir(join_folder):
        chunk_path = os.path.join(join_folder, chunk_name)
        chunk_size = os.path.getsize(chunk_path)

        # Calculate the hash value for this chunk
        hash_value = hash_metadata_text(chunk_name, chunk_size)

        # Find out the order of this chunk
        try:
            index = hash_metadata.index(hash_value)
            ordered_chunk_files[index] = (chunk_path, chunk_size)
        except ValueError:
            print(f"WARNING: Unrecognized chunk {chunk_name}")

    # Open the output file in binary write mode
    with open(output_file_name, 'wb') as f:
        for chunk_path, chunk_size in ordered_chunk_files:
            if chunk_path is not None:
                # Open each chunk file and write its contents into the original file
                with open(chunk_path, 'rb') as chunk_file:
                    f.write(chunk_file.read(chunk_size))


def hash_metadata_text(chunk_name, chunk_size):
    hasher = hashlib.sha256()
    hasher.update(f"{chunk_name},{chunk_size}".encode('utf-8'))
    return hasher.hexdigest()


def encrypt_file(filepath):
    key = get_random_bytes(32)  # 256-bit key
    cipher = AES.new(key, AES.MODE_EAX)
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return key, cipher.nonce, tag, ciphertext


def decrypt_file(key, nonce, tag, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def encrypt_all_files():
    # Create encrypted folder if don't exist
    os.makedirs(encrypted_folder_path, exist_ok=True)
    # Encrypt multiple files
    global key_storage
    for filename in os.listdir(chunk_dir):
        filepath = os.path.join(chunk_dir, filename)
        if os.path.isfile(filepath):  # Skip subdirectories
            key, nonce, tag, ciphertext = encrypt_file(filepath)
            with open(os.path.join(encrypted_folder_path, f"{filename}.enc"), 'wb') as f:
                f.write(ciphertext)
            key_storage[filename] = {
                'key': key.hex(),
                'nonce': nonce.hex(),
                'tag': tag.hex()
            }

    # Save keys to a file
    with open('keys.json', 'w') as f:
        json.dump(key_storage, f)


def decrypt_all_files():
    # Create decrypted folder if don't exist
    os.makedirs(decrypted_folder_path, exist_ok=True)
    # Decrypt files (for demonstration)
    global key_storage
    with open('keys.json', 'r') as f:
        key_storage = json.load(f)

    for filename in key_storage.keys():
        enc_filepath = os.path.join(encrypted_folder_path, f"{filename}.enc")

        if os.path.isfile(enc_filepath):
            key_data = key_storage[filename]
            key = bytes.fromhex(key_data['key'])
            nonce = bytes.fromhex(key_data['nonce'])
            tag = bytes.fromhex(key_data['tag'])

            with open(enc_filepath, 'rb') as f:
                ciphertext = f.read()

            plaintext = decrypt_file(key, nonce, tag, ciphertext)

            # Prepending "decrypted_" to file name not needed
            with open(os.path.join(decrypted_folder_path, f"{filename}"), 'wb') as f:
                f.write(plaintext)


split_file(original_file_path, num_chunks=chunk_amount, random_size_for_each_chunk=random_chunk_sizes,
           random_name_for_each_chunk=random_chunk_names)

if encrypt_files:
    encrypt_all_files()
    join_folder = decrypted_folder_path
    decrypt_all_files()

join_file("metadata.txt", output_file_name="original_file.png")
