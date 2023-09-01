# File Splitter and Joiner

## Overview
The File Splitter and Joiner is a Python program designed to break a single large file into multiple smaller chunks, which can later be joined to reconstruct the original file. This utility provides multiple customization options for users and has built-in support for encryption and hashing features. The created chunk names and sizes can be randomly generated and the amount of chunk files can be given as an argument. The optional encryption feature allows the chunks to be encrypted and decrypted with different keys using AES-GCM. A key file will be created during the encryption process, which can be used to decrypt the file later. The created chunks will be stored in a newly created chunks folder. The example-image.png file can be used to test the program. The joined chunks are combined to a single file under the name original-file to create the original file.

## Features

### File Splitting
- **Number of Chunks**: Specify the number of chunks to create.
- **Variable Chunk Size**: Optionally, create chunks with random sizes.
- **File Naming Convention**: Choose between sequential naming and random unique naming for the file chunks.

### File Joining
- **Metadata Handling**: The program creates a metadata file with the hash of the file name and size for each chunk.
- **Ordered Reassembly**: The utility uses metadata to reassemble the chunks in the correct order.

### Security
- **Hashing**: The program hashes each metadata entry using SHA-256 to not to use the chunk names in plaintext in the metadata file.
- **(Optional) Encryption**: Uses AES-GCM algorithm to encrypt each chunk with a unique key, stored in a separate key file.

## Dependencies
- Python 3.x
- hashlib
- pycryptodome

## How to Use

### Installation
1. Clone the repository
    ```bash
    git clone https://github.com/egegirit/file-scrambler.git
    ```
2. Change directory to the cloned repository
    ```bash
    cd file-scrambler
    ```

## Contributing
Feel free to fork the project and submit a pull request with your changes!
