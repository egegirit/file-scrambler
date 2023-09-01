# File Splitter and Joiner

## Overview
The File Splitter and Joiner is a Python program designed to break a single large file into multiple smaller chunks, which can later be joined to reconstruct the original file. This utility provides multiple customization options for users and has built-in support for encryption and hashing features.

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
