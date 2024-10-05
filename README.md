# AES-256-CBC Encryption and Decryption with OpenSSL

This project demonstrates how to securely encrypt and decrypt files using the AES-256-CBC encryption algorithm from the OpenSSL library. The code is written in C++ and handles random key and IV generation, secure encryption, decryption, and safe file handling.

## Features

- **AES-256-CBC Encryption**: Secure encryption using a 256-bit key and CBC mode.
- **Random Key and IV Generation**: Secure random bytes are generated for both the AES key and initialization vector (IV).
- **File Handling**: Binary-safe reading and writing of both plaintext and ciphertext files.
- **Error Handling**: Graceful error handling and program exit in case of failure.
- **Sensitive Data Cleanup**: Key and IV are securely wiped from memory after use.

## Requirements

- **OpenSSL**: Ensure that you have OpenSSL installed on your system. OpenSSL provides the cryptographic functionality for this project.
- **C++ Compiler**: A C++ compiler that supports C++11 or later.

### Install OpenSSL (Linux/macOS)
If OpenSSL is not already installed, you can install it via the following commands:

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

#### macOS (using Homebrew):
```bash
brew install openssl
```

### Install OpenSSL (Windows)
For Windows, you can download and install OpenSSL from:
[https://slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)

Make sure to add OpenSSL to your system's PATH or set up the include and lib directories correctly in your project.

## How to Build and Run

1. **Clone or Download the Project**  
   Clone the project repository to your local machine or download it as a zip file.

2. **Compile the Program**  
   Compile the C++ code using your preferred compiler. Make sure to link against the OpenSSL library.

   Example compile command on Linux/macOS:
   ```bash
   g++ -o aes_encryption aes_encryption.cpp -lssl -lcrypto
   ```

   On Windows (with MinGW):
   ```bash
   g++ -o aes_encryption aes_encryption.cpp -lssl -lcrypto -lws2_32 -lgdi32
   ```

3. **Prepare an Input File**  
   Create an `input.txt` file with the content you want to encrypt.

4. **Run the Program**  
   After compiling, run the program:

   ```bash
   ./aes_encryption
   ```

   The program will:
   - Encrypt the contents of `input.txt` and store the encrypted data in `encrypted.bin`.
   - Decrypt `encrypted.bin` and store the decrypted data in `decrypted.txt`.

5. **Verify the Output**  
   Compare the contents of `input.txt` and `decrypted.txt`. They should be identical if the encryption and decryption processes were successful.

## File Structure

- `aes_encryption.cpp`: The main C++ file that implements AES encryption and decryption.
- `input.txt`: The plaintext file to be encrypted.
- `encrypted.bin`: The binary file that holds the encrypted ciphertext.
- `decrypted.txt`: The file containing the decrypted plaintext after decryption.

## Example Usage

1. **Create the `input.txt` file**:
   Create a simple text file named `input.txt` with any content you'd like to encrypt.

2. **Run the program**:
   After compilation, running the program will automatically:
   - Encrypt `input.txt` into `encrypted.bin`.
   - Decrypt `encrypted.bin` back into `decrypted.txt`.

3. **Check the Results**:
   Ensure that the contents of `decrypted.txt` match the original content in `input.txt`.

## Notes

- The encryption uses AES-256 in CBC mode, which provides strong security but does not include authentication. For authenticated encryption, consider using AES-GCM or AES-CCM modes.
- This program is for demonstration purposes and should be adapted and enhanced for production use, especially regarding secure key management, error handling, and file integrity checks.

## Security Considerations

- **Key Management**: Ensure that keys are stored securely and never hardcoded in production environments. Use proper key management systems.
- **Padding Oracles**: CBC mode can be vulnerable to padding oracle attacks if implemented incorrectly. Always use a secure padding method.
- **Authenticated Encryption**: If integrity is a concern, consider using AES-GCM, which provides both encryption and integrity checking.
