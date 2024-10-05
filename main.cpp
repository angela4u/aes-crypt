#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>  // For memset

// Error handling function
void handleErrors() {
    std::cerr << "An error occurred!" << std::endl;
    exit(1);
}

// AES encryption function
void aesEncrypt(const unsigned char* plaintext, int plaintext_len, std::vector<unsigned char>& ciphertext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    int len;
    int ciphertext_len;

    // Initialize encryption operation (AES-256-CBC)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    // Resize the ciphertext buffer to accommodate potential padding
    ciphertext.resize(plaintext_len + AES_BLOCK_SIZE);

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len) != 1)
        handleErrors();
    ciphertext_len = len;

    // Finalize encryption (handles padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        handleErrors();
    ciphertext_len += len;

    // Resize ciphertext to actual length
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);  // Free the encryption context
}

// AES decryption function
void aesDecrypt(const unsigned char* ciphertext, int ciphertext_len, std::vector<unsigned char>& plaintext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    int len;
    int plaintext_len;

    // Initialize decryption operation (AES-256-CBC)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    // Resize the plaintext buffer to accommodate decrypted data
    plaintext.resize(ciphertext_len);

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1)
        handleErrors();
    plaintext_len = len;

    // Finalize decryption (handles padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
        handleErrors();
    plaintext_len += len;

    // Resize plaintext to actual length
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);  // Free the decryption context
}

// Function to read a file in binary mode
std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for reading." << std::endl;
        exit(1);
    }

    return std::vector<unsigned char>(std::istreambuf_iterator<char>(file), {});
}

// Function to write a file in binary mode
void writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for writing." << std::endl;
        exit(1);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    // Generate a random AES-256 key and IV
    unsigned char key[32];  // 32 bytes = 256 bits
    unsigned char iv[16];   // 16 bytes = 128 bits

    // Securely generate random bytes for key and IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Error generating key/IV." << std::endl;
        return 1;
    }

    // Read the input file (plaintext)
    std::string inputFilename = "input.txt";
    std::vector<unsigned char> plaintext = readFile(inputFilename);

    // Encrypt the plaintext
    std::vector<unsigned char> ciphertext;
    aesEncrypt(plaintext.data(), plaintext.size(), ciphertext, key, iv);

    // Write the encrypted data to a binary file
    writeFile("encrypted.bin", ciphertext);

    // Read the encrypted file for decryption
    std::vector<unsigned char> encryptedData = readFile("encrypted.bin");

    // Decrypt the encrypted data
    std::vector<unsigned char> decryptedText;
    aesDecrypt(encryptedData.data(), encryptedData.size(), decryptedText, key, iv);

    // Write the decrypted data to a file
    writeFile("decrypted.txt", decryptedText);

    std::cout << "File successfully encrypted and decrypted." << std::endl;

    // Securely zero out sensitive data (key and IV) from memory
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    return 0;
}
