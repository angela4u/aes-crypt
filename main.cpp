#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>  // For memset

void handleErrors() {
    std::cerr << "An error occurred!" << std::endl;
    exit(1);
}

void aesEncrypt(const unsigned char* plaintext, int plaintext_len, std::vector<unsigned char>& ciphertext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    int len;
    int ciphertext_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    ciphertext.resize(plaintext_len + AES_BLOCK_SIZE);

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len) != 1)
        handleErrors();
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        handleErrors();
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);  // Resize to actual length
    EVP_CIPHER_CTX_free(ctx);
}

void aesDecrypt(const unsigned char* ciphertext, int ciphertext_len, std::vector<unsigned char>& plaintext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    int len;
    int plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    plaintext.resize(ciphertext_len);

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1)
        handleErrors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
        handleErrors();
    plaintext_len += len;

    plaintext.resize(plaintext_len);  // Resize to actual length
    EVP_CIPHER_CTX_free(ctx);
}

std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for reading." << std::endl;
        exit(1);
    }

    return std::vector<unsigned char>(std::istreambuf_iterator<char>(file), {});
}

void writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for writing." << std::endl;
        exit(1);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    unsigned char key[32];
    unsigned char iv[16];

    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Error generating key/IV." << std::endl;
        return 1;
    }

    std::string inputFilename = "input.txt";
    std::vector<unsigned char> plaintext = readFile(inputFilename);

    std::vector<unsigned char> ciphertext;
    aesEncrypt(plaintext.data(), plaintext.size(), ciphertext, key, iv);
    writeFile("encrypted.bin", ciphertext);

    std::vector<unsigned char> encryptedData = readFile("encrypted.bin");

    std::vector<unsigned char> decryptedText;
    aesDecrypt(encryptedData.data(), encryptedData.size(), decryptedText, key, iv);
    writeFile("decrypted.txt", decryptedText);

    std::cout << "File successfully encrypted and decrypted." << std::endl;

    // Zero out sensitive data in memory
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    return 0;
}
