#include <openssl/evp.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>
#include <vector>

// Funkcja do obsługi błędów / Error handling function
void handleErrors() {
    std::cerr << "Wystąpił błąd!" << std::endl;
    exit(1);
}

// Funkcja do szyfrowania AES / AES encryption function
void aesEncrypt(const unsigned char* plaintext, unsigned char* ciphertext, int plaintext_len, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Tworzymy nowy kontekst szyfrowania / Creating a new encryption context
    if (!ctx) handleErrors();

    int len;
    int ciphertext_len;

    // Inicjalizacja szyfrowania AES CBC / Initialize AES CBC encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    // Szyfrowanie danych / Encrypt data
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        handleErrors();
    ciphertext_len = len;

    // Zakończenie szyfrowania / Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);  // Zwolnienie pamięci kontekstu / Free the encryption context
}

// Funkcja do odszyfrowania AES / AES decryption function
void aesDecrypt(const unsigned char* ciphertext, unsigned char* plaintext, int ciphertext_len, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Tworzymy nowy kontekst odszyfrowania / Creating a new decryption context
    if (!ctx) handleErrors();

    int len;
    int plaintext_len;

    // Inicjalizacja odszyfrowania AES CBC / Initialize AES CBC decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    // Odszyfrowanie danych / Decrypt data
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        handleErrors();
    plaintext_len = len;

    // Zakończenie odszyfrowania / Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);  // Zwolnienie pamięci kontekstu / Free the decryption context
}

// Funkcja do odczytu pliku w trybie binarnym / Function to read a file in binary mode
std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Błąd otwarcia pliku do odczytu." << std::endl;
        exit(1);
    }

    // Zwracamy zawartość pliku jako wektor bajtów / Return file content as a vector of bytes
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(file), {});
}

// Funkcja do zapisu pliku w trybie binarnym / Function to write a file in binary mode
void writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Błąd otwarcia pliku do zapisu." << std::endl;
        exit(1);
    }
    // Zapisujemy wektor bajtów do pliku / Write vector of bytes to file
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    // Klucz i wektor inicjalizacyjny (IV) dla AES / AES key and initialization vector (IV)
    unsigned char key[32] = "01234567890123456789012345678901"; // 32 bajty / 32 bytes
    unsigned char iv[16] = "0123456789012345"; // 16 bajtów / 16 bytes

    // Odczyt pliku wejściowego / Read the input file
    std::string inputFilename = "input.txt";
    std::vector<unsigned char> plaintext = readFile(inputFilename);

    // Bufor do przechowywania zaszyfrowanych danych / Buffer to store encrypted data
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);

    // Szyfrowanie pliku / Encrypt the file
    aesEncrypt(plaintext.data(), ciphertext.data(), plaintext.size(), key, iv);

    // Zapis zaszyfrowanych danych do pliku / Write encrypted data to file
    writeFile("encrypted.bin", ciphertext);

    // Odczyt zaszyfrowanego pliku do odszyfrowania / Read encrypted file for decryption
    std::vector<unsigned char> encryptedData = readFile("encrypted.bin");

    // Bufor do przechowywania odszyfrowanego tekstu / Buffer to store decrypted data
    std::vector<unsigned char> decryptedText(encryptedData.size());

    // Odszyfrowanie pliku / Decrypt the file
    aesDecrypt(encryptedData.data(), decryptedText.data(), encryptedData.size(), key, iv);

    // Zapis odszyfrowanych danych do pliku / Write decrypted data to file
    writeFile("decrypted.txt", decryptedText);

    std::cout << "Plik został pomyślnie zaszyfrowany i odszyfrowany." << std::endl;
    return 0;
}
