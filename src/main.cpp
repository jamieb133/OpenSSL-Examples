#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string>
#include <string.h>

#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024

std::string char2str(unsigned char* arr, size_t size);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void handleErrors();

int main()
{
    std::cout << "Starting OpenSSL Example" << std::endl;

    unsigned char aes_key[AES_256_KEY_SIZE], iv[AES_256_KEY_SIZE];

    if (!RAND_bytes(aes_key, sizeof(aes_key)))
    { 
        std::cerr << "[ERROR] failed to generate AES key" << std::endl;
    }

    if (!RAND_bytes(iv, sizeof(iv)))
    {
        std::cerr << "[ERROR] failed to generate AES key" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "KEY: " << char2str(aes_key, sizeof(aes_key) / sizeof(char)) << std::endl;

    unsigned char* plaintext = (unsigned char*)"hello there";
    unsigned char ciphertext[256];
    unsigned char output[256];

    int decrypted_len, ciphertext_len;

    std::cout << std::endl;
    std::cout << "PLAINTEXT: " << char2str(plaintext, sizeof(plaintext) / sizeof(unsigned char)) << std::endl;

    ciphertext_len = encrypt(plaintext, strlen((char*)plaintext), aes_key, iv, ciphertext);

    std::cout << std::endl;
    std::cout << "CIPHERTEXT: " << char2str(ciphertext, ciphertext_len) << std::endl;

    decrypted_len = decrypt(ciphertext, ciphertext_len, aes_key, iv, output);

    std::cout << std::endl;
    std::cout << "DECRYPTED TEXT: " << char2str(output, decrypted_len) << std::endl;

    return 0;
}

std::string char2str(unsigned char* arr, size_t size)
{
    int length = size;
    std::string outString = "";
    for (int i = 0; i <= length + 2; i++)
    {
        outString += arr[i];
    }
    return outString;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    //create context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    //init encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    //provide data to be encrypted
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();

    ciphertext_len = len;

    //further ciphertext bytes may be written
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();

    ciphertext_len += len;

    //clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    //create context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    //init decryption
    if(1 !=  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    //provide data to be decrypted
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();

    plaintext_len = len;

    //further plaintext bytes may be written
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();

    plaintext_len += len;

    //clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void handleErrors()
{

}