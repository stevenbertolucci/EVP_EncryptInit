// Author: Steven Bertolucci
// Course: CS370 - Introduction to Security
// Assignment: Project 1 - 3.4 Programming Project
// Due Date: 10/20/24
// -----------------------------------------------------------------------------------------
//  Citations:
//
//  The C code below for do_crypt() function was copied from OpenSSL's documentation
//  which can be found here: https://docs.openssl.org/3.1/man3/EVP_EncryptInit/#examples
//  I modified it a little bit because I was using local arrays to pass on to the function
//  as parameters instead of File I/0. 
//
//  The link to this documentation was also provided via the Project's PDF document. 
//
//  Helper 3.4 provided students with code to convert hex to binary, but it was in python. 
//  My code is in C, so I researched online and found how to convert hex to binary in C
//  from StackOverflow. The link is: 
//  https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c 
//  and the author to this conversion is Michael F. 
// -----------------------------------------------------------------------------------------

#include <openssl/evp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int decrypted_len;
int buffer_len;

// See citation section. I modified the some of the code because the sample code uses File I/O. I wanted to use local 
// variables that contains the value of the ciphertext and plaintext.
// Citation fro the following functions:
// Date: 10/13/2024
// Copied and adapted from:
// Source URL: https://docs.openssl.org/3.1/man3/EVP_EncryptInit/#examples
int do_crypt(char *inbuf, size_t inlen, char *out, int do_encrypt, const char *key, const char *iv) {

    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outlen, finalLen;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    if (!EVP_CipherInit_ex2(ctx, EVP_aes_128_cbc(), key, iv, do_encrypt, NULL)) {
        /* ERROR */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    size_t buffer_len = 0;

    if (!EVP_CipherUpdate(ctx, out, &outlen, inbuf, inlen)) {
        /* ERROR */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    buffer_len += outlen;

    if (!EVP_CipherFinal_ex(ctx, out + buffer_len, &finalLen)) {
        /* ERROR */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    buffer_len += finalLen;
    decrypted_len = buffer_len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// Function to try decrypting with each key
void find_key(char *wordlist, char *ciphertext, char *plaintext, int ciphertext_len) {

    // Variables
    FILE *wordList;
    char word[17];
    char key[16];
    // Initialize the byte array with 16 zeros
    char iv[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    char decrypted_text[17];

    // Terminal texts
    printf("Opening the words list file...\n\n");
    // Open the word list file for reading
    wordList = fopen(wordlist, "r");
    
    // Error checking to make sure that the word list exists. 
    if (wordList == NULL) {
        perror("Failed to open word list file");
        exit(EXIT_FAILURE);
    }

    // Terminal texts
    printf("Iterating through the words list and decrypting the ciphertext with the current word...\n\n");

    // Looping through the word list
    while (fgets(word, sizeof(word), wordList) != NULL) {

        // Get the word length
        int length = strlen(word);

        // printf("Word Length: %d\n", length);

        // Key is an English word with less than 16 characters
        // I didn't see any word that is more than 16 characters,
        // but created this check anyway to speed up time
        if (length > 16) {
            continue;
        }

        // printf("Word: %s", word);
        //printf("\n");

        // Replace newline with null terminator
        if (word[length - 1] == '\n') 
            word[length - 1] = 0;

        // printf("Word: %s", word);
        // printf("\n");

        // Initialize key with spaces
        for (int i = 0; i < sizeof(key); i++) {
            key[i] = 0x20;
        }

        // printf("Key: %s", key);

        // Copy the word over to the key for decryption
        for (int i = 0; i < strlen(word); i++) {
            key[i] = word[i];
        }

        // Decrypting the ciphertext
        if (do_crypt(ciphertext, ciphertext_len, decrypted_text, 0, key, iv) == 1) {

            // Null terminate the string
            decrypted_text[decrypted_len] = '\0';

            // printf("Decrypted text: %s\n", decrypted_text);

            // Check if string matches
            if (strcmp((char *)decrypted_text, plaintext) == 0) {
                printf("Key found: %s\n", word);
                break;
            }
        }
    }

    fclose(wordList);
}

int main() {

    char *plaintext = "This is a top secret.";
    char *ciphertext_hex = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
    char ciphertext[32];
    int ciphertext_length = sizeof(ciphertext);

    // Convert hex to binary.
    // Citation for the following code snippet:
    // Date: 10/16/2024
    // Copied and adapted from:
    // Source URL: https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
    for (size_t count = 0; count < sizeof(ciphertext); count++) {
        sscanf(&ciphertext_hex[2 * count], "%2hhx", &ciphertext[count]);
    }

    // printf(ciphertext);
    // printf("\n");

    // Terminal Text
    printf("Sucessfully converted the ciphertext hex to binary...\n\n");

    // Find the key
    find_key("words.txt", ciphertext, plaintext, sizeof(ciphertext));

    return 0;
}