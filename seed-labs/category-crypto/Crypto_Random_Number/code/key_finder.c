#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>

#define KEYSIZE 16
#define AES_BLOCK_SIZE 16

// Convert hex string to byte array
void hex_to_bytes(const char *hex, unsigned char *bytes) {
    for (size_t i = 0; i < KEYSIZE; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// XOR function for IV and plaintext
void xor_blocks(const unsigned char *block1, const unsigned char *block2, unsigned char *out) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        out[i] = block1[i] ^ block2[i];
    }
}

// Encrypt one block using AES-128-ECB (without padding)
int aes_128_ecb_encrypt(const unsigned char *key, const unsigned char *input_block, unsigned char *output_block) {
    EVP_CIPHER_CTX *ctx;
    int len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        perror("EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_EncryptUpdate(ctx, output_block, &len, input_block, AES_BLOCK_SIZE) != 1) {
        perror("EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return len;
}

// Convert byte array to hex string
void bytes_to_hex(const unsigned char *bytes, char *hex) {
    for (size_t i = 0; i < KEYSIZE; i++) {
        sprintf(hex + 2 * i, "%02x", bytes[i]);
    }
    hex[2 * KEYSIZE] = '\0'; // Null-terminate
}

int main() {
    const char *iv_hex = "09080706050403020100A2B2C2D2E2F2";
    const char *plaintext_hex = "255044462d312e350a25d0d4c5d80a34";
    const char *expected_ciphertext_hex = "d06bf9d0dab8e8ef880660d2af65aa82";

    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext_block[AES_BLOCK_SIZE];
    unsigned char xor_result[AES_BLOCK_SIZE];
    unsigned char ciphertext_block[AES_BLOCK_SIZE];
    char computed_ciphertext_hex[2 * AES_BLOCK_SIZE + 1];

    // Convert hex strings to byte arrays
    hex_to_bytes(iv_hex, iv);
    hex_to_bytes(plaintext_hex, plaintext_block);

    printf("Starting brute force search...\n");

    // Try different seeds to find the correct key
    for (long t = 1523992129; t < 1525002929; t++) {
        unsigned char key[KEYSIZE];
        char key_hex[2 * KEYSIZE + 1];

        srand(t);
        for (int i = 0; i < KEYSIZE; i++) {
            key[i] = rand() % 256;
        }
        
        // Convert key to hex string
        bytes_to_hex(key, key_hex);

        // Step 1: XOR plaintext with IV
        xor_blocks(plaintext_block, iv, xor_result);
        
        // Step 2: Encrypt with AES-128-ECB
        int ciphertext_len = aes_128_ecb_encrypt(key, xor_result, ciphertext_block);
        if (ciphertext_len > 0) {
            // Convert computed ciphertext to hex string
            bytes_to_hex(ciphertext_block, computed_ciphertext_hex);
            
            if (strcmp(computed_ciphertext_hex, expected_ciphertext_hex) == 0) {
                printf("\nKey Found! ✅\n");
                printf("Key: %s\n", key_hex);
                printf("Computed Ciphertext: %s\n", computed_ciphertext_hex);
                printf("Expected  Ciphertext: %s\n", expected_ciphertext_hex);
                return 0;
            }
        }

        // Progress indication every 10,000 iterations
        if (t % 10000 == 0) {
            printf("Trying seed %ld...\n", t);
        }
    }

    printf("Key not found in the given range.\n");
    return 1;
}
