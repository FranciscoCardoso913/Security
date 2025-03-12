# Pseudo Random Number Generation Lab

## Overview

This lab focuses on understanding the importance of secure random number generation for cryptographic applications. It explores why conventional random number generation methods, commonly used in simulations, are unsuitable for generating encryption keys. The lab demonstrates how insecure random number generation can lead to predictable keys, making encryption vulnerable to attacks. A standard approach to generating cryptographically secure pseudo-random numbers is introduced, along with an analysis of common mistakes made in real-world implementations. Additionally, the lab covers the use of system tools like /dev/random and /dev/urandom for secure key generation.

## Lab Tasks

### Generate Encryption Key in a Wrong Way

In this task, we created a C program to generate encryption keys using the time library function to obtain the current timestamp, which is then used as a seed for the srand function.

```c
#define KEYSIZE 16
int i;
char key[KEYSIZE];
printf("%lld\n", (long long) time(NULL));
srand (time(NULL)); 
for (i = 0; i< KEYSIZE; i++){
key[i] = rand()%256;
printf("%.2x", (unsigned char)key[i]);
}
printf("\n");

```
This approach is flawed because keys generated within the same second will be identical. Since `time(NULL)` returns the number of seconds since the Unix epoch, the seed remains constant for all executions occurring within the same second. As a result, the output is highly predictable and vulnerable to brute-force attacks.

```sh
$ ./key_generator && ./key_generator && ./key_generator     

1741709354
39432fc58c2363be789ffd2d16eab3ed
1741709354
39432fc58c2363be789ffd2d16eab3ed
1741709354
39432fc58c2363be789ffd2d16eab3ed
```
This demonstrates that relying on time(NULL) for randomness in cryptographic applications is insecure, as an attacker can easily reproduce the same keys by guessing or knowing the timestamp.

### Guessing the Key

This task demonstrates why the previously implemented key generation method is insecure by simulating an attack.

We assume access to an encrypted PDF file created on 2018-04-17 23:08:49. From the file metadata, we know that it is encrypted using the AES-128-CBC algorithm, which operates on 16-byte blocks. Additionally, by analyzing the PDF structure, we can determine that the first 16 bytes of plaintext are 255044462d312e350a25d0d4c5d80a34, and we also have the corresponding ciphertext d06bf9d0dab8e8ef880660d2af65aa82. Since the IV is not encrypted in CBC mode, we know that it is 09080706050403020100A2B2C2D2E2F2.

Given that the encryption key was likely generated within a few hours before the file’s creation, we can brute-force the key by iterating over all possible timestamps within this range. The attack works by:

- Generating potential keys using the flawed key generation program for each second in the given time window.
- Using each generated key and the known IV to encrypt the first 16 bytes of plaintext.
- Comparing the resulting ciphertext with the known encrypted value.
- If a match is found, the correct key is identified, allowing us to decrypt the entire PDF.

The following brute-force program implements this attack:

```c
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

```
Code execution:

```sh
$ ./key_finder                                                                                 

Starting brute force search...
Trying seed 1524000000...
Trying seed 1524010000...

Key Found! ✅
Key: 95fa2030e73ed3f8da761b4eb805dfd7
Computed Ciphertext: d06bf9d0dab8e8ef880660d2af65aa82
Expected  Ciphertext: d06bf9d0dab8e8ef880660d2af65aa82

```

This demonstrates that using time(NULL) as a seed for encryption key generation makes it trivial for an attacker to recover the key, reinforcing the need for cryptographically secure random number generation methods.

### Measure the Entropy of Kernel

To analyze how the Linux kernel gathers randomness, we monitored the available entropy using the watch command. Initially, we observed that entropy changes on its own. However, interacting with the system,such as moving the mouse or typing caused the entropy value to change more rapidly.

### Get Pseudo Random Numbers from /dev/random

To analyze how `/dev/random` operates, we continuously read from it while monitoring entropy levels. Initially, without user input, entropy gradually decreased until `/dev/random` blocked, waiting for more randomness. When we moved the mouse or typed, the entropy increased, allowing `/dev/random` to continue generating output. This demonstrates how `/dev/random` depends on system activity for randomness.  

A Denial-of-Service (DoS) attack could be launched against a server using `/dev/random` for session keys by continuously draining its entropy pool. If the pool is exhausted and not replenished quickly, the server would be forced to wait, delaying or blocking cryptographic operations.

### Get Random Numbers from /dev/urandom
In this task, we observed the behavior of /dev/urandom, which provides continuous pseudo-random numbers without blocking.
We started by generating 1MB of pseudo-random numbers and analyzed their quality using the ent tool:

```sh
$ head -c 1M /dev/urandom > output.bin
$ ent output.bin

```

The ent tool results showed that the randomness was statistically adequate, indicating that the numbers are suitable for non-secure applications like session keys, though /dev/random remains a more secure option for cryptographic purposes due to its reliance on entropy sources.

We then developed the following program that uses `/dev/urandom` to generate random keys.

```c
#define LEN 16
unsigned char *key = (unsigned char *)malloc(LEN);
FILE *random = fopen("/dev/urandom", "r");
fread(key, 1, LEN, random);

fclose(random);

printf("Generated Key: ");
for (int i = 0; i < LEN; i++) {
    printf("%02x", key[i]);  // Print as hex
}
printf("\n");

free(key);
return 0;

```

```sh
$ ./urand_key_generator && ./urand_key_generator && ./urand_key_generator  

Generated Key: 957573193318b8b7c42f1224f8440621
Generated Key: bbee994956d34f5cd8c2a4961bbda1b1
Generated Key: 4a79818f878be98039ee7831b04c9e13

```
The output of the key generation was consistent, and moving the mouse or performing other activities did not affect the result, as /dev/urandom does not rely on system entropy in the same way as /dev/random.

