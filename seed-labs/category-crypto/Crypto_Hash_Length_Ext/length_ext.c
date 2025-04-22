/* length_ext.c */

#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

int main(int argc, const char *argv[])
{
    int i;
    unsigned char buffer[SHA256_DIGEST_LENGTH];

    SHA256_CTX c;
    SHA256_Init(&c);

    for(i=0; i<64; i++)
        SHA256_Update(&c, "*", 1);

    // MAC of the original message M (padded)
    c.h[0] = htole32(0xc0725fc9);
    c.h[1] = htole32(0xf2eb89dc);
    c.h[2] = htole32(0x1b01ca78);
    c.h[3] = htole32(0x74c371b4);
    c.h[4] = htole32(0x5c0f0e71);
    c.h[5] = htole32(0xd3a3cd3e);
    c.h[6] = htole32(0x53bb465c);
    c.h[7] = htole32(0xb747f2a6);

    // Append additional message
    SHA256_Update(&c, "&download=secret.txt", 20);
    SHA256_Final(buffer, &c);
    
    for(i = 0; i < 32; i++) {
        printf("%02x", buffer[i]);
    }

    printf("\n");
    return 0;
}