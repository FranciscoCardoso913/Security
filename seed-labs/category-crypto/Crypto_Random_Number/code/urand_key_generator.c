

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define LEN 16

int main() {
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
}
