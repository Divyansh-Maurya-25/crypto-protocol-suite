// ----------------------------------------------------
// Names : Jacob Moran, Anthony Lozbin, Divyansh Maurya
//                      Group : 9
//                     Homework #6
// ----------------------------------------------------
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tomcrypt.h>
#include <gmp.h>

typedef unsigned __int128 __uint128_t;

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
unsigned char* Read_File(char fileName[], int *fileLen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
__uint128_t Convert_to_128(unsigned char a[]);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void Strip_Whitespace(unsigned char *str, int len);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main(int argc, char *argv[]) \
{
    // 1. Input Validation & Setup
    if (argc != 3) 
    {
        printf("Please use Message.txt and SharedSeed.txt files. Try again.");
        return 1;
    }

    // 2. Message Processing
    int raw_message_len;    
    unsigned char* raw_message = Read_File(argv[1], &raw_message_len);

    // Stripping spaces, tabs, newlines, and returns and creating a fresh copy.
    Strip_Whitespace(raw_message, raw_message_len);
    int strip_message_len = strlen((char*) raw_message);
    unsigned char* strip_message = malloc(strip_message_len);
    memcpy(strip_message, raw_message, strip_message_len);

    // Calculating padded length to ensure messge length is multiple of 8 bytes.
    int pad_len = ((strip_message_len + 7) / 8) * 8;
    unsigned char* pad_message = calloc(pad_len, 1);
    memcpy(pad_message, strip_message, strip_message_len);

    // 3. Seed Preprocessing
    int raw_seed_len;
    unsigned char* raw_seed = Read_File(argv[2], &raw_seed_len);

    // Stripping spaces, tabs, newlines, and returns and creating a fresh copy.
    Strip_Whitespace(raw_seed, raw_seed_len);
    int strip_seed_len = strlen((char*) raw_seed);
    unsigned char* strip_seed = malloc(strip_seed_len);
    memcpy(strip_seed, raw_seed, strip_seed_len);

    // 4. Message Block Conversion
    int num_blocks = pad_len / 8;
    __uint128_t* msg_blocks = malloc(num_blocks * sizeof(__uint128_t));
    for (int i = 0; i < num_blocks; ++i)
    {
        __uint128_t val = 0;
        for (int j = 0; j < 8; ++j)
        {
            val = (val << 8) | pad_message[i * 8 + j];
        }
        msg_blocks[i] = val;
    }

    // 5. Key Generation
    unsigned char* prng_output = PRNG(strip_seed, strip_seed_len, 2 * num_blocks * 8);
    __uint128_t* key_array = malloc(num_blocks * sizeof(__uint128_t));
    for (int i = 0; i < num_blocks; ++i)
    {
        __uint128_t a = 0, b = 0;
        for (int j = 0; j < 8; ++j)
        {
            // Converts the first 8 bytes to "a" starting with MSB.
            a = (a << 8) | prng_output[i * 16 + j];
            // Converts the next 8 bytes to "b" starting with MSB.
            b = (b << 8) | prng_output[i * 16 + 8 + j];
        }
        // a in upper 64 bits of array and b in lower 64 bits of array.
        key_array[i] = ((__uint128_t)a << 64) | b;
    }

    // 6. Prime Setup
    unsigned char q_bytes[16] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x43
    }; 

    __uint128_t q = Convert_to_128(q_bytes);
    __uint128_t sigma = 0;  // Initializing sigma

    // 7. LC-UMAC Computation
    for (int i = 0; i < num_blocks; ++i)
    {
        __uint128_t m = msg_blocks[i];
        __uint128_t a = key_array[i] >> 64;
        __uint128_t b = key_array[i] & 0xFFFFFFFFFFFFFFFFULL;

        __uint128_t term = (a * m + b) % q;
        sigma = (sigma + term) % q;

    }

    // 8. Format and Output Results
    unsigned char sigma_bytes[16];
    for (int i = 0; i < 16; ++i)
    {
        sigma_bytes[15 - i] = (sigma >> (i * 8)) & 0xFF;
    }

    // Writing sigma to file in Hex.
    char sigma_hex[33];
    Convert_to_Hex(sigma_hex, sigma_bytes, 16);
    FILE *out = fopen("LCUMAC_Intel.txt", "w");
    fprintf(out, "%s", sigma_hex);
    fclose(out);

    // Printing sigma.
    Show_in_Hex("LC-UMAC", sigma_bytes, 16);

    // 9. Cleanup
    free(raw_message);
    free(strip_message);
    free(raw_seed);
    free(strip_seed);
    free(msg_blocks);
    free(key_array);

    return 0;
}
// ----------------------------------------------------
//                  Function Definitions
// ----------------------------------------------------
unsigned char* Read_File(char fileName[], int *fileLen) {
    FILE *pFile;
    pFile = fopen(fileName, "r");
    if (pFile == NULL) {
        printf("Error opening file.\n");
        exit(0);
    }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
    fgets((char*)output, temp_size, pFile);
    fclose(pFile);

    *fileLen = temp_size-1;
    return output;
}

unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen) {
    int err;
    unsigned char *pseudoRandomNumber = (unsigned char*) malloc(prnlen);

    prng_state prng;
    if ((err = chacha20_prng_start(&prng)) != CRYPT_OK) {
        printf("Start error: %s\n", error_to_string(err));
    }
    if ((err = chacha20_prng_add_entropy(seed, seedlen, &prng)) != CRYPT_OK) {
        printf("Add_entropy error: %s\n", error_to_string(err));
    }
    if ((err = chacha20_prng_ready(&prng)) != CRYPT_OK) {
        printf("Ready error: %s\n", error_to_string(err));
    }
    chacha20_prng_read(pseudoRandomNumber, prnlen, &prng);
    
    if ((err = chacha20_prng_done(&prng)) != CRYPT_OK) {
        printf("Done error: %s\n", error_to_string(err));
    }

    return pseudoRandomNumber;
}

__uint128_t Convert_to_128(unsigned char a[]) {
    __uint128_t temp = 0;
    for(int i = 0; i < 16; i++) {
        temp = (temp << 8) | a[i];
    }
    return temp;
}

void Convert_to_Hex(char output[], unsigned char input[], int inputlength) {
    for (int i=0; i<inputlength; i++) {
        sprintf(&output[2*i], "%02x", input[i]);
    }
    output[inputlength*2] = '\0';
}

void Show_in_Hex(char name[], unsigned char hex[], int hexlen) {
    printf("%s: ", name);
    for (int i = 0; i < hexlen; i++)
        printf("%02x", hex[i]);
    printf("\n");
}

void Strip_Whitespace(unsigned char *str, int len) {
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (str[i] != ' ' && str[i] != '\t' && str[i] != '\n' && str[i] != '\r') {
            str[j++] = str[i];
        }
    }
    str[j] = '\0';
}