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

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
unsigned char* Read_File(char fileName[], int *fileLen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main (int argc, char* argv[])
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
    int n = (raw_message_len + 31) / 32;
    
    // Creating zero padded message blocks.
    unsigned char* msgs = calloc(n, 32);
    memcpy(msgs, raw_message, raw_message_len);

    // 3. Seed Processing
    int raw_seed_len;
    unsigned char* raw_seed = Read_File(argv[2], &raw_seed_len);
    
    // Handling seed length variety.
    unsigned char* seed = calloc(1, 32);
    int seed_len = raw_seed_len < 32 ? raw_seed_len : 32;
    memcpy(seed, raw_seed, seed_len);

    // 4. Random Number Generation
    unsigned char* ab = PRNG(seed, 32, 2 * n * 32);

    // 5. GMP Variable Initialization
    mpz_t q, sig;
    mpz_inits(q, sig, NULL);
    mpz_set_str(q, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    
    // 6. LC-UMAC Computation
    for (int i = 0; i < n; ++i)
    {
        // Initializing block variables.
        mpz_t a, b, m, x;
        mpz_inits(a, b, m, x, NULL);

        // Buffer for hex conversions.
        char hex_buf[32 * 2 + 1];

        // Converting a_i to GMP integer.
        Convert_to_Hex(hex_buf, &ab[i * 64], 32);
        mpz_set_str(a, hex_buf, 16);

        // Converting b_i to GMP integer.
        Convert_to_Hex(hex_buf, &ab[i * 64 + 32], 32);
        mpz_set_str(b, hex_buf, 16);

        // Converting m_i to GMP integer.
        Convert_to_Hex(hex_buf, &msgs[i * 32], 32);
        mpz_set_str(m, hex_buf, 16);

        // x = (a * m) % q
        mpz_mul(x, a, m);
        mpz_mod(x, x, q);

        // x = (x + b) % q
        mpz_add(x, x, b);
        mpz_mod(x, x, q);

        // Update Sigma
        mpz_add(sig, sig, x);
        mpz_mod(sig, sig, q);

        // Free Block Variables
        mpz_clears(a, b, m, x, NULL);
    }

    // 7. Output Processing
    // Writing result to file.
    FILE *out = fopen("LCUMAC_GMP.txt", "w");
    mpz_out_str(out, 16, sig);
    fclose(out);

    // Pritning sig.
    mpz_out_str(stdout, 16, sig);

    // 8. Cleanup
    mpz_clears(q, sig, NULL);
    free(raw_message);
    free(msgs);
    free(raw_seed);
    free(seed);
    free(ab);

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

void Convert_to_Hex(char output[], unsigned char input[], int inputlength) {
    for (int i=0; i<inputlength; i++) {
        sprintf(&output[2*i], "%02x", input[i]);
    }
    output[inputlength*2] = '\0';
}