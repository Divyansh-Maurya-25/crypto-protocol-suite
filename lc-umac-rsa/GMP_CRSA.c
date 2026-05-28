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

#define NUM_BLOCKS 10  // 10 message blocks.
#define BLOCK_SIZE 19  // Message is 190 chararcters, 10 blocks = 19 character blocks.

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
void Read_RSA_Params(char* e_str, char* d_str, char* n_str);
unsigned char* Read_File(char fileName[], int *fileLen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main() {

    // Defining and obtaining e and (d, n).
    char e_str[2048], d_str[2048], n_str[2048];
    Read_RSA_Params(e_str, d_str, n_str);

    // Defining an initializing GMP integers.
    mpz_t e, d, n, sigma, H, S, temp;
    mpz_inits(e, d, n, sigma, H, S, temp, NULL);

    // Converting e, d, and n from string to GMP 2048-bit integers.
    mpz_set_str(e, e_str, 10);
    mpz_set_str(d, d_str, 16);
    mpz_set_str(n, n_str, 16);

    // Reading MessageRSA.txt and saving its length.
    int message_len;
    unsigned char *message = Read_File("MessageRSA.txt", &message_len);

    // Initializing sigma with 1.
    mpz_set_ui(sigma, 1);

    // RSA Multiplicative Homomorphism
    for (int i = 0; i < NUM_BLOCKS; ++i) 
    {
        // Obtaining characters for each block.
        char block[BLOCK_SIZE + 1] = {0};  
        strncpy(block, (char *)&message[i * BLOCK_SIZE], BLOCK_SIZE);

        // Hashing the block of characters.
        unsigned char *hash_value = Hash_SHA256((unsigned char *)block, BLOCK_SIZE);

        // Converting the hash to Hex from unsigned char and terminating with null terminator.
        char hash_hex[65];  
        Convert_to_Hex(hash_hex, hash_value, 32);
        hash_hex[64] = '\0';  

        // Converting hex hash to GMP integer.
        mpz_set_str(H, hash_hex, 16);

        // Signature (s) = Hash(m_i)^d mod n
        mpz_powm(S, H, d, n);

        // sigma = sigma * S mod n
        mpz_mul(temp, sigma, S);
        mpz_mod(sigma, temp, n);

        // Printing sigma
        gmp_printf("sigma[%d] = %Zx\n", i, sigma);

        // Memory Cleanup
        free(hash_value);
    }

    // Writing result to file.
    FILE *outFile = fopen("Result.txt", "w");
    if (outFile) {
        mpz_out_str(outFile, 16, sigma);
        fclose(outFile);
    }

    // Memory Cleanup
    mpz_clears(e, d, n, sigma, H, S, temp, NULL);
    free(message);

    return 0;
}

// ----------------------------------------------------
//                  Function Definitions
// ----------------------------------------------------
void Read_RSA_Params(char* e_str, char* d_str, char* n_str) {
    FILE *pFile = fopen("RSAParams.txt", "r");
    if (pFile == NULL) {
        printf("Error opening RSA parameters file.\n");
        exit(0);
    }
    
    // Read parameters with error checking
    if (fscanf(pFile, "e=%s\n", e_str) != 1 ||
        fscanf(pFile, "d=%s\n", d_str) != 1 ||
        fscanf(pFile, "n=%s\n", n_str) != 1) {
        printf("Error reading RSA parameters.\n");
        fclose(pFile);
        exit(0);
    }
    
    fclose(pFile);
}

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

unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen) {
    unsigned char *hash_result = (unsigned char*) malloc(32);
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, input, inputlen);
    sha256_done(&md, hash_result);
    return hash_result;
}

void Convert_to_Hex(char output[], unsigned char input[], int inputlength) {
    for (int i=0; i<inputlength; i++) {
        sprintf(&output[2*i], "%02x", input[i]);
    }
    output[inputlength*2] = '\0';
}