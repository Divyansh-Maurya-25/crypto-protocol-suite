// ----------------------------------------------------
// Names : Jacob Moran, Anthony Lozbin, Divyansh Maurya
//                      Group : 9
//                     Homework #4
// ----------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

#define SEEDLEN 30  // 30 bytes of seed
#define ELEMENTBYTES 32  // element = 256 bits / 8 bits = 32 bytes
#define ROWS 2  // {0,1}
#define COLUMNS 256  // {0, 1, ... , 255}

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
unsigned char* Read_File(char fileName[], int *fileLen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main(int argc, char **argv)
{
    // Verifying comrrect number of arguements.
    if (argc != 2)
    {
        printf("Invalid number of arguments. Please include a seed.txt file.");
        return 1;
    }

    unsigned char* seed = Read_File(argv[1], NULL);  // seed read from file

    unsigned char* secretKey[ROWS][COLUMNS];
    unsigned char* publicKey[ROWS][COLUMNS];

    // generate SK elements using PRNG and PK elements using SHA256
    for (int i = 0; i < ROWS; i++)
    {
        for (int j = 0; j < COLUMNS; j++)
        {
            secretKey[i][j] = (unsigned char*) malloc(ELEMENTBYTES);  // memory allocated for each SK element
            if (secretKey[i][j] == NULL) {
                printf("Memory allocation failed for secretKey[%d][%d]\n", i, j);
                return 1;
            }

            publicKey[i][j] = (unsigned char*) malloc(ELEMENTBYTES);  // memory allocated for each PK element
            if (publicKey[i][j] == NULL) {
                printf("Memory allocation failed for publicKey[%d][%d]\n", i, j);
                return 1;
            }

            unsigned char inputSeed[SEEDLEN + 2];  // append two characters to end of seed
            memcpy(inputSeed, seed, SEEDLEN);  // 30 bytes of seed copied
            inputSeed[SEEDLEN] = i;  // append i at position 30
            inputSeed[SEEDLEN + 1] = j;  // append j at position 31

            unsigned char *data = PRNG(inputSeed, SEEDLEN + 2, ELEMENTBYTES);  // SK elements from PRNG function using seed
            memcpy(secretKey[i][j], data, ELEMENTBYTES);  // store SK element at i,j
            free(data);

            unsigned char *hashed = Hash_SHA256(secretKey[i][j], ELEMENTBYTES);  // PK elements from SHA256 hash function
            memcpy(publicKey[i][j], hashed, ELEMENTBYTES);  // store PK element at i,j
            free(hashed);
        }
    }

    FILE *skFile = fopen("SK.txt", "w");
    if (skFile == NULL) {
        printf("Error opening SK.txt\n");
        return 1;
    }

    FILE *pkFile = fopen("PK.txt", "w");
    if (pkFile == NULL) {
        printf("Error opening PK.txt\n");
        return 1;
    }

    int lineCount = 1;

    // write SK and PK elements to respective files in column-wise order
    for (int j = 0; j < COLUMNS; j++)
    {
        for (int i = 0; i < ROWS; i++)
        {
            char skHex[2 * ELEMENTBYTES + 1];  // buffer for SK hex (2 chars per byte + null terminator)
            char pkHex[2 * ELEMENTBYTES + 1];  // buffer for SK hex (2 chars per byte + null terminator)

            // convert SK and PK to hex
            Convert_to_Hex(skHex, secretKey[i][j], ELEMENTBYTES);
            Convert_to_Hex(pkHex, publicKey[i][j], ELEMENTBYTES);

            // write hex values to files
            if (lineCount != 512)
            {
            fprintf(skFile, "%s\n", skHex);
            fprintf(pkFile, "%s\n", pkHex);
            }
            else
            {
                fprintf(skFile, "%s", skHex);
                fprintf(pkFile, "%s", pkHex);
            }
            lineCount++;
            
        }
    }

    fclose(skFile);
    fclose(pkFile);
    free(seed);

    return 0;
}

// ----------------------------------------------------
//                  Function Definitions
// ----------------------------------------------------
unsigned char* Read_File(char fileName[], int *fileLen)
{
    FILE *pFile;
    pFile = fopen(fileName, "r");
    if (pFile == NULL)
    {
        printf("Error opening file.\n");
        exit(0);
    }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile);
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size + 1); // Add 1 for null termination
    fread(output, 1, temp_size, pFile);  // Read the whole file
    output[temp_size] = '\0';  // Null terminate
    fclose(pFile);

    if (fileLen != NULL)
        *fileLen = temp_size;

    return output;
}

unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen)
{
    int err;
    unsigned char *pseudoRandomNumber = (unsigned char*) malloc(prnlen);
    if (pseudoRandomNumber == NULL) {
        printf("Memory allocation failed for PRNG\n");
        exit(1);
    }

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

unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash_result = (unsigned char*) malloc(inputlen);
    if (hash_result == NULL) {
        printf("Memory allocation failed for SHA256\n");
        exit(1);
    }

    hash_state md;
    sha256_init(&md);
    sha256_process(&md, (const unsigned char*)input, inputlen);
    sha256_done(&md, hash_result);

    return hash_result;
}

void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}
