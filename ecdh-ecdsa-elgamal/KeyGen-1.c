// ----------------------------------------------------
// Names : Jacob Moran, Anthony Lozbin, Divyansh Maurya
//                      Group : 9
//                     Homework #5
// ----------------------------------------------------
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main (int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("Please include only a seed.txt file. Try again.");
        return 1;
    }

    // Reading seed (full length)
    int seed_len;
    unsigned char* seed = Read_File(argv[1], &seed_len);

    // Hashing first 32 bytes of seed.
    unsigned char secret_key[32];
    SHA256(seed, 32, secret_key);

    // Creating EC_GROUP and group generator
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp192k1);
    const EC_POINT *G = EC_POINT_new(ec_group);
    G = EC_GROUP_get0_generator(ec_group);

    // Creating BIGNUM Context
    BN_CTX *bn_ctx = BN_CTX_new();

    // Converting hashed seed (SK) to hex
    char hex_sk[65];
    Convert_to_Hex(hex_sk, secret_key, 32);

    // Converting Hex SK to BIGNUM
    BIGNUM* bn_sk = NULL;
    BN_hex2bn(&bn_sk, hex_sk);

    // PK = y * G where y is the SK
    EC_POINT *pk = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, pk, bn_sk, NULL, NULL, bn_ctx);

    // Converting PK from EC_POINT to Hex and writing both SK and PK to respective files.
    char* pk_hex = EC_POINT_point2hex(ec_group, pk, EC_GROUP_get_point_conversion_form(ec_group), bn_ctx);
    Write_File("PK_Hex.txt", pk_hex);
    Write_File("SK_Hex.txt", hex_sk);

    // Memory Cleanup
    OPENSSL_free(pk_hex);
    EC_POINT_free(pk);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(ec_group);

    return 0;
}
// ----------------------------------------------------
//                  Function Definitions
// ----------------------------------------------------
char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    char *output = (char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

void Write_File(char fileName[], char input[])
{
    FILE *pFile;
    pFile = fopen(fileName,"w");
    if (pFile == NULL){
      printf("Error opening file. \n");
      exit(0);
    }
    fputs(input, pFile);
    fclose(pFile);
}

void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
}