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

    if (argc != 4)
    {
        printf("Please include the SK_Hex.txt, C_Hex.txt, and D_Hex.txt file. Try again.");
        return 1;
    }

    // Reading C, D, and PK (SK).
    int C_len, D_len, SK_len;
    char* C = Read_File(argv[2], &C_len);
    char* D = Read_File(argv[3], &D_len);
    char* sk = Read_File(argv[1], &SK_len);

    // Creating EC_GROUP and BIGNUM Context
    EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_secp192k1);
    BN_CTX* bn_ctx = BN_CTX_new();

    // Converting SK to BIGNUM
    BIGNUM* bn_sk = NULL;
    BN_hex2bn(&bn_sk, sk);

    // Converting C and D from Hex to EC_POINT
    EC_POINT* C_point = EC_POINT_hex2point(ec_group, C, NULL, bn_ctx);
    EC_POINT* D_point = EC_POINT_hex2point(ec_group, D, NULL, bn_ctx);

    // C' = y * C where y = SK
    EC_POINT* C_prime = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, C_prime, NULL, C_point, bn_sk, bn_ctx);

    // Converting C' to -C'
    EC_POINT_invert(ec_group, C_prime, bn_ctx);

    // P_m = D + (-C')
    EC_POINT* message_point = EC_POINT_new(ec_group);
    EC_POINT_add(ec_group, message_point, D_point, C_prime, bn_ctx);

    // Converting message from EC_POINT to Hex and writing to plaintext file.
    char* message_hex = EC_POINT_point2hex(ec_group, message_point, EC_GROUP_get_point_conversion_form(ec_group), bn_ctx);
    Write_File("Plaintext.txt", message_hex);
    
    // Memory Cleanup
    EC_POINT_free(C_point);
    EC_POINT_free(D_point);
    EC_POINT_free(C_prime);
    EC_POINT_free(message_point);
    BN_free(bn_sk);
    BN_CTX_free(bn_ctx);
    OPENSSL_free(message_hex);
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