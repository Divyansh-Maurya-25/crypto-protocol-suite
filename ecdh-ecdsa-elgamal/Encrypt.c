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
        printf("Please include a Message.txt file, PK_Hex.txt file, as well as a random_k_Hex.txt file. Try again.");
        return 1;
    }

    // Reading Message, PK, and random num k
    int random_len, message_len, pk_len;
    char* random_k = Read_File(argv[3], &random_len);
    char* message = Read_File(argv[1], &message_len);
    char* pk = Read_File(argv[2], &pk_len);

    // Creating EC_GROUP and BIGNUM Context
    EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_secp192k1);
    BN_CTX* bn_ctx = BN_CTX_new();

    // Converting random number k to BIGNUM
    BIGNUM* k = NULL;
    BN_hex2bn(&k, random_k);

    // Converting PK from Hex to EC_POINT
    EC_POINT* pk_point = EC_POINT_hex2point(ec_group, pk, NULL, bn_ctx);

    // C = k * G
    EC_POINT* C = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, C, k, NULL, NULL, bn_ctx);

    // C' = k * Y where Y is the PK
    EC_POINT* C_prime = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, C_prime, NULL, pk_point, k, bn_ctx);

    // Converting message from Hex to EC_POINT
    EC_POINT* message_point = EC_POINT_hex2point(ec_group, message, NULL, bn_ctx);

    // D = C' + P_m where P_m is the message
    EC_POINT* D = EC_POINT_new(ec_group);
    EC_POINT_add(ec_group, D, C_prime, message_point, bn_ctx);

    // Converting C and D from EC_POINT to Hex and writing to respective text files.
    char* C_hex = EC_POINT_point2hex(ec_group, C, EC_GROUP_get_point_conversion_form(ec_group), bn_ctx);
    char* D_hex = EC_POINT_point2hex(ec_group, D, EC_GROUP_get_point_conversion_form(ec_group), bn_ctx);

    Write_File("C_Hex.txt", C_hex);
    Write_File("D_Hex.txt", D_hex);

    // Memory Cleanup
    EC_POINT_free(C);
    EC_POINT_free(C_prime);
    EC_POINT_free(D);
    EC_POINT_free(message_point);
    EC_POINT_free(pk_point);
    BN_free(k);
    BN_CTX_free(bn_ctx);
    OPENSSL_free(C_hex);
    OPENSSL_free(D_hex);
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