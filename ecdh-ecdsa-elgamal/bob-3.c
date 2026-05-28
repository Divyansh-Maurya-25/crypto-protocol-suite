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
#include <unistd.h>

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Convert_from_Hex(unsigned char output[], const char input[], int inputlength);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main (int argc, char* argv[])
{
    // Reading Bob's DSA and DH keys along with Alice's DSA public key.
    int key_len;
    char *bob_dsa_sk_hex = Read_File(argv[1], &key_len);
    char *bob_dsa_pk_hex = Read_File(argv[2], &key_len);

    char *bob_dh_sk_hex = Read_File(argv[3], &key_len);
    char *bob_dh_pk_hex = Read_File(argv[4], &key_len);

    char *alice_dsa_pk_hex = Read_File(argv[5], &key_len);

    // Creating BN Context
    BN_CTX *bn_ctx = BN_CTX_new();
    
    // Converting Private/Secret Keys to BN
    BIGNUM *bob_dsa_sk = NULL;
    BIGNUM *bob_dh_sk = NULL;
    BN_hex2bn(&bob_dsa_sk, bob_dsa_sk_hex);
    BN_hex2bn(&bob_dh_sk, bob_dh_sk_hex);
    
    // Creating EC_GROUP
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp192k1);

    // Converting Public Keys to EC_POINT
    EC_POINT *bob_dsa_pk = NULL;
    EC_POINT *bob_dh_pk = NULL;
    bob_dsa_pk = EC_POINT_hex2point(ec_group, bob_dsa_pk_hex, NULL, bn_ctx);
    bob_dh_pk = EC_POINT_hex2point(ec_group, bob_dh_pk_hex, NULL, bn_ctx);
    
    EC_POINT *alice_dsa_pk = NULL;
    alice_dsa_pk = EC_POINT_hex2point(ec_group, alice_dsa_pk_hex, NULL, bn_ctx);

    // Creating Bob EC_KEY with Private and Public keys
    EC_KEY *bob_dsa_key = EC_KEY_new_by_curve_name(NID_secp192k1);
    EC_KEY_set_private_key(bob_dsa_key, bob_dsa_sk);
    EC_KEY_set_public_key(bob_dsa_key, bob_dsa_pk);

    // Signing Bob's ECDH public key using ECDSA private key
    unsigned char hash[32];
    SHA256((unsigned char *)bob_dh_pk_hex, strlen(bob_dh_pk_hex), hash);

    unsigned int sig_len = ECDSA_size(bob_dsa_key);
    unsigned char *signature = (unsigned char *)malloc(sig_len);

    if (!ECDSA_sign(0, hash, 32, signature, &sig_len, bob_dsa_key)) 
    {
        printf("Signing failed\n");
        return 1;
    }

    // Converting Signature to Hex and writing to file.
    char signature_hex[sig_len * 2 + 1];
    Convert_to_Hex(signature_hex, signature, sig_len);
    Write_File("Signature_Bob.txt", signature_hex);

    // Reading Alice's DH public key
    char *alice_dh_pk_hex = Read_File("Alice_DH_PK.txt", &key_len);

    // Reading Alice's Signature (waiting so Alice can generate their signature).
    char *alice_signature_hex = NULL;
    sleep(1);
    alice_signature_hex = Read_File("Signature_Alice.txt", &key_len);

    // Converting Alice's DH public key from Hex to EC_POINT.
    EC_POINT *alice_dh_pk = EC_POINT_hex2point(ec_group, alice_dh_pk_hex, NULL, bn_ctx);

    unsigned char alice_hash[32];
    SHA256((unsigned char *)alice_dh_pk_hex, strlen(alice_dh_pk_hex), alice_hash);

    // Converting Alice's signature from hex.
    unsigned char alice_signature[key_len / 2];
    Convert_from_Hex(alice_signature, alice_signature_hex, key_len / 2);

    // Creating Alice's key with public key and verifying signature.
    EC_KEY *alice_dsa_key = EC_KEY_new_by_curve_name(NID_secp192k1);
    EC_KEY_set_public_key(alice_dsa_key, alice_dsa_pk);

    int verify_status = ECDSA_verify(0, alice_hash, 32, alice_signature, key_len / 2, alice_dsa_key);

    if (verify_status == 1)
    {
        // Verification successful, calculate Bob-Alice_DH key agreement.
        Write_File("Verification_Result_Bob.txt", "Successful Verification on Bob Side\n");

        EC_POINT *dh_key = EC_POINT_new(ec_group);
        EC_POINT_mul(ec_group, dh_key, NULL, alice_dh_pk, bob_dh_sk, bn_ctx);

        char *dh_key_hex = EC_POINT_point2hex(ec_group, dh_key, EC_KEY_get_conv_form(bob_dsa_key), bn_ctx);
        Write_File("DH_Key_Agreement_Bob.txt", dh_key_hex);

        OPENSSL_free(dh_key_hex);
        EC_POINT_free(dh_key);
    } 
    else
    {
        // Verification failed, no key agreement.
        Write_File("Verification_Result_Bob.txt", "Verification Failed on Bob Side\n");
    }

    // Memory Cleanup
    BN_CTX_free(bn_ctx);
    EC_KEY_free(bob_dsa_key);
    EC_KEY_free(alice_dsa_key);
    EC_GROUP_free(ec_group);
    free(signature);

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

void Convert_from_Hex(unsigned char output[], const char input[], int inputlength)
{
    for (int i = 0; i < inputlength; ++i){
        sscanf(&input[2*i], "%2hhx", &output[i]);
    }
}