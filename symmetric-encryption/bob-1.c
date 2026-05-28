// ----------------------------------------------------
// Names : Jacob Moran, Anthony Lozbin, Divyansh Maurya
//                      Group : 9
//                     Homework #1
// ----------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <tomcrypt.h>

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Convert_from_Hex(unsigned char* output, const char* input, int inputlength);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main(int argc, char* argv[])
{
    // Checking if too many or too little arguements are passed when running bob.c
    
    if (argc != 2)
    {
        printf("Please include a shared seed text file only.\n");
        return 0;
    }

    // Reading the ciphertext file into an unsigned char pointer.
    int ciphertext_length = 0;
    unsigned char* ciphertext = Read_File("Ciphertext.txt", &ciphertext_length);

    // Reading the shared seed file into an unsigned char pointer.
    int seed_length = 0;
    unsigned char* seed = Read_File(argv[1], &seed_length);

    if (seed_length != 32) 
    {
        printf("The seed length must be equal to 32 bytes. Try again.\n");
        return 0;
    }

    // Generating Secert Key using PRNG by passing the shared seed, its length, and the length of the message.
    unsigned char* secret_key = PRNG(seed, seed_length, ciphertext_length / 2);

    // Convert Ciphertext from Hex back to bytes.
    unsigned char* converted_cipher = malloc(ciphertext_length);
    Convert_from_Hex(converted_cipher, (const char*) ciphertext, ciphertext_length);

    // XOR Ciphertext and key to generate plaintext.
    unsigned char* plaintext = malloc(ciphertext_length);
    
    int plaintext_length = 0;
    for (int i = 0; i < (ciphertext_length / 2); ++i)
    {
        plaintext[i] = converted_cipher[i] ^ secret_key[i];
        plaintext_length++;
    }

    // Write Plaintext to file.
    Write_File("Plaintext.txt", plaintext);

    // Hash plaintext and write to file.
    unsigned char* bob_hash = Hash_SHA256(plaintext, plaintext_length);
    unsigned char* bob_hash_hex = malloc(64);
    Convert_to_Hex(bob_hash_hex, bob_hash, 32);

    Write_File("Hash.txt", bob_hash_hex);

    free(plaintext);
    free(bob_hash_hex);
    free(converted_cipher);

    return 0;
}

// ----------------------------------------------------
//                  Function Definitions
// ----------------------------------------------------

unsigned char* Read_File (char fileName[], int *fileLen)
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
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

void Write_File(char fileName[], char input[]){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  fputs(input, pFile);
  fclose(pFile);
}

unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen)
{
	int err;
    unsigned char *pseudoRandomNumber = (unsigned char*) malloc(prnlen);

	prng_state prng;                                                                     //LibTomCrypt structure for PRNG
    if ((err = chacha20_prng_start(&prng)) != CRYPT_OK){                                //Sets up the PRNG state without a seed
        printf("Start error: %s\n", error_to_string(err));
    }					                
	if ((err = chacha20_prng_add_entropy(seed, seedlen, &prng)) != CRYPT_OK) {           //Uses a seed to add entropy to the PRNG
        printf("Add_entropy error: %s\n", error_to_string(err));
    }	            
    if ((err = chacha20_prng_ready(&prng)) != CRYPT_OK) {                                   //Puts the entropy into action
        printf("Ready error: %s\n", error_to_string(err));
    }
    chacha20_prng_read(pseudoRandomNumber, prnlen, &prng);                                //Writes the result into pseudoRandomNumber[]

    if ((err = chacha20_prng_done(&prng)) != CRYPT_OK) {                                   //Finishes the PRNG state
        printf("Done error: %s\n", error_to_string(err));
    }

    return (unsigned char*)pseudoRandomNumber;
}

void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
}

unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash_result = (unsigned char*) malloc(inputlen);
    hash_state md;                                                          //LibTomCrypt structure for hash
    sha256_init(&md);                                                       //Initializing the hash set up
    sha256_process(&md, (const unsigned char*)input, inputlen);            //Hashing the data given as input with specified length
    sha256_done(&md, hash_result);                                         //Produces the hash (message digest)
    
    return hash_result;
}

void Convert_from_Hex(unsigned char* output, const char* input, int inputlength)
{
    for (int i = 0; i < inputlength; ++i){
        sscanf(&input[2*i], "%2hhx", &output[i]);
    }

}
