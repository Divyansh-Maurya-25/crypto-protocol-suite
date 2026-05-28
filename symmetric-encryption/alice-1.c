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

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main(int argc, char* argv[])
{
    // Checking if too many or too little arguements are passed when running alice.c

    if (argc != 3)
    {
        printf("Please include a message and shared seed text file only.\n");
        return 0;
    }

    // Reading the message file into an unsigned char pointer.
    
    int message_length = 0;
    unsigned char* message = Read_File(argv[1], &message_length);

    // Checking if the message is greater than 32 bytes.

    if (message_length < 32) 
    {
        printf("Message length is too small. Try again with a larger message.\n");
        return 0;
    }

    // Reading the shared seed file into an unsigned char pointer.
    
    int seed_length = 0;
    unsigned char* seed = Read_File(argv[2], &seed_length);

    // Verifying seed length is 32 bytes.

    if (seed_length != 32) 
    {
        printf("The seed length must be equal to 32 bytes. Try again.\n");
        return 0;
    }

    // Generating Secert Key using PRNG by passing the shared seed, its length, and the length of the message.
    
    unsigned char* secret_key = PRNG(seed, seed_length, message_length);
    
    // Write the secret key in hex to file named "Key.txt"

    unsigned char* hex_key = malloc(2 * message_length);
    Convert_to_Hex(hex_key, secret_key, message_length);
    Write_File("Key.txt", hex_key);
    
    // XOR message with secret key to generate ciphertext.
    
    unsigned char* ciphertext = malloc(2 * message_length);

    for (int i = 0; i < message_length; ++i)
    {
        ciphertext[i] = message[i] ^ secret_key[i];
    }

    // Write the ciphertext in hex to file named "Ciphertext.txt"

    unsigned char* hex_ciphertext = malloc(2 * message_length);
    Convert_to_Hex(hex_ciphertext, ciphertext, message_length);
    Write_File("Ciphertext.txt", hex_ciphertext);

    // Memory Cleanup

    free(hex_key);
    free(ciphertext);
    free(hex_ciphertext);

    // Checking for Bob's hash.

    int bob_length = 0;
    unsigned char* bob_hash = Read_File("Hash.txt", &bob_length);

    // Hashing alice's plaintext and converting to hex for comparison.

    unsigned char* alice_hash = Hash_SHA256(message, message_length);
    unsigned char* alice_hash_hex = malloc(64);
    Convert_to_Hex(alice_hash_hex, alice_hash, 32);

    // Char holding success or failure result for file.

    unsigned char* acknow_failure = "Acknowledgment Failed.";
    unsigned char* acknow_success = "Acknowledgment Successful";

    // Writing acknowledgement file.

    for (int i = 0; i < 64; ++i)
    {
        if (alice_hash_hex[i] != bob_hash[i]) {
            Write_File("Acknowledgment.txt", acknow_failure);
            break;
        }
        Write_File("Acknowledgment.txt", acknow_success);
    }

    // Memory Cleanup

    free(alice_hash_hex);

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

void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
}

unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen)
{
	int err;
    unsigned char *pseudoRandomNumber = (unsigned char*) malloc(prnlen);

	prng_state prng;                                                                    
    if ((err = chacha20_prng_start(&prng)) != CRYPT_OK){                                
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

    return (unsigned char*)pseudoRandomNumber;
}

unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash_result = (unsigned char*) malloc(inputlen);
    hash_state md;                                                          
    sha256_init(&md);                                                      
    sha256_process(&md, (const unsigned char*)input, inputlen);           
    sha256_done(&md, hash_result);                                      
    
    return hash_result;
}
