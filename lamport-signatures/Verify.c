// ----------------------------------------------------
// Names : Jacob Moran, Anthony Lozbin, Divyansh Maurya
//                      Group : 9
//                     Homework #4
// ----------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
unsigned char* Read_File (char fileName[], int *fileLen);
void Read_Multiple_Lines_from_File (char fileName[], char message[][65]);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Convert_from_Hex(unsigned char output[], const char input[], int inputlength);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main(int argc, char **argv)
{
    // Verifying correct number of arguments.
    if (argc != 4)
    {
        printf("Invalid number of arguments. Please include a PK.txt file, Message.txt file, and integer message length.");
        return 1;
    }
    
    // Reading message.
    int msgLen;
    unsigned char *message = Read_File(argv[2], &msgLen);
    
    // Obtaining message length passed into argv[3] and hashing message.
    long message_len = strtol(argv[3], NULL, 10);
    unsigned char *hash = Hash_SHA256(message, (int)message_len);
    
    // Obtaining signature from Alice (Signature file).
    char signature[256][65];
    Read_Multiple_Lines_from_File("Signature.txt", signature);
    
    // Obtaning public keys from Certificate Authority.
    char PK[512][65];
    Read_Multiple_Lines_from_File(argv[1], PK);
    
    // Looping across each byte in hash, then iterating over each bit.
    int valid = 1;
    for (int i = 0; i < 32; i++)
    {
        for (int bit = 0; bit < 8; bit++)
        {
            int index = (i * 8) + bit;  // Obtains index of the bit (0-255).
            int row = (hash[i] >> (7 - bit)) & 1;   // Moving bit to LSB then AND with 1 to obtain value of said bit.
            
            // Converting hex representation of sig. to uchar.
            unsigned char computedHash[32];
            Convert_from_Hex(computedHash, signature[index], 32);
            // Hashing uchar signature and converting hash to hex.
            unsigned char *hashed = Hash_SHA256(computedHash, 32);
            char hashedHex[64];
            Convert_to_Hex(hashedHex, hashed, 32);

            // Checking if the value resulting from f does not match corresponding PK value.
            if (strcmp(hashedHex, PK[2 * index + row]) != 0)
            {
                // If result of f does not matching corresponding PK value, verification failed.
                valid = 0;
                break;
            }
        }
        // Ending loop if verification process fails.
        if (!valid) break;
    }
    
    // Print result of verification process to file.
    FILE *verFile = fopen("Verification.txt", "w");
    if (verFile)
    {
        if (valid)
            fputs("Signature is Valid\n", verFile);
        else
            fputs("Verification Failed\n", verFile);
        fclose(verFile);
    }
    
    // Memory Cleanup
    free(message);
    free(hash);

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

void Read_Multiple_Lines_from_File (char fileName[], char message[][65])
{
  char *line_buf = NULL;
  size_t line_buf_size = 0;
  int line_count = 0;
  ssize_t line_size;
  FILE *fp = fopen(fileName, "r");
  if (!fp)
  {
    fprintf(stderr, "Error opening file '%s'\n", fileName);
  }
  int j=0;
  line_size = getline(&line_buf, &line_buf_size, fp);
  while (line_size >= 0)
  {
    for(int i=0; i<65; i++){
      message[j][i] = line_buf[i];
    }
    message[j][64] ='\0';
    //printf("SK%d == %s\n", j+1, message[j]);
    j++;
    line_size = getline(&line_buf, &line_buf_size, fp);
  }
  free(line_buf);
  line_buf = NULL;
  fclose(fp);
}

void Convert_from_Hex(unsigned char output[], const char input[], int inputlength)
{
    for (int i = 0; i < inputlength; ++i){
        sscanf(&input[2*i], "%2hhx", &output[i]);
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

void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}