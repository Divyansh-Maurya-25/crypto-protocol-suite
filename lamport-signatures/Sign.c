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
void Write_Multiple_Lines_to_File(char fileName[], char input[][64], int no);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------
int main(int argc, char **argv)
{
  // Verifying correct number of arguements.
  if (argc != 3)
  {
      printf("Invalid number of arguments. Please include a SK.txt and Message.txt file.");
      return 1;
  }
    
  // Reading message and then obtaining the hash of the message.
  int msgLen;
  unsigned char *message = Read_File(argv[1], &msgLen);
  unsigned char *hash = Hash_SHA256(message, msgLen);
    
  // Obtaining the secret keys and storing in an array (512 64 char + newline).
  char SK[512][65];
  Read_Multiple_Lines_from_File(argv[2], SK);

  // Looping across each byte, then iterating across each bit.
  char signature[256][64];
  for (int i = 0; i < 32; i++)
  {
    for (int bit = 0; bit < 8; bit++)
    {
      int index = (i * 8) + bit;
      int row = (hash[i] >> (7 - bit)) & 1;   // Moving bit to LSB then AND with 1 to obtain value of said bit.
      strcpy(signature[index], SK[2 * index + row]);  // Copying corresponding SK value to signature.
    }
  }
    
  // Writing signature result.
  Write_Multiple_Lines_to_File("Signature.txt", signature, 256);
  
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

void Write_Multiple_Lines_to_File(char fileName[], char input[][64], int no)
{ 
    FILE *pFile;
    pFile = fopen(fileName,"w");
    if (pFile == NULL){
      printf("Error opening file. \n");
      exit(0);
    }
    for(int i=0; i<no; i++){
      char temp[64];
      temp[64] = '\0';
      memcpy(temp, input[i], 64);
      fputs(temp, pFile);
      
      if (i < (no-1)) fputs("\n", pFile);
    }
      fclose(pFile);
}

void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
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
