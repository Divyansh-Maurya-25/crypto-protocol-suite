// ----------------------------------------------------
// Names : Jacob Moran, Anthony Lozbin, Divyansh Maurya
//                      Group : 9
//                     Homework #2
// ----------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <tomcrypt.h>

// Macros for MHT structure (8 leafs max results in a max tree size of 15 nodes).
#define KEY_MAX 8
#define TREE_MAX 15

// ----------------------------------------------------
//                      Prototypes
// ----------------------------------------------------
void Read_Multiple_Lines_from_File (char fileName[], unsigned char message[8][32]);
void Write_File(char fileName[], char input[]);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Write_Multiple_Lines_to_File(char fileName[], char input[3][64], int no);
void Merkle_Tree(unsigned char* tree[TREE_MAX], unsigned char keys[KEY_MAX][32]);
void Auxiliary_Path(char path[3][64], unsigned char* tree[TREE_MAX], int index);

// ----------------------------------------------------
//                     Main Function
// ----------------------------------------------------

int main(int argc, char* argv[])
{
    // Verifying enough arguments are given when running the program.
    if (argc != 3)
    {
        printf("Please provide a file with 8 keys and a desired auxilliary path.\n");
        return 0;
    }

    // Creating array that will act as the MHT and allocating memory to each entry in the array.
    unsigned char* merkle_hash_tree[TREE_MAX];

    for (int i = 0; i < TREE_MAX; ++i)
    {
        merkle_hash_tree[i] = (unsigned char*)malloc(32);
    }

    // Creating a 2D array that holds 8 keys (rows) with each holding 32 bytes.
    unsigned char keys[KEY_MAX][32];

    // Reading the keys from a given file and then constructing the Merkle Hash Tree based on these keys.
    Read_Multiple_Lines_from_File(argv[1], keys);
    Merkle_Tree(merkle_hash_tree, keys);
    
    // Obtaining root from MHT and writing to file.
    char hex_root[64];
    Convert_to_Hex(hex_root, merkle_hash_tree[TREE_MAX - 1], 32);
    Write_File("TheRoot.txt", hex_root);

    // Extract Index from argc and decrementing as expected inputs range from 1-8 when leafs are 0-7.
    int index = atoi(argv[2] + 1);
    index -= 1;                      

    if (index < 0 || index > 7)
    {
       fprintf(stderr, "Index is out of range. Try again.\n");
       return 0;
    }

    // Creating variable to hold auxiliary path and then obtaining said path.
    char path[3][64];

    Auxiliary_Path(path, merkle_hash_tree, index);

    // Memory Cleanup for MHT
    for (int i = 0; i < TREE_MAX; ++i)
    {
        free(merkle_hash_tree[i]);
    }

    return 0;
}

// ----------------------------------------------------
//                  Function Definitions
// ----------------------------------------------------

void Read_Multiple_Lines_from_File (char fileName[], unsigned char message[8][32])
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
    for(int i=0; i<32; i++){
      message[j][i] = line_buf[i];
    }
    message[j][32] ='\0';
    printf("Message%d == %s\n", j+1, message[j]);
    j++;
    line_size = getline(&line_buf, &line_buf_size, fp);
  }
  free(line_buf);
  line_buf = NULL;
  fclose(fp);
}

void Write_Multiple_Lines_to_File(char fileName[], char input[3][64], int no){ 
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
}

void Merkle_Tree(unsigned char* tree[TREE_MAX], unsigned char keys[KEY_MAX][32])
{
    // Creating leaves from keys
    for (int i = 0; i < KEY_MAX; ++i)
    {
        memcpy(tree[i], Hash_SHA256(keys[i], 32), 32);
    }

    // Build Merkle Tree
    int level_start = 0, next_level_start = KEY_MAX, count = KEY_MAX;
    while (count > 1)
    { 
        for (int i = 0; i < count / 2; ++i)
        {
            unsigned char concatenate[64];
            memcpy(concatenate, tree[level_start + 2 * i], 32);
            memcpy(concatenate + 32, tree[level_start + 2 * i + 1], 32);

            memcpy(tree[next_level_start + i], Hash_SHA256(concatenate, 64), 32);
        }

        level_start = next_level_start;
        next_level_start += count / 2;
        count /= 2;
    }
}

void Auxiliary_Path(char path[3][64], unsigned char* tree[TREE_MAX], int index)
{
  int current_node = index, path_entry = 0, level_count = KEY_MAX;

  for (int i = 0; i < TREE_MAX - 1; i += level_count, level_count /= 2)
  {
    // Finding sibling of given index in argv[2]
    int sibling;

    if ((current_node % 2) == 0)
    {
      sibling = current_node + 1;
    }
    else
    {
      sibling = current_node - 1;
    }
    
    // Saving hashes for verification
    char hex[64];
    Convert_to_Hex(hex, tree[i + sibling], 32);
    strcpy(path[path_entry], hex);

    path_entry++;
    current_node /= 2;

  }
  Write_Multiple_Lines_to_File("ThePath.txt", path, path_entry);
}
