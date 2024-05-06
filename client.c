#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()

#define CHUNK 140000

const char allowedChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

/**
* Client code
* 1. Create a socket and connect to the server specified in the command arugments.
* 2. Parse plaintext file and key file from input and verify that the files don't containg bad characters.
* 3. Send that input as a message to the server.
* 3. Print the message received from the server and exit the program.
*/

// Error function used for reporting issues
void error(const char *msg) { 
  perror(msg); 
} 

// Remove new line
void removeNewLine(char *str){
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n'){
        str[len - 1] = '\0';
    }
}

// Returns size of a file
off_t fileSize(const char* file){
    struct stat st;
    stat(file, &st);
    off_t size = st.st_size;
    return size;
}

// check if bad characters in plaintext
int isBadChar(char c) {
  return !strchr(allowedChars, c);
}

void sendPair(FILE *serverStream, char pt_char, char key_char){
    char buffer[2];
    buffer[0] = pt_char;
    buffer[1] = key_char;
    
    fwrite(buffer, 1, 2, serverStream);
    fflush(serverStream);
    //printf("CLIENT: Sent pair - Plaintext: %c, Key: %c\n", buffer[0], buffer[1]);
    fflush(stdout);
    memset(buffer, '\0', sizeof(buffer));
}

void printSeverResp(FILE *serverStream){
    char buffer[1];
    size_t n_read = fread(buffer, 1, 1, serverStream);
    fwrite(buffer, 1, 1, stdout);
    memset(buffer, '\0', sizeof(buffer));
}

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);
  
  // Get the DNS entry for this host name
  struct hostent* hostInfo = gethostbyname("localhost");
  if (hostInfo == NULL) {
    fprintf(stderr, "CLIENT: ERROR, no such host\n");
    exit(1);
  }
  //copy the first IP address from the DNS entry to sin_addr.s_addr
  memcpy((char*) &address ->sin_addr.s_addr,
        hostInfo->h_addr_list[0],
        hostInfo->h_length);
}

/*
* Client encrypt fucntion used to:
* 1. send verification to the server
* 2. send plaintext and key to server
* 3. recieve and print enrypted text from the server
*/
void encryptClient(int serverSocket, const char *plaintext, const char *key){
    char buffer[CHUNK];
    //clear out the buffer array
    memset(buffer, '\0', sizeof(buffer));

    FILE *serverStream = fdopen(serverSocket, "r+");
    if (serverStream == NULL){
        error("ERROR converting to file stream");
        exit(1);
    }

    //send the verification character
    char verify = 'e';
    fwrite(&verify, 1, sizeof(char), serverStream);
    fflush(serverStream);
    //printf("CLIENT: Sent verification character 'e'\n");

    //recieve the response to the verification
    char response;
    fread(&response, 1, sizeof(char), serverStream);
    if ('y' != response){
        error("Invalid handshake response");
        fclose(serverStream);
        exit(2);
    }
    //printf("CLIENT: Received response: %c\n", response);

    //read the key file
    FILE *keyStream = fopen(key, "r");
    if (keyStream == NULL) {
        error("ERROR opening key file");
        fclose(serverStream);
        exit(1);
    }

    //read the plaintext file
    FILE *ptStream = fopen(plaintext, "r");
    if (ptStream == NULL) {
        error("ERROR opening plaintext file");
        fclose(serverStream);
        fclose(keyStream);
        exit(1);
    }
    size_t key_read, pt_read;
    while ((pt_read = fread(buffer, 1, sizeof(buffer)/ 2, ptStream)) > 0){
        key_read = fread(buffer + pt_read, 1, sizeof(buffer)/ 2, keyStream );
        char* returnLoc = strchr(buffer, '\n');
        *returnLoc = '\0';
        for (size_t i = 0; i < pt_read; i++) {
            if (isBadChar(buffer[i]) || isBadChar(buffer[i + pt_read])){
                error("enc_client error: input contains bad characters");
                fclose(serverStream);
                fclose(keyStream);
                fclose(ptStream);
                exit(1);
            }
        }
        for (size_t i = 0; i < pt_read; i++) {
            if(buffer[i] == '\0') {
                // got to the end of plaintext
                break; 
            }
            sendPair(serverStream, buffer[i], buffer[i + pt_read]);
            printSeverResp(serverStream);
        }
        memset(buffer, '\0', sizeof(buffer));
    }
    if (pt_read <= 0){
        if (feof(ptStream)){
            putchar('\n');
            //printf("CLIENT: EOF reached entering return character and shutting down\n");
        } else {
            error("ERROR reading from plaintext file");
            fclose(serverStream);
            fclose(keyStream);
            fclose(ptStream);
            exit(1);
        }
    }

    fclose(serverStream);
    fclose(ptStream);
    fclose(keyStream);
}

/*
* Client decrypt fucntion used to:
* 1. send verification to the server
* 2. send encrypted text and key to server
* 3. recieve and print decrypted text from the server
*/
void decryptClient(int serverSocket, const char *ciphertext, const char *key){
    char buffer[CHUNK];
    //clear out the buffer array
    memset(buffer, '\0', sizeof(buffer));

    FILE *serverStream = fdopen(serverSocket, "r+");
    if (serverStream == NULL){
        error("ERROR converting to file stream");
        exit(1);
    }

    //send the verification character
    char verify = 'd';
    fwrite(&verify, 1, sizeof(char), serverStream);
    fflush(serverStream);
    //printf("CLIENT: Sent verification character 'd'\n");

    //recieve the response to the verification
    char response;
    fread(&response, 1, sizeof(char), serverStream);
    if ('y' != response){
        error("Invalid handshake response");
        fclose(serverStream);
        exit(2);
    }
    //printf("CLIENT: Received response: %c\n", response);

    //read the key file
    FILE *keyStream = fopen(key, "r");
    if (keyStream == NULL) {
        error("ERROR opening key file");
        fclose(serverStream);
        exit(1);
    }

    //read the ciphertext file
    FILE *ctStream = fopen(ciphertext, "r");
    if (ctStream == NULL) {
        error("ERROR opening ciphertext file");
        fclose(serverStream);
        fclose(keyStream);
        exit(1);
    }
    size_t key_read, ct_read;
    while ((ct_read = fread(buffer, 1, sizeof(buffer)/ 2, ctStream)) > 0){
        key_read = fread(buffer + ct_read, 1, sizeof(buffer)/ 2, keyStream );
        char* returnLoc = strchr(buffer, '\n');
        *returnLoc = '\0';
        for (size_t i = 0; i < ct_read; i++) {
            if (isBadChar(buffer[i]) || isBadChar(buffer[i + ct_read])){
                error("enc_client error: input contains bad characters");
                fclose(serverStream);
                fclose(keyStream);
                fclose(ctStream);
                exit(1);
            }
        }
        for (size_t i = 0; i < ct_read; i++) {
            if(buffer[i] == '\0') {
                // got to the end of plaintext
                break; 
            }
            sendPair(serverStream, buffer[i], buffer[i + ct_read]);
            printSeverResp(serverStream);
        }
        memset(buffer, '\0', sizeof(buffer));
    }
    if (ct_read <= 0){
        if (feof(ctStream)){
            putchar('\n');
            //printf("CLIENT: EOF reached entering return character and shutting down\n");
        } else {
            error("ERROR reading from plaintext file");
            fclose(serverStream);
            fclose(keyStream);
            fclose(ctStream);
            exit(1);
        }
    }

    fclose(serverStream);
    fclose(ctStream);
    fclose(keyStream);
}



int main(int argc, char *argv[]) {
  int socketFD, portNumber;
  struct sockaddr_in serverAddress;
  // Check usage & args
  if (argc != 4) { 
    #ifdef DEC
        fprintf(stderr,"USAGE: %s ciphertext key port\n", argv[0]); 
        exit(1);
    #else
        fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]);
        exit(1); 
    #endif
  } 
  // Parse the command line arguements
  char *text = argv[1];
  char *key = argv[2];
  portNumber = atoi(argv[3]);

  off_t keySize = fileSize(key);
  off_t textSize = fileSize(text);
  if(keySize < textSize){
    error("Error: Key is too short");
    exit(1);
  }

  // Create a socket
  socketFD = socket(AF_INET, SOCK_STREAM, 0); 
  if (socketFD < 0){
    error("CLIENT: ERROR opening socket");
    exit(1);
  }

   // Set up the server address struct
  setupAddressStruct(&serverAddress, portNumber);

  // Connect to server
  if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
    fprintf(stderr, "ERROR connecting to server on port %d\n", portNumber);
    close(socketFD);
    exit(2);
  }
  //printf("CLIENT: Connected to the server on port %d\n", portNumber);
  #ifdef DEC
  // do decryption with server
    decryptClient(socketFD, text, key);
  #else
  // do encryptuion with server
    encryptClient(socketFD, text, key);
  #endif
  // close the socket
  close(socketFD);
  return 0;
}
