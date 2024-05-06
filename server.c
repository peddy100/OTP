#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

const char Characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(1);
} 

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);
  // Allow a client at any address to connect to this server
  address->sin_addr.s_addr = INADDR_ANY;
}

/* Encrypt function used by child to:
1. verify commuincation with client
2. recieve plaintext and key
3. encpryt the plaintext using the key
4. wrtie back the encrypted text to the client
*/
void encryptCharacter(int clientSocket) {
    char plaintext[2];
    char buffer[2];
    char key[2];

    // Initialize the buffers
    memset(plaintext, '\0', sizeof(plaintext));
    memset(buffer, '\0', sizeof(buffer));
    memset(key, '\0', sizeof(key));

    FILE *clientStream = fdopen(clientSocket, "r+");
    if (clientStream == NULL) {
        error("Client stream empty");
    }

    // Verify client
    char verify;
    fread(&verify, 1, sizeof(char), clientStream);
    //printf("SERVER: Read the following verification from the client: %c\n", verify);
    if (verify != 'e') {
      perror("invalid client");
      char response = 'n';
      fwrite(&response, 1, sizeof(char), clientStream);
      fflush(clientStream);
      //printf("SERVER: Sent the following verfication response: %c\n", response);
      exit(2);
    } else {
      char response = 'y';
      fwrite(&response, 1, sizeof(char), clientStream);
      fflush(clientStream);
      //printf("SERVER: Sent the following verification response: %c\n", response);
    }

    size_t bytes_read;
    while((bytes_read = fread(buffer, 1, sizeof(buffer), clientStream)) > 0) {
      for (size_t i = 0; i < bytes_read; i+=2) {
        plaintext[0] = buffer[i];
        key[0] = buffer[i + 1];
      }

      int i, j, k;
      if (plaintext[0] == ' '){
        i = 26;
      } else {
        i = plaintext[0] - 65;
      }

      if (key[0] == ' ') {
        j = 26;
      } else {
        j =  key[0] - 65;
      }
      k = (i + j) % 27;
      char ciphertext = Characters[k];

      fwrite(&ciphertext, 1, sizeof(char), clientStream);
      fflush(clientStream);
    }
    fclose(clientStream);
}

/* decrypt function used by child to:
1. verify commuincation with client
2. recieve cyphertext and key
3. decpryt the cyphertext using the key
4. wrtie back the plaintext to the client
*/
void decryptCharacter(int clientSocket) {
    char ciphertext[2];
    char buffer[2];
    char key[2];

    // Initialize the buffers
    memset(ciphertext, '\0', sizeof(ciphertext));
    memset(buffer, '\0', sizeof(buffer));
    memset(key, '\0', sizeof(key));

    FILE *clientStream = fdopen(clientSocket, "r+");
    if (clientStream == NULL) {
        error("Client stream empty");
    }

    // Verify client
    char verify;
    fread(&verify, 1, sizeof(char), clientStream);
    //printf("SERVER: Read the following verification from the client: %c\n", verify);
    if (verify != 'd') {
      perror("invalid client");
      char response = 'n';
      fwrite(&response, 1, sizeof(char), clientStream);
      fflush(clientStream);
      //printf("SERVER: Sent the following verfication response: %c\n", response);
      exit(2);
    } else {
      char response = 'y';
      fwrite(&response, 1, sizeof(char), clientStream);
      fflush(clientStream);
      //printf("SERVER: Sent the following verification response: %c\n", response);
    }

    size_t bytes_read;
    while((bytes_read = fread(buffer, 1, sizeof(buffer), clientStream)) > 0) {
      for (size_t i = 0; i < bytes_read; i+=2) {
        ciphertext[0] = buffer[i];
        key[0] = buffer[i + 1];
      }

      int i, j, k;
      if (ciphertext[0] == ' ') {
        i = 26;
      } else{
        i = ciphertext[0] - 65;
      }

      if (key[0] == ' ') {
        j = 26;
      } else{
        j = key[0] - 65;
      }

      k = ((i - j) + 27) % 27;
      char plaintext = Characters[k];

      fwrite(&plaintext, 1, sizeof(char), clientStream);
      fflush(clientStream);
    }
    fclose(clientStream);
}


int main(int argc, char *argv[]){
  int connectionSocket;
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t sizeOfClientInfo = sizeof(clientAddress);

  // Check usage & args
  if (argc < 2) { 
    fprintf(stderr,"USAGE: %s port\n", argv[0]); 
    exit(1);
  } 
  
  // Create the socket that will listen for connections
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0) {
    error("ERROR opening socket");
  }

  // Set up the address struct for the server socket
  setupAddressStruct(&serverAddress, atoi(argv[1]));

  // Associate the socket to the port
  if (bind(listenSocket, 
          (struct sockaddr *)&serverAddress, 
          sizeof(serverAddress)) < 0){
    error("ERROR on binding");
  }

  // Start listening for connetions. Allow up to 5 connections to queue up
  if (listen(listenSocket, 5) == -1){
    error("ERROR listening");
  }
  
  // Accept a connection, blocking if one is not available until one connects
  while(1){
    // Accept the connection request which creates a connection socket
    connectionSocket = accept(listenSocket, 
                (struct sockaddr *)&clientAddress, 
                &sizeOfClientInfo); 
    if (connectionSocket < 0){
      error("ERROR on accept");
    }

    //printf("SERVER: Connected to client running at host %d port %d\n", 
                          //ntohs(clientAddress.sin_addr.s_addr),
                          //ntohs(clientAddress.sin_port));
    //fork child processes
    pid_t pid = fork();

    if (pid == -1) {
        perror("ERROR forking");
        close(listenSocket);
        close(connectionSocket);
        return 1;
    }
    if (pid == 0) {
        close(listenSocket);
        #ifdef DEC
          decryptCharacter(connectionSocket);
        #else
          encryptCharacter(connectionSocket);
        #endif
        return 0;
    }
    else {
        close(connectionSocket);
    }
  }
  // Close the listening socket
  close(listenSocket); 
  return 0;
}
