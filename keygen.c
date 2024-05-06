#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Function to generate a random character from the allowed set
char getRandomChar() {
    // Characters: A-Z and space (27 characters in total)
    char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
    int index = rand() % 27;
    return characters[index];
}

int main(int argc, char *argv[]) {
    // Check for the correct number of command-line arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        return 1; // Exit with an error code
    }

    // Parse key length from command-line arguments
    int keyLength = atoi(argv[1]);

    // Seed the random number generator with the current time
    srand(time(NULL));

    // Generate key of specified length
    for (int i = 0; i < keyLength; ++i) {
        char randomChar = getRandomChar();
        printf("%c", randomChar);
    }

    // Output a newline as the last character
    printf("\n");

    return 0;
}