#include <stdio.h> // Standard I/O library
#include <stdlib.h> // Standard library for memory allocation, process control, etc.
#include <string.h> // String handling functions
#include <unistd.h> // POSIX API for Unix-like systems
#include <arpa/inet.h> // Definitions for internet operations
#include <signal.h> // Signal handling
#include "sha256_lib.h" // Custom SHA-256 library

#define BUFFER_SIZE 1024 // Buffer size for reading data
#define MAX_CREDENTIALS 1000000 // Maximum number of credentials

char credentials[MAX_CREDENTIALS][SHA256_DIGEST_SIZE * 2 + 1]; // Array to store credentials
int credential_count = 0; // Counter for the number of credentials
int server_fd; // Server file descriptor

void load_credentials(const char *filename); // Function to load credentials from a file
void handle_client(int client_sock); // Function to handle client connections
void sigint_handler(int sig); // Signal handler for SIGINT

int main(int argc, char *argv[]) {
    if (argc != 3) { // Check if the correct number of arguments is provided
        fprintf(stderr, "Usage: %s <port> <credentials_file>\n", argv[0]);
        exit(EXIT_FAILURE); // Exit if arguments are incorrect
    }

    int port = atoi(argv[1]); // Convert port argument to integer
    const char *credentials_file = argv[2]; // Get the credentials file path

    load_credentials(credentials_file); // Load credentials from the file

    struct sockaddr_in address; // Structure to hold server address
    int addrlen = sizeof(address); // Length of the address structure

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed"); // Print error if socket creation fails
        exit(EXIT_FAILURE); // Exit if socket creation fails
    }

    // Set socket options to reuse port
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt"); // Print error if setting socket options fails
        exit(EXIT_FAILURE); // Exit if setting socket options fails
    }

    // Bind to port
    address.sin_family = AF_INET; // Set address family to Internet
    address.sin_addr.s_addr = INADDR_ANY; // Accept connections from any IP address
    address.sin_port = htons(port); // Set port number

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed"); // Print error if binding fails
        exit(EXIT_FAILURE); // Exit if binding fails
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed"); // Print error if listening fails
        exit(EXIT_FAILURE); // Exit if listening fails
    }

    signal(SIGINT, sigint_handler); // Set up signal handler for SIGINT

    printf("Server listening on port %d\n", port); // Print server listening message

    while (1) { // Infinite loop to accept and handle client connections
        int client_sock;
        if ((client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed"); // Print error if accepting connection fails
            exit(EXIT_FAILURE); // Exit if accepting connection fails
        }

        handle_client(client_sock); // Handle the client connection
        close(client_sock); // Close the client socket
    }

    return 0; // Return 0 to indicate successful execution
}

void load_credentials(const char *filename) {
    FILE *file = fopen(filename, "r"); // Open the credentials file for reading
    if (!file) {
        perror("Failed to open credentials file"); // Print error if file opening fails
        exit(EXIT_FAILURE); // Exit if file opening fails
    }

    char line[BUFFER_SIZE]; // Buffer to hold each line from the file
    while (fgets(line, sizeof(line), file) && credential_count < MAX_CREDENTIALS) {
        line[strcspn(line, "\n")] = 0; // Remove newline character from the line

        // Split the line by ':' and store each part as a separate credential
        char *token = strtok(line, ":");
        while (token != NULL && credential_count < MAX_CREDENTIALS) {
            strcpy(credentials[credential_count++], token); // Copy token to credentials array
            token = strtok(NULL, ":"); // Get the next token
        }
    }

    fclose(file); // Close the file
}

void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE]; // Buffer to hold data from the client
    int valread; // Number of bytes read from the client
    int check_username = 0; // Flag to check username
    int check_password = 0; // Flag to check password
    int check_both = 0; // Flag to check both username and password
    char username_hash[SHA256_DIGEST_SIZE * 2 + 1] = {0}; // Buffer to hold username hash
    char password_hash[SHA256_DIGEST_SIZE * 2 + 1] = {0}; // Buffer to hold password hash

    while ((valread = read(client_sock, buffer, BUFFER_SIZE)) > 0) { // Read data from the client
        buffer[valread] = '\0'; // Null-terminate the buffer

        if (strncmp(buffer, "exit", 4) == 0) { // Check if the client wants to exit
            break; // Exit the loop
        }

        // Determine the type of check
        if (strncmp(buffer, "check_username:", 15) == 0) {
            check_username = 1; // Set flag to check username
            strcpy(username_hash, buffer + 15); // Copy username hash from buffer
            printf("Received username hash: %s\n", username_hash); // Debug print
        } else if (strncmp(buffer, "check_password:", 15) == 0) {
            check_password = 1; // Set flag to check password
            strcpy(password_hash, buffer + 15); // Copy password hash from buffer
            printf("Received password hash: %s\n", password_hash); // Debug print
        } else if (strncmp(buffer, "check_both:", 11) == 0) {
            check_both = 1; // Set flag to check both username and password
            char *token = strtok(buffer + 11, ":"); // Split buffer to get username hash
            if (token) {
                strcpy(username_hash, token); // Copy username hash
                token = strtok(NULL, ":"); // Get the next token for password hash
                if (token) {
                    strcpy(password_hash, token); // Copy password hash
                }
            }
            printf("Received both hashes - Username: %s, Password: %s\n", username_hash, password_hash); // Debug print
        }

        int found_username = 0, found_password = 0; // Flags to indicate if username/password is found
        if (check_username || check_both) { // Check if username or both need to be checked
            for (int i = 0; i < credential_count; i++) {
                printf("Comparing username hash with credential: %s\n", credentials[i]); // Debug print
                if (strcmp(username_hash, credentials[i]) == 0) { // Compare username hash
                    found_username = 1; // Set flag if username is found
                    break; // Exit the loop
                }
            }
        }

        if (check_password || check_both) { // Check if password or both need to be checked
            for (int i = 0; i < credential_count; i++) {
                printf("Comparing password hash with credential: %s\n", credentials[i]); // Debug print
                if (strcmp(password_hash, credentials[i]) == 0) { // Compare password hash
                    found_password = 1; // Set flag if password is found
                    break; // Exit the loop
                }
            }
        }

        if (check_both) { // If both username and password need to be checked
            if (found_username && found_password) {
                send(client_sock, "FoundBoth", strlen("FoundBoth"), 0); // Send response if both are found
            } else if (found_username) {
                send(client_sock, "FoundUsernameOnly", strlen("FoundUsernameOnly"), 0); // Send response if only username is found
            } else if (found_password) {
                send(client_sock, "FoundPasswordOnly", strlen("FoundPasswordOnly"), 0); // Send response if only password is found
            } else {
                send(client_sock, "NotFound", strlen("NotFound"), 0); // Send response if neither is found
            }
        } else if (check_username) { // If only username needs to be checked
            if (found_username) {
                send(client_sock, "Found", strlen("Found"), 0); // Send response if username is found
            } else {
                send(client_sock, "Not Found", strlen("Not Found"), 0); // Send response if username is not found
            }
        } else if (check_password) { // If only password needs to be checked
            if (found_password) {
                send(client_sock, "Found", strlen("Found"), 0); // Send response if password is found
            } else {
                send(client_sock, "Not Found", strlen("Not Found"), 0); // Send response if password is not found
            }
        }

        // Reset check flags
        check_username = check_password = check_both = 0; // Reset flags for the next iteration
    }
}

void sigint_handler(int sig) {
    printf("Caught signal %d, closing server...\n", sig); // Print signal caught message
    close(server_fd); // Close the server socket
    exit(0); // Exit the program
}