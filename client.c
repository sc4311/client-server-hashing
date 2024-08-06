#include <stdio.h> // Standard I/O library
#include <stdlib.h> // Standard library for memory allocation, process control, etc.
#include <string.h> // String handling functions
#include <unistd.h> // POSIX API for Unix-like systems
#include <arpa/inet.h> // Definitions for internet operations
#include <time.h> // Time-related functions
#include "sha256_lib.h" // Custom SHA-256 library

#define BUFFER_SIZE 1024 // Buffer size for reading data

void handle_connection(int sock); // Function to handle connection with the server
void sha256(const char *input, size_t len, unsigned char output[SHA256_DIGEST_SIZE]); // Function to compute SHA-256 hash

int main(int argc, char *argv[]) {
    if (argc != 3) { // Check if the correct number of arguments is provided
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        exit(EXIT_FAILURE); // Exit if arguments are incorrect
    }

    char *hostname = argv[1]; // Get the hostname from arguments
    int port = atoi(argv[2]); // Convert port argument to integer

    int sock; // Socket descriptor
    struct sockaddr_in server_addr; // Structure to hold server address

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error"); // Print error if socket creation fails
        exit(EXIT_FAILURE); // Exit if socket creation fails
    }

    server_addr.sin_family = AF_INET; // Set address family to Internet
    server_addr.sin_port = htons(port); // Set port number

    // Convert hostname to IP address
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported"); // Print error if address conversion fails
        exit(EXIT_FAILURE); // Exit if address conversion fails
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed"); // Print error if connection fails
        exit(EXIT_FAILURE); // Exit if connection fails
    }

    handle_connection(sock); // Handle the connection with the server
    close(sock); // Close the socket
    return 0; // Return 0 to indicate successful execution
}

void handle_connection(int sock) {
    char buffer[BUFFER_SIZE]; // Buffer to hold data from the server
    int option; // Variable to store user option
    char input[BUFFER_SIZE]; // Buffer to hold user input
    unsigned char hash[SHA256_DIGEST_SIZE]; // Buffer to hold SHA-256 hash
    char hash_str[SHA256_DIGEST_SIZE * 2 + 1]; // Buffer to hold hash as a string
    clock_t start, end; // Variables to measure time
    double cpu_time_used; // Variable to store CPU time used

    while (1) {
        printf("Enter option (1: check username/email, 2: check password, 3: check both, 4: exit): ");
        scanf("%d", &option); // Get user option
        getchar(); // Consume newline

        if (option == 4) { // If user wants to exit
            send(sock, "exit", strlen("exit"), 0); // Send exit command to server
            break; // Exit the loop
        }

        if (option == 1) { // If user wants to check username/email
            printf("Enter username/email: ");
            fgets(input, BUFFER_SIZE, stdin); // Get username/email from user
            input[strcspn(input, "\n")] = 0; // Remove newline
            sha256(input, strlen(input), hash); // Compute SHA-256 hash
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
                sprintf(hash_str + (i * 2), "%02x", hash[i]); // Convert hash to string
            }
            printf("Username/email hash: %s\n", hash_str); // Debug print
            sprintf(buffer, "check_username:%s", hash_str); // Prepare buffer to send to server
            send(sock, buffer, strlen(buffer), 0); // Send buffer to server
        }

        if (option == 2) { // If user wants to check password
            printf("Enter password: ");
            fgets(input, BUFFER_SIZE, stdin); // Get password from user
            input[strcspn(input, "\n")] = 0; // Remove newline
            sha256(input, strlen(input), hash); // Compute SHA-256 hash
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
                sprintf(hash_str + (i * 2), "%02x", hash[i]); // Convert hash to string
            }
            printf("Password hash: %s\n", hash_str); // Debug print
            sprintf(buffer, "check_password:%s", hash_str); // Prepare buffer to send to server
            send(sock, buffer, strlen(buffer), 0); // Send buffer to server
        }

        if (option == 3) { // If user wants to check both username/email and password
            char username_hash[SHA256_DIGEST_SIZE * 2 + 1]; // Buffer to hold username hash
            char password_hash[SHA256_DIGEST_SIZE * 2 + 1]; // Buffer to hold password hash

            printf("Enter username/email: ");
            fgets(input, BUFFER_SIZE, stdin); // Get username/email from user
            input[strcspn(input, "\n")] = 0; // Remove newline
            sha256(input, strlen(input), hash); // Compute SHA-256 hash
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
                sprintf(username_hash + (i * 2), "%02x", hash[i]); // Convert hash to string
            }
            printf("Username/email hash: %s\n", username_hash); // Debug print

            printf("Enter password: ");
            fgets(input, BUFFER_SIZE, stdin); // Get password from user
            input[strcspn(input, "\n")] = 0; // Remove newline
            sha256(input, strlen(input), hash); // Compute SHA-256 hash
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
                sprintf(password_hash + (i * 2), "%02x", hash[i]); // Convert hash to string
            }
            printf("Password hash: %s\n", password_hash); // Debug print

            sprintf(buffer, "check_both:%s:%s", username_hash, password_hash); // Prepare buffer to send to server
            send(sock, buffer, strlen(buffer), 0); // Send buffer to server
        }

        start = clock(); // Start time measurement
        int valread = read(sock, buffer, BUFFER_SIZE); // Read response from server
        end = clock(); // End time measurement
        buffer[valread] = '\0'; // Null-terminate the buffer
        cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC; // Calculate CPU time used
        printf("Server response: %s\n", buffer); // Print server response
        printf("Response time: %f seconds\n", cpu_time_used); // Print response time
    }
}

void sha256(const char *input, size_t len, unsigned char output[SHA256_DIGEST_SIZE]) {
    SHA256_CTX ctx; // SHA-256 context
    sha256_init(&ctx); // Initialize SHA-256 context
    sha256_update(&ctx, (const uint8_t *)input, len); // Update SHA-256 context with input
    sha256_final(&ctx, output); // Finalize SHA-256 hash
}