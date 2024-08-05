#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include "sha256_lib.h"

#define BUFFER_SIZE 1024

void handle_connection(int sock);
void sha256(const char *input, size_t len, unsigned char output[SHA256_DIGEST_SIZE]);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    
    int sock;
    struct sockaddr_in server_addr;
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Convert hostname to IP address
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    handle_connection(sock);
    close(sock);
    return 0;
}

void handle_connection(int sock) {
    char buffer[BUFFER_SIZE];
    int option;
    char input[BUFFER_SIZE];
    unsigned char hash[SHA256_DIGEST_SIZE];
    char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
    clock_t start, end;
    double cpu_time_used;

    while (1) {
        printf("Enter option (1: check username/email, 2: check password, 3: check both, 4: exit): ");
        scanf("%d", &option);
        getchar(); // consume newline

        if (option == 4) {
            send(sock, "exit", strlen("exit"), 0);
            break;
        }

        if (option == 1) {
            printf("Enter username/email: ");
            fgets(input, BUFFER_SIZE, stdin);
            input[strcspn(input, "\n")] = 0; // remove newline
            sha256(input, strlen(input), hash);
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
                sprintf(hash_str + (i * 2), "%02x", hash[i]);
            }
            printf("Username/email hash: %s\n", hash_str); // Debug print
            sprintf(buffer, "check_username:%s", hash_str);
            send(sock, buffer, strlen(buffer), 0);
        }

        if (option == 2) {
            printf("Enter password: ");
            fgets(input, BUFFER_SIZE, stdin);
            input[strcspn(input, "\n")] = 0; // remove newline
            sha256(input, strlen(input), hash);
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
                sprintf(hash_str + (i * 2), "%02x", hash[i]);
            }
            printf("Password hash: %s\n", hash_str); // Debug print
            sprintf(buffer, "check_password:%s", hash_str);
            send(sock, buffer, strlen(buffer), 0);
        }

        if (option == 3) {
            char username_hash[SHA256_DIGEST_SIZE * 2 + 1];
            char password_hash[SHA256_DIGEST_SIZE * 2 + 1];

            printf("Enter username/email: ");
            fgets(input, BUFFER_SIZE, stdin);
            input[strcspn(input, "\n")] = 0; // remove newline
            sha256(input, strlen(input), hash);
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
                sprintf(username_hash + (i * 2), "%02x", hash[i]);
            }
            printf("Username/email hash: %s\n", username_hash); // Debug print

            printf("Enter password: ");
            fgets(input, BUFFER_SIZE, stdin);
            input[strcspn(input, "\n")] = 0; // remove newline
            sha256(input, strlen(input), hash);
            for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
                sprintf(password_hash + (i * 2), "%02x", hash[i]);
            }
            printf("Password hash: %s\n", password_hash); // Debug print

            sprintf(buffer, "check_both:%s:%s", username_hash, password_hash);
            send(sock, buffer, strlen(buffer), 0);
        }

        start = clock();
        int valread = read(sock, buffer, BUFFER_SIZE);
        end = clock();
        buffer[valread] = '\0';
        cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
        printf("Server response: %s\n", buffer);
        printf("Response time: %f seconds\n", cpu_time_used);
    }
}

void sha256(const char *input, size_t len, unsigned char output[SHA256_DIGEST_SIZE]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)input, len);
    sha256_final(&ctx, output);
}
