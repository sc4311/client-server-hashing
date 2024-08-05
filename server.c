#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include "sha256_lib.h"

#define BUFFER_SIZE 1024
#define MAX_CREDENTIALS 1000000

char credentials[MAX_CREDENTIALS][SHA256_DIGEST_SIZE * 2 + 1];
int credential_count = 0;
int server_fd;

void load_credentials(const char *filename);
void handle_client(int client_sock);
void sigint_handler(int sig);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <credentials_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    const char *credentials_file = argv[2];

    load_credentials(credentials_file);

    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse port
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, sigint_handler);

    printf("Server listening on port %d\n", port);

    while (1) {
        int client_sock;
        if ((client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        handle_client(client_sock);
        close(client_sock);
    }

    return 0;
}

void load_credentials(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open credentials file");
        exit(EXIT_FAILURE);
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file) && credential_count < MAX_CREDENTIALS) {
        line[strcspn(line, "\n")] = 0; // remove newline

        // Split the line by ':' and store each part as a separate credential
        char *token = strtok(line, ":");
        while (token != NULL && credential_count < MAX_CREDENTIALS) {
            strcpy(credentials[credential_count++], token);
            token = strtok(NULL, ":");
        }
    }

    fclose(file);
}

void handle_client(int client_sock) {
    char buffer[BUFFER_SIZE];
    int valread;
    int check_username = 0;
    int check_password = 0;
    int check_both = 0;
    char username_hash[SHA256_DIGEST_SIZE * 2 + 1] = {0};
    char password_hash[SHA256_DIGEST_SIZE * 2 + 1] = {0};

    while ((valread = read(client_sock, buffer, BUFFER_SIZE)) > 0) {
        buffer[valread] = '\0';

        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }

        // Determine the type of check
        if (strncmp(buffer, "check_username:", 15) == 0) {
            check_username = 1;
            strcpy(username_hash, buffer + 15);
            printf("Received username hash: %s\n", username_hash); // Debug print
        } else if (strncmp(buffer, "check_password:", 15) == 0) {
            check_password = 1;
            strcpy(password_hash, buffer + 15);
            printf("Received password hash: %s\n", password_hash); // Debug print
        } else if (strncmp(buffer, "check_both:", 11) == 0) {
            check_both = 1;
            char *token = strtok(buffer + 11, ":");
            if (token) {
                strcpy(username_hash, token);
                token = strtok(NULL, ":");
                if (token) {
                    strcpy(password_hash, token);
                }
            }
            printf("Received both hashes - Username: %s, Password: %s\n", username_hash, password_hash); // Debug print
        }

        int found_username = 0, found_password = 0;
        if (check_username || check_both) {
            for (int i = 0; i < credential_count; i++) {
                printf("Comparing username hash with credential: %s\n", credentials[i]); // Debug print
                if (strcmp(username_hash, credentials[i]) == 0) {
                    found_username = 1;
                    break;
                }
            }
        }

        if (check_password || check_both) {
            for (int i = 0; i < credential_count; i++) {
                printf("Comparing password hash with credential: %s\n", credentials[i]); // Debug print
                if (strcmp(password_hash, credentials[i]) == 0) {
                    found_password = 1;
                    break;
                }
            }
        }

        if (check_both) {
            if (found_username && found_password) {
                send(client_sock, "FoundBoth", strlen("FoundBoth"), 0);
            } else if (found_username) {
                send(client_sock, "FoundUsernameOnly", strlen("FoundUsernameOnly"), 0);
            } else if (found_password) {
                send(client_sock, "FoundPasswordOnly", strlen("FoundPasswordOnly"), 0);
            } else {
                send(client_sock, "NotFound", strlen("NotFound"), 0);
            }
        } else if (check_username) {
            if (found_username) {
                send(client_sock, "Found", strlen("Found"), 0);
            } else {
                send(client_sock, "Not Found", strlen("Not Found"), 0);
            }
        } else if (check_password) {
            if (found_password) {
                send(client_sock, "Found", strlen("Found"), 0);
            } else {
                send(client_sock, "Not Found", strlen("Not Found"), 0);
            }
        }

        // Reset check flags
        check_username = check_password = check_both = 0;
    }
}

void sigint_handler(int sig) {
    printf("Caught signal %d, closing server...\n", sig);
    close(server_fd);
    exit(0);
}
