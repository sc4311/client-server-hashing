# Client-Server Hashing Project

## Overview
This project implements a client-server application in C to verify if a username/email or password appears in a list of breached credentials using SHA-256 hashing for privacy preservation.

## Directory Structure
```plaintext
client-server-hashing/
├── client.c
├── server.c
├── sha256_lib.c
├── sha256_lib.h
├── Makefile
├── credentials0-plain.txt
├── credentials0-sha256.txt
├── credentials1-sha256.txt
├── out-client.txt
└── out-server.txt
```

## Usage

1. **Start the Server**:
    ```sh
    ./server <port_number> <credentials_file>
    # Example
    ./server 8080 credentials1-sha256.txt
    ```

2. **Run the Client**:
    ```sh
    ./client <hostname> <port_number>
    # Example
    ./client localhost 8080
    ```

3. **Client Options**:
    - 1: Check username/email
    - 2: Check password
    - 3: Check both
    - 4: Exit

## Example Interaction

**Client**:
$ ./client localhost 8080
Enter option (1: check username/email, 2: check password, 3: check both, 4: exit): 1
Enter username/email: user1@abc.com
Username/email hash: ea68415238fab6f7167d9e7ffaaed64caab10de9edfbb5bc26008f3d1d78c25e
Server response: Found
Response time: 0.000004 seconds


**Server**:
$ ./server 8080 credentials0-sha256.txt
Server listening on port 8080
Received username hash: ea68415238fab6f7167d9e7ffaaed64caab10de9edfbb5bc26008f3d1d78c25e
Comparing username hash with credential: ea68415238fab6f7167d9e7ffaaed64caab10de9edfbb5bc26008f3d1d78c25e


## Implementation Details

- **Client**:
    - Connects to the server using TCP.
    - Prompts the user for an option to check username/email, password, or both.
    - Computes the SHA-256 hash of the input credentials.
    - Sends the hash to the server and waits for the response.
    - Displays the server's response and the response time.

- **Server**:
    - Loads SHA-256 hash values of breached credentials from a file.
    - Listens for client connections on the specified port.
    - Processes client requests to verify hash values against the stored credentials.
    - Sends appropriate responses to the client.
    - Handles graceful shutdown on receiving SIGINT.

## About
This project is part of the CS3733 FinalTakeHome_Q2 assignment focusing on Client-Server Paradigm and Socket Programming in C on Linux.

[GitHub Repository](https://github.com/sc4311/client-server-hashing)
