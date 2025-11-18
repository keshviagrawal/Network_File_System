
# Distributed File System in C

This project is a lightweight, scalable Distributed File System (DFS) built entirely in C. It demonstrates the core principles of networked systems by implementing a client-server architecture where files are stored across multiple, independent storage servers.

The system is composed of three main components: a **Client**, a **NameServer** (for metadata), and one or more **StorageServers** (for file data). All communication is handled over TCP sockets using a custom-defined protocol, ensuring reliable and ordered data transfer.

## System Architecture

The file system is composed of three primary components that work together to manage and serve files.

### 1. The Client (`client_main.c`)
The client is the entry point for users to interact with the file system. It handles all client-side operations, including:
*   Sending requests to the NameServer to locate a file.
*   Connecting directly to a StorageServer to read or write file data.
*   Receiving and interpreting responses from other system components.

### 2. The NameServer (`nm_main.c`, `nm_registry.c`)
The NameServer is the brain of the distributed system. It doesn't store any file data itself; instead, it maintains a registry of all available storage servers and a mapping of which server holds which file. Its key responsibilities are:
*   Registering new storage servers as they come online.
*   Responding to client queries by providing the address of the correct StorageServer for a requested file.

### 3. The StorageServer (`ss_main.c`)
The StorageServer is the workhorse of the system. It is responsible for the physical storage of files. Multiple storage servers can run concurrently. Its duties include:
*   Registering itself with the NameServer upon startup.
*   Storing files on its local filesystem.
*   Handling read and write requests directly from clients.

## Project Structure & Core Components

The project is organized into several key modules, each with a specific responsibility.

*   **`client_main.c`**: Handles all client-side operations — sending file requests, receiving responses, and communicating with the NameServer and StorageServer.
*   **`nm_main.c` & `nm_registry.c`**: Implement the NameServer, which keeps track of registered storage servers and maps filenames to the correct server location.
*   **`ss_main.c`**: Implements the StorageServer, responsible for storing files, serving client read/write requests, and registering itself with the NameServer.
*   **`protocol.h`**: Defines the request/response message formats and the shared protocol used by all components in the system.
*   **`socket_utils.c`**: Provides helper functions for creating, binding, connecting, and managing TCP sockets between the client, NameServer, and StorageServers.
*   **`logger.c`**: Offers a lightweight logging utility to track client, server, and system events in real time.
*   **`constants.h` & `error_codes.h`**: Store all shared constants and structured error codes used across the system for clean, consistent behavior.


## 📜 License

This project is open-source and available under the **MIT License**.
