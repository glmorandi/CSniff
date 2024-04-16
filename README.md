# CSniff
Simple Linux C++ application built using ImGUI to capture packets.

# Documentation

## Description
The `PacketSniffer` class provides functionality for capturing packets from a network interface using raw sockets. It allows starting and stopping packet capture and provides methods to retrieve captured packets.

## Example usage
An example is available in the `teste.cpp` file.

## Class Members
### `PacketSniffer()`
- Constructor: Creates a raw socket for packet capturing and initializes `captureActive` to `false`.

### `~PacketSniffer()`
- Destructor: Stops packet capture and closes the socket.

### `void startCapture(std::vector<std::pair<int, unsigned char *>> &packetBuffer)`
- Starts packet capture in a separate thread.
- Parameters:
  - `packetBuffer`: A reference to a vector where captured packets will be stored.

### `void stopCapture()`
- Stops packet capture.

### `std::vector<std::pair<int, unsigned char *>> capturePackets()`
- Captures a single packet synchronously.
- Returns:
  - A vector containing a single pair of packet size and data.

### `std::string printData(const std::pair<int, unsigned char *> &packet)`
- Formats and prints the captured packet data.
- Parameters:
  - `packet`: A pair containing packet size and data.
- Returns:
  - A string representation of the packet data.

## Private Members
### `int sock`
- Raw socket descriptor.

### `std::atomic<bool> captureActive`
- Atomic boolean flag to control packet capture.

### `int createSocket()`
- Creates a raw socket for packet capture.
- Returns:
  - The socket descriptor.

### `void closeSocket()`
- Closes the raw socket.

### `std::pair<int, unsigned char *> readSocket()`
- Reads data from the raw socket.
- Returns:
  - A pair containing the size of the received data and a pointer to the data buffer.

### `void captureThreadFunc(std::vector<std::pair<int, unsigned char *>> &packetBuffer)`
- Thread function for continuously capturing packets.
- Parameters:
  - `packetBuffer`: A reference to a vector where captured packets will be stored.
