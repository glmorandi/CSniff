#include "sniff.h"
#include <iostream>
#include <chrono>
#include <cassert>

/*
Used for testing the sniff.h functions
*/

int main() {
  PacketSniffer sniffer;
  std::vector<std::pair<int, unsigned char *>> capturedPackets;

  // Start capturing packets
  sniffer.startCapture(capturedPackets);

  // Wait 5 seconds for packet capturing
  std::this_thread::sleep_for(std::chrono::seconds(5));

  // Stop capturing packets
  sniffer.stopCapture();

  // Ensure that at least one packet is captured
  assert(!capturedPackets.empty());

  // Print captured packets information
  std::cout << "Captured Packets:" << std::endl;
  for (const auto& p : capturedPackets) {
	std::cout << sniffer.printData(p) << std::endl;
    // Free allocated memory for packet
    free(p.second);
  }

  return 0;
}
