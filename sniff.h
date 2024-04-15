#pragma once

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>

#include <net/ethernet.h>     //For ether_header
#include <netinet/if_ether.h> //For ETH_P_ALL
#include <sys/socket.h>
#include <sys/types.h>

#include <atomic>
#include <iostream>
#include <mutex>
#include <thread>
#include <utility> // for std::pair
#include <vector>
#include <iomanip>
#include <sstream>

#define BUFFSIZE 65536

class PacketSniffer
{
private:
    int sock;

    std::atomic<bool> captureActive;

    int createSocket() { return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); }

    void closeSocket() { close(sock); }

    std::pair<int, unsigned char *> readSocket()
    {
        unsigned char *buf =
            (unsigned char *)malloc(BUFFSIZE); // Allocate memory for buffer
        if (!buf)
        {
            std::cerr << "Error allocating memory for buffer" << std::endl;
            exit(EXIT_FAILURE);
        }

        struct sockaddr saddr;
        socklen_t saddr_size = sizeof(saddr);

        int data_size = recvfrom(sock, buf, BUFFSIZE, 0, &saddr, &saddr_size);
        if (data_size < 0)
        {
            std::cerr << "Error reading the socket, are you running as sudo?" << std::endl;
            free(buf); // Free allocated memory before exit
            exit(EXIT_FAILURE);
        }

        return std::make_pair(data_size, buf);
    }

    void captureThreadFunc(std::vector<std::pair<int, unsigned char *>> &packetBuffer)
    {
        while (captureActive)
        {
            packetBuffer.push_back(readSocket());
        }
    }

public:
    PacketSniffer() : sock(createSocket()), captureActive(false) {}

    ~PacketSniffer()
    {
        stopCapture();
        closeSocket();
    }

    void startCapture(std::vector<std::pair<int, unsigned char *>> &packetBuffer)
    {
        if (!captureActive)
        {
            captureActive = true;
            std::thread captureThread(&PacketSniffer::captureThreadFunc, this, std::ref(packetBuffer));
            captureThread.detach();
        }
    }

    void stopCapture()
    {
        captureActive = false;
    }

    std::vector<std::pair<int, unsigned char *>> capturePackets()
    {
        std::vector<std::pair<int, unsigned char *>> vec;

        vec.push_back(readSocket());

        return vec;
    }

    std::string printData(const std::pair<int, unsigned char *> &packet)
    {
        int data_size = packet.first;
        unsigned char *data = packet.second;

        std::ostringstream output;
        output << "Packet size: " << data_size << std::endl
               << "Packet content:" << std::endl;
        int i, j;
        for (i = 0; i < data_size; i++)
        {
            if (i != 0 && i % 16 == 0)
            {
                output << "         ";
                for (j = i - 16; j < i; j++)
                {
                    if (data[j] >= 32 && data[j] <= 128)
                        output << (char)data[j];
                    else
                        output << ".";
                }
                output << std::endl;
            }

            if (i % 16 == 0)
                output << "   ";
            output << " " << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];

            if (i == data_size - 1)
            {
                for (j = 0; j < 15 - i % 16; j++)
                {
                    output << "   ";
                }

                output << "         ";

                for (j = i - i % 16; j <= i; j++)
                {
                    if (data[j] >= 32 && data[j] <= 128)
                    {
                        output << (char)data[j];
                    }
                    else
                    {
                        output << ".";
                    }
                }

                output << std::endl;
            }
        }
        return output.str();
    }
};