#pragma once
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAC_ADDR "\x40\xec\x99\x50\x40\x42"

#define ETH_LEN 14
#define IPV6_LEN 40
#define UDP_LEN 8

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD

struct eth_header {
	uint8_t mac_dest[6]; // should be 6 bytes
	uint8_t mac_src[6]; // should also be 6 bytes
	uint16_t type; // 2bytes
};

struct ipv4_stub {
	uint8_t version_IHL;
	/*uint8_t type_of_service;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_fragment_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src_addr[4];
	uint8_t dest_addr[4];
	uint8_t options[40];*/
};

// for ipv6 we just increment

struct tcpudp_stub {
	uint16_t src_port;
	uint16_t dest_port;
	// for our use case only this is relevant, we only need to monitor the ports
};

int recv_all(SOCKET sock, char** response) {
	int read_size, total_size = 0;
	char buffer[512];

	while ((read_size = recv(sock, buffer, 512, 0)))
	{
		*response = (char*)realloc(*response, read_size + total_size);
		if (*response == NULL)
		{
			printf("realloc failed");
		}
		memcpy(*response + total_size, buffer, read_size);
		total_size += read_size;
	}

	*response = (char*)realloc(*response, total_size + 1);
	*(*response + total_size) = '\0';

	return 0;
}

std::string getIpStringFromDword(DWORD ipv4_addr) {
	char ipv4_cstr[64];
	unsigned char* conv_ref = (unsigned char*)&ipv4_addr;

	snprintf(ipv4_cstr, 64, "%u.%u.%u.%u", conv_ref[0], conv_ref[1], conv_ref[2], conv_ref[3]);

	return std::string(ipv4_cstr);
}