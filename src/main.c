#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static uint16_t read_u16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static int skip_dns_name(const unsigned char *packet, size_t length, size_t *offset)
{
	while (*offset < length)
	{
		unsigned char label_length = packet[(*offset)++];
		if (label_length == 0)
		{
			return 1;
		}

		if ((label_length & 0xC0) == 0xC0)
		{
			if (*offset >= length)
			{
				return 0;
			}
			++(*offset);
			return 1;
		}

		if ((label_length & 0xC0) != 0 || label_length > length - *offset)
		{
			return 0;
		}
		*offset += label_length;
	}

	return 0;
}

static int append_a_answers(unsigned char *packet, size_t *length, size_t capacity)
{
	if (*length < 12 || *length > capacity)
	{
		return 0;
	}

	size_t question_length = *length;
	size_t offset = 12;
	uint16_t question_count = read_u16(packet + 4);
	uint16_t answer_count = 0;

	for (uint16_t i = 0; i < question_count; ++i)
	{
		size_t name_offset = offset;
		if (!skip_dns_name(packet, question_length, &offset) || question_length - offset < 4)
		{
			return 0;
		}

		uint16_t qtype = read_u16(packet + offset);
		uint16_t qclass = read_u16(packet + offset + 2);
		offset += 4;

		if (qtype != 1 || qclass != 1)
		{
			continue;
		}

		if (name_offset > 0x3FFF || capacity - *length < 16)
		{
			return 0;
		}

		// DNS Compression Pointer
		packet[*length] = (unsigned char)(0xC0 | (name_offset >> 8));
		packet[*length + 1] = (unsigned char)name_offset;

		packet[*length + 2] = 0;
		packet[*length + 3] = 1; // TYPE: A
		packet[*length + 4] = 0;
		packet[*length + 5] = 1; // CLASS: IN
		packet[*length + 6] = 0;
		packet[*length + 7] = 0;
		packet[*length + 8] = 0;
		packet[*length + 9] = 60; // TTL: 60 seconds
		packet[*length + 10] = 0;
		packet[*length + 11] = 4; // RDLENGTH: 4 bytes
		packet[*length + 12] = 8;
		packet[*length + 13] = 8;
		packet[*length + 14] = 8;
		packet[*length + 15] = 8;
		*length += 16;
		++answer_count;
	}

	packet[6] = (unsigned char)(answer_count >> 8);
	packet[7] = (unsigned char)answer_count;
	return 1;
}

static void print_dns_sections(const unsigned char *packet, size_t length)
{
	if (length < 12)
	{
		printf("Packet is too short for a DNS header\n");
		return;
	}

	uint16_t flags = read_u16(packet + 2);
	uint16_t questions = read_u16(packet + 4);
	uint16_t answers = read_u16(packet + 6);
	uint16_t authority = read_u16(packet + 8);
	uint16_t additional = read_u16(packet + 10);

	printf("Header:\n");
	printf("  ID: 0x%04x\n", read_u16(packet));
	printf("  Flags: 0x%04x\n", flags);
	printf("  QR: %u\n", (flags >> 15) & 1);

	printf("Question section: %u record(s)\n", questions);
	printf("Answer section: %u record(s)\n", answers);
	printf("Authority section: %u record(s)\n", authority);
	printf("Additional section: %u record(s)\n", additional);
}

static void print_questions(const unsigned char *packet, size_t length)
{
}

int main(int argc, char *argv[])
{

	char *resolver_address = NULL;
	char *resolver_ip = NULL;
	char *resolver_port = NULL;
	if (argc > 2 && strcmp(argv[1], "--resolver") == 0)
	{
		resolver_address = argv[2];
		resolver_ip = strtok(resolver_address, ":");
		resolver_port = strtok(NULL, ":");
	}
	printf("%s \n", resolver_address);

	// Disable output buffering
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");

	// TODO: Uncomment the code below to pass the first stage
	int udpSocket, client_addr_len;
	struct sockaddr_in clientAddress;

	udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpSocket == -1)
	{
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}

	// Since the tester restarts your program quite often, setting REUSE_PORT
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
	{
		printf("SO_REUSEPORT failed: %s \n", strerror(errno));
		return 1;
	}

	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(2053),
		.sin_addr = {htonl(INADDR_ANY)},
	};

	if (bind(udpSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
	{
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

	// Open Forwarding Port
	int forward_socket;
	if (resolver_address)
	{
		forward_socket = socket(AF_INET, SOCK_DGRAM, 0);
		if (forward_socket < 0)
		{
			perror("failed to open socket for forwarding");
			return 1;
		}

		struct sockaddr_in resolver_address = {
			.sin_family = AF_INET,
			.sin_port = htons(atoi(resolver_port))};
		inet_pton(AF_INET, resolver_ip, &resolver_address.sin_addr);
	}

	int bytesRead;
	unsigned char request[512];
	unsigned char response[4096];
	socklen_t clientAddrLen = sizeof(clientAddress);

	while (1)
	{
		// Receive data
		bytesRead = recvfrom(udpSocket, request, sizeof(request), 0, (struct sockaddr *)&clientAddress, &clientAddrLen);
		if (bytesRead == -1)
		{
			perror("Error receiving data");
			break;
		}

		printf("Received %d bytes\n", bytesRead);

		memcpy(response, request, (size_t)bytesRead);
		size_t responseLength = (size_t)bytesRead;

		// Set Header
		response[2] &= (unsigned char)~0x06; // Clear AA and TC flags.
		response[2] |= 0x80;				 // Set QR field to 1.
		unsigned char opcode = (response[2] & 0x78) >> 3;
		response[3] = opcode == 0 ? 0x00 : 0x04; // RA, Z, RCODE

		/*
		if (!append_a_answers(response, &responseLength, sizeof(response)))
		{
			fprintf(stderr, "Invalid or oversized DNS question section\n");
			continue;
		}
		*/

		// Print
		// print_dns_sections(response, responseLength);
		// print_questions(response, responseLength);

		// For each question, forward it to the resolver with the header in each

		size_t offset = 12; // Byte offset
		uint16_t question_count = read_u16(response + 4);
		
		for (uint16_t i = 0; i < question_count; i++)
		{
			printf("Question %u: ", i + 1);
			int first_label = 1;

			while (offset < responseLength)
			{
				unsigned char label_length = response[offset++];

				if (label_length == 0)
				{
					break; // End of QNAME
				}

				// Top bits 11 indicate a DNS compression pointer.
				if ((label_length & 0xC0) != 0 || label_length > responseLength - offset)
				{
					printf("[compressed or malformed name]\n");
					return;
				}

				if (!first_label)
				{
					putchar('.');
				}
				fwrite(response + offset, 1, label_length, stdout);
				first_label = 0;
				offset += label_length;
			}

			if (offset + 4 > responseLength)
			{
				printf("\nIncomplete question\n");
				return;
			}

			uint16_t qtype = read_u16(response + offset);
			uint16_t qclass = read_u16(response + offset + 2);
			offset += 4;

			printf(" (type %u, class %u)\n", qtype, qclass);
		}
	}

	close(udpSocket);

	return 0;
}
