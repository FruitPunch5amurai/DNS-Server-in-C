#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

typedef struct
{
	uint16_t id, flags, qdcount, ancount, nscount, arcount;
} Header;

static uint16_t read_u16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
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
	size_t offset = 12;	// Byte offset
	uint16_t question_count = read_u16(packet + 4);

	for (uint16_t i = 0; i < question_count; i++)
	{
		printf("Question %u: ", i + 1);
		int first_label = 1;

		while (offset < length)
		{
			unsigned char label_length = packet[offset++];

			if (label_length == 0)
			{
				break; // End of QNAME
			}

			// Top bits 11 indicate a DNS compression pointer.
			if ((label_length & 0xC0) != 0 || label_length > length - offset)
			{
				printf("[compressed or malformed name]\n");
				return;
			}

			if (!first_label)
			{
				putchar('.');
			}
			fwrite(packet + offset, 1, label_length, stdout);
			first_label = 0;
			offset += label_length;
		}

		if (offset + 4 > length)
		{
			printf("\nIncomplete question\n");
			return;
		}

		uint16_t qtype = read_u16(packet + offset);
		uint16_t qclass = read_u16(packet + offset + 2);
		offset += 4;

		printf(" (type %u, class %u)\n", qtype, qclass);
	}
}

int main()
{
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

	int bytesRead;
	char buffer[512];
	socklen_t clientAddrLen = sizeof(clientAddress);

	printf("Socket Opened \n", bytesRead, buffer);
	while (1)
	{
		// Receive data
		bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&clientAddress, &clientAddrLen);
		if (bytesRead == -1)
		{
			perror("Error receiving data");
			break;
		}

		buffer[bytesRead] = '\0';
		printf("Received %d bytes: %s\n", bytesRead, buffer);

		Header *response = (Header *)buffer;
		((unsigned char *)response)[2] |= 0x80; // Set QR field to 1 using Bitwise OR;
		print_dns_sections((unsigned char *)response, (size_t)bytesRead);
		print_questions((unsigned char *)response, (size_t)bytesRead);
		
		// Send response
		if (sendto(udpSocket, response, sizeof(*response), 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress)) == -1)
		{
			perror("Failed to send response");
		}
	}

	close(udpSocket);

	return 0;
}
