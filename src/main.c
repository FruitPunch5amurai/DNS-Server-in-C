#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

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

static int decode_dns_name(const unsigned char *packet, size_t length, size_t start,
						   unsigned char *name, size_t *name_length, size_t *encoded_end)
{
	size_t offset = start;
	size_t output_length = 0;
	size_t steps = 0;
	int jumped = 0;

	while (offset < length && steps++ < length)
	{
		unsigned char label_length = packet[offset];
		if ((label_length & 0xC0) == 0xC0) // Check if top 2 bits are 11, means compression pointer
		{
			if (length - offset < 2)
			{
				return 0;
			}

			size_t pointer = ((size_t)(label_length & 0x3F) << 8) | packet[offset + 1];
			if (pointer >= offset || pointer >= length)
			{
				return 0;
			}
			if (!jumped)
			{
				*encoded_end = offset + 2;
				jumped = 1;
			}
			offset = pointer;
			continue;
		}

		if ((label_length & 0xC0) != 0)
		{
			return 0;
		}

		++offset;
		if (label_length == 0)
		{
			if (!jumped)
			{
				*encoded_end = offset;
			}
			if (output_length >= 255)
			{
				return 0;
			}
			name[output_length++] = 0;
			*name_length = output_length;
			return 1;
		}

		if (label_length > length - offset || output_length + label_length + 2 > 255)
		{
			return 0;
		}
		name[output_length++] = label_length;
		memcpy(name + output_length, packet + offset, label_length);
		output_length += label_length;
		offset += label_length;
	}

	return 0;
}

static int build_single_question(const unsigned char *request, size_t request_length,
								 size_t question_offset, unsigned char *message,
								 size_t capacity, size_t *message_length, size_t *next_question_offset)
{
	if (request_length < 12 || question_offset >= request_length || capacity < 17)
	{
		return 0;
	}

	unsigned char name[255];
	size_t name_length = 0; // Length of QNAME
	size_t encoded_end = 0; // Where QNAME ends
	if (!decode_dns_name(request, request_length, question_offset, name, &name_length, &encoded_end) ||
		encoded_end > request_length || request_length - encoded_end < 4 ||
		capacity - 12 < name_length + 4)
	{
		return 0;
	}

	memcpy(message, request, 12);								  // Copy header from the request to the new message
	message[4] = 0;												  // High Byte
	message[5] = 1;												  // Low Byte, Set Number of Question to 1
	memset(message + 6, 0, 6);									  // Clear ANCOUNT, NSCOUNT, ARCOUNT
	memcpy(message + 12, name, name_length);					  // Copy the QNAME into the message
	memcpy(message + 12 + name_length, request + encoded_end, 4); // Copy QTYPE and QCLASS into the new message
	*message_length = 12 + name_length + 4;
	*next_question_offset = encoded_end + 4; // Where the next question starts
	return 1;
}

static void write_u16(unsigned char *p, uint16_t value)
{
	p[0] = (unsigned char)(value >> 8);
	p[1] = (unsigned char)value;
}

static int append_resolver_answers(const unsigned char *upstream, size_t upstream_length,
								   unsigned char *response, size_t *response_length,
								   size_t capacity, uint16_t *answers_added)
{
	if (upstream_length < 12 || *response_length > capacity)
	{
		return 0;
	}

	size_t offset = 12;
	uint16_t question_count = read_u16(upstream + 4);
	for (uint16_t i = 0; i < question_count; ++i)
	{
		if (!skip_dns_name(upstream, upstream_length, &offset) ||
			upstream_length - offset < 4)
		{
			return 0;
		}
		offset += 4;
	}

	uint16_t answer_count = read_u16(upstream + 6);
	for (uint16_t i = 0; i < answer_count; ++i)
	{
		unsigned char owner_name[255];
		size_t owner_length = 0;
		size_t owner_end = 0;
		if (!decode_dns_name(upstream, upstream_length, offset,
							 owner_name, &owner_length, &owner_end) ||
			owner_end > upstream_length || upstream_length - owner_end < 10)
		{
			return 0;
		}

		uint16_t type = read_u16(upstream + owner_end);
		uint16_t data_length = read_u16(upstream + owner_end + 8);
		size_t data_start = owner_end + 10;
		if (data_length > upstream_length - data_start)
		{
			return 0;
		}
		size_t data_end = data_start + data_length;

		if (capacity - *response_length < owner_length + 10)
		{
			return 0;
		}
		memcpy(response + *response_length, owner_name, owner_length);
		*response_length += owner_length;
		memcpy(response + *response_length, upstream + owner_end, 8);
		*response_length += 8;
		size_t output_data_length_offset = *response_length;
		*response_length += 2;
		size_t output_data_start = *response_length;

		size_t prefix_length = 0;
		int has_name_rdata = 0;
		switch (type)
		{
		case 2:  // NS
		case 5:  // CNAME
		case 12: // PTR
		case 39: // DNAME
			has_name_rdata = 1;
			break;
		case 15: // MX
			prefix_length = 2;
			has_name_rdata = 1;
			break;
		case 33: // SRV
			prefix_length = 6;
			has_name_rdata = 1;
			break;
		default:
			break;
		}

		if (type == 6) // SOA: two names followed by five 32-bit values
		{
			unsigned char name[255];
			size_t name_length = 0;
			size_t encoded_end = 0;
			if (!decode_dns_name(upstream, upstream_length, data_start,
								 name, &name_length, &encoded_end) ||
				encoded_end > data_end || capacity - *response_length < name_length)
			{
				return 0;
			}
			memcpy(response + *response_length, name, name_length);
			*response_length += name_length;

			unsigned char second_name[255];
			size_t second_name_length = 0;
			size_t second_encoded_end = 0;
			if (!decode_dns_name(upstream, upstream_length, encoded_end,
								 second_name, &second_name_length, &second_encoded_end) ||
				second_encoded_end > data_end || data_end - second_encoded_end != 20 ||
				capacity - *response_length < second_name_length + 20)
			{
				return 0;
			}
			memcpy(response + *response_length, second_name, second_name_length);
			*response_length += second_name_length;
			memcpy(response + *response_length, upstream + second_encoded_end, 20);
			*response_length += 20;
		}
		else if (has_name_rdata)
		{
			if (prefix_length > data_length || capacity - *response_length < prefix_length)
			{
				return 0;
			}
			memcpy(response + *response_length, upstream + data_start, prefix_length);
			*response_length += prefix_length;
			unsigned char name[255];
			size_t name_length = 0;
			size_t encoded_end = 0;
			if (!decode_dns_name(upstream, upstream_length, data_start + prefix_length,
								 name, &name_length, &encoded_end) ||
				encoded_end != data_end || capacity - *response_length < name_length)
			{
				return 0;
			}
			memcpy(response + *response_length, name, name_length);
			*response_length += name_length;
		}
		else
		{
			if (capacity - *response_length < data_length)
			{
				return 0;
			}
			memcpy(response + *response_length, upstream + data_start, data_length);
			*response_length += data_length;
		}

		if (*response_length - output_data_start > UINT16_MAX)
		{
			return 0;
		}
		write_u16(response + output_data_length_offset,
				  (uint16_t)(*response_length - output_data_start));
		offset = data_end;
		++*answers_added;
	}

	return 1;
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
	int udpSocket;
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
	struct sockaddr_in resolver_addr;

	if (resolver_address)
	{
		forward_socket = socket(AF_INET, SOCK_DGRAM, 0);
		if (forward_socket < 0)
		{
			perror("failed to open socket for forwarding");
			return 1;
		}

		resolver_addr = (struct sockaddr_in){
			.sin_family = AF_INET,
			.sin_port = htons(atoi(resolver_port)),
		};

		if (inet_pton(AF_INET, resolver_ip, &resolver_addr.sin_addr) != 1)
		{
			fprintf(stderr, "Invalid resolver IP address\n");
			return 1;
		}
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
		if (bytesRead < 12)
		{
			fprintf(stderr, "Received packet is too short for a DNS header\n");
			continue;
		}

		if (!resolver_address)
		{
			memcpy(response, request, (size_t)bytesRead);
			size_t response_length = (size_t)bytesRead;
			response[2] &= (unsigned char)~0x06;
			response[2] |= 0x80;
			unsigned char opcode = (response[2] & 0x78) >> 3;
			response[3] = opcode == 0 ? 0x00 : 0x04;
			if (!append_a_answers(response, &response_length, sizeof(response)))
			{
				fprintf(stderr, "Invalid or oversized DNS question section\n");
				continue;
			}
			if (sendto(udpSocket, response, response_length, 0,
					   (struct sockaddr *)&clientAddress, clientAddrLen) == -1)
			{
				perror("Failed to send response");
			}
			continue;
		}

		size_t offset = 12;
		size_t question_end = bytesRead;
		memcpy(response, request, question_end);
		size_t response_length = question_end;
		write_u16(response + 6, 0);
		write_u16(response + 8, 0);
		write_u16(response + 10, 0);
		uint16_t answers_added = 0;
		int have_response_flags = 0;
		uint16_t question_count = read_u16(request + 4);

		for (uint16_t i = 0; i < question_count; i++)
		{
			unsigned char message[512];
			size_t message_length = 0;
			size_t next_question_offset = 0;
			if (!build_single_question(request, (size_t)bytesRead, offset, message,
									   sizeof(message), &message_length, &next_question_offset))
			{
				fprintf(stderr, "Invalid or incomplete DNS question\n");
				break;
			}

			offset = next_question_offset;
			if (sendto(forward_socket, message, message_length, 0,
				   (struct sockaddr *)&resolver_addr, sizeof(resolver_addr)) == -1)
			{
				perror("Failed to forward question to resolver");
				continue;
			}

			printf("Prepared question %u of %u (%zu bytes)\n",
				   i + 1, question_count, message_length);

			unsigned char resolver_response[4096];
			ssize_t resolver_bytes = recvfrom(forward_socket, resolver_response,
											 sizeof(resolver_response), 0, NULL, NULL);
			if (resolver_bytes < 12)
			{
				if (resolver_bytes < 0)
				{
					perror("recvfrom resolver");
				}
				else
				{
					fprintf(stderr, "Resolver response is too short\n");
				}
				continue;
			}

			if (read_u16(resolver_response) != read_u16(request))
			{
				fprintf(stderr, "Resolver response ID does not match request\n");
				continue;
			}
			if (!have_response_flags)
			{
				response[2] = resolver_response[2];
				response[3] = resolver_response[3];
				have_response_flags = 1;
			}

			uint16_t previous_answer_count = answers_added;
			size_t previous_response_length = response_length;
			if (!append_resolver_answers(resolver_response, (size_t)resolver_bytes,
									 response, &response_length, sizeof(response), &answers_added))
			{
				fprintf(stderr, "Invalid or oversized resolver answer section\n");
				answers_added = previous_answer_count;
				response_length = previous_response_length;
			}
		}

		if (have_response_flags)
		{
			write_u16(response + 6, answers_added);
			if (sendto(udpSocket, response, response_length, 0,
					   (struct sockaddr *)&clientAddress, clientAddrLen) == -1)
			{
				perror("Failed to send response to client");
			}
		}
	}

	close(udpSocket);

	return 0;
}
