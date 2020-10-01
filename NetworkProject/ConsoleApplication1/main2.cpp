
#include<errno.h>
#include<stdio.h> 
#include<stdlib.h>    
#include<string.h>    
#include "stdafx.h"

#define HAVE_REMOTE
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "pcap.h"
#include "remote-ext.h"
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h> 
#include <remote-ext.h>        //winpcap的头文件
#include <winsock2.h>
#include <process.h>              //多线程编程的头文件
#include <windows.h>
#include <Iphlpapi.h>             //提取网关用的头文件
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"wpcap")
#pragma comment(lib,"IPHlpApi")
void ProcessPacket(unsigned char*, int, int);
void print_ip_header(unsigned char*, int);
void print_tcp_packet(unsigned char*, int);
void printdata(unsigned char*, int);
void print_http(unsigned char*, int);
void print_dns(unsigned char*, int);
void print_smtp(unsigned char* Buffer, int Size);
void print_p2p(unsigned char* Buffer, int Size);
void print_ip_flags_frag(int);
void print_tcp_flags(int);
void print_set(int);
void print_dns_response_flags(char[], char[]);
void print_dns_request_flags(char[], char[]);
int iden_http(char[3][10]);
void check_res(int);
void check_red(int);
void check_rea(int);
int tran_hex(char[2][2]);
void ans_data(int, int, int, unsigned char*, char[1000], int, int);

struct sockaddr_in source, dest;

int main(void) {
	int saddr_size, data_size, num;
	struct sockaddr saddr;
	struct iphdr* iph;
	unsigned char* buffer = (unsigned char*)malloc(65536);

	while (1) {
		printf("1. HTTP  2. DNS  3. SMTP  4. BITTORRENT 5. POP\n");
		printf("Enter the number you would like to sniff : ");
		scanf("%d", &num);
		if (num <= 5 && num > 0)
			break;
		printf("Wrong number!\n");
	}

	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock_raw < 0) {
		perror("Socket Error");
		return 1;
	}

	while (1) {
		saddr_size = sizeof(saddr);//sizeof saddr;
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
		if (data_size < 0) {
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		//except local loopback
		if (strcmp(inet_ntoa(source.sin_addr), "127.0.1.1") != 0 && strcmp(inet_ntoa(source.sin_addr), "127.0.0.1") != 0)
			ProcessPacket(buffer, data_size, num);
	}
	close(sock_raw);
	printf("Finished");

	return 0;
}

void ProcessPacket(unsigned char* buffer, int size, int num) {
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	struct tcphdr* tcph;
	struct udphdr* udph;
	int header_size = 0;
	unsigned short iphdrlen = iph->ihl * 4;
	unsigned int protocol = iph->protocol;

	//tcp or udp
	if (protocol == 6) {
		tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
		header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
	}
	else if (protocol == 17) {
		udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	}

	switch (num) {
	case 1:
		//filtering HTTP	
		if (ntohs(tcph->dest) == 80 || ntohs(tcph->source) == 80)
			print_http(buffer, size);
		break;
	case 2:
		//filtering DNS
		if (protocol == 6) {
			if (ntohs(tcph->dest) == 53 || ntohs(tcph->source) == 53)
				print_dns(buffer, size);
		}
		else if (protocol == 17) {
			if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53)
				print_dns(buffer, size);
		}
		break;
	case 3:
		//filtering SMTP
		if (ntohs(tcph->dest) == 25 || ntohs(tcph->source) == 25)
			print_smtp(buffer, size);
		break;
	case 4:
		//filtering BITTORRENT
		if (ntohs(tcph->dest) != 1)
			print_p2p(buffer, size);
		break;
	case 5:
		if (ntohs(tcph->dest) == 110 || ntohs(tcph->source) == 110)
			print_pop(buffer, size);
		break;
	}
}

void print_ip_header(unsigned char* Buffer, int Size) {
	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	int frag;
	char frag_hex[2][2];

	unsigned char* data = Buffer + sizeof(struct ethhdr);

	sprintf(frag_hex[0], "%02x", data[6]);
	sprintf(frag_hex[1], "%02x", data[7]);
	frag = tran_hex(frag_hex);

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	printf("\n");
	printf("IP Header\n");
	printf("    Version: %d\n", (unsigned int)iph->version);
	printf("    Header Length: %d bytes\n", ((unsigned int)(iph->ihl)) * 4);
	printf("    Differentiated Services Field: 0x%02x\n", (unsigned int)iph->tos);
	printf("    Total Length: %d bytes\n", ntohs(iph->tot_len));
	printf("    Identification: 0x%04x (%d)\n", ntohs(iph->id), ntohs(iph->id));
	print_ip_flags_frag(frag);
	printf("    Time to live: %d\n", (unsigned int)iph->ttl);
	printf("    Protocol: ");
	if ((unsigned int)iph->protocol == 6)
		printf("TCP (6)\n");
	else if ((unsigned int)iph->protocol == 17)
		printf("UDP (17)\n");
	printf("    Header checksum: 0x%04x\n", ntohs(iph->check));
	printf("    Source: %s\n", inet_ntoa(source.sin_addr));
	printf("    Destination: %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size) {
	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int flags = (unsigned int)tcph->th_flags;

	printf("\n\n********************************************************************************\n");

	print_ip_header(Buffer, Size);

	printf("\n");
	printf("Transmission Control Protocol\n");
	printf("    Source Port: %u\n", ntohs(tcph->source));
	printf("    Destination Port: %u\n", ntohs(tcph->dest));
	printf("    Sequence Number: %u\n", ntohl(tcph->seq));
	printf("    Acknowledge Number: %u\n", ntohl(tcph->ack_seq));
	printf("    Header Length: %d bytes\n", ((unsigned int)tcph->doff) * 4);
	printf("    Flag: 0x%03x\n", (unsigned int)tcph->th_flags);
	print_tcp_flags(flags);
	printf("    Window size value: %d\n", ntohs(tcph->window));
	printf("    Checksum: 0x%04x\n", ntohs(tcph->check));
	printf("    Urgent pointer: %d\n", tcph->urg_ptr);
	printf("\n");
}

void print_http(unsigned char* Buffer, int Size) {
	int i, j, http_len = 0;
	print_tcp_packet(Buffer, Size);
	int data_len = 0;
	int etherlen = sizeof(struct ethhdr);
	struct iphdr* iph = (struct iphdr*)(Buffer + etherlen);
	unsigned short iphdrlen = iph->ihl * 4; //test

	struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + etherlen);

	int header_size = etherlen + iphdrlen + tcph->doff * 4;

	unsigned char* data = Buffer + header_size;
	char temp[3][10], iden[3][10];
	int method;

	for (j = 0; j < 4; j++) {
		sprintf(temp[j], "%c", data[j]);
		sprintf(iden[j], "%s", temp[j]);
	}

	method = iden_http(iden);

	if (method == 1) {
		printf("Hypertext Transfer Protocol\n");
		printf("    ");
		for (i = 0; i < Size - header_size; i++) {
			printf("%c", data[i]);

			for (j = 0; j < 4; j++)
				sprintf(temp[j], "%02x", data[i + j]);

			if (strcmp(temp[0], "0a") == 0)
				printf("    ");

			//CR LF CR LF means \n
			if (strcmp(temp[0], "0d") == 0 && strcmp(temp[1], "0a") == 0 && strcmp(temp[2], "0d") == 0 && strcmp(temp[3], "0a") == 0) {
				printf("\n");
				i += 4;
				http_len += 4;
				break;
			}
			http_len++;
		}
		data_len = Size - header_size - i;
	}


	if (data_len != 0)
		printf("    File Data: %d bytes\n", data_len);

	printf("\nEthernet Header\n");
	printdata(Buffer, etherlen);

	printf("IP Header\n");
	printdata(Buffer + etherlen, iphdrlen);

	printf("TCP Header\n");
	printdata(Buffer + iphdrlen + etherlen, tcph->doff * 4);

	if (http_len > 0) {
		if (Size == 60 && iphdrlen + tcph->doff * 4 == ntohs(iph->tot_len)) // no payload?
			printf("\n");
		else if (Size == 60) {
			printf("HTTP Header\n");
			printdata(Buffer + header_size, http_len);
			if (data_len > 0) {
				printf("HTTP Payload\n");
				printdata(Buffer + header_size + http_len, ntohs(iph->tot_len) - iphdrlen - tcph->doff * 4 - http_len);
			}
		}
		else {
			printf("HTTP Header\n");
			printdata(Buffer + header_size, http_len);
			if (data_len > 0) {
				printf("HTTP Payload\n");
				printdata(Buffer + header_size + http_len, data_len);
			}
		}
	}
	printf("\n\n********************************************************************************\n");
}

int iden_http(char temp[3][10]) {
	int ok = 0;
	if (strcmp(temp[0], "G") == 0 && strcmp(temp[1], "E") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], " ") == 0)
		ok = 1;
	else if (strcmp(temp[0], "H") == 0 && strcmp(temp[1], "T") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], "P") == 0)
		ok = 1;
	else if (strcmp(temp[0], "P") == 0 && strcmp(temp[1], "O") == 0 && strcmp(temp[2], "S") == 0 && strcmp(temp[3], "T") == 0)
		ok = 1;
	else if (strcmp(temp[0], "P") == 0 && strcmp(temp[1], "U") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], " ") == 0)
		ok = 1;
	else if (strcmp(temp[0], "D") == 0 && strcmp(temp[1], "E") == 0 && strcmp(temp[2], "L") == 0 && strcmp(temp[3], "E") == 0 && strcmp(temp[4], "T") == 0 && strcmp(temp[5], "E") == 0 && strcmp(temp[6], "E") == 0)
		ok = 1;
	else if (strcmp(temp[0], "C") == 0 && strcmp(temp[1], "O") == 0 && strcmp(temp[2], "N") == 0 && strcmp(temp[3], "N") == 0 && strcmp(temp[4], "E") == 0 && strcmp(temp[5], "C") == 0 && strcmp(temp[6], "T") == 0)
		ok = 1;
	else if (strcmp(temp[0], "O") == 0 && strcmp(temp[1], "P") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], "I") == 0 && strcmp(temp[4], "O") == 0 && strcmp(temp[5], "N") == 0)
		ok = 1;
	else if (strcmp(temp[0], "T") == 0 && strcmp(temp[1], "R") == 0 && strcmp(temp[2], "A") == 0 && strcmp(temp[3], "C") == 0 && strcmp(temp[4], "E") == 0)
		ok = 1;
	else if (strcmp(temp[0], "P") == 0 && strcmp(temp[1], "A") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], "C") == 0 && strcmp(temp[4], "H") == 0)
		ok = 1;

	return ok;
}

char domain_name[1000];
char name[1000];
char name_data[1000];
int first;

void print_dns(unsigned char* Buffer, int Size) {
	int i, j, k, l, payload_len = 0, dns_header;
	unsigned short iphdrlen;
	int etherlen = sizeof(struct ethhdr);
	char tran_id[2][10], flags[2][10];
	int ques, ans_rrs, auth_rrs, add_rrs, quer_type, res_type, res_class, data_len, quer_class;
	char data_len_hex[2][2], ques_hex[2][2], ans_rrs_hex[2][2], auth_rrs_hex[2][2], add_rrs_hex[2][2], res_type_hex[2][2], quer_type_hex[2][2];
	char temp[4];
	char* bin;


	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	struct udphdr* udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	unsigned char* data = Buffer + header_size;

	printf("\n\n***************************************************************************\n");

	print_ip_header(Buffer, Size);

	printf("\nUser Datagram Protocol\n");
	printf("    Source Port: %d\n", ntohs(udph->source));
	printf("    Destination Port: %d\n", ntohs(udph->dest));
	printf("    Length: %d\n", ntohs(udph->len));
	printf("    Checksum: %d\n", ntohs(udph->check));


	sprintf(tran_id[0], "%02x", data[0]);
	sprintf(tran_id[1], "%02x", data[1]);

	sprintf(flags[0], "%02x", data[2]);
	sprintf(flags[1], "%02x", data[3]);

	sprintf(ques_hex[0], "%02x", data[4]);
	sprintf(ques_hex[1], "%02x", data[5]);
	ques = tran_hex(ques_hex);

	sprintf(ans_rrs_hex[0], "%02x", data[6]);
	sprintf(ans_rrs_hex[1], "%02x", data[7]);
	ans_rrs = tran_hex(ans_rrs_hex);

	sprintf(auth_rrs_hex[0], "%02x", data[8]);
	sprintf(auth_rrs_hex[1], "%02x", data[9]);
	auth_rrs = tran_hex(auth_rrs_hex);

	sprintf(add_rrs_hex[0], "%02x", data[10]);
	sprintf(add_rrs_hex[1], "%02x", data[11]);
	add_rrs = tran_hex(add_rrs_hex);

	printf("\nDomain Name System");
	if (ntohs(udph->source) == 53)//Response
		printf(" (response)\n");
	else if (ntohs(udph->dest) == 53)//Request
		printf(" (query)\n");
	printf("    Transaction ID: 0x%s%s\n", tran_id[0], tran_id[1]);
	printf("    Flags: 0x%s%s\n", flags[0], flags[1]);

	if (ntohs(udph->source) == 53)//Response
		print_dns_response_flags(flags[0], flags[1]);
	else if (ntohs(udph->dest) == 53)//Request
		print_dns_request_flags(flags[0], flags[1]);

	printf("    Questions: %d\n", ques);
	printf("    Answer RRs: %d\n", ans_rrs);
	printf("    Authority RRS: %d\n", auth_rrs);
	printf("    Additional RRs: %d\n", add_rrs);
	printf("    Queries\n");

	k = 12;
	dns_header = 12;

	for (i = 0; i < strlen(domain_name); i++)
		domain_name[i] = '\0';

	for (i = 0; i < ques; i++) {
		printf("      ");
		l = 0;
		for (j = k + 1; j < 100000; j++) {
			k++;
			if (data[j] >= 33 && data[j] <= 127) {
				domain_name[l] = data[j];
				l++;
			}
			else if (data[j] == 0) {
				domain_name[l] = '\0';
				break;
			}
			else {
				domain_name[l] = '.';
				l++;
			}
		}

		sprintf(quer_type_hex[0], "%02x", data[j + 1]);
		sprintf(quer_type_hex[1], "%02x", data[j + 2]);
		quer_type = tran_hex(quer_type_hex);

		sprintf(temp, "%02x%02x", data[j + 3], data[j + 4]);
		quer_class = strtol(temp, &bin, 16);

		printf("%s:", domain_name);

		if (quer_type == 1)
			printf(" type %c,", 'A');
		else if (quer_type == 2)
			printf(" type %s,", "NS");
		else if (quer_type == 5)
			printf(" type %s,", "CNAME");
		else if (quer_type == 6)
			printf(" type %s,", "SOA");
		else if (quer_type == 28)
			printf(" type %s,", "AAAA");
		else
			printf(" type %d,", quer_type);

		if (quer_class == 1)
			printf(" class %s\n", "IN");
		else if (quer_class == 2)
			printf(" class %s\n", "Unassigned");
		else if (quer_class == 3)
			printf(" class %s\n", "CH");
		else if (quer_class == 4)
			printf(" class %s\n", "HS");
		else
			printf(" type 0x%04x\n", quer_class);

		k += 5;
	}

	first = 1;
	if (ans_rrs != 0)
		printf("    Answers\n");

	strcpy(name, domain_name);

	for (i = 0; i < ans_rrs; i++) {
		k += 2;
		sprintf(res_type_hex[0], "%02x", data[k]);
		sprintf(res_type_hex[1], "%02x", data[k + 1]);
		res_type = tran_hex(res_type_hex);

		sprintf(temp, "%02x%02x", data[k + 2], data[k + 3]);
		res_class = strtol(temp, &bin, 16);

		sprintf(data_len_hex[0], "%02x", data[k + 8]);
		sprintf(data_len_hex[1], "%02x", data[k + 9]);
		data_len = tran_hex(data_len_hex);

		ans_data(res_type, data_len, k + 10, data, domain_name, res_type, res_class);
		first = 0;

		printf("\n");
		k += 10 + data_len;
	}

	if (auth_rrs != 0)
		printf("    Authoritative nameservers\n");

	for (i = 0; i < auth_rrs; i++) {
		k += 2;
		sprintf(res_type_hex[0], "%02x", data[k]);
		sprintf(res_type_hex[1], "%02x", data[k + 1]);
		res_type = tran_hex(res_type_hex);

		sprintf(temp, "%02x%02x", data[k + 2], data[k + 3]);
		res_class = strtol(temp, &bin, 16);

		sprintf(data_len_hex[0], "%02x", data[k + 8]);
		sprintf(data_len_hex[1], "%02x", data[k + 9]);
		data_len = tran_hex(data_len_hex);

		ans_data(res_type, data_len, k + 10, data, domain_name, res_type, res_class);

		printf("\n");
		k += 10 + data_len;
	}

	if (add_rrs != 0)
		printf("    Additional records\n");

	for (i = 0; i < add_rrs; i++) {
		k += 2;
		sprintf(res_type_hex[0], "%02x", data[k]);
		sprintf(res_type_hex[1], "%02x", data[k + 1]);
		res_type = tran_hex(res_type_hex);

		sprintf(temp, "%02x%02x", data[k + 2], data[k + 3]);
		res_class = strtol(temp, &bin, 16);

		sprintf(data_len_hex[0], "%02x", data[k + 8]);
		sprintf(data_len_hex[1], "%02x", data[k + 9]);
		data_len = tran_hex(data_len_hex);

		ans_data(res_type, data_len, k + 10, data, domain_name, res_type, res_class);

		printf("\n");
		k += 10 + data_len;
	}

	payload_len = k;

	printf("\nEthernet Header\n");
	printdata(Buffer, etherlen);

	printf("IP Header\n");
	printdata(Buffer + etherlen, iphdrlen);

	printf("UDP Header\n");
	printdata(Buffer + iphdrlen + etherlen, sizeof(udph));

	if (payload_len > 0) {
		if (Size == 60 && iphdrlen + sizeof(udph) == ntohs(iph->tot_len))
			printf("\n");
		else if (Size == 60) {
			printf("DNS Header\n");
			printdata(Buffer + header_size, dns_header);
			printf("DNS Payload\n");
			printdata(Buffer + header_size + dns_header, ntohs(iph->tot_len) - iphdrlen - sizeof(udph) - dns_header);
		}
		else {
			printf("DNS Header\n");
			printdata(Buffer + header_size, dns_header);
			printf("DNS Payload\n");
			printdata(Buffer + header_size + dns_header, ntohs(iph->tot_len) - iphdrlen - sizeof(udph) - dns_header);
		}
	}
	printf("\n\n***************************************************************************\n");
}

//Print Data Dump
void printdata(unsigned char* data, int Size)
{
	int i, j;

	for (i = 0; i < Size; i++)
	{
		if (i != 0 && i % 16 == 0)   //if one line of hex printing is complete...
		{
			printf("         ");
			for (j = i - 16; j < i; j++)
			{
				if (data[j] >= 33 && data[j] <= 127)
					printf("%c", (unsigned char)data[j]); //if its a number or alphabet

				else printf("."); //otherwise print a dot
			}
			printf("\n");
		}

		if (i % 16 == 0) printf("   ");
		printf(" %02x", (unsigned int)data[i]);

		if (i == Size - 1)  //print the last spaces
		{
			for (j = 0; j < 15 - i % 16; j++)
			{
				printf("   "); //extra spaces
			}

			printf("         ");

			for (j = i - i % 16; j <= i; j++)
			{
				if (data[j] >= 33 && data[j] <= 127)
				{
					printf("%c", (unsigned char)data[j]);
				}
				else
				{
					printf(".");
				}
			}

			printf("\n");
		}
	}
}

//Print TCP Header flags
void print_tcp_flags(int flags) {
	int non, con, ecn, urg, ack, pus, res, syn, fin;
	int n, i;
	int bin[14];
	n = sizeof(bin) / sizeof(int);
	for (i = n - 1; i >= 0; i--) {
		if (i == 4 || i == 9) {
			bin[i] = 2;
			continue;
		}
		bin[i] = flags % 2;
		flags /= 2;
	}

	i = 5;
	printf("      ");
	printf("%d", bin[i]);
	con = bin[i];
	printf(" = Congest Window Reduced (CWR): ");
	print_set(con);

	i = 7;
	printf("      ");
	printf("%d", bin[i]);
	urg = bin[i];
	printf(" = Urgent: ");
	print_set(urg);

	i = 8;
	printf("      ");
	printf("%d", bin[i]);
	ack = bin[i];
	printf(" = Acknowledgment: ");
	print_set(ack);

	i = 12;
	printf("      ");
	printf("%d", bin[i]);
	syn = bin[i];
	printf(" = Syn: ");
	print_set(syn);

	i = 13;
	printf("      ");
	printf("%d", bin[i]);
	fin = bin[i];
	printf(" = Fin: ");
	print_set(fin);
}


void print_set(int check) {
	if (check == 1)
		printf("Set\n");
	else if (check == 0)
		printf("Not set\n");
}

//Print IP Header flags
void print_ip_flags_frag(int frag) {
	int dont, more, flag, offset = 0;
	int n, i, j, square;
	int bin[17];
	int temp[16];
	int remain;

	remain = frag;
	n = sizeof(bin) / sizeof(int);
	for (i = n - 1; i >= 0; i--) {
		if (i == 4) {
			bin[i] = 2;
			continue;
		}
		bin[i] = remain % 2;
		remain /= 2;
	}

	dont = bin[1];
	more = bin[2];

	if (dont == 1 && more == 1)
		flag = 3;
	else if (dont == 1 && more == 0)
		flag = 2;
	else if (dont == 0 && more == 1)
		flag = 1;
	else if (dont == 0 && more == 0)
		flag = 0;

	printf("    Flag: 0x0%d\n", flag);

	i = 0;
	printf("      ");
	printf("%d", bin[0]);
	i++;
	printf(" = Reserved bit: Not set\n");//Reserved bit is always "Not set"

	printf("      ");
	printf("%d", bin[1]);
	i++;
	printf(" = Don't fragment: ");
	print_set(dont);

	printf("      ");
	printf("%d", bin[2]);
	i++;
	printf(" = More fragment: ");
	print_set(more);

	remain = frag;
	n = sizeof(temp) / sizeof(int);
	for (i = n - 1; i >= 0; i--) {
		temp[i] = remain % 2;
		remain /= 2;
	}

	for (i = 3; i < 16; i++) {
		square = 1;
		for (j = i; j < 12; j++)
			square *= 2;
		offset += temp[i] * square;
	}

	printf("    Fragment offset: %d\n", offset);
}

//Printf DNS Request flags
void print_dns_request_flags(char flags1[], char flags2[]) {
	int res, opc[4], trun, red, non;
	char* temp1;
	int temp2 = strtol(flags1, &temp1, 16);
	int bin[19];
	int i, j;
	int n = sizeof(bin) / sizeof(int);

	for (i = 8; i >= 0; i--) {
		if (i == 4) {
			bin[i] = 2;
			continue;
		}
		bin[i] = temp2 % 2;
		temp2 /= 2;
	}
	temp2 = strtol(flags2, &temp1, 16);

	for (i = 18; i >= 9; i--) {
		if (i == 14 || i == 9) {
			bin[i] = 2;
			continue;
		}
		bin[i] = temp2 % 2;
		temp2 /= 2;
	}
	i = 0;
	printf("      ");
	printf("%d", bin[i]);
	res = bin[i];
	printf(" = Response: Message is a ");
	check_res(res);

	i = 8;
	printf("      ");
	printf("%d", bin[i]);
	red = bin[i];
	printf(" = Recursion desired: ");
	check_red(red);
}

//Printf DNS Response flags
void print_dns_response_flags(char flags1[], char flags2[]) {
	int res, opc[4], auth, trun, red, rea, ans, non, rec[4];
	char* temp1;
	int temp2 = strtol(flags1, &temp1, 16);
	int bin[19];
	int i, j, l = 0;
	int n = sizeof(bin) / sizeof(int);

	for (i = 8; i >= 0; i--) {
		if (i == 4) {
			bin[i] = 2;
			continue;
		}
		bin[i] = temp2 % 2;
		temp2 /= 2;
	}

	temp2 = strtol(flags2, &temp1, 16);

	for (i = 18; i >= 9; i--) {
		if (i == 14 || i == 9) {
			bin[i] = 2;
			continue;
		}
		bin[i] = temp2 % 2;
		temp2 /= 2;
	}
	i = 0;
	printf("      ");
	printf("%d", bin[i]);
	res = bin[i];
	printf(" = Response: Message is a ");
	check_res(res);

	i = 8;
	printf("      ");
	printf("%d", bin[i]);
	red = bin[i];
	printf(" = Recursion desired: ");
	check_red(red);

	i = 10;
	printf("      ");
	printf("%d", bin[i]);
	rea = bin[i];
	printf(" = Recursion available: Server can ");
	check_rea(rea);
}

//Check DNS flags
void check_res(int check) {
	if (check == 1)
		printf("response\n");
	else if (check == 0)
		printf("query\n");
}

void check_red(int check) {
	if (check == 1)
		printf("Do query recursively\n");
	else if (check == 0)
		printf("Do not query recursively\n");
}

void check_rea(int check) {
	if (check == 1)
		printf("do recursive queries\n");
	else if (check == 0)
		printf("do not recursive queries\n");
}

//Trans hex to dec
int tran_hex(char hex[2][2]) {
	char temp;
	int bin, result = 0;
	int i, j, k;

	for (i = 0; i < 4; i++) {
		k = 1;
		temp = hex[0][i];
		switch (temp) {
		case '0':
			bin = 0; break;
		case '1':
			bin = 1; break;
		case '2':
			bin = 2; break;
		case '3':
			bin = 3; break;
		case '4':
			bin = 4; break;
		case '5':
			bin = 5; break;
		case '6':
			bin = 6; break;
		case '7':
			bin = 7; break;
		case '8':
			bin = 8; break;
		case '9':
			bin = 9; break;
		case 'a':
			bin = 10; break;
		case 'b':
			bin = 11; break;
		case 'c':
			bin = 12; break;
		case 'd':
			bin = 13; break;
		case 'e':
			bin = 14; break;
		case 'f':
			bin = 15; break;
		defalut:
			printf("hex error"); break;
		}
		for (j = i; j < 3; j++)
			k *= 16;
		result += bin * k;
	}
	return result;
}

//DNS Response data
void ans_data(int type, int data_len, int k, unsigned char* data, char domain_name[1000], int res_type, int res_class) {
	int i, l;
	l = 0;
	char data_type[10];
	int* aa_name_data = malloc(1000);

	if (first == 0) {
		sprintf(&name[0], "%02x", data[k - 12]);
		sprintf(&name[2], "%02x", data[k - 11]);
	}
	switch (type) {
	case 2: {//NS
		strcpy(data_type, " ns ");
		for (i = k; i < k + data_len; i++) {
			aa_name_data[l] = data[i];
			l++;
		}
		break;
	}
	case 5: {//CNAME
		strcpy(data_type, " cname ");
		for (i = k; i < k + data_len; i++) {
			aa_name_data[l] = data[i];
			l++;
		}
		break;
	}
	case 6: {//SOA
		strcpy(data_type, " mname ");
		for (i = k + 1; i < k + data_len; i++) {
			if (data[i - 1] == 0 || data[i - 2] == 192)
				break;
			else {
				for (i = k; i < k + data_len; i++) {
					aa_name_data[l] = data[i];
					l++;
				}
			}
		}
		break;
	}
	default:
		break;
	}

	printf("      ");
	printf("%s:", name);

	if (res_type == 1)
		printf(" type %c,", 'A');
	else if (res_type == 2)
		printf(" type %s,", "NS");
	else if (res_type == 5)
		printf(" type %s,", "CNAME");
	else if (res_type == 6)
		printf(" type %s,", "SOA");
	else if (res_type == 28)
		printf(" type %s,", "AAAA");
	else
		printf(" type %d,", res_type);

	if (res_class == 1)
		printf(" class %s,", "IN");
	else if (res_class == 2)
		printf(" class %s,", "Unassigned");
	else if (res_class == 3)
		printf(" class %s,", "CH");
	else if (res_class == 4)
		printf(" class %s,", "HS");
	else
		printf(" type 0x%04x,", res_class);

	if (type == 1 || type == 28) {//A
		if (type == 1) {
			printf(" addr ");
			for (i = k; i < k + data_len; i++) {
				printf("%d", data[i]);
				if (i == k + data_len - 1)
					break;
				else
					printf(".");
			}
		}
		else if (type == 28) {//AAAA
			printf(" addr ");
			for (i = k; i < k + data_len; i += 2) {
				if (data[i] == 0 && data[i + 1] == 0) {
					l += 1;
					continue;
				}
				else if (data[i] == 0 && data[i + 1] != 0) {
					if (l >= 2) {
						printf(":");
						l = 0;
					}
					printf("%x", data[i + 1]);
					if (i == k + data_len - 2)
						break;
					else
						printf(":");
					continue;
				}
				if (l >= 2) {
					printf(":");
					l = 0;
				}
				printf("%x", data[i]);
				printf("%02x", data[i + 1]);
				if (i == k + data_len - 2)
					break;
				else
					printf(":");
			}
		}
	}
	else {
		printf("%s", data_type);
		for (i = 0; i < sizeof(aa_name_data); i++)
			printf("%02x", aa_name_data[i]);
	}
}

void print_smtp(unsigned char* Buffer, int Size) {
	int etherlen = sizeof(struct ethhdr);
	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl * 4;
	struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	print_tcp_packet(Buffer, Size);

	printf("IP Header\n");
	printdata(Buffer + etherlen, iphdrlen);

	printf("TCP Header\n");
	printdata(Buffer + iphdrlen + etherlen, tcph->doff * 4);

	if (Size - header_size != 0) {
		printf("SMTP Payload\n");
		printdata(Buffer + header_size, Size - header_size);
	}
}

void print_p2p(unsigned char* Buffer, int Size) {
	int etherlen = sizeof(struct ethhdr);
	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl * 4;
	struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	print_tcp_packet(Buffer, Size);

	printf("IP Header\n");
	printdata(Buffer + etherlen, iphdrlen);

	printf("TCP Header\n");
	printdata(Buffer + iphdrlen + etherlen, tcph->doff * 4);

	if (Size - header_size != 0) {
		printf("Torrent Payload\n");
		printdata(Buffer + header_size, Size - header_size);
	}
}

void print_pop(unsigned char* Buffer, int Size) {
	int etherlen = sizeof(struct ethhdr);
	struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl * 4;
	struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	print_tcp_packet(Buffer, Size);

	printf("IP Header\n");
	printdata(Buffer + etherlen, iphdrlen);

	printf("TCP Header\n");
	printdata(Buffer + iphdrlen + etherlen, tcph->doff * 4);

	if (Size - header_size != 0) {
		printf("POP Payload\n");
		printdata(Buffer + header_size, Size - header_size);
	}
}
