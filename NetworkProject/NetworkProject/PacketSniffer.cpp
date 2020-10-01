#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include "pcap.h"

#include <stdio.h>
#include <winsock2.h>
#include <stdlib.h>

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

#define TCP_OPTION 12
#define TCP_HEADER_JMP 20
#define SIZE_ETHERNET 14
#define ARP_REPLY_SIZE 46
#define ARP_REQUEST_SIZE 28
#define HTTP 80
#define SMTP 25
#define POP3 110
#define IMAP 143
#define DNS 53
#define SSH 22
#define FTP_DATA 20
#define FTP_CONTROLL 21
#define TELNET 23
#define TCP 6
#define UDP 17
#define SYN 0x02
#define PUSH 0x08
#define ACK 0x10
#define SYN_ACK 0x12
#define PUSH_ACK 0x18
#define FIN_ACK 0x11
#define DHCP_SERVER 67
#define DHCP_CLIENT 68

struct ether_addr
{
	unsigned char ether_addr_octet[6];
};

struct ether_header
{
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;
};

struct ip_header
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};

struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;

	unsigned char reserved_part1 : 3;
	unsigned char ns : 1;
	unsigned char data_offset : 4;
	unsigned char cwr : 1;
	unsigned char ecn : 1;
	unsigned char urg : 1;
	unsigned char ack : 1;
	unsigned char psh : 1;
	unsigned char rst : 1;
	unsigned char syn : 1;
	unsigned char fin : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};
struct udp_header
{
	unsigned short sourcePort;
	unsigned short destPort;
	unsigned short udpLength;
	unsigned short udpChecksum;
};
struct arp_header {
	u_int16_t htype;
	u_int16_t ptype;
	u_int8_t hlen;
	u_int8_t plen;
	u_int16_t opcode;
	u_int8_t sender_mac[6];
	u_int8_t sender_ip[4];
	u_int8_t target_mac[6];
	u_int8_t target_ip[4];
};
struct dns_header {
	unsigned short id;
	unsigned short flag;
	unsigned short qCount;
	unsigned short ansCount;
	unsigned short authCount;
	unsigned short addCount;
};
struct dhcp_packet {
	u_int8_t op; /* 0: Message opcode/type */
	u_int8_t htype; /* 1: Hardware addr type (net/if_types.h) */
	u_int8_t hlen; /* 2: Hardware addr length */
	u_int8_t hops; /* 3: Number of relay agent hops from client */
	u_int32_t xid; /* 4: Transaction ID */
	u_int16_t secs; /* 8: Seconds since client started looking */
	u_int16_t flags; /* 10: Flag bits */
	struct in_addr ciaddr; /* 12: Client IP address (if already in use) */
	struct in_addr yiaddr; /* 16: Client IP address */
	struct in_addr siaddr; /* 18: IP address of next server to talk to */
	struct in_addr giaddr; /* 20: DHCP relay agent IP address */
	const unsigned char chaddr[16]; /* 24: Client hardware address */
	char sname[64]; /* 40: Server name */
	char file[128]; /* 104: Boot filename */
	/* 212: Optional parameters
	(actual length dependent on MTU). */
};
struct packet {
	ether_header* eh;
	arp_header* ah;
	ip_header* ip;
	tcp_header* tcp = NULL;
	udp_header* udp = NULL;
	dns_header* dns;
	const unsigned char* app;
	int tcpCheck = 0;
	int udpCheck = 0;
};
struct CheckSummer
{
	u_short part1;
	u_short part2;
	u_short part3;
	u_short part4;
	u_short part5;
	u_short checksum;
	u_short part6;
	u_short part7;
	u_short part8;
	u_short part9;
};

void print_ether_header(ether_header* data);
void print_arp(arp_header* arp);
void print_ip(ip_header* ip);
void print_tcp(ip_header* ip, tcp_header* tcp);
void print_tcp_app(ip_header* ip, tcp_header* tcp, const char* appHeader);
void print_udp(ip_header* ip, udp_header* udp);
void print_udp_app(ip_header* ip, udp_header* udp, const char* appHeader);
void print_dns(dns_header* dns);
void print_payload(const unsigned char* app);
void print_dump(const unsigned char* app, int size);
void print_main();
void setTcpPayload(const unsigned char* packet, int ipLen);
void setUdpPayload(const unsigned char* packet, int ipLen);
void checksum_test(const unsigned char* pkt_data);
int check_torrent(const unsigned char* pkt_data, int size);
void print_dhcp(dhcp_packet* dhcp);

const u_char* tcp_payload;
struct packet* pk = (packet*)malloc(sizeof(struct packet));

int main() {
	pcap_if_t* alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	// find all network adapters
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("dev find failed\n");
		return -1;
	}
	if (alldevs == NULL) {
		printf("no devs found\n");
		return -1;
	}
	// print them
	pcap_if_t* d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	int inum, inum1, inum2;
	const char* packet_filter = "";

	printf("enter the interface number : ");
	scanf("%d", &inum);
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // jump to the i-th dev

	printf("\n\n--------------------------------------------------------\n");
	printf("choose the packet you want to catch.\n");
	printf("--------------------------------------------------------\n");
	printf("1:TCP(HTTP, FTP, TELNET, SSH, SMTP, POP3, IMAP, P2P)\n");
	printf("2:UDP(DNS, DHCP)\n");
	printf("3:ARP\n");
	printf("4:ALL\n");
	printf("--------------------------------------------------------\n");
	printf("Enter the number (1-4) : ");
	
	scanf_s("%d", &inum1);
	
	if (inum1 == 1) {
		packet_filter = "tcp";
		printf("\n--------------------------------------------------------\n");
		printf("choose the one packet you want to catch.\n");
		printf("--------------------------------------------------------\n");
		printf("1:HTTP\n");
		printf("2:FTP\n");
		printf("3:TELNET\n");
		printf("4:SSH\n");
		printf("5:SMTP\n");
		printf("6:POP3\n");
		printf("7:IMAP\n");
		printf("8:P2P\n");
		printf("9:ALL(TCP)\n");
		printf("--------------------------------------------------------\n");
		printf("Enter the number : ");
		scanf_s("%d", &inum2);
	}
	else if (inum1 == 2) {
		packet_filter = "udp";
		printf("\n--------------------------------------------------------\n");
		printf("choose the one packet you want to catch.\n");
		printf("--------------------------------------------------------\n");
		printf("1:DNS\n");
		printf("2:DHCP\n");
		printf("3:ALL(UDP)\n");
		printf("--------------------------------------------------------\n");
		printf("Enter the number : ");
		scanf_s("%d", &inum2);
	}
	else if (inum1 == 3) {
		packet_filter = "arp";
		inum2 = 0;
	}
	else if (inum1 == 4)
		inum2 = 0;
	// open
	pcap_t* fp;
	if ((fp = pcap_open_live(d->name,      // name of the device
		65536,                   // capture size
		1,  // promiscuous mode
		20,                    // read timeout
		errbuf
	)) == NULL) {
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("pcap open successful\n");

	struct bpf_program  fcode;
	if (pcap_compile(fp,  // pcap handle
		&fcode,  // compiled rule
		packet_filter,  // filter rule
		1,            // optimize
		NULL) < 0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(fp, &fcode) < 0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs); // we don't need this anymore

	struct pcap_pkthdr* header;

	const unsigned char* pkt_data;
	const unsigned char* ether_data;
	int res;

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;

		ether_data = pkt_data;
		if (pkt_data[13] == 0x00) {
			pk->eh = (struct ether_header*)pkt_data;
			pkt_data = pkt_data + SIZE_ETHERNET;

			struct  ip_header* ih;
			ih = (ip_header*)pkt_data;
			int ipLen = ih->ip_header_len * 4;
			pk->ip = ih;
			pkt_data = pkt_data + ipLen;
			int tcpLen;
			int udpLen;
			switch (ih->ip_protocol)
			{
			case TCP:
				pk->tcp = (tcp_header*)pkt_data;
				tcpLen = pk->tcp->data_offset * 4;
				setTcpPayload(pkt_data, ipLen);
				switch (inum2)
				{
				case 1://HTTP
					if (((ntohs(pk->tcp->source_port) == HTTP) || (ntohs(pk->tcp->dest_port) == HTTP)) 
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION) 
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 1)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 6)) {
						checksum_test(ether_data);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "HTTP");
						print_tcp(pk->ip, pk->tcp);
						printf("============HTTP Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============HTTP Header======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					break;
				case 2: //FTP 데이터 포트
					if (((ntohs(pk->tcp->source_port) == FTP_DATA) || (ntohs(pk->tcp->dest_port) == FTP_DATA)
						|| (ntohs(pk->tcp->source_port) == FTP_CONTROLL) || (ntohs(pk->tcp->dest_port) == FTP_CONTROLL)) 
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 6)) {
						checksum_test(ether_data);
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "FTP");
						print_tcp(pk->ip, pk->tcp);
						printf("============FTP Header=======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============FTP Header=======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					break;
				case 3: //Telnet 포트
					if (((ntohs(pk->tcp->source_port) == TELNET) || (ntohs(pk->tcp->dest_port) == TELNET))
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 6)) {
						checksum_test(ether_data);
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "TELNET");
						print_tcp(pk->ip, pk->tcp);
						printf("============TELNET Header====================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============TELNET Header====================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					break;
				case 4: { //SSH
					if (((ntohs(pk->tcp->source_port) == SSH) || (ntohs(pk->tcp->dest_port) == SSH)) && !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)) {
						checksum_test(ether_data);
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "SSH");
						print_tcp(pk->ip, pk->tcp);
						printf("============SSH Header=======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============SSH Header=======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					break;
				}
				case 5://SMTP
					if (((ntohs(pk->tcp->source_port) == SMTP) || (ntohs(pk->tcp->dest_port) == SMTP))
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_HEADER_JMP)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)) {
						checksum_test(ether_data);
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "SMTP");
						print_tcp(pk->ip, pk->tcp);
						printf("============SMTP Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============SMTP Header======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					break;
				case 6://POP3
					if (((ntohs(pk->tcp->source_port) == POP3) || (ntohs(pk->tcp->dest_port) == POP3))
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_HEADER_JMP)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)) {
						checksum_test(ether_data);
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "POP3");
						print_tcp(pk->ip, pk->tcp);
						printf("============POP3 Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============POP3 Header======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					break;
				case 7://IMAP
					if (((ntohs(pk->tcp->source_port) == IMAP) || (ntohs(pk->tcp->dest_port) == IMAP))
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_HEADER_JMP)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)) {
						checksum_test(ether_data);
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "IMAP");
						print_tcp(pk->ip, pk->tcp);
						printf("============IMAP Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============IMAP Header======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					break;
				case 8: //P2P
				{
					int check = check_torrent(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
					if (check) {
						checksum_test(ether_data);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "P2P");
						print_tcp(pk->ip, pk->tcp);
						printf("============P2P==============================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============P2P==============================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					else if ((ntohs(pk->tcp->dest_port) >= 6881 && ntohs(pk->tcp->dest_port) <= 6889) || (ntohs(pk->tcp->source_port) >= 6881 && ntohs(pk->tcp->source_port) <= 6889)) { //비트토렌트 프로토콜
						checksum_test(ether_data);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "P2P");
						print_tcp(pk->ip, pk->tcp);
						printf("============P2P==============================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============P2P==============================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
				}
				break;
				default: //ALL
					checksum_test(ether_data);
					pk->tcpCheck = 1;
					setTcpPayload(pkt_data, ipLen);
					//HTTP
					if (((ntohs(pk->tcp->source_port) == HTTP) || (ntohs(pk->tcp->dest_port) == HTTP)) 
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0) 
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION) 
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 1)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 6)) {
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "HTTP");
						print_tcp(pk->ip, pk->tcp);
						printf("============HTTP Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============HTTP Header======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}//FTP
					if (((ntohs(pk->tcp->source_port) == FTP_DATA) || (ntohs(pk->tcp->dest_port) == FTP_DATA)
						|| (ntohs(pk->tcp->source_port) == FTP_CONTROLL) || (ntohs(pk->tcp->dest_port) == FTP_CONTROLL))
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 6)) {
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "FTP");
						print_tcp(pk->ip, pk->tcp);
						printf("============FTP Header=======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============FTP Header=======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}//telnet
					if (((ntohs(pk->tcp->source_port) == TELNET) || (ntohs(pk->tcp->dest_port) == TELNET)) 
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 6)) {
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "TELNET");
						print_tcp(pk->ip, pk->tcp);
						printf("============TELNET Header====================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============TELNET Header====================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}//ssh
					if (((ntohs(pk->tcp->source_port) == SSH) || (ntohs(pk->tcp->dest_port) == SSH)) 
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)) {
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "SSH");
						print_tcp(pk->ip, pk->tcp);
						printf("============SSH Header=======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============SSH Header=======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}//SMTP
					if (((ntohs(pk->tcp->source_port) == SMTP) || (ntohs(pk->tcp->dest_port) == SMTP))
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_HEADER_JMP)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)) {
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "SMTP");
						print_tcp(pk->ip, pk->tcp);
						printf("============SMTP Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============SMTP Header======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}//POP3
					if (((ntohs(pk->tcp->source_port) == POP3) || (ntohs(pk->tcp->dest_port) == POP3))
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_HEADER_JMP)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)) {
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "POP3");
						print_tcp(pk->ip, pk->tcp);
						printf("============POP3 Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============POP3 Header======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}//IMAP
					if (((ntohs(pk->tcp->source_port) == IMAP) || (ntohs(pk->tcp->dest_port) == IMAP))
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_HEADER_JMP)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION)
						&& !(((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0)) {
						setTcpPayload(pkt_data, ipLen);
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "IMAP");
						print_tcp(pk->ip, pk->tcp);
						printf("============IMAP Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============IMAP Header======================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}//P2P
					int check = check_torrent(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
					if (check) {
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "P2P");
						print_tcp(pk->ip, pk->tcp);
						printf("============P2P==============================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============P2P==============================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}
					else if ((ntohs(pk->tcp->dest_port) >= 6881 && ntohs(pk->tcp->dest_port) <= 6889) || (ntohs(pk->tcp->source_port) >= 6881 && ntohs(pk->tcp->source_port) <= 6889)) { //비트토렌트 프로토콜
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "P2P");
						print_tcp(pk->ip, pk->tcp);
						printf("============P2P==============================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============P2P==============================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
						break;
					}
					if (((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 0) {
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "TCP");
						print_tcp(pk->ip, pk->tcp);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("=============================================================================================================================================\n");
					}
					else if (((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == TCP_OPTION) {
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "TCP");
						print_tcp(pk->ip, pk->tcp);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP + TCP_OPTION);
						printf("=============================================================================================================================================\n");
					}
					else if (((ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen) == 1) {
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "TCP");
						print_tcp(pk->ip, pk->tcp);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP + 1);
						printf("=============================================================================================================================================\n");
					}
					else {
						print_main();
						print_tcp_app(pk->ip, pk->tcp, "TCP");
						print_tcp(pk->ip, pk->tcp);
						printf("============Data=============================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============TCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->tcp, TCP_HEADER_JMP);
						printf("============Data=============================================================================================================================\n");
						print_dump(pk->app, (ntohs(pk->ip->ip_total_length)) - TCP_HEADER_JMP - ipLen);
						printf("=============================================================================================================================================\n");
					}
					break;
				}
				break;
			case UDP:
				pk->udp = (udp_header*)pkt_data;
				udpLen = sizeof(udp_header);
				switch (inum2)
				{
				case 1:  //DNS
				{
					dns_header* dns = (dns_header*)(pkt_data + udpLen);
					setUdpPayload(pkt_data, udpLen);
					if ((ntohs(pk->udp->sourcePort) == DNS) || ((ntohs(pk->udp->destPort) == DNS))) {
						checksum_test(ether_data);
						print_main();
						print_udp_app(pk->ip, pk->udp, "DNS");
						print_udp(pk->ip, pk->udp);
						print_dns(dns);
						printf("============DNS Header=======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============UDP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->udp, udpLen);
						printf("============DNS Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->app, (ntohs(pk->ip->ip_total_length)) - ipLen - udpLen);
						printf("=============================================================================================================================================\n");
					}
				}
				break;
				case 2: //DHCP
				{
					dhcp_packet* dhcp = (dhcp_packet*)(pkt_data + udpLen);
					setUdpPayload(pkt_data, udpLen);
					if ((ntohs(pk->udp->sourcePort) == DHCP_SERVER) || (ntohs(pk->udp->destPort) == DHCP_SERVER) && (ntohs(pk->udp->sourcePort) == DHCP_CLIENT) || (ntohs(pk->udp->destPort) == DHCP_CLIENT)) {
						checksum_test(ether_data);
						print_main();
						print_udp_app(pk->ip, pk->udp, "DHCP");
						print_udp(pk->ip, pk->udp);
						print_dhcp(dhcp);
						printf("============DHCP Header=======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header===================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header=========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============UDP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->udp, udpLen);
						printf("============DHCP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->app, (ntohs(pk->ip->ip_total_length)) - ipLen - udpLen);
						printf("==============================================================================================================================================\n");
					}
					break;
				}

				default:

					checksum_test(ether_data);
					pk->udpCheck = 1;
					setUdpPayload(pkt_data, udpLen);

					if ((ntohs(pk->udp->sourcePort) == DNS) || ((ntohs(pk->udp->destPort) == DNS))) {
						dns_header* dns = (dns_header*)(pkt_data + udpLen);
						print_main();
						print_udp_app(pk->ip, pk->udp, "DNS");
						print_udp(pk->ip, pk->udp);
						print_dns(dns);
						printf("============DNS Header=======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============UDP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->udp, udpLen);
						printf("============DNS Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->app, (ntohs(pk->ip->ip_total_length)) - ipLen - udpLen);
						printf("=============================================================================================================================================\n");
						break;
					}

					if ((ntohs(pk->udp->sourcePort) == DHCP_SERVER) || (ntohs(pk->udp->destPort) == DHCP_SERVER) && (ntohs(pk->udp->sourcePort) == DHCP_CLIENT) || (ntohs(pk->udp->destPort) == DHCP_CLIENT)) {
						dhcp_packet* dhcp = (dhcp_packet*)(pkt_data + udpLen);
						print_main();
						print_udp_app(pk->ip, pk->udp, "DHCP");
						print_udp(pk->ip, pk->udp);
						print_dhcp(dhcp);
						printf("============DHCP Header======================================================================================================================\n");
						print_payload(pk->app);
						printf("============ETHERNET Header==================================================================================================================\n");
						print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
						printf("============IP Header========================================================================================================================\n");
						print_dump((const unsigned char*)pk->ip, ipLen);
						printf("============UDP Header=======================================================================================================================\n");
						print_dump((const unsigned char*)pk->udp, udpLen);
						printf("============DHCP Header======================================================================================================================\n");
						print_dump((const unsigned char*)pk->app, (ntohs(pk->ip->ip_total_length)) - ipLen - udpLen);
						printf("=============================================================================================================================================\n");
						break;
					}

					print_main();
					print_udp_app(pk->ip, pk->udp, "UDP");
					print_udp(pk->ip, pk->udp);
					printf("============Data=================================================================================================================================\n");
					print_payload(pk->app);
					printf("============ETHERNET Header======================================================================================================================\n");
					print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
					printf("============IP Header============================================================================================================================\n");
					print_dump((const unsigned char*)pk->ip, ipLen);
					printf("============UDP Header===========================================================================================================================\n");
					print_dump((const unsigned char*)pk->udp, udpLen);
					printf("============Data=================================================================================================================================\n");
					print_dump((const unsigned char*)pk->app, (ntohs(pk->ip->ip_total_length)) - ipLen - udpLen);
					printf("=================================================================================================================================================\n");
					break;
				}
				break;
			default:
				break;
			}
		}
		else if (pkt_data[13] == 6) {
			pk->eh = (struct ether_header*)pkt_data;
			pkt_data = pkt_data + SIZE_ETHERNET;
			struct arp_header* ah = (arp_header*)pkt_data;
			pk->ah = ah;
			print_arp(pk->ah);
			printf("============ETHERNET Header==================================================================================================================\n");
			print_dump((const unsigned char*)pk->eh, SIZE_ETHERNET);
			printf("============ARP Header=======================================================================================================================\n");
			if (ntohs(pk->ah->opcode) == 1)
				print_dump((const unsigned char*)pk->ah, ARP_REQUEST_SIZE);
			else
				print_dump((const unsigned char*)pk->ah, ARP_REPLY_SIZE);
			printf("=============================================================================================================================================\n");
		}
	}
	return 0;
}
void print_ether_header(ether_header* data)
{
	struct  ether_header* eh;               // 이더넷 헤더 구조체
	unsigned short ether_type;
	eh = data;
	ether_type = ntohs(eh->ether_type);       // 숫자는 네트워크 바이트 순서에서 호스트 바이트 순서로 바꿔야함

	if (ether_type == 0x0800)
	{
		printf("<<<IPv4>>>\n");
	}
	else if (ether_type == 0x0806)
	{
		printf("\n\n\n<<<ARP>>>\n");
	}
	// 이더넷 헤더 출력
	printf("============Ethernet Header==================================================================================================================\n");
	printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
		eh->ether_dhost.ether_addr_octet[0],
		eh->ether_dhost.ether_addr_octet[1],
		eh->ether_dhost.ether_addr_octet[2],
		eh->ether_dhost.ether_addr_octet[3],
		eh->ether_dhost.ether_addr_octet[4],
		eh->ether_dhost.ether_addr_octet[5]);
	printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
		eh->ether_shost.ether_addr_octet[0],
		eh->ether_shost.ether_addr_octet[1],
		eh->ether_shost.ether_addr_octet[2],
		eh->ether_shost.ether_addr_octet[3],
		eh->ether_shost.ether_addr_octet[4],
		eh->ether_shost.ether_addr_octet[5]);
	printf("=============================================================================================================================================\n");
}
void print_ip(ip_header* ip)
{
	print_ether_header(pk->eh);

	printf("============IP Header========================================================================================================================\n");
	printf(" |-IP Version : %d\n", (unsigned int)ip->ip_version);
	printf(" |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)ip->ip_header_len, ((unsigned int)(ip->ip_header_len) * 4));
	printf(" |-Type Of Service : %d\n", (unsigned int)ip->ip_tos);
	printf(" |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(ip->ip_total_length));
	printf(" |-Identification : %d\n", ntohs(ip->ip_id));
	printf(" |-TTL : %d\n", (unsigned int)ip->ip_ttl);
	printf(" |-Protocol : %d\n", (unsigned int)ip->ip_protocol);
	printf(" |-Checksum : %d\n", ntohs(ip->ip_checksum));
	printf(" |-Source IP : %s\n", inet_ntoa(ip->ip_srcaddr));
	printf(" |-Destination IP : %s\n", inet_ntoa(ip->ip_destaddr));
	printf("=============================================================================================================================================\n");
}
void print_tcp(ip_header* ip, tcp_header* tcp)
{
	print_ip(ip);
	printf("============TCP Header=======================================================================================================================\n");
	printf(" |-Source Port : %u\n", ntohs(tcp->source_port));
	printf(" |-Destination Port : %u\n", ntohs(tcp->dest_port));
	printf(" |-Sequence Number : %u\n", ntohl(tcp->sequence));
	printf(" |-Acknowledge Number : %u\n", ntohl(tcp->acknowledge));
	printf(" |-Header Length : %d DWORDS or %d BYTES\n"
		, (unsigned int)tcp->data_offset, (unsigned int)tcp->data_offset * 4);
	const char* flag = " ";
	if ((unsigned int)tcp->syn == 1)
	{
		if ((unsigned int)tcp->ack == 1)
			flag = "SYN, ACK";
		else
			flag = "SYN";
	}
	else if ((unsigned int)tcp->psh == 1) {
		if ((unsigned int)tcp->ack == 1)
			flag = "PSH, ACK";
		else
			flag = "PUSH";
	}
	else if ((unsigned int)tcp->ack == 1) {
		if ((unsigned int)tcp->fin == 1)
			flag = "FIN, ACK";
		else if ((unsigned int)tcp->rst == 1)
			flag = "RST, ACK";
		else
			flag = "ACK";
	}
	else
		flag = "Unknown";
	printf(" |-Flags : %s\n", flag);
	printf(" |-Urgent Flag : %d\n", (unsigned int)tcp->urg);
	printf(" |-Acknowledgement Flag : %d\n", (unsigned int)tcp->ack);
	printf(" |-Push Flag : %d\n", (unsigned int)tcp->psh);
	printf(" |-Reset Flag : %d\n", (unsigned int)tcp->rst);
	printf(" |-Synchronise Flag : %d\n", (unsigned int)tcp->syn);
	printf(" |-Finish Flag : %d\n", (unsigned int)tcp->fin);
	printf(" |-Window : %d\n", ntohs(tcp->window));
	printf(" |-Checksum : %d\n", ntohs(tcp->checksum));
	printf(" |-Urgent Pointer : %d\n", tcp->urgent_pointer);
	printf("=============================================================================================================================================\n");
}
void print_udp(ip_header* ip, udp_header* udp)
{
	print_ip(ip);
	printf("============UDP Header=======================================================================================================================\n");
	printf(" |-Source Port : %u\n", ntohs(udp->sourcePort));
	printf(" |-Destination Port : %u\n", ntohs(udp->destPort));
	printf(" |-Length : %u\n", ntohs(udp->udpLength));
	printf(" |-Checksum : 0x%04x\n", ntohs(udp->udpChecksum));
}
void print_payload(const unsigned char* app)
{
	printf("%s\n", app);
	printf("=============================================================================================================================================\n");
}
void setTcpPayload(const unsigned char* packet, int ipLen) {
	pk->app = (packet + ipLen);
}
void setUdpPayload(const unsigned char* packet, int udpLen)
{
	pk->app = (packet + udpLen);
}
void print_dump(const unsigned char* app, int size) {
	for (int i = 0; i < size; i++)
	{
		if (i % 16 == 0 && i != 0) {
			printf("   ");
		}
		if (i != 0 && i % 16 == 0)
		{
			for (int j = i - 16; j < i; j++)
			{
				if (app[j] >= 32 && app[j] <= 128) {
					printf("%c", ((unsigned char)app[j]));
				}
				else {
					printf(".");
				}
			}
			printf("\n");
		}
		printf(" %02X", (unsigned int)app[i]);
		if (i == size - 1)
		{
			for (int j = 2; j < 15 - i % 16; j++) {
				printf("   ");
			}
			printf("         ");

			for (int j = i - i % 16; j <= i; j++)
			{
				if (app[j] >= 32 && app[j] <= 128) {
					printf("%c", (unsigned char)app[j]);
				}
				else {
					printf(".");
				}
			}
			printf("\n");
		}
	}
}
void print_tcp_app(ip_header* ip, tcp_header* tcp, const char* appHeader)
{
	printf("%s      %s      %s      %u      %u      %u      %u\n", appHeader, _strdup(inet_ntoa(ip->ip_srcaddr)), _strdup(inet_ntoa(ip->ip_destaddr)), ntohs(tcp->source_port), ntohs(tcp->dest_port), ntohl(tcp->sequence), ntohl(tcp->acknowledge));
	printf("=============================================================================================================================================\n");
}
void print_udp_app(ip_header* ip, udp_header* udp, const char* appHeader)
{
	printf("%s      %s      %s      %u      %u\n", appHeader, _strdup(inet_ntoa(ip->ip_srcaddr)), _strdup(inet_ntoa(ip->ip_destaddr)), ntohs(udp->sourcePort), ntohs(udp->destPort));
	printf("=============================================================================================================================================\n");
}
void print_main() {
	printf("=============================================================================================================================================\n");
	printf("프로토콜   출발IP         목적IP          출발Port      목적Port   SeqNo         AckNo\n");
	printf("=============================================================================================================================================\n");
}
void print_arp(arp_header* arp) {
	print_ether_header(pk->eh);
	printf("============ARP Header=======================================================================================================================\n");
	if (ntohs(arp->htype) == 1) {
		printf(" |-Hardware type: Ethernet (%d)\n", ntohs(arp->htype));
	}
	else
		printf(" |-Hardware type: %04x\n", ntohs(arp->htype));
	if (ntohs(arp->ptype) == 0x0800) {
		printf(" |-Protocol type: IPv4 (0x%04x)\n", ntohs(arp->ptype));
	}
	else
		printf(" |-Protocol type: %04x\n", ntohs(arp->ptype));
	printf(" |-Hardware size: %x\n", arp->hlen);
	printf(" |-Protocol size: %x\n", arp->plen);
	printf(" |-ARP opcode: %x\n", ntohs(arp->opcode));
	printf(" |-Sender MAC address: ");
	for (int i = 0; i < 6; ++i) {
		printf("%x", arp->sender_mac[i]);
		if (i != 5)
			printf(":");
	}
	printf("\n");
	printf(" |-Sender IP address: ");
	for (int i = 0; i < 4; ++i) {
		printf("%d", arp->sender_ip[i]);
		if (i != 3)
			printf(".");
	}
	printf("\n");
	printf(" |-Target MAC address: ");
	for (int i = 0; i < 6; ++i) {
		printf("%x", arp->target_mac[i]);
		if (i != 5)
			printf(":");
	}
	printf("\n");
	printf(" |-Target IP address: ");
	for (int i = 0; i < 4; ++i) {
		printf("%d", arp->target_ip[i]);
		if (i != 3)
			printf(".");
	}
	printf("\n");
}
void checksum_test(const unsigned char* pkt_data)
{
	CheckSummer* CS = (struct CheckSummer*)(pkt_data + SIZE_ETHERNET);
	int partSum = ntohs(CS->part1) + ntohs(CS->part2) + ntohs(CS->part3) + ntohs(CS->part4) + ntohs(CS->part5) + ntohs(CS->part6) + ntohs(CS->part7) + ntohs(CS->part8) + ntohs(CS->part9);
	u_short Bit = partSum >> 16;
	printf("\n\n\n============Checksum Test====================================================================================================================\n");
	printf(" |-파트 합 : %08x\n", partSum);
	printf(" |-4칸 이동 : %08x\n", Bit);
	partSum = partSum - (Bit * 65536);
	printf(" |-넘긴것 더한 파트 합 : %04x\n", partSum + Bit);
	printf(" |-보수 취하기 : %04x\n", (u_short)~(partSum + Bit));
	printf(" |-체크섬 : %04x\n", ntohs(CS->checksum));
	if (ntohs(CS->checksum) == (u_short)~(partSum + Bit))
		printf(" |-손상되지 않은 정상 패킷입니다.\n");
	else
		printf(" |-손상된 패킷입니다. 재 전송 요청을 해야 합니다.\n");
}
void print_dns(dns_header* dns)
{
	printf("============DNS Header========================================================================================================================\n");
	printf(" |-Transaction ID: 0x%04x\n", ntohs(dns->id));
	printf(" |-Flag : 0x%04x\n", ntohs(dns->flag));
	printf(" |-Questions : %d\n", ntohs(dns->qCount));
	printf(" |-Answer RRs : %d\n", ntohs(dns->ansCount));
	printf(" |-Authority RRs : %d\n", ntohs(dns->authCount));
	printf(" |-Additional RRs : %d\n", ntohs(dns->addCount));
}
void print_dhcp(dhcp_packet* dhcp)
{
	printf("============DHCP Header=======================================================================================================================\n");
	if (ntohs(dhcp->op) == 1)
		printf(" |-Message type : Boot Request (%d)\n", ntohs(dhcp->op));
	else if (ntohs(dhcp->op) == 2)
		printf(" |-Message type : Boot Require (%d)\n", ntohs(dhcp->op));
	printf(" |-Hardware type : %d\n", ntohs(dhcp->op));
	printf(" |-Hardware Address Length : %d\n", (unsigned int)ntohs(dhcp->htype));
	printf(" |-Hops : %d\n", ntohs(dhcp->hlen));
	printf(" |-Transaction ID : %d\n", ntohs(dhcp->hops));
	printf(" |-Seconds : %d\n", ntohs(dhcp->xid));
	printf(" |-Boot flags : %d\n", ntohs(dhcp->secs));
	printf(" |-Client IP Address : %d\n", ntohs(dhcp->flags));
	printf(" |-Your IP Address : %s\n", inet_ntoa(dhcp->ciaddr));
	printf(" |-Next server IP Address : %s\n", inet_ntoa(dhcp->yiaddr));
	printf(" |-Relay agent IP Address : %s\n", inet_ntoa(dhcp->siaddr));
	printf(" |-Client Ethernet Address : %s\n", inet_ntoa(dhcp->giaddr));
	printf(" |-Client hardware address padding : %s\n", dhcp->chaddr);
	printf(" |-Server host name : %s\n", dhcp->sname);
	printf(" |-Boot File Name : %s\n", dhcp->file);
}
int check_torrent(const unsigned char* pkt_data, int size)
{
	for (int i = 1; i < size; ++i)
	{
		if (pk->app[i] == 'B' && pk->app[i + 1] == 'i'
			&& pk->app[i + 2] == 't')
			return 1;
		if ((pk->app[i] == 'T' || pk->app[i] == 't') && pk->app[i + 1] == 'o'
			&& pk->app[i + 2] == 'r' && pk->app[i + 3] == 'r' && pk->app[i + 4] == 'e'
			&& pk->app[i + 5] == 'n' && pk->app[i + 6] == 't')
			return 1;
	}
	return 0;
}