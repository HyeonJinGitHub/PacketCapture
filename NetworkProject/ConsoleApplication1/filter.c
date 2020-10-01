#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifdef WIN32
#include <winsock2.h> /* Needed for ntohs() in Windows */
#endif
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

//#include <netinet/in.h>
//#include <linux/ip.h>
//#include <arpa/inet.h>
//#include <netinet/udp.h>
//#include <netinet/tcp.h>
#define IP_HL(ip)       (((ip)->ihl))
#define TH_OFF(th)      ((th)->th_off)
#include <time.h>
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"wpcap")
#pragma comment(lib,"IPHlpApi")
struct  ether_header {
	u_int8_t ether_dhost[6];   /* 6 bytes destination address */
	u_int8_t ether_shost[6];   /* 6 bytes source address */
	u_int16_t ether_type;      /* 2 bytes ethertype */
};
typedef struct _iphdr {
	unsigned char h_lenver;        //4位首部长度+4位IP版本号
	unsigned short h_length;
	unsigned char tos;             //8位服务类型TOS  
	unsigned short total_len;      //16位总长度（字节）  
	unsigned short ident;          //16位标识  
	unsigned short frag_and_flags; //3位标志位  
	unsigned char ttl;             //8位生存时间 TTL  
	unsigned char proto;           //8位协议 (TCP, UDP 或其他)  
	unsigned short checksum;       //16位IP首部校验和  
	unsigned int sourceIP;         //32位源IP地址  
	unsigned int destIP;           //32位目的IP地址  
} IP_HEADER;

//定义TCP报文首部
typedef struct _tcphdr {
	unsigned short th_sport;       //16位源端口  
	unsigned short th_dport;       //16位目的端口  
	unsigned int  th_seq;          //32位序列号  
	unsigned int  th_ack;          //32位确认号  
	unsigned char th_lenres;       //4 자리 헤더 길이 / 6 자리 예약어  
	unsigned char th_flag;         //6 비트 플래그 
	unsigned short th_win;         //16 비트 window 크기  
	unsigned short th_sum;         //16 비트 체크섬  
	unsigned short th_urp;         //16 비트 긴급 데이터 오프셋
} TCP_HEADER;

//定义UDP报文首部
typedef struct _udphdr {
	unsigned short uh_sport;    //16位源端口  
	unsigned short uh_dport;    //16位目的端口  
	unsigned short uh_len;      //16位长度  
	unsigned short uh_sum;      //16位校验和  
} UDP_HEADER;

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define MAXBYTE2CAPTURE 2048
#define IP_HL(ip)       (((ip)->ihl))
#define TH_OFF(th)      ((th)->th_off)

int32_t gmt2local(time_t t);
char* get_device(pcap_if_t* alldevs);
void get_http_method(const char* tcp_payload, size_t size_payload);
int get_http_uri(const char* ptr, int index, int size_payload);

int main(int argc, char* argv[]) {

	pcap_if_t* alldevs = NULL;
	pcap_t* device = NULL;
	char err_buffer[PCAP_ERRBUF_SIZE];
	char* device_name;
	struct pcap_pkthdr* pkthdr;

	u_int16_t etherType;
	const unsigned char* packet = NULL;
	const u_char* tcp_payload;
	struct sockaddr_in sourceIP, destinationIP;
	char source_address[INET_ADDRSTRLEN];
	char destination_address[INET_ADDRSTRLEN];

	/* Pointer to the  ether_header structure */
	struct ether_header* eptr;
	int res, size_ip, size_tcp, size_payload;
	TCP_HEADER* tcp = NULL;
	UDP_HEADER* udp = NULL;
	int32_t timezone;
	register int timestamp;

	timezone = gmt2local(0);
	memset(err_buffer, 0, PCAP_ERRBUF_SIZE);

	if (pcap_findalldevs(&alldevs, err_buffer) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs(): %s\n", err_buffer);
		exit(-1);
	}

	device_name = get_device(alldevs);
	if (device_name == NULL)
		exit(-1);

	device = pcap_open_live(device_name, MAXBYTE2CAPTURE, 1, 512, err_buffer);

	if (device == NULL) {
		printf("You must have sudo rights!\n");
		exit(1);
	}

	printf("Listening on interface %s\n", device_name);

	pcap_freealldevs(alldevs);

	// Retrieve the packets
	while ((res = pcap_next_ex(device, &pkthdr, &packet)) >= 0) {

		if (res == 0)
			/* Timeout elapsed */
			continue;

		if (packet == NULL)
			continue;

		eptr = (struct ether_header*) packet;

		timestamp = (int)((pkthdr->ts.tv_sec + timezone) % 86400);
		// print hour:minutes:seconds:usec
		printf("%02d:%02d:%02d.%06u ",
			timestamp / 3600, (timestamp % 3600) / 60, timestamp % 60, (unsigned)pkthdr->ts.tv_usec);
		fflush(stdout);

		printf("%02x:%02x:%02x:%02x:%02x:%02x --> %02x:%02x:%02x:%02x:%02x:%02x ",
			eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2],
			eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5],
			eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2],
			eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);
		fflush(stdout);

		// Get the etherType
		etherType = ntohs(eptr->ether_type);

		if (etherType == 0x800) {

			IP_HEADER* ipHeader;

			// Same offset even if it's a 802.11 data link type, cause it's converted by the NIC
			ipHeader = (IP_HEADER*)(packet + SIZE_ETHERNET);
			size_ip = sizeof(ipHeader) * 4;
			//size_ip = IP_HL(ipHeader) * 4;
			/*if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", (IP_HL(ipHeader) * 4));
				continue;
			}*/

			// Get IPv4 addresses
			memset(&sourceIP, 0, sizeof(sourceIP));
			sourceIP.sin_addr.s_addr = ipHeader->sourceIP;

			memset(&destinationIP, 0, sizeof(destinationIP));
			destinationIP.sin_addr.s_addr = ipHeader->destIP;

			strcpy(source_address, inet_ntoa(sourceIP.sin_addr));
			strcpy(destination_address, inet_ntoa(destinationIP.sin_addr));

			printf("%s --> %s  ", source_address, destination_address);
			fflush(stdout);

			// Switch between IP protocols
			switch (ipHeader->proto) {

			case IPPROTO_TCP:
				printf("TCP ");
				tcp = (TCP_HEADER*)(packet + SIZE_ETHERNET);
				size_tcp = tcp->th_lenres * 4;
				// TCP data offset * 4
				//size_tcp = TH_OFF(tcp) * 4;
				/*if (size_tcp < 20) {
					printf("   * Invalid TCP header length: %u!\n", size_tcp);
					break;
				}*/
				printf("%d --> %d", ntohs((u_int16_t)tcp->th_sport), ntohs((u_int16_t)tcp->th_dport));
				fflush(stdout);

				// Check if the port destination is 80 (Probably http request)
				if (ntohs((u_int16_t)tcp->th_dport) == 80) {

					/* define/compute tcp payload (segment) offset */
					tcp_payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
					/* compute tcp payload (segment) size */
					size_payload = ipHeader->total_len - (size_ip + size_tcp);

					if (size_payload > 0) {
						get_http_method((const char*)tcp_payload, (size_t)size_payload);
					}
				}
				break;

			case IPPROTO_UDP:
				printf("UDP ");
				udp = (struct udphdr*) ((char*)ipHeader + sizeof(ipHeader));
				printf("%d --> %d", ntohs((u_int16_t)udp->uh_sport), ntohs((u_int16_t)udp->uh_dport));
				break;

			case IPPROTO_ICMP:
				printf("ICMP");
				break;

			default:
				break;
				//printf("%d", ipHeader->header);
			}
			fflush(stdout);
		}
		else
			printf("\nNot an IPv4 packet: ethertype = 0x%04x\n", etherType);

		printf("\n");
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(device));
		return -1;
	}

	return 0;
}

/*
 * Ask the user to select a device from a list retrieved with pcap_findalldevs()
 */
char* get_device(pcap_if_t* alldevs) {

	/* Retrieve the device list on the local machine */
	pcap_if_t* selectedDevice;
	char* device_name;

	int i = 0, interface_number;

	/* Print the list */
	for (selectedDevice = alldevs; selectedDevice; selectedDevice = selectedDevice->next) {
		printf("%d) %s", ++i, selectedDevice->name);
		if (selectedDevice->description)
			printf(" (%s)\n", selectedDevice->description);
		else
			printf(" (Description N/A)\n");
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		pcap_freealldevs(alldevs);
		return NULL;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &interface_number);

	if (interface_number < 1 || interface_number > i) {
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return NULL;
	}

	/* Jump to the selected adapter */
	for (selectedDevice = alldevs, i = 0; i < interface_number - 1; selectedDevice = selectedDevice->next, i++);

	device_name = selectedDevice->name;

	return device_name;
}

/*
* Returns the difference between gmt and local time in seconds.
* Use gmtime() and localtime() to keep things simple. (Stolen
* verbatim from tcpdump.)
*/
int32_t gmt2local(time_t t) {
	register int dt, dir;
	register struct tm* gmt, * loc;
	struct tm sgmt;

	if (t == 0)
		t = time(NULL);
	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);
	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
		(loc->tm_min - gmt->tm_min) * 60;

	/*
	 * If the year or julian day is different, we span 00:00 GMT
	 * and must add or subtract a day. Check the year first to
	 * avoid problems when the julian day wraps.
	 */
	dir = loc->tm_year - gmt->tm_year;
	if (dir == 0)
		dir = loc->tm_yday - gmt->tm_yday;
	dt += dir * 24 * 60 * 60;

	return (dt);
}

void get_http_method(const char* tcp_payload, size_t size_payload) {

	int index = 0;
	const char* ptr;

	ptr = tcp_payload;
	/* Look for the space following the Method */
	while (index < size_payload) {
		if (*ptr == ' ') {
			ptr++;
			break;
		}
		else {
			ptr++;
			index++;
		}
	}

	/* Check the methods that have same length */
	switch (index) {
	case 3:
		if (strncmp(tcp_payload, "GET", (size_t)index) == 0) {
			printf("\nGET");

			index = get_http_uri(ptr, index, (int)size_payload);
			printf("%.*s", index, tcp_payload + 3);
		}
		else if (strncmp(tcp_payload, "PUT", (size_t)index) == 0) {
			printf("\nPUT!");

			index = get_http_uri(ptr, index, (int)size_payload);
			printf("%.*s", index, tcp_payload + 3);
		}
		break;
	case 4:
		if (strncmp(tcp_payload, "POST", (size_t)index) == 0) {
			printf("\nPOST!");

			index = get_http_uri(ptr, index, (int)size_payload);
			printf("%.*s", index, tcp_payload + 4);
		}
		else if (strncmp(tcp_payload, "HEAD", (size_t)index) == 0) {
			printf("\nHEAD!");

			index = get_http_uri(ptr, index, (int)size_payload);
			printf("%.*s", index, tcp_payload + 4);
		}
		break;
	case 5:
		if (strncmp(tcp_payload, "PATCH", (size_t)index) == 0) {
			printf("\nPATCH!");

			index = get_http_uri(ptr, index, (int)size_payload);
			printf("%.*s", index, tcp_payload + 5);
		}
		else if (strncmp(tcp_payload, "JSONP", (size_t)index) == 0) {
			printf("\nJSONP!");

			index = get_http_uri(ptr, index, (int)size_payload);
			printf("%.*s", index, tcp_payload + 5);
		}
		break;
	case 6:
		if (strncmp(tcp_payload, "DELETE", (size_t)index) == 0) {
			printf("\nDELETE!");

			index = get_http_uri(ptr, index, (int)size_payload);
			printf("%.*s", index, tcp_payload + 6);
		}
		break;
	default:
		break;
	}

	return;
}

/*
 * Retrieve the path to which the http request refers to.
 * After the http method (e.g. GET, POST) there is an http resource and the a space. So I search for that space,
 * then I return the offset.
 */
int get_http_uri(const char* ptr, int index, int size_payload) {

	while (index < size_payload) {
		if (*ptr == ' ')
			break;
		else {
			ptr++;
			index++;
		}
	}

	return index;
}