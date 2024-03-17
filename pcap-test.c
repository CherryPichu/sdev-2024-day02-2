#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include "pcap-test.h"
#include <netinet/in.h>

// 참고 : 
// https://mayple.tistory.com/entry/Network-Pcap-을-이용한-패킷캡쳐응용

void usage()
{
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct
{
	char *dev_;
} Param;

Param param = {
	.dev_ = "eth0"};

bool parse(Param *param, int argc, char *argv[])
{
	if (argc != 2)
	{
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_packetData(struct pcap_pkthdr *header, u_char *packet)
{

	printf("\n\n---- Packet Start ----\n\n");

	for (int i = 0; i < header->caplen; i++)
	{
		printf("%02X", packet[i]);
	}

	printf("\n\n---- Packet End ----\n\n");
}
void print_hex(char* text, uint8_t *buffer, size_t size){
	printf("%s", text);
	for(int i = 0; i < size; i++ ){
		printf("%02X",buffer[i]);
	}
	printf("\n");
}

void print_uint32(char* text, uint32_t buffer){
	printf("%s", text);
	for(int i = 0; i < 4; i++ ){
		printf("%d", *((u_int8_t *) &buffer));
		if(i != 3) printf(".");
		buffer = buffer >> 8;
	}
	
	printf("\n");
}

void print_uint16(char* text, uint16_t buffer){
	buffer = ntohs(buffer);
	printf("%s", text);
	printf("%d",buffer);
	printf("\n");
}

int main(int argc, char *argv[])
{
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL)
	{
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		struct libnet_ethernet_hdr *etherNet = (struct libnet_ethernet_hdr *)packet;
		packet += sizeof(struct libnet_ethernet_hdr);
		struct libnet_ipv4_hdr *ipv4Net = (struct libnet_ipv4_hdr*) packet;
		packet += sizeof(struct libnet_ipv4_hdr);
		struct libnet_tcp_hdr *tcpNet =  (struct libnet_tcp_hdr*) packet;
		packet += sizeof(struct libnet_tcp_hdr) + 12; // 이 망할 optional 은 뭐길레 12바이트나 잡아먹을까요

		printf("---- start ----\n\n");

		print_hex("출발지 Mac : ", etherNet->ether_shost, sizeof(etherNet->ether_shost) );
		print_hex("목적지 Mac : ", etherNet->ether_dhost, sizeof(etherNet->ether_dhost) );

		print_uint32("출발지 IP : ", ipv4Net->ip_src.s_addr );
		print_uint32("도착지 IP : ", ipv4Net->ip_dst.s_addr );

		print_uint16("출발지 port : ",  tcpNet->th_sport);
		print_uint16("목적지 port : ", tcpNet->th_dport);

		// prinf("%X", ())
		printf("payload(Data) : 0x");
		for(int i = 0; i < 10; i++){
			printf("%02X" , packet[i]);
		}
		printf(" (max 10byte)\n");
		

		printf("---- end ----\n\n");


	}

	pcap_close(pcap);
}
