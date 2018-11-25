#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <thread>
#include <iostream>
#include <string>
#include <vector>
#include "TabelaArp.h"
#include "Iface.h"

/* */
/* */
#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 20
/* */
#define MAX_IFACES 64
#define MAX_IFNAME_LEN 22
#define ETH_ADDR_LEN 6
/* */

#define ARP_REQUEST 1 /* ARP Request             */
#define ARP_REPLY 2   /* ARP Reply               */

using namespace std;



TabelaArp tabelaArp;

//struct iface
//{
//	int sockfd;
//	int ttl;
//	int mtu;
//	char ifname[MAX_IFNAME_LEN];
//	unsigned char mac_addr[6];
//	string ip_addr;
//	unsigned int rx_pkts;
//	unsigned int rx_bytes;
//	unsigned int tx_pkts;
//	unsigned int tx_bytes;
//};

/* */
struct ether_hdr
{
	unsigned char ether_dhost[6]; // Destination address
	unsigned char ether_shost[6]; // Source address
	unsigned short ether_type;	// Type of the payload
};
/* */
struct ip_hdr
{

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unsigned char ip_ihl : 4,
		ip_v : 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	unsigned char ip_ihl : 4,
		ip_v : 4;
#endif
	unsigned char ip_tos;	 // Type of service
	unsigned short ip_len;	// Datagram Length
	unsigned short ip_id;	 // Datagram identifier
	unsigned short ip_offset; // Fragment offset
	unsigned char ip_ttl;	 // Time To Live
	unsigned char ip_proto;   // Protocol
	unsigned short ip_csum;   // Header checksum
	unsigned int ip_src;	  // Source IP address
	unsigned int ip_dst;	  // Destination IP address
};

/* */
typedef struct arpheader
{
	u_int16_t htype;	  /* Hardware Type           */
	u_int16_t ptype;	  /* Protocol Type           */
	unsigned char hlen;   /* Hardware Address Length */
	unsigned char plen;   /* Protocol Address Length */
	u_int16_t oper;		  /* Operation Code          */
	unsigned char sha[6]; /* Sender hardware address */
	unsigned char spa[4]; /* Sender IP address       */
	unsigned char tha[6]; /* Target hardware address */
	unsigned char tpa[4]; /* Target IP address       */
} arphdr_t;
//
//
Iface my_ifaces[MAX_IFACES];
mutex mtx_print;
//
// Print an Ethernet address
void print_eth_address(char *s, unsigned char *eth_addr)
{
	printf("Interface: %s\nMAC: %02X:%02X:%02X:%02X:%02X:%02X\n", s,
		   eth_addr[0], eth_addr[1], eth_addr[2],
		   eth_addr[3], eth_addr[4], eth_addr[5]);
}

/* */
// Bind a socket to an interface
int bind_iface_name(int fd, char *iface_name)
{
	return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, strlen(iface_name));
}
/* */
void get_iface_info(int sockfd, char *ifname, Iface *ifn)
{
	//PEGAR ENDEREÇO MAC
	struct ifreq s{};
	strcpy(s.ifr_name, ifname);
	if (0 == ioctl(sockfd, SIOCGIFHWADDR, &s))
	{
		memcpy(ifn->mac_addr, s.ifr_addr.sa_data, ETH_ADDR_LEN);
		ifn->sockfd = sockfd;
		strcpy(ifn->ifname, ifname);
	}
	else
	{
		perror("Error getting MAC address");
		exit(1);
	}

	//PEGAR ENDEREÇO IPV4
	struct ifreq s2{};
	strcpy(s2.ifr_name, ifname);
	int sockudp;
	if ((sockudp = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Erro ao criar socket udp()");
	}

	if ((ioctl(sockudp, SIOCGIFADDR, &s2)) < 0){
		perror("Erro ao bindar interface ao socket udp");
		exit(1);
	}
	close(sockudp);

	auto* ipaddr = (struct sockaddr_in*)&s2.ifr_addr;
	ifn->ip_addr = inet_ntoa(ipaddr->sin_addr);
}
// Print the expected command line for the program
void print_usage()
{
	printf("/xarpd <interface> [<interfaces>]\n");
	exit(1);
}

/**
* Trata sinais
*/
void treat_sign(int signal)
{
	if (signal == SIGINT) {
	    cout << "Recebido SIGINT, encerrando aplicação..." << endl;
	}
	exit(0);
}

/* */
// Break this function to implement the ARP functionalities.
void doProcess(unsigned char *packet, int len)
{
	if (!len || len < MIN_PACKET_SIZE)
		return;

	struct ether_hdr *eth = (struct ether_hdr *)packet;
	arphdr_t *arpheader = NULL; /* Pointer to the ARP header              */

	if (htons(0x0806) == eth->ether_type)
	{
		arpheader = (struct arpheader *)(packet + 14);
//		printf("\n");
//		printf("ARP\n");
//		printf("   |-Hardware type: %d\n", ntohs(arpheader->htype));
//		printf("   |-Protocol type: 0x%04X\n", ntohs(arpheader->ptype));
//		printf("   |-Length of hardware adress: %d\n", ((unsigned int)arpheader->hlen)) * 4;
//		printf("   |-Length of protocol adress: %d\n", ((unsigned int)arpheader->plen)) * 4;
//		printf("   |-Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");
//		printf("   |-Sender's hardware adress: %02X:%02X:%02X:%02X:%02X:%02X\n", arpheader->sha[0], arpheader->sha[1], arpheader->sha[2], arpheader->sha[3], arpheader->sha[4], arpheader->sha[5]);
//		printf("   |-Sender's protocol adress: %u.%u.%u.%u\n", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]);
//		printf("   |-Target hardware adress: %02X:%02X:%02X:%02X:%02X:%02X\n", arpheader->tha[0], arpheader->tha[1], arpheader->tha[2], arpheader->tha[3], arpheader->tha[4], arpheader->tha[5]);
//		printf("   |-Target protocol adress: %u.%u.%u.%u\n", arpheader->tpa[0], arpheader->tpa[1], arpheader->tpa[2], arpheader->tpa[3]);

        char buf[100]{};
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", arpheader->tpa[0], arpheader->tpa[1], arpheader->tpa[2], arpheader->tpa[3]);
        string ip_dest = buf;

        memset(buf ,0 , sizeof(buf));
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", arpheader->tha[0], arpheader->tha[1], arpheader->tha[2], arpheader->tha[3], arpheader->tha[4], arpheader->tha[5]);
        string eth_dest = buf;

        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]);
        string ip_src = buf;

        memset(buf ,0 , sizeof(buf));
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", arpheader->sha[0], arpheader->sha[1], arpheader->sha[2], arpheader->sha[3], arpheader->sha[4], arpheader->sha[5]);
        string eth_src = buf;

		/** Verifica se está esperando um arq reply e se estiver avisa a thread bloqueada **/
		if (ntohs(arpheader->oper) != ARP_REQUEST && tabelaArp.aguardando_reply){
			lock_guard<mutex> lck(tabelaArp.mtx_req);
			if (tabelaArp.ip_a_resolver == ip_src){
				tabelaArp.aguardando_reply = false;
				tabelaArp.semaforo.notify_one();
			}
		}

        tabelaArp.add(ip_src, eth_src);
        tabelaArp.add(ip_dest, eth_dest);
    }
	// Ignore if it is not an ARP packet
}
/* */
// This function should be one thread for each interface.
void read_iface(Iface *ifn){
	socklen_t saddr_len;
	struct sockaddr saddr{};
	unsigned char *packet_buffer;
	int n;

	saddr_len = sizeof(saddr);
	packet_buffer = new unsigned char[MAX_PACKET_SIZE];

	while (true){
		n = recvfrom(ifn->sockfd, packet_buffer, MAX_PACKET_SIZE, 0, &saddr, &saddr_len);
		if (n < 0)
		{
			fprintf(stderr, "ERROR: %s\n", strerror(errno));
			exit(1);
		}
		doProcess(packet_buffer, n);

		signal(SIGINT, treat_sign);
	}
}

void verifica_tabela(){
    while(true) {
        this_thread::sleep_for(chrono::seconds(1));
        tabelaArp.decrementa_ttl();
    }
}

/* */
// main function
int main(int argc, char **argv)
{
	int i, sockfd;

	if (argc < 2)
		print_usage();

	for (i = 1; i < argc; i++)
	{
		sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sockfd < 0)
		{
			fprintf(stderr, "ERROR: %s\n", strerror(errno));
			exit(1);
		}

		if (bind_iface_name(sockfd, argv[i]) < 0)
		{
			perror("Server-setsockopt() error for SO_BINDTODEVICE");
			printf("%s\n", strerror(errno));
			close(sockfd);
			exit(1);
		}

		tabelaArp.raw_sock = sockfd;
		get_iface_info(sockfd, argv[i], &my_ifaces[i - 1]);
	}

	/** IMPRIME DADOS DE CADA INTERFACE **/
	cout << "ARP Deamon rodando...\nInterfaces identificadas:\n\n";
	for (i = 0; i < argc - 1; i++) {
	    lock_guard<mutex> lck(mtx_print);
		print_eth_address(my_ifaces[i].ifname, my_ifaces[i].mac_addr);
		cout << "IPv4: " << my_ifaces[i].ip_addr  << "\n" << endl;
		tabelaArp.ifaces.emplace_back(my_ifaces[i]);
	}

	vector<thread*> pool_threads;

	for (i = 0; i < argc - 1; i++) {
        pool_threads.emplace_back(new thread(read_iface, &my_ifaces[i]));
	}
	pool_threads.emplace_back(new thread(verifica_tabela));
	pool_threads.emplace_back(new thread(&TabelaArp::trata_requisicao, &tabelaArp));

	for (i = 0; i < pool_threads.size(); i++) {
	    pool_threads[i]->join(); /* Esperar a junção das threads */
    }

	
	return 0;
}
/* */