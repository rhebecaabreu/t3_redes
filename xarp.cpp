#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <utility>
#include <iostream>
#include <condition_variable>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <csignal>
#include <wait.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>


using namespace std;

#define xstr(s) str(s)
#define str(s) #s

#define ARP_CACHE "/proc/net/arp"
#define ARP_STRING_LEN 1023
#define ARP_BUFFER_LEN (ARP_STRING_LEN + 1)

/* Format for fscanf() to read the 1st, 4th, and 6th space-delimited fields */
#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s "                      \
						"%" xstr(ARP_STRING_LEN) "s %*s " \
						"%" xstr(ARP_STRING_LEN) "s"

struct arp_table
{
	int id[ARP_BUFFER_LEN];
	char ipAddr[ARP_BUFFER_LEN];
	char hwAddr[ARP_BUFFER_LEN];
	char device[ARP_BUFFER_LEN];
	int time;
};

FILE *arpCache;

struct arp_table arptables;
struct arp_table *arptable;

// Print the expected command line for the program
void print_usage()
{
	printf("/xarp show - shows ARP table\n");
	printf("/xarp res <IP adress>\n");
	printf("/xarp add <IP adress> <ethernet adress> <ttl>\n");
	printf("/xarp del <IP adress>\n");
	printf("/xarp <ttl>\n");

	exit(1);
}

void readArpTable() { 

}

void showEthernetAdress(char *argv){
	printf("pao\n");
}

void showArpTable()
{
	arpCache = fopen(ARP_CACHE, "r");

	if (!arpCache)
	{
		perror("Arp Cache: Failed to open file \"" ARP_CACHE "\"");
		exit(1);
	}

	arptable = &arptables;

	/* Ignore the first line, which contains the header */
	char header[ARP_BUFFER_LEN];
	if (!fgets(header, sizeof(header), arpCache))
	{
		exit(1);
	}

	int count = 0;

	while (3 == fscanf(arpCache, ARP_LINE_FORMAT, arptable->ipAddr, arptable->hwAddr, arptable->device))
	{
		arptable->id[count] = count;
		printf("%d    %s    %s\n", arptable->id[count], arptable->ipAddr, arptable->hwAddr);
		count++;
	}

	fclose(arpCache);
}


/* */
// main function
int main(int argc, char **argv)
{
	int i, sockfd;

	if (argc < 2) {
		print_usage();

	}

	readArpTable();

	if (strcmp(argv[1], "show") == 0)
	{
		showArpTable();
	}

	if (strcmp(argv[1], "res") == 0)
	{ 
		if(argc == 2){
			print_usage();
		} 		
		showEthernetAdress(argv[3]);
	}

	if (strcmp(argv[1], "del") == 0)
	{
		if(argc == 2){
			print_usage();
		} 
		//TODO
	}

	if(strcmp(argv[1], "add") == 0){
		if(argc == 5){
			//TODO
		} else {
			print_usage();
		}
	}
}
/* */