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

#define xstr(s) str(s)
#define str(s) #s

#define ARP_CACHE       "/proc/net/arp"
#define ARP_STRING_LEN  1023
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)

/* Format for fscanf() to read the 1st, 4th, and 6th space-delimited fields */
#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s"

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

void showArpTable() { 
	printf("pao");
}
/* */
// main function
int main(int argc, char **argv)
{
	int i, sockfd;

	if (argc < 2)
		print_usage();

	printf("%s \n", argv[1]);
	if(strcmp(argv[1], "show")==0){
		showArpTable();
	}

}
/* */