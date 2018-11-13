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
#include <pthread.h>


// Print the expected command line for the program
void print_usage()
{
	printf("\xarp <interface> [<interfaces>]\n");
	exit(1);
}

/* */
// main function
int main(int argc, char **argv)
{
	int i, sockfd;

	if (argc < 2)
		print_usage();

}
/* */