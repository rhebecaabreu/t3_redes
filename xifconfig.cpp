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

int sockfd;
int portno = 5050;
char buffer[256];

void connectDaemon()
{
	struct sockaddr_in serv_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0)
	{
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}
	memset((char *)&serv_addr, 0, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(portno);

	//man connect
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}
}

void xifconfig()
{
	strcpy(buffer, "xifconfig");
	
	//man send
	if(send(sockfd, buffer, strlen(buffer), 0) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}

	memset(buffer, 0, sizeof(buffer));
	string rec;
	while((read(sockfd, buffer, sizeof(buffer))) != 0){
		rec += buffer;
		memset(buffer, 0, sizeof(buffer));
	}

	cout << rec;
	close(sockfd);
}

// Print the expected command line for the program
void print_usage()
{
	printf("/xifconfig <interface> <IP adress> <IP Netmask>\n");
	printf("/xifconfig <interface> mtu size");
	exit(1);
}

// ========== xifconfig <interface> <IP address> <IP Netmask>
// => usando socket => https://www.pacificsimplicity.ca/blog/set-ip-address-and-routing-c
// => usando socket => https://stackoverflow.com/questions/6652384/how-to-set-the-ip-address-from-c-in-linux 
// => usando socket => https://stackoverflow.com/questions/39832427/unable-to-change-ip-address-using-ioctl-siocsifaddr
// => rolé do mtu tb=> https://stackoverflow.com/questions/4951257/using-c-code-to-get-same-info-as-ifconfig
// => meio meh ======> https://www.linuxquestions.org/questions/programming-9/problem-to-set-gateway-using-c-program-846692/
// RUIM  => https://www.includehelp.com/cpp-programs/set-ip-address-subnet-mask-network-gateway-in-linux-system.aspx

// ========== xifconfig 
// https://stackoverflow.com/questions/4951257/using-c-code-to-get-same-info-as-ifconfig
// 

/* */
// main function
int main(int argc, char **argv)
{
	int i, sockfd;

	connectDaemon(); 

	if (argc < 2) {
		xifconfig();
	}
	if(argc > 3) {
		print_usage();
	}

}
/* */