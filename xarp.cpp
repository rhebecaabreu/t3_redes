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

void showEthernetAdress(char *argv)
{
	
 	char *variavel1, *variavel2;
    variavel2 = argv;
    variavel1 = "res ";
    int tamanho = strlen(variavel1) + strlen(variavel2) + 1;
    
    char *s = new char[tamanho];

    strcat(buffer, variavel1);
    strcat(buffer, variavel2);
    
	cout << buffer << endl; 

	if(send(sockfd, buffer, strlen(buffer), 0) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}
  
	memset(buffer, 0, sizeof(buffer));
	//man recv
	if(recv(sockfd, buffer, sizeof(buffer), 0) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}

	//TODO ----------------------------------------
	printf("Mensagem recebida: \"%s\"\n", buffer);
}

void showArpTable()
{
	strcpy(buffer, "show");
	
	//man send
	if(send(sockfd, buffer, strlen(buffer), 0) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}
  
	memset(buffer, 0, sizeof(buffer));
	//man recv
	if(recv(sockfd, buffer, sizeof(buffer), 0) < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}

	//TODO ----------------------------------------
	printf("Mensagem recebida: \"%s\"\n", buffer);
}

/* */
// main function
int main(int argc, char **argv)
{
	int i, sockfd;

	if (argc < 2)
	{
		print_usage();
	}

	connectDaemon();

	if (strcmp(argv[1], "show") == 0)
	{
		showArpTable();
	}

	if (strcmp(argv[1], "res") == 0)
	{
		if (argc == 2)
		{
			print_usage();
		}
		showEthernetAdress(argv[2]);
	}

	if (strcmp(argv[1], "del") == 0)
	{
		if (argc == 2)
		{
			print_usage();
		}
		//TODO
	}

	if (strcmp(argv[1], "add") == 0)
	{
		if (argc == 5)
		{
			//TODO
		}
		else
		{
			print_usage();
		}
	}
}