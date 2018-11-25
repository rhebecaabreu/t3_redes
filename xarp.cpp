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
#include <thread>

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

class arp_table
{
    int id;
    string ipAddr, hwAddr;
    int time;
};

struct arp_table arptables;
struct arp_table *arptable;

int sockfd;
int portno = 5050;

void connectDaemon()
{

    struct sockaddr_in serv_addr{};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0){
        fprintf(stderr, "ERROR: %s\n", strerror(errno));
        exit(1);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(portno);

    //man connect
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "ERROR: %s\n", strerror(errno));
        exit(1);
    }
}

// Print the expected command line for the program
void print_usage() {
    printf("./xarp show - shows ARP table\n");
    printf("./xarp res <IP adress>\n");
    printf("./xarp add <IP adress> <ethernet adress> <ttl>\n");
    printf("./xarp del <IP adress>\n");
    printf("./xarp <ttl>\n");
    printf("./xarp <clear>\n");

    exit(1);
}

string send_tcp(const string &op){
    char buffer[4096]{};

    if(write(sockfd, op.c_str(), op.size()) < 0) {
        perror("Erro ao escrever no socket");
        exit(1);
    }

    string rec;
    while((read(sockfd, buffer, sizeof(buffer))) != 0){
        rec += buffer;
        memset(buffer, 0, sizeof(buffer));
    }

    close(sockfd);
    return rec;
}

void showEthernetAdress(const string &ip){
    string op = "res:" + ip;
    cout << "Aguardando resposta..." << endl;
    cout << send_tcp(op) << endl;
}

void showArpTable() {
    cout << "Entrada\t\t\tEndereço IP\t\tEndereço Ethernet\t\tTTL" << endl;
    cout << send_tcp("show");
}

void del(const string &ip) {
    cout << send_tcp("del:" + ip) << endl;
}

void add(const string &ip, const string &eth, const string &ttl){
    string op = "add:" + ip + "|" + eth + "|" + ttl;
    cout << send_tcp(op) << endl;
}

void ttl(int val){
    cout << send_tcp("ttl:" + to_string(val)) << endl;
}

void clear(){
    cout << send_tcp("clear") << endl;
}

int main(int argc, char **argv)
{
    int i, sockfd;

    if (argc < 2)
    {
        print_usage();
    }

    connectDaemon();

    if (argc == 2 && strcmp(argv[1], "show") != 0 && strcmp(argv[1], "clear") != 0){
        ttl(atoi(argv[1]));
    }

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
        del(argv[2]);
    }

    if (strcmp(argv[1], "add") == 0)
    {
        if (argc == 5)
        {
            add(argv[2], argv[3], argv[4]);
        }
        else
        {
            print_usage();
        }
    }

    if (argc == 2 && strcmp(argv[1], "clear") == 0)
    {
        clear();
    }

}
/* */