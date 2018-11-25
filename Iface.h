//
// Created by root on 11/20/18.
//

#ifndef T3_IFACE_H
#define T3_IFACE_H

#define MAX_IFNAME_LEN 22
#include <iostream>
#include <string>

using namespace std;

class Iface {
public:
    int sockfd;
    int ttl;
    int mtu;
    char ifname[MAX_IFNAME_LEN];
    unsigned char bcast_addr[14];
    unsigned char mac_addr[6];
    unsigned char masc_addr[14];
    string ip_addr;
    unsigned int rx_pkts;
    unsigned int rx_bytes;
    unsigned int tx_pkts;
    unsigned int tx_bytes;
};


#endif //T3_IFACE_H
