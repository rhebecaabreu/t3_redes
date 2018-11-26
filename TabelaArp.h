//
// Created by luizfilho on 11/18/18.
//

#ifndef T3_TABLE_H
#define T3_TABLE_H
#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <mutex>
#include <thread>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <asm/ioctls.h>
#include "Iface.h"
#include <condition_variable>
#include <atomic>

#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01

using namespace std;

struct arp_header
{
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char  protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

class TabelaArp {
private:
    class entrada{
    public:
        int ttl = 60;
        string ip_addr, eth_addr;

        entrada(string ip_addr, string eth_addr, int ttl){
            this->ip_addr = ip_addr;
            this->eth_addr = eth_addr;
            this->ttl = ttl;
        }
    };

    map<string, entrada> tabela;


public:

    TabelaArp() = default;;
    void aguarda_conexao(int sockfd, Iface *ifn, int qtd_interfaces);
    void trata_requisicao(Iface *ifn, int qtd_interfaces);
    void trata_conexao(int client_sock, Iface *ifn, int qtd_interfaces);
    void add(string ip, string eth);
    void add(string ip, string eth, int ttl);
    void decrementa_ttl();
    bool req_arp(unsigned char* ip_src, unsigned char* ip_dst, string iface_name, Iface iface);
    void show(int client_sock);
    void del(string ip, int client_sock);
    void altera_ttl(int ttl);
    string res(string ip);
    void clear();

    void xifconfig_exibe(int client_sock, Iface *ifn, int qtd_interfaces);
    void change_mtu(string interface, int client_soc, int mtu, Iface *ifn);
    void conf_ip_mask(int client_sock, string interface, string ip, string ip_mask, Iface *ifn );

    condition_variable semaforo;
    bool aguardando_reply = false;
    string ip_a_resolver;
    int raw_sock;
    mutex mtx_tabela, mtx_req;

    int ttl_default = 60;
    vector<Iface> ifaces;

};


#endif //T3_TABLE_H
