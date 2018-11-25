//
// Created by luizfilho on 11/18/18.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <unistd.h>
#include <sstream>
#include <thread>

#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "TabelaArp.h"

#define MAX_IFACES 64
#define MAX_IFNAME_LEN 22

using namespace std;


struct iface
{
    int sockfd;
    int ttl;
    int mtu;
    char ifname[MAX_IFNAME_LEN];
    unsigned char mac_addr[6];
    unsigned char ip_addr[14];
    unsigned char bcast_addr[14];
    unsigned char masc_addr[14];
    unsigned int rx_pkts;
    unsigned int rx_bytes;
    unsigned int tx_pkts;
    unsigned int tx_bytes;
};


vector<string> split_to_vector(string str, char delimiter){
    //Separa palavras de 'str' de acordo com 'delimiter' e retorna um vector com as palavras sem o delimiter
    vector<string> tokens;
    string token;
    istringstream token_stream(str);
    while (getline(token_stream, token, delimiter)){
        tokens.push_back(token);
    }
    return tokens;
}

void TabelaArp::add(string ip, string eth) {
    lock_guard<mutex> lck(mtx_tabela);
    if (eth == "00:00:00:00:00:00") return;
    auto it = tabela.find(ip);
    if (it != tabela.end()){
        it->second.eth_addr = eth;
    }
    else tabela.emplace(ip, entrada(ip, eth, ttl_default));

}
void TabelaArp::add(string ip, string eth, int ttl) {
    lock_guard<mutex> lck(mtx_tabela);
    auto it = tabela.find(ip);
    if (it != tabela.end()){
        it->second.eth_addr = eth;
        it->second.ttl = ttl;
    }
    else tabela.emplace(ip, entrada(ip, eth, ttl));
}

void TabelaArp::decrementa_ttl() {
    lock_guard<mutex> lck(mtx_tabela);
    for (auto &entrada : tabela){
        if (entrada.second.ttl > 0)
            entrada.second.ttl--;
        if (entrada.second.ttl == 0){
            //Apaga entrada da tabela de acordo com a chave que é o IP
            tabela.erase(entrada.second.ip_addr);
        }
    }
}

void TabelaArp::altera_ttl(int ttl){
    this->ttl_default = ttl;
}

void TabelaArp::show(int client_sock) {
    int i = 0;
    lock_guard<mutex> lck(mtx_tabela);
    for (auto entrada : tabela){
        string id = to_string(i++) + "\t\t\t";
        string ip = entrada.second.ip_addr + "\t\t";
        string eth = entrada.second.eth_addr + "\t\t";
        string ttl = to_string(entrada.second.ttl) + "\n";
        write(client_sock, id.c_str(), id.size());
        write(client_sock, ip.c_str(), ip.size());
        write(client_sock, eth.c_str(), eth.size());
        write(client_sock, ttl.c_str(), ttl.size());
    }
}

void TabelaArp::del(string ip, int client_sock){
    lock_guard<mutex> lck(mtx_tabela);
    auto it = tabela.find(ip);
    string result;
    if (it != tabela.end()) {
        tabela.erase(ip);
        result = "Sucess!\n";
        write(client_sock, result.c_str(), result.size());
    }
    else{
        result = "Ip not found!\n";
        write(client_sock, result.c_str(), result.size());
    }
}

string TabelaArp::res(string ip){
    unique_lock<mutex> lck(mtx_tabela);
    auto it = tabela.find(ip);
    string result;
    if (it != tabela.end()){
        return result = "(" + ip + ", " + it->second.eth_addr + ", " + to_string(it->second.ttl) + ")\n";
    }
    else{
        lck.unlock();
        for (auto iface : ifaces){
            string ifname = iface.ifname;
            vector<string> ip_src_str = split_to_vector(iface.ip_addr, '.');
            vector<string> ip_dst_str = split_to_vector(ip, '.');
            int array_ip_src[4] = {atoi(ip_src_str[0].c_str()), atoi(ip_src_str[1].c_str()),
                                   atoi(ip_src_str[2].c_str()), atoi(ip_src_str[3].c_str())};
            int array_ip_dst[4] = {atoi(ip_dst_str[0].c_str()), atoi(ip_dst_str[1].c_str()),
                                   atoi(ip_dst_str[2].c_str()), atoi(ip_dst_str[3].c_str())};
            unsigned char ip_src[4];
            unsigned char ip_dst[4];
            for (int i = 0; i < 4; i++){
                ip_src[i] = array_ip_src[i];
                ip_dst[i] = array_ip_dst[i];
            }
            ip_a_resolver = ip;
            if (!req_arp(ip_src, ip_dst, ifname, iface)){
                return result = "Endereço IP desconhecido!\n";
            }
            lck.lock();
            it = tabela.find(ip);
            if (it != tabela.end()){
                return result = "(" + ip + ", " + it->second.eth_addr + ", " + to_string(it->second.ttl) + ")\n";
            }
        }
        return result = "Endereço IP desconhecido!\n";
    }
}

void TabelaArp::clear(){
    lock_guard<mutex> lck(mtx_tabela);
    tabela.clear();
}

void TabelaArp::xifconfig_exibe(int client_sock, struct iface *ifn) {

//     eth0
//              Link encap:Ethernet Endereço de HW 00:1e:4f:43:48:06
//              inet end.: 200.129.207.50 Bcast:200.129.207.63 Masc:255.255.255.224
//              UP MTU:1500
//              RX packets:64763539 TX packets:146111148
//              RX bytes:9474581484 (8.8 GiB) TX bytes:202753664071 (188.8 GiB)

    string interface;
    string inetEnd;
    string mac;
    string mac2;
    string mtu;

     string rxPackets;
     string rxBytes;

    for(int i = 0; i < 1; i++){     // TODO arrumar isso aqui, esta lendo apenas para uma interface, se passar mais de uma da bosta

        char buf[100]{};
        snprintf(buf, sizeof(buf),"%02X:%02X:%02X:%02X:%02X:%02X \n", ifn[i].mac_addr[0], ifn[i].mac_addr[1], ifn[i].mac_addr[2], ifn[i].mac_addr[3], ifn[i].mac_addr[4], ifn[i].mac_addr[5]);
        mac2 = buf;
        snprintf(buf, sizeof(buf), "%s", ifn[i].ip_addr);
        string ip_src = buf;
        snprintf(buf, sizeof(buf), "%s", ifn[i].bcast_addr);
        string bcast_src = buf;
        snprintf(buf, sizeof(buf), "%s", ifn[i].masc_addr);
        string masc_src = buf;

        interface = strcat(ifn[i].ifname, "\n");
        mac = "         Link encap: Ethernet Endereço de HW: ";
        mtu = "         UP MTU: "+ to_string(ifn[i].mtu)+"\n";
        inetEnd = "         inet end.: "+ip_src+" Bcast: "+bcast_src+" Masc: "+masc_src+"\n";
        rxPackets = "         RX packets: ";    //TODO rx packtes tx packets
        rxBytes = "         RX bytes: ";        //TODO rx bytes tx bytes

        write(client_sock, interface.c_str(), interface.size());
        write(client_sock, mac.c_str(), mac.size());
        write(client_sock, mac2.c_str(), mac2.size());
        write(client_sock, inetEnd.c_str(), inetEnd.size());
        write(client_sock, mtu.c_str(), mtu.size());

        write(client_sock, rxPackets.c_str(), rxPackets.size());
        write(client_sock, rxBytes.c_str(), rxBytes.size());

    }
}

void TabelaArp::conf_ip_mask(int client_sock, string interface, string ip, string ip_mask) {

    char buf[100]{};
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ);

    ifr.ifr_addr.sa_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), ifr.ifr_addr.sa_data + 2);
    ioctl(client_sock, SIOCSIFADDR, &ifr);
    snprintf(buf, sizeof(buf),"%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    string ip_src = buf;
    string msg ="IP address is now " + ip_src + "\n";

    memset(buf, 0 , sizeof(buf));

    inet_pton(AF_INET, ip_mask.c_str(), ifr.ifr_addr.sa_data + 2);
    ioctl(client_sock, SIOCSIFNETMASK, &ifr);
    snprintf(buf, sizeof(buf),"%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr));
    string netmask = buf;
    string msg2 ="IP netmask is now " + netmask + "\n";

    write(client_sock, msg.c_str(), msg.size());
    write(client_sock, msg2.c_str(), msg2.size());
}

void TabelaArp::change_mtu(string interface, int client_socket, int mtu) {

    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface.c_str());
    if(!ioctl(client_socket, SIOCGIFMTU, &ifr)) {
        ifr.ifr_mtu; // Contains current mtu value
    }
    ifr.ifr_mtu = mtu; // Change value if it needed
    if(!ioctl(client_socket, SIOCSIFMTU, &ifr)) {
        ifr.ifr_mtu;
    }

    auto msg ="MTU now is "+ std::to_string(ifr.ifr_mtu) + "\n";

    write(client_socket, msg.c_str(), msg.size());

}


void TabelaArp::trata_requisicao(struct iface *ifn) {
    struct sockaddr_in serverIPAddress{};
    serverIPAddress.sin_family = AF_INET;
    serverIPAddress.sin_addr.s_addr = INADDR_ANY;
    serverIPAddress.sin_port = htons(5050);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Erro ao criar socket");
        exit(1);
    }

    int one = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &one, sizeof(one));

    if (bind(sockfd, (struct sockaddr*)&serverIPAddress, sizeof(serverIPAddress)) < 0){
        perror("Erro em bind()");
        exit(1);
    }

    if (listen(sockfd, 100) == -1){
        perror("Erro em listen()");
        exit(1);
    }

    aguarda_conexao(sockfd);
}

void TabelaArp::aguarda_conexao(int sockfd) {
    int j = 0;
    while(true){
        //Cria struct que vai receber informações do cliente conectado
        struct sockaddr_in client_ip_addr{};
        int addr_len = sizeof(client_ip_addr);
        //cout << "Aguardando conexão..." << endl;
        int client_sock = accept(sockfd, (struct sockaddr *) &client_ip_addr, (socklen_t*) &addr_len);

//         thread t(&TabelaArp::pao, this, client_sock, ifn);
//         t.join();

        //cout << "Cliente " << j++ << " conectado!" << endl;
        trata_conexao(client_sock, ifn);

        if (client_sock < 0){
            perror("Erro em accept()");
            continue;
        }
    }
}

void TabelaArp::trata_conexao(int client_sock, struct iface *ifn) {
    char buffer[2048]{};
    string request;

    read(client_sock, buffer, sizeof(buffer));
    request += buffer;

    if (request == "show"){
        show(client_sock);
    }
    else if (request.find("del") != -1) {
        int pos = request.find(":");
        string ip = request.substr(pos+1);
        del(ip, client_sock);
    }
    else if (request.find("add") != -1){
        int pos = request.find(":");
        string ip, eth, ttl, msg;
        request = request.substr(pos+1);
        vector<string> dados = split_to_vector(request, '|');
        if (dados.size() < 3){
            msg = "Dados inválidos!\n";
            write(client_sock, msg.c_str(), msg.size());
        }
        else{
            add(dados[0], dados[1], atoi(dados[2].c_str()));
            msg = "Entrada add na tabela!\n";
            write(client_sock, msg.c_str(), msg.size());
        }
    }
    else if (request.find("ttl") != -1){
        int pos = request.find(":");
        string ttl;
        ttl = request.substr(pos+1);
        int val_ttl = atoi(ttl.c_str());
        if (val_ttl > 0) {
            altera_ttl(val_ttl);
            string msg = "TTL alterado para " + ttl + " segundos!\n";
            write(client_sock, msg.c_str(), msg.size());
        }
        else{
            string msg = "Valor informado é invalido!\n";
            write(client_sock, msg.c_str(), msg.size());
        }
    }
    else if (request.find("res") != -1){
        int pos = request.find(":");
        string ip;
        ip = request.substr(pos+1);
        string result = res(ip);
        write(client_sock, result.c_str(), result.size());
    }
    else if (request.find("xifconfig") != -1) {
        xifconfig_exibe(client_sock, ifn);
    }
    else if (request.find("conf_ip_mask") != -1) {
        int pos = request.find(":");
        string interface, ip, mask, msg;
        request = request.substr(pos+1);
        vector<string> dados = split_to_vector(request, '|');
        if (dados.size() < 3){
            msg = "Dados inválidos!\n";
            write(client_sock, msg.c_str(), msg.size());
        }
        else{
//            add(dados[0], dados[1], atoi(dados[2].c_str()));
            conf_ip_mask(client_sock, dados[0], dados[1], dados[2]);

            //TODO -----------------------------------------------

        }

    } 
    else if(request.find("mtu") != -1) {
        int pos = request.find(":");
        string interface, ip, mask, msg;
        request = request.substr(pos+1);
        vector<string> dados = split_to_vector(request, '|');
        if (dados.size() < 2){
            msg = "Dados inválidos!\n";
            write(client_sock, msg.c_str(), msg.size());
        }
        else{
            change_mtu(dados[0], client_sock, stoi(dados[1]));
        }
    } 
    else if (request.find("clear") != 1){
        clear();
        string result = "Tabela limpa!";
        write(client_sock, result.c_str(), result.size());
    }

    close(client_sock);
}

bool TabelaArp::req_arp(unsigned char *ip_src, unsigned char *ip_dst, string iface_name, Iface iface) {
    int sd;
    unsigned char buffer[60];
    unsigned char source_ip[4] = {ip_src[0], ip_src[1], ip_src[2], ip_src[3]};
    unsigned char target_ip[4] = {ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3]};
    struct ifreq ifr{};
    auto *send_req = (struct ethhdr *)buffer;
    auto *arp_req = (struct arp_header *)(buffer+ETH2_HEADER_LEN);
    struct sockaddr_ll socket_address{};
    int index, ret, ifindex;

    memset(buffer,0x00,60);

    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd == -1) {
        perror("socket():");
        exit(1);
    }
    strcpy(ifr.ifr_name, iface_name.c_str());

    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    ifindex = ifr.ifr_ifindex;

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    close(sd);

    for (index = 0; index < 6; index++) {
        send_req->h_dest[index] = (unsigned char)0xff;
        arp_req->target_mac[index] = (unsigned char)0x00;
        send_req->h_source[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];
        arp_req->sender_mac[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];
        socket_address.sll_addr[index] = (unsigned char)ifr.ifr_hwaddr.sa_data[index];
    }

    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    send_req->h_proto = htons(ETH_P_ARP);

    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len =IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    for(index=0;index<5;index++) {
        arp_req->sender_ip[index] = source_ip[index];
        arp_req->target_ip[index] = target_ip[index];
    }

    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }



    /** Bloqueia thread até chegar resposta do arq request ou timeout de 60seg ser atingido **/
    unique_lock<mutex> lck(mtx_req);
    aguardando_reply = true;
    buffer[32] = 0x00;
    ret = sendto(sd, buffer, 42, 0, (struct  sockaddr*)&socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("Erro em sendto()");
        exit(1);
    }
    cv_status status{};
    while (aguardando_reply){
        status = semaforo.wait_for(lck, chrono::milliseconds(3000));
        if (status == cv_status::timeout && aguardando_reply){
            aguardando_reply = false;
            ip_a_resolver = "";
            return false;
        }
    }
    ip_a_resolver = "";
    return true;


}
