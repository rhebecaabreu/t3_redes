//
// Created by luizfilho on 11/18/18.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <net/if.h>
#include <sys/ioctl.h>
#include "TabelaArp.h"

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

void TabelaArp::trata_requisicao() {
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
        //cout << "Cliente " << j++ << " conectado!" << endl;
        trata_conexao(client_sock);
        if (client_sock < 0){
            perror("Erro em accept()");
            continue;
        }
    }
}

void TabelaArp::trata_conexao(int client_sock) {
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
