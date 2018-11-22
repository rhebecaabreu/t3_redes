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

#include "TabelaArp.h"

#define MAX_IFACES 64
#define MAX_IFNAME_LEN 22

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
    auto it = tabela.find(ip);
    if (eth == "00:00:00:00:00:00") return;
    tabela.emplace(ip, entrada(ip, eth, ttl_default));
}
void TabelaArp::add(string ip, string eth, int ttl) {
    lock_guard<mutex> lck(mtx_tabela);
    auto it = tabela.find(ip);
    tabela.emplace(ip, entrada(ip, eth, ttl));
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
    //cout << "Entrada\t\tEndereço IP\t\t\tEndereço Ethernet\t\tTTL" << endl;
    int i = 0;
    lock_guard<mutex> lck(mtx_tabela);
    for (auto &entrada : tabela){
        string id = to_string(i++) + "\t\t\t";
        string ip = entrada.second.ip_addr + "\t\t";
        string eth = entrada.second.eth_addr + "\t\t";
        string ttl = to_string(entrada.second.ttl) + "\n";
        write(client_sock, id.c_str(), id.size());
        write(client_sock, ip.c_str(), ip.size());
        write(client_sock, eth.c_str(), eth.size());
        write(client_sock, ttl.c_str(), ttl.size());
//        cout << i++ << "\t\t";
//        cout << entrada.second.ip_addr << "\t\t\t";
//        cout << entrada.second.eth_addr << "\t\t";
//        cout << entrada.second.ttl << endl;
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

long TabelaArp::qntd_entradas() {
    lock_guard<mutex> lck(mtx_tabela);
    return this->tabela.size();
}

string TabelaArp::res(string ip) {
    //TODO enviar requisicao arp caso o ip não esteja na tabela e aguardar um timeout de resposta
    lock_guard<mutex> lck(mtx_tabela);
    auto it = tabela.find(ip);
    string result;
    if (it != tabela.end()){
        return result = "(" + ip + ", " + it->second.eth_addr + ", " + to_string(it->second.ttl) + ")\n";
    }
    else return result = "Endereço IP desconhecido!\n";
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

    for(int i = 0; i < 1; i++){

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
        rxPackets = "         RX packets: ";
        rxBytes = "         RX bytes: ";

        write(client_sock, interface.c_str(), interface.size());
        write(client_sock, mac.c_str(), mac.size());
        write(client_sock, mac2.c_str(), mac2.size());
        write(client_sock, inetEnd.c_str(), inetEnd.size());
        write(client_sock, mtu.c_str(), mtu.size());

    }
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

    int j = 0;
    while(true){
        //Cria struct que vai receber informações do cliente conectado
        struct sockaddr_in client_ip_addr{};
        int addr_len = sizeof(client_ip_addr);
        cout << "Aguardando conexão..." << endl;
        int client_sock = accept(sockfd, (struct sockaddr *) &client_ip_addr, (socklen_t*) &addr_len);
        cout << "Cliente " << j++ << " conectado!" << endl;
        thread t(&TabelaArp::pao, this, client_sock, ifn);
        t.join();
        if (client_sock < 0){
            perror("Erro em accept()");
            continue;
        }
    }
}

void TabelaArp::pao(int client_sock, struct iface *ifn) {

    char buffer[4096]{};
    string request;
    read(client_sock, buffer, sizeof(buffer));
    request += buffer;

    cout << "op: " << request << endl;

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
        altera_ttl(atoi(ttl.c_str()));
        string msg = "TTL alterado para " + ttl + " segundos!\n";
        write(client_sock, msg.c_str(), msg.size());
    }
    else if (request.find("res") != -1){
        int pos = request.find(":");
        string ip;
        ip = request.substr(pos+1);
        string result = res(ip);
        write(client_sock, result.c_str(), result.size());
    }
    else if (request.find("xifconfig") != -1){
        xifconfig_exibe(client_sock, ifn);
    }

    close(client_sock);
}
