//
// Created by luizfilho on 11/18/18.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <unistd.h>
#include "TabelaArp.h"

TabelaArp::TabelaArp(){
}

void TabelaArp::add(string ip, string eth) {
    auto it = tabela.find(ip);
    if (eth == "00:00:00:00:00:00") return;
    tabela.emplace(ip, entrada(ip, eth, 60));
}
void TabelaArp::add(string ip, string eth, int ttl) {
    auto it = tabela.find(ip);
    tabela.emplace(ip, entrada(ip, eth, ttl));
}

void TabelaArp::decrementa_ttl() {
    for (auto &entrada : tabela){
        entrada.second.ttl--;
        if (entrada.second.ttl == 0){
            //Apaga entrada da tabela de acordo com a chave que é o IP
            tabela.erase(entrada.second.ip_addr);
        }
    }
}

void TabelaArp::show(int client_sock) {
    cout << "Entrada\t\tEndereço IP\t\t\tEndereço Ethernet\t\tTTL" << endl;
    int i = 0;
    for (auto &entrada : tabela){
        string id = to_string(i) + "\t\t\t";
        string ip = entrada.second.ip_addr + "\t\t";
        string eth = entrada.second.eth_addr + "\t\t";
        string ttl = to_string(entrada.second.ttl) + "\n";
        write(client_sock, id.c_str(), id.size());
        write(client_sock, ip.c_str(), ip.size());
        write(client_sock, eth.c_str(), eth.size());
        write(client_sock, ttl.c_str(), ttl.size());
        cout << i++ << "\t\t";
        cout << entrada.second.ip_addr << "\t\t\t";
        cout << entrada.second.eth_addr << "\t\t";
        cout << entrada.second.ttl << endl;
    }
}

void TabelaArp::del(string ip, int client_sock){
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
    return this->tabela.size();
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

    while(true){
        //Cria struct que vai receber informações do cliente conectado
        struct sockaddr_in client_ip_addr{};
        int addr_len = sizeof(client_ip_addr);
        int client_sock = accept(sockfd, (struct sockaddr *) &client_ip_addr, (socklen_t*) &addr_len);
        if (client_sock < 0){
            perror("Erro em accept()");
            continue;
        }

        cout << "Cliente conectado!" << endl;

        char buffer[4096]{};
        string request;
        read(client_sock, buffer, sizeof(buffer));
        request += buffer;
        cout << request << endl;

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
            string ip, eth, ttl;
            int barra = request.find("|");
            ip = request.substr(pos+1, barra);
            cout << "ip: " << ip << endl;
            request = request.substr(request.find_first_of("|"));
            pos = request.find("|");
            eth = request.substr(pos+1, request.find_first_of("|"));
            cout << "eth: " << eth << endl;
            request = request.substr(request.find("|"));
            ttl = request.substr(pos+1);
            cout << "ttl: " << ttl << endl;
        }

        close(client_sock);
    }


    //TODO tratar requisicação TCP do programa xarp
}
