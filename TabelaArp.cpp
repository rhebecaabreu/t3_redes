//
// Created by luizfilho on 11/18/18.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <unistd.h>
#include <sstream>
#include <thread>
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

string TabelaArp::res(string ip){
    //TODO enviar requisicao arp caso o ip não esteja na tabela e aguardar um timeout de resposta
    lock_guard<mutex> lck(mtx_tabela);
    auto it = tabela.find(ip);
    string result;
    if (it != tabela.end()){
        return result = "(" + ip + ", " + it->second.eth_addr + ", " + to_string(it->second.ttl) + ")\n";
    }
    else return result = "Endereço IP desconhecido!\n";
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

    int j = 0;
    while(true){
        //Cria struct que vai receber informações do cliente conectado
        struct sockaddr_in client_ip_addr{};
        int addr_len = sizeof(client_ip_addr);
        cout << "Aguardando conexão..." << endl;
        int client_sock = accept(sockfd, (struct sockaddr *) &client_ip_addr, (socklen_t*) &addr_len);
        cout << "Cliente " << j++ << " conectado!" << endl;
        thread t(&TabelaArp::pao, this, client_sock);
        t.join();
        if (client_sock < 0){
            perror("Erro em accept()");
            continue;
        }
    }
}

void TabelaArp::pao(int client_sock) {
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

    close(client_sock);
}
