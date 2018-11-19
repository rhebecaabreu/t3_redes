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

using namespace std;

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
    TabelaArp() {}
    void trata_requisicao();
    void pao(int client_sock);
    void add(string ip, string eth);
    void add(string ip, string eth, int ttl);
    void decrementa_ttl();
    long qntd_entradas();
    void show(int client_sock);
    void del(string ip, int client_sock);
    void altera_ttl(int ttl);
    string res(string ip);

    mutex mtx_tabela;
    int ttl_default = 60;

};


#endif //T3_TABLE_H
