//
// Created by root on 30/06/19.
//

#ifndef DPPML_MLSP_H
#define DPPML_MLSP_H

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include "HEAAN.h"

using namespace std;



class MLSP {
public:
    // Client side
    int csp_sock = 0, valread;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[1024] = {0};
    int csp_port = 8080;
    char *csp_ip = "127.0.0.1";

    // Cluster infos
    int nb_workers = 1;
    std::vector<int> workers_sockets;

    std::vector<struct sockaddr_in> addresses;
    int port = 8090;
    int opt = 1;
    int addrlen = sizeof(struct sockaddr_in);
    // Serveer side
    /*int server_fd, new_socket;
    int port = 8080;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);*/


    MLSP();
    void send_message();
    bool send_file(int sock, char* path);
    void test_send_file();
    void test_key_exchange();


    bool read_file(int sock, char* path);
    bool read_long(int sock, long *value);


};


#endif //DPPML_MLSP_H
