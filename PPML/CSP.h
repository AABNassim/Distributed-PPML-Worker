//
// Created by root on 30/06/19.
//

#ifndef DPPML_CSP_H
#define DPPML_CSP_H

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

class CSP {
public:
    int server_fd, new_socket;
    int port = 8080;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello = "Hello from server";


    CSP();

};


#endif //DPPML_CSP_H
