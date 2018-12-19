#ifndef SOCKHOLDER_H
#define SOCKHOLDER_H

#include "epolsocket.h"
//max                             2147483647
#define TYPE_SRV_ESOCK 708112018
#define TYPE_CLI_ESOCK 408112018

class SockHolder {
public:
    SockHolder(int type){
        if (TYPE_CLI_ESOCK == type) {
            sockType = TYPE_CLI_ESOCK;
            sock = new EpolSocket();
        } else if(TYPE_SRV_ESOCK == type) {
            sockType = TYPE_SRV_ESOCK;
            sock = nullptr;
        } else {
            sockType = -1;
            sock = nullptr;
        }
    }

    ~SockHolder(){
        if (sock) { delete sock; }
    }

    int sockType;
    EpolSocket * sock;

    void * sslStaff = nullptr;    
    int connectState = 0; //0=not, 1=TCP, 2=SSL, 3=Authenticated
    //groupID in network byte order:
    unsigned long long connectedGroup = 0;
    time_t lastActTime = 0;

    /* READ expected packet */
    char * readPacket = nullptr;
    long readLenLeft = 0;
    char * readCur = nullptr;

    /* WRITE packet */
    char * writePacket = nullptr;
    int writeLenLeft = 0;
    char * writeCur = nullptr;

};

#endif // SOCKHOLDER_H
