#ifndef SOCKHOLDER_H
#define SOCKHOLDER_H

#include "selectsocket.h"


class SockHolder {
public:
	SelectSocket sock;
    //long sockType = 0;
	T_SOCKET cli_socket = NOT_SOCKET;
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
