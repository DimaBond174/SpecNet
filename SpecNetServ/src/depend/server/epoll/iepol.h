#ifndef IEPOL_H
#define IEPOL_H

#include <string>
#include <sys/epoll.h>

class IEpoll {
public:
    virtual ~IEpoll(){ sockType = 0; }
    long sockType = 0;


    /* Server side - do not use it in the Socket thread! */
    struct epoll_event _epol_ev;
    void * sslStaff = nullptr;
    int _socket_id =-1;
    //int _events =0;
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

#endif // IEPOL_H
