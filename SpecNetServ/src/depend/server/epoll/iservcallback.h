#ifndef ISERVCALLBACK_H
#define ISERVCALLBACK_H

#include <string>
#include "epolsocket.h"


class IServCallback {
public:
//    virtual void  onSocketEvent()  = 0;
    virtual const char * getMessagesPath() = 0;
    virtual const char * getAvaCertsPath() = 0;
    virtual std::string getServPassword() = 0;
    virtual EpolSocket * getStackSockNeedWorker() = 0;
    virtual void returnSocketToWork(EpolSocket * sock) = 0;
    virtual void returnSocketToFree(EpolSocket * sock) = 0;
    virtual void workerGoneDown(void * worker) = 0;
};


#endif // ISERVCALLBACK_H
