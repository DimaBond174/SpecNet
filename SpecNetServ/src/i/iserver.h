#ifndef ISERVER_H
#define ISERVER_H

class IServer {
public:
    virtual ~IServer() {}
    //Working
    virtual bool  start()  = 0;
    virtual void  stop()   = 0;

};

#endif // ISERVER_H
