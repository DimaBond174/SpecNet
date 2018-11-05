#ifndef TestSSL_H
#define TestSSL_H

#include <string>
#include "i/ilib.h"
#include "i/ialloc.h"

class TestSSL: public ILib
{
public:
    TestSSL() {}
    virtual ~TestSSL(){}
    std::string getTAG() {return std::string(TAG);}

    virtual bool sslConnect(IAlloc * iAlloc, const char * host, const char * port, int idleConnLife) = 0;    
    virtual void stop() = 0;
    virtual int getJobResults() = 0;
    virtual bool putPackToSend(char * ptr) = 0;
    virtual char * readPack() = 0;
    virtual void eraseReadPack() = 0;
    virtual time_t getLastActTime() = 0;
    virtual bool setPKEY(const char * pkey, int len) = 0;    
    virtual bool sign_it(const void* msg, int msglen, void* sig, int* slen) = 0;
    virtual bool setX509(const char * x509str, int len) = 0;
    virtual bool checkAvaSign(const void* msg, size_t mlen, const void* sig, size_t slen) = 0;
    virtual long long getGUID09() = 0;
private:
    const char * const TAG = "TestSSL";    
};



#endif // TestSSL_H
