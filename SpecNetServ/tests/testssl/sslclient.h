#ifndef SSLCLIENT_H
#define SSLCLIENT_H

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <queue>

//#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "testssl.h"
//#include "i/ialloc.h"
#include "depend/tools/memory/calloc.h"


#define SSL_CLI_ERROR  -1
#define SSL_CLI_NOTHING  0
#define SSL_CLI_CONNECTED  1
#define SSL_CLI_READED  2
#define SSL_CLI_WRITED  3
#define SSL_CLI_READING 4
#define SSL_CLI_WRITING 5

class SSLClient: public TestSSL
{
public:
    SSLClient();
    ~SSLClient();

    /* single thread loop once: */
    int getJobResults() override;
    bool sslConnect(IAlloc * iAlloc, const char * host, const char* port, int idleConnLife) override;
    void stop() override;
    bool putPackToSend(char * ptr) override;
    char * readPack() override;
    void eraseReadPack() override;
    time_t getLastActTime() override;
    bool setPKEY(const char * pkey, int len) override;
    bool sign_it(const void* msg, int msglen, void* sig, int* slen) override;
    bool setX509(const char * x509str, int len) override;
    bool checkAvaSign(const void* msg, size_t mlen, const void* sig, size_t slen) override;
    long long getGUID09() override;

private:

    SSL_CTX *sslContext {nullptr};
    SSL *sslStaff {nullptr};
    IAlloc * _iAlloc{nullptr};

    int _idleConnLife = 5;

    struct pollfd pfd;
    bool _connected =false;

    time_t lastActTime = 0;

    /* READ expected packet */
    bool readWait = true;
    char * readPacket = nullptr;
    long readLenLeft = 0;
    char * readCur = nullptr;

    /* WRITE packet */
    char * writePacket = nullptr;
    long writeLenLeft = 0;
    char * writeCur = nullptr;
    std::queue<char *> writeQueue;

    EVP_PKEY * pkeyEVP = nullptr;
    X509 * x509 = nullptr;
    EVP_PKEY * evpX509 = nullptr;

    bool sslInit();
    int tcpConnect (const char* host, const char* port);
    int handleRead();
    int handleWrite();
    void _putPackToSend(char * ptr, uint32_t len) ;
    X509 * extractX509  (const void *x509, int len);
    bool verify_it(const void* msg, size_t mlen, const void* sig, size_t slen, EVP_PKEY* evpX509);
};

#endif // SSLCLIENT_H
