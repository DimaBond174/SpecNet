#ifndef SPECSSL_H
#define SPECSSL_H


#include <atomic>
#include <set>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>


#include "i/ilog.h"
#include "i/ifileadapter.h"
#include "i/iconfig.h"


/*
 * Tips:
    BoringSSL disables renegotiation by default.
*/
//class SpecSSL : public IEncrypt
class SpecSSL {
public:
    SpecSSL(ILog * iLog_, IFileAdapter * iFileAdapter_, IConfig * iConfig_);
    bool  start() ;
    void  stop()  ;


    SSL * startEncryptSocket(int socket) ;
    //void stopEncryptSocket(SSL * staff) ;
    //int getSocketState(SSL * staff, int code) ;
    //int do_handshakeSocket(SSL * staff) ;
    //int readSocket(SSL * staff, void *buf, int num) ;
    //int writeSocket(SSL * staff, const void *buf, int num) ;
    void logErrors() ;
    bool groupX509exists(unsigned long long groupID) ;


    X509 * getX509(const void *buf, int num) ;
    EVP_PKEY * getX509evp(X509 * x509) ;
    //void freeX509(X509 * x509) ;
    //void freeEVP(EVP_PKEY * evp) ;
    bool checkX509(unsigned long long groupID, unsigned long long avatarID,
                            const char * strX509, int strX509len) ;
    bool verify_it(const void* msg, size_t mlen, const void* sig, size_t slen, EVP_PKEY* evpX509) ;


private:
    const char * TAG = "SpecSSL";
    int logLevel     {0};
    int idleConnLife {5};
    SSL_CTX *ctx  {nullptr};
    BIO *errBIO   {nullptr};

    ILog * iLog;
    IFileAdapter * iFileAdapter;
    IConfig * iConfig;



    //std::atomic<bool> keepRun {false};
    //std::atomic<long long> useCount {0};

    std::set<unsigned long long> specGroupIDs;
    std::map<unsigned long long, X509 *> specGroupX509s;

    static int printSSLErrors(const char *str, size_t len, void *anyData);
    bool loadSpecGroups();
    X509 * extractX509   (const std::string &inX509);
    X509 * extractX509   (const void *buf, int num);    
    time_t ASN1_TIME_to_DWORD(time_t curTime, ASN1_TIME * from);

};

#endif // SPECSSL_H
