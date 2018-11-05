#ifndef SPECSSL_H
#define SPECSSL_H


#include <atomic>
#include <set>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "i/iencrypt.h"
#include "i/ilog.h"
#include "i/ifileadapter.h"
#include "i/iconfig.h"


/*
 * Tips:
    BoringSSL disables renegotiation by default.
*/
class SpecSSL : public IEncrypt
{
public:
    SpecSSL();
    bool  start() override;
    void  stop()  override;


    void * startEncryptSocket(int socket) override;
    void stopEncryptSocket(void * staff) override;
    int getSocketState(void * staff, int code) override;
    int do_handshakeSocket(void * staff) override;
    int readSocket(void * staff, void *buf, int num) override;
    int writeSocket(void * staff, const void *buf, int num) override;
    void logErrors() override;
    bool groupX509exists(unsigned long long groupID) override;


    X509 * getX509(const void *buf, int num) override;
    EVP_PKEY * getX509evp(X509 * x509) override;
    void freeX509(X509 * x509) override;
    void freeEVP(EVP_PKEY * evp) override;
    bool checkX509(unsigned long long groupID, unsigned long long avatarID,
                            const char * strX509, int strX509len) override;
    bool verify_it(const void* msg, size_t mlen, const void* sig, size_t slen, EVP_PKEY* evpX509) override;


private:
    const char * TAG = "SpecSSL";
    int logLevel     {0};
    int idleConnLife {5};
    SSL_CTX *ctx  {nullptr};
    BIO *errBIO   {nullptr};

    ILog * iLog = nullptr;
    IFileAdapter * iFileAdapter = nullptr;



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
