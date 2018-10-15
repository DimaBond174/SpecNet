#ifndef IENCRYPT_H
#define IENCRYPT_H


#include <openssl/base.h>


class IEncrypt {
public:
    virtual ~IEncrypt() {}
    virtual bool  start()  = 0;
    virtual void  stop()   = 0;


    virtual void * startEncryptSocket(int socket) = 0;
    virtual void stopEncryptSocket(void * staff) = 0;
    virtual int getSocketState(void * staff, int code) = 0;
    virtual int do_handshakeSocket(void * staff) = 0;
    virtual int readSocket(void * staff, void *buf, int num) = 0;
    virtual int writeSocket(void * staff, const void *buf, int num) = 0;
    virtual void logErrors() = 0;
    /* check if we works with that group: */
    virtual bool groupX509exists(unsigned long long groupID) = 0;

    virtual  X509 * getX509(const void *buf, int num) = 0;
    virtual  EVP_PKEY * getX509evp(X509 * x509) = 0;
    virtual  void freeX509(X509 * x509) = 0;
    virtual  void freeEVP(EVP_PKEY * evp) = 0;

    virtual bool checkX509(unsigned long long groupID, unsigned long long avatarID,
                            const char * strX509, int strX509len) = 0;
    virtual bool verify_it(const void* msg, size_t mlen, const void* sig, size_t slen, EVP_PKEY* evpX509) = 0;
};

#endif // IENCRYPT_H
