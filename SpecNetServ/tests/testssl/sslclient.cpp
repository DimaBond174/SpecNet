#include "sslclient.h"
#include <iostream>
#include "i/ipack.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h> /* Added for the nonblocking socket */
#include <sys/epoll.h>
#include <ctime>
#include <openssl/rand.h>
#define GUID_BASE 1000000000000000000LL

SSLClient::SSLClient()
{
    pfd.fd = -1;    
}

long long SSLClient::getGUID09() {
    uint8_t buf[sizeof(long long)];
    RAND_bytes(buf, sizeof(long long));
    long long * p_re = (long long *)buf;
    double re = (*p_re)/10;
    if (re<0LL) { re = -re;}
    return GUID_BASE + re;
}

SSLClient::~SSLClient() {
    stop();
    if (sslContext) {
        SSL_CTX_free (sslContext);
        sslContext = nullptr;
    }
}

int SSLClient::tcpConnect (const char* host, const char* port)
{    
    int re = -1;

    struct addrinfo *peer = nullptr;
    //faux loop
    do {
//        struct hostent *host = gethostbyname (svr);
//        if (!host) {
//            std::cerr << "Error: null==gethostbyname ( " << svr << std::endl;
//            break;
//        }

        struct addrinfo hints;
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;
        hints.ai_protocol = 0;          /* Any protocol */

        struct addrinfo *p = nullptr;
        int client_socket;


//        if (0 != getaddrinfo(host, port, &hints, &peer)) {
//            std::cerr << "Error: 0 != getaddrinfo(" << host <<","<< port << std::endl;
//            break;
//        }
        int s = getaddrinfo(host, port, &hints, &peer);
        if (s != 0) {
            //fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
            std::cerr << "Error: 0 != getaddrinfo(" << host <<","<< port <<") error:"
                      << std::endl
                      <<gai_strerror(s)
                        << std::endl;
            break;
        }

        for (p=peer; p ; p = p->ai_next) {
            client_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (client_socket < 0) {
    //#ifdef DEBUG
                perror("socket");
    //#endif
                continue;
            }

            if (connect(client_socket, p->ai_addr, p->ai_addrlen) == -1) {
                close(client_socket);
//    #ifdef DEBUG
                perror("connect");
//    #endif
                continue;
            }

            // Connected succesfully!
            break;
        }

        if (!p) {
            std::cerr << "Error: Couldn't connect to the server: " << host <<","<< port << std::endl;
            break;
        }

        re = client_socket;
        int flags = fcntl(client_socket, F_GETFL, 0);
        if (flags < 0) {
            std::cerr << "Error:  0>create_socket.fcntl(" << client_socket  << std::endl;
            break;
        }
        if (-1==fcntl(client_socket, F_SETFL, flags | O_NONBLOCK)) {
            std::cerr << "Error:  -1==fcntl(client_socket, F_SETFL, flags | O_NONBLOCK)"  << std::endl;
            break;
        }

//        re = socket (AF_INET, SOCK_STREAM, 0);
//        if (re < 0 ) {
//            std::cerr << "Error: socket (AF_INET, SOCK_STREAM, 0)= "<< re << std::endl;
//            break;
//        }

//    struct sockaddr_in server;
//    bzero (&server, sizeof server);
//    server.sin_family = AF_INET;
//    server.sin_port = htons (port);
//    server.sin_addr = *((struct in_addr *) host->h_addr);


//     int r = connect (re, (struct sockaddr *) &server,
//                       sizeof (struct sockaddr));
//     if (r != 0) {
//         std::cerr << "Error: cant connect to " << svr << std::endl;
//         close(re);
//         re = -1;
//     }
    } while (false);

    if (peer) {
         freeaddrinfo(peer);
    }
     return re;
}

bool SSLClient::sslConnect(IAlloc * iAlloc, const char * host, const char* port, int idleConnLife) {
    bool re = false;
    _idleConnLife = idleConnLife;
    stop();
    _iAlloc = iAlloc;
    //faux loop
    do {

        if (!sslInit()) {  break;  }

        pfd.fd = tcpConnect (host, port);
        if (pfd.fd <0) { break; }
        sslStaff = SSL_new (sslContext);
        if (!sslStaff) {
            ERR_print_errors_fp (stderr);
            break;
        }

        if (!SSL_set_fd (sslStaff, pfd.fd)) {
            ERR_print_errors_fp (stderr);
            break;
        }

//        if (SSL_connect (sslHandle) != 1) {
//            ERR_print_errors_fp (stderr);
//            break;
//        }
        SSL_set_connect_state (sslStaff);
        int r = 0;
        pfd.events = POLLIN | POLLOUT | POLLERR;
        lastActTime = std::time(nullptr);
        while ((r = SSL_do_handshake(sslStaff)) != 1
               && (std::time(nullptr) - lastActTime)<=idleConnLife) {
            int err = SSL_get_error(sslStaff, r);
            if (err == SSL_ERROR_WANT_WRITE) {
                pfd.events |= POLLOUT;
                pfd.events &= ~POLLIN;
                std::cerr << "return want write set events:" << pfd.events  << std::endl;

            } else if (err == SSL_ERROR_WANT_READ) {
                pfd.events |= POLLIN;
                pfd.events &= ~POLLOUT;
                std::cerr << "return want read set events:" << pfd.events  << std::endl;
            } else {
                std::cerr << "SSL_do_handshake return:"
                          << r
                          << " error  "
                          << err
                          << " errno  "
                          << errno
                          << " msg  "
                          <<  strerror(errno)
                          << std::endl;
                ERR_print_errors_fp(stderr);
                return re;
            }


            do {
                r = poll(&pfd, 1, 100);
            } while  (r == 0 && (std::time(nullptr) - lastActTime)<=idleConnLife);

            if (r != 1) {
                std::cerr << "poll return :"
                          << r
                          << " pfd.revents  "
                          << pfd.revents
                          << " errno  "
                          << errno
                          << " msg  "
                          <<  strerror(errno)
                          << std::endl;
                return re;
            }
        }//while

        re = r==1;
        if (re) {
             pfd.events = POLLIN | POLLOUT | POLLERR;
        }
    } while(false);

    return re;
}

bool SSLClient::sslInit() {
    if (!sslContext) {
        SSL_load_error_strings ();
        SSL_library_init ();
        sslContext = SSL_CTX_new (SSLv23_client_method ());
    }
    if (!sslContext) {
        ERR_print_errors_fp (stderr);
        return false;
    }
    return true;
}

void SSLClient::stop(){
    if (sslStaff) {
        //SIGPIPE SSL_shutdown (sslStaff);
        SSL_free (sslStaff);
        sslStaff = nullptr;
    }
    if (pfd.fd >=0) {
        close(pfd.fd);
        pfd.fd = -1;
        _connected = false;
    }

    while (!writeQueue.empty()) {
        char * ptr = writeQueue.front();
        _iAlloc->specFree(ptr);
        writeQueue.pop();
    }

    if (readPacket) {
        _iAlloc->specFree(readPacket);
        readPacket = nullptr;
    }

    if (writePacket) {
        _iAlloc->specFree(writePacket);
        writePacket = nullptr;
    }

    if (pkeyEVP) {
        EVP_PKEY_free(pkeyEVP);
        pkeyEVP = nullptr;
    }

    if (x509) {
        X509_free(x509);
        x509= nullptr;
    }

    if (evpX509) {
        EVP_PKEY_free(evpX509);
        evpX509 = nullptr;
    }
}

//void SSLClient::updateEPoll(int events) {
//    if (events!=_events) {
//        _events = events;
//        struct epoll_event ev;
//        memset(&ev, 0, sizeof(ev));
//        ev.events = _events;
//        ev.data.ptr = s;
////        log("modifying fd %d events read %d write %d\n",
////            fd_, ev.events & EPOLLIN, ev.events & EPOLLOUT);
//    int res = epoll_ctl(epollfd, EPOLL_CTL_MOD, s->_socket_id, &ev);
//    if (-1==res) {
//        keepRun.store(false, std::memory_order_release);
//        iLog->log("e","[EpolSrv::updateEPoll]: updateEPoll: %d %s",
//                     errno, strerror(errno));
//    }
//    }
//}

int SSLClient::getJobResults(){
    int re = SSL_CLI_NOTHING;
    int r = poll(&pfd, 1, 100);
    if (-1==r) {
        std::cerr << "SSLClient::getJobResults() poll return :"
                  << r
                  << " pfd.revents  "
                  << pfd.revents
                  << " errno  "
                  << errno
                  << " msg  "
                  <<  strerror(errno)
                  << std::endl;
        re = SSL_CLI_ERROR;
    } else if (r>0) {
        if (readWait && pfd.revents & POLLIN){
            //printf ("stdin is readable\n");
            re = handleRead();
        } else if(writePacket && (pfd.revents & POLLOUT)){
           //printf ("stdout is writable\n");
            re = handleWrite();
        }
    }
    return re;
}

int SSLClient::handleRead() {
    int re = SSL_CLI_NOTHING;
    int res = 0;
    //faux loop
    do {
        if (!readPacket) {
            /* loading just header */
            char buf[SPEC_LEN_HEAD_2];
            res = SSL_read(sslStaff, buf, SPEC_LEN_HEAD_2);
            if (res >=0) {
                /* check packet header */
                long len = IPack0::eatPacket(buf, res);
                if (len<=0) {
                    std::cerr << "Error: [SSLClient::handleRead()] IPack0::eatPacket(%i)="
                          << len << std::endl;
                    re = SSL_CLI_ERROR;
                    break;
                }
                /* allocate len for packet */
                readPacket = (char *)_iAlloc->specAlloc(len+SPEC_LEN_HEAD_1);
                if (!readPacket) {
                    std::cerr << "Error: [SSLClient::handleRead()] null==iAlloc.specAlloc("
                          << (len+SPEC_LEN_HEAD_1)  << std::endl;
                    re = SSL_CLI_ERROR;
                    break;
                }
                readCur = readPacket + SPEC_LEN_HEAD_1;
                readLenLeft = len;
                /* fist bytes == len */
                *((uint32_t*)(readPacket)) = len;
                lastActTime = std::time(nullptr);
            } else {
                int errE = SSL_get_error(sslStaff, res);
                if (SSL_ERROR_WANT_READ != errE ) {
                     std::cerr << "Error: [SSLClient::handleRead()] SSL_read return error: "
                           << errE << std::endl;
                   re = SSL_CLI_ERROR;
                   break;
                 }
            }
        }
       re = SSL_CLI_READING;
       while(0<(res = SSL_read(sslStaff,
                                       readCur,
                                       readLenLeft))) {

            readLenLeft -= res;
            readCur += res;
            if (0==readLenLeft) {
                /* all readed */
                readWait = false;
                re = SSL_CLI_READED;
                break;
            }
        }//while

       if (res<=0) {
           int errE = SSL_get_error(sslStaff, res);
            if (SSL_ERROR_WANT_READ != errE ) {
                std::cerr << "Error: [SSLClient::handleRead()] SSL_read return error: "
                          << errE << std::endl;
                re = SSL_CLI_ERROR;
                break;
            }
       }

    } while (false);

    return re;
}

void SSLClient::_putPackToSend(char * ptr, uint32_t len) {
    writeLenLeft = len + SPEC_LEN_HEAD_2;
    writeCur = writePacket = ptr;
}

int SSLClient::handleWrite(){
    int re = SSL_CLI_NOTHING;
    if (writePacket){
        re = SSL_CLI_WRITING;
        long res = SSL_write(sslStaff, writeCur, writeLenLeft);
        if (res > 0) {
            writeCur+=res;
            writeLenLeft -=res;
            if (0==writeLenLeft) {
                _iAlloc->specFree(writePacket);
                writePacket = nullptr;
                if (!writeQueue.empty()) {
                    char * ptr = writeQueue.front();
                    _putPackToSend(ptr, IPack0::lenPacket(ptr));
                    writeQueue.pop();
                }
                re = SSL_CLI_WRITED;
            }
        } else {
            int errE = SSL_get_error(sslStaff, res);
             if (SSL_ERROR_WANT_WRITE != errE ) {
                 std::cerr << "Error: [SSLClient::handleWrite()] SSL_write return error: "
                           << errE << std::endl;
                 re = SSL_CLI_ERROR;
             }
        }
    }
    return re;
}

bool SSLClient::putPackToSend(char * ptr){
    bool re = false;    
    uint32_t writeLen = IPack0::lenPacket(ptr);
    if (writeLen>0) {
        if (!writePacket) {
            _putPackToSend(ptr, writeLen);
            re = SSL_CLI_ERROR!= handleWrite();
        } else {
            writeQueue.push(ptr);
            re = true;
        }
    }
    return re;
}

char * SSLClient::readPack(){
    char * re = nullptr;
    if (!readWait){
        /* packet ready */
        re = readPacket;
    }
    return re;
}

void SSLClient::eraseReadPack() {
    if (readPacket) {
        _iAlloc->specFree(readPacket);
        readPacket = nullptr;
    }
    readWait = true;
}

time_t SSLClient::getLastActTime(){ return lastActTime; }

bool SSLClient::setPKEY(const char * pkey, int len) {
    if (pkeyEVP) {
        EVP_PKEY_free(pkeyEVP);
        pkeyEVP = nullptr;
    }

    BIO *bio = BIO_new_mem_buf((void*)(pkey), len);
    if (bio) {
        pkeyEVP = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    if (pkeyEVP) { return true;}
    return false;
}

/**
 * Создание цифровой подписи
 * Обязятельно делай OPENSSL_free(*sig) на возвращаемый буффер с подписью
 * @param msg
 * @param mlen
 * @param sig
 * @param slen
 * @param pkey
 * @return
 */
bool SSLClient::sign_it(const void* msg, int msglen, void* sig, int* slen)
{

    /* Returned to caller */
    bool re = false;
    size_t mlen=msglen;
    if(!msg || !mlen || !sig || !pkeyEVP) {
        //assert(0);
        return re;
    }

//    if(*sig)
//        OPENSSL_free(*sig);
//    *sig = NULL;
   // *slen = 0;

    EVP_MD_CTX* ctx = NULL;
    //faux loop
    do
    {
        ctx = EVP_MD_CTX_create();
        //assert(ctx != NULL);
        if(ctx == NULL) {
            //printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        const EVP_MD* md = EVP_sha256();//EVP_get_digestbyname("SHA256");
        //assert(md != NULL);
        if(md == NULL) {
           // printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        //assert(rc == 1);
        if(rc != 1) {
          //  printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkeyEVP);
        //assert(rc == 1);
        if(rc != 1) {
          //  printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        //assert(rc == 1);
        if(rc != 1) {
          //  printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        //assert(rc == 1);
        if(rc != 1) {
          //  printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        //assert(req > 0);
        //if(!(req > 0)) {
        if(req <= 0 || req>*slen) {
          //  printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

//        *sig = (BYTE *)OPENSSL_malloc(req);
//        //assert(*sig != NULL);
//        if(*sig == NULL) {
//          //  printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
//            break; /* failed */
//        }


        //rc = EVP_DigestSignFinal(ctx, *sig, slen);
        mlen = req;
        rc = EVP_DigestSignFinal(ctx, (uint8_t *)sig, &mlen);
        //assert(rc == 1);
        if(rc != 1 || req != mlen) {
         //   printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }
        *slen = req;
        //assert(req == *slen);
//        if(rc != 1) {
//          //  printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
//            break; /* failed */
//        }

        re = true;

    } while(0);

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        //ctx = NULL;
    }

    /* Convert to 0/1 result */
    return re;
}

bool SSLClient::verify_it(const void* msg, size_t mlen, const void* sig, size_t slen, EVP_PKEY* evpX509)
{
    bool re = false;

    if(!msg || !mlen || !sig || !slen || !evpX509) {
        return re;
    }

    EVP_MD_CTX* ctx = NULL;

    do
    {
        ctx = EVP_MD_CTX_create();

        if(ctx == NULL) { break;  }

        const EVP_MD* md = EVP_sha256();

        if(md == NULL) { break;  }

        int rc = EVP_DigestInit_ex(ctx, md, NULL);

        if(rc != 1) { break; }

        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, evpX509);

        if(rc != 1) { break; }

        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);

        if(rc != 1) { break;  }

        /* Clear any errors for the call below */
        ERR_clear_error();

        rc = EVP_DigestVerifyFinal(ctx, (const uint8_t *)sig, slen);

        if(rc != 1) { break; }

        re = true;

    } while(0);

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
    }

    return re;

}//verify DigSign


bool SSLClient::checkAvaSign(const void* msg, size_t mlen, const void* sig, size_t slen) {
    bool re = false;    
    if (evpX509) {
        re = verify_it(msg, mlen, sig, slen, evpX509);
    }
    return re;
}


X509 * SSLClient::extractX509  (const void *x509, int len) {
    X509 * cert = nullptr;
    if (x509 && len>0) {
        BIO *bio = BIO_new_mem_buf(x509, len);
        if (bio) {
            PEM_read_bio_X509(bio, &cert, NULL, NULL);
            BIO_free(bio);
        }
    }

    return cert;
}

bool SSLClient::setX509(const char * x509str, int len) {
    if (x509) { X509_free(x509);}
    x509 = extractX509(x509str, len);
    if (evpX509) {
        EVP_PKEY_free(evpX509);
        evpX509 = nullptr;
    }

    if (x509) {
        evpX509 = X509_get_pubkey(x509);
     }

    if (x509 && evpX509) { return true; }
    return false;
}



