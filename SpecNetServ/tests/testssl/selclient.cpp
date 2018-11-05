#include "selclient.h"
#include <iostream>
#include "i/ipack.h"
#if defined(Windows)
#define WIN32_LEAN_AND_MEAN

#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
// Needed for the Windows 2000 IPv6 Tech Preview.
#if (_WIN32_WINNT == 0x0500)
#include <tpipv6.h>
#endif

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")
#define STRICMP _stricmp

#define SPEC_MAXHOST	NI_MAXHOST /* Max size of a fully-qualified domain name */
#define SPEC_MAXSERV	NI_MAXSERV /* Max size of a service name */
#define CLOSE_SOCK(a) (closesocket(a))
#else

#define SPEC_MAXHOST      1025  /* Max size of a fully-qualified domain name */
#define SPEC_MAXSERV      32    /* Max size of a service name */
#define CLOSE_SOCK(a) (close(a))
#endif

#include <ctime>
#include <openssl/rand.h>
#define GUID_BASE 1000000000000000000LL



SSLClient::SSLClient()
{
 
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

#if defined(Windows)
LPTSTR PrintError(int ErrorCode)
{
	static TCHAR Message[1024];

	// If this program was multithreaded, we'd want to use
	// FORMAT_MESSAGE_ALLOCATE_BUFFER instead of a static buffer here.
	// (And of course, free the buffer when we were done with it)

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_MAX_WIDTH_MASK,
		NULL, ErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		Message, 1024, NULL);
	return Message;
}
#endif

int SSLClient::tcpConnect (const char* host, const char* port)
{    
    int re = -1;

	//faux loop
	do {
		char addrName[SPEC_MAXHOST];

		int i, RetVal, AddrLen, AmountToSend;
		int ExtraBytes = 0;
		unsigned int Iteration, MaxIterations = 1;
		BOOL RunForever = FALSE;

		ADDRINFO Hints, *AddrInfo, *AI;	
		T_SOCKET cliSocket = NOT_SOCKET;
		struct sockaddr_storage Addr;

		
#if defined(Windows)
		// Ask for Winsock version 2.2.
		WSADATA wsaData;
		if ((RetVal = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0) {
			fprintf(stderr, "WSAStartup failed with error %d: %s\n",
				RetVal, PrintError(RetVal));
			WSACleanup();
			break;
		}
#endif

		// By not setting the AI_PASSIVE flag in the hints to getaddrinfo, we're
		// indicating that we intend to use the resulting address(es) to connect
		// to a service.  This means that when the Server parameter is NULL,
		// getaddrinfo will return one entry per allowed protocol family
		// containing the loopback address for that family.
		//

		memset(&Hints, 0, sizeof(Hints));
		Hints.ai_family = AF_UNSPEC;
		Hints.ai_socktype = SOCK_STREAM;
		RetVal = getaddrinfo(host, port, &Hints, &AddrInfo);
		if (RetVal != 0) {
			fprintf(stderr,
				"Cannot resolve address [%s] and port [%s], error %d: %s\n",
				host, port, RetVal, gai_strerror(RetVal));
			//WSACleanup();
			break;
		}

		//
		// Try each address getaddrinfo returned, until we find one to which
		// we can successfully connect.
		//
		for (AI = AddrInfo; AI != NULL; AI = AI->ai_next) {

			// Open a socket with the correct address family for this address.

			cliSocket = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol);

			//**** DEBUG
#if defined(Debug)
			printf("socket call with family: %d socktype: %d, protocol: %d\n",
				AI->ai_family, AI->ai_socktype, AI->ai_protocol);
			if (connSocket == SPEC_ERR_SOCKET)
				printf("socket call failed with %d\n", WSAGetLastError());
#endif
			//**** DEBUG END

			if (cliSocket == NOT_SOCKET) {
				fprintf(stderr, "Error Opening socket, error %d: %s\n",
					WSAGetLastError(), PrintError(WSAGetLastError()));
				continue;
			}
			//
			// Notice that nothing in this code is specific to whether we 
			// are using UDP or TCP.
			//
			// When connect() is called on a datagram socket, it does not 
			// actually establish the connection as a stream (TCP) socket
			// would. Instead, TCP/IP establishes the remote half of the
			// (LocalIPAddress, LocalPort, RemoteIP, RemotePort) mapping.
			// This enables us to use send() and recv() on datagram sockets,
			// instead of recvfrom() and sendto().
			//

			printf("Attempting to connect to: %s\n", host);
			if (connect(cliSocket, AI->ai_addr, (int)AI->ai_addrlen) != -1) {
				//We found and connected, leave loop and go next step
				break;
			}

			i = WSAGetLastError();
			if (getnameinfo(AI->ai_addr, (int)AI->ai_addrlen, addrName,
				sizeof(addrName), NULL, 0, NI_NUMERICHOST) != 0)
				strcpy_s(addrName, sizeof(addrName), "<unknown>");
			fprintf(stderr, "connect() to %s failed with error %d: %s\n",
				addrName, i, PrintError(i));
			CLOSE_SOCK(cliSocket);			
		}

		if (AI == NULL) {
			fprintf(stderr, "Fatal error: unable to connect to the server.\n");
			//WSACleanup();
			break;
		}

		//
		// This demonstrates how to determine to where a socket is connected.
		//
		AddrLen = sizeof(Addr);
		if (getpeername(cliSocket, (LPSOCKADDR)& Addr, (int *)&AddrLen) == -1) {
			fprintf(stderr, "getpeername() failed with error %d: %s\n",
				WSAGetLastError(), PrintError(WSAGetLastError()));
		}
		else {
			if (getnameinfo((LPSOCKADDR)& Addr, AddrLen, addrName,
				sizeof(addrName), NULL, 0, NI_NUMERICHOST) != 0)
				strcpy_s(addrName, sizeof(addrName), "<unknown>");
			printf("Connected to %s, port %d, protocol %s, protocol family %s\n",
				addrName, ntohs(SS_PORT(&Addr)),
				(AI->ai_socktype == SOCK_STREAM) ? "TCP" : "UDP",
				(AI->ai_family == PF_INET) ? "PF_INET" : "PF_INET6");
		}

		// We are done with the address info chain, so we can free it.
		freeaddrinfo(AddrInfo);

		//
		// Find out what local address and port the system picked for us.
		//
		AddrLen = sizeof(Addr);
		if (getsockname(cliSocket, (LPSOCKADDR)& Addr, &AddrLen) == SOCKET_ERROR) {
			fprintf(stderr, "getsockname() failed with error %d: %s\n",
				WSAGetLastError(), PrintError(WSAGetLastError()));
		}
		else {
			if (getnameinfo((LPSOCKADDR)& Addr, AddrLen, addrName,
				sizeof(addrName), NULL, 0, NI_NUMERICHOST) != 0)
				strcpy_s(addrName, sizeof(addrName), "<unknown>");
			printf("Using local address %s, port %d\n",
				addrName, ntohs(SS_PORT(&Addr)));
		}

		setNONBLOCK(cliSocket);
		clientSocket = cliSocket;
		FD_ZERO(&cliSet);
		FD_SET(cliSocket, &cliSet);
		re = cliSocket;
	} while (false);

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

		if (-1 == tcpConnect(host, port)) { break; }        
        sslStaff = SSL_new (sslContext);
        if (!sslStaff) {
            ERR_print_errors_fp (stderr);
            break;
        }

        if (!SSL_set_fd (sslStaff, clientSocket)) {
            ERR_print_errors_fp (stderr);
            break;
        }

//        if (SSL_connect (sslHandle) != 1) {
//            ERR_print_errors_fp (stderr);
//            break;
//        }
        SSL_set_connect_state (sslStaff);
        int r = 0;        
        lastActTime = std::time(nullptr);
        while ((r = SSL_do_handshake(sslStaff)) != 1
               && (std::time(nullptr) - lastActTime)<=idleConnLife) {
			FD_ZERO(&w_cliSet);
			FD_ZERO(&r_cliSet);
            int err = SSL_get_error(sslStaff, r);
            if (err == SSL_ERROR_WANT_WRITE) {
				FD_SET(clientSocket, &w_cliSet);
                std::cerr << "SSL_do_handshake==SSL_ERROR_WANT_WRITE" << std::endl;
            } else if (err == SSL_ERROR_WANT_READ) {
				FD_SET(clientSocket, &r_cliSet);
                std::cerr << "SSL_do_handshake==SSL_ERROR_WANT_READ"  << std::endl;
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

			int selecEventCnt = 0;
            //do {                
				timeval tv;
				tv.tv_sec = 0;
				tv.tv_usec = 100;
				selecEventCnt = select(2, //len + 1
					&r_cliSet,
					&w_cliSet,
					nullptr,//&e_cliSet,
					&tv);
            //} while  (0 == selecEventCnt && (std::time(nullptr) - lastActTime)<=idleConnLife);

			if (selecEventCnt < 0) {				
				printSocketError("SSL_do_handshake->select()");
				return re;
			}
            
        }//while

        re = r==1;       
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
    if (clientSocket!=NOT_SOCKET) {
		CLOSE_SOCK(clientSocket);
		clientSocket = NOT_SOCKET;		
		FD_ZERO(&cliSet);
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

#if defined(Windows)
	WSACleanup();
#endif
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


std::string SSLClient::getLastSocketErrorString() {
#if defined(Windows)
	int error = WSAGetLastError();
	char *buffer;
	DWORD len = FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, error, 0,
		reinterpret_cast<char *>(&buffer), 0, nullptr);
	if (len == 0) {
		char buf[256];
		snprintf(buf, sizeof(buf), "unknown error (0x%x)", error);
		return buf;
	}
	std::string ret(buffer, len);
	LocalFree(buffer);
	return ret;
#else
	return strerror(errno);
#endif
}

void SSLClient::printSocketError(const char *function) {
	std::cerr << "SSLClient::"
		<< function
		<< " ERROR: "
		<< getLastSocketErrorString()	
		<< std::endl;
}

int SSLClient::getJobResults(){
    int re = SSL_CLI_NOTHING;
	memcpy(&w_cliSet, &cliSet, sizeof(w_cliSet));
	memcpy(&r_cliSet, &cliSet, sizeof(r_cliSet));	
	timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100;
	int selecEventCnt = select(3, //len+1
		&r_cliSet,
		&w_cliSet,
		nullptr,//&e_cliSet,
		&tv);
	if (selecEventCnt < 0) {		
		printSocketError("select()");
		re = SSL_CLI_ERROR;
	} else if (selecEventCnt > 0) {
		//Check if read ready
		if (FD_ISSET(clientSocket, &r_cliSet)) {
			re = handleRead();
		}//r_cliSet

		//Check if write ready
		if (re != SSL_CLI_ERROR && FD_ISSET(clientSocket, &w_cliSet)) {
			re = handleWrite();			
		}//w_cliSet        
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
            char buf[sizeof(T_IPack0_Network)];
            res = SSL_read(sslStaff, buf, sizeof(T_IPack0_Network));
            if (sizeof(T_IPack0_Network) ==res) {
                readPacket = IPack0::eatPacket(_iAlloc , buf);
                if (!readPacket) {
                    std::cerr << "Error: [SSLClient::handleRead()] null==IPack0::eatPacket()"
                           << std::endl;
                    re = SSL_CLI_ERROR;
                    break;
                }

                readCur = readPacket + sizeof(T_IPack0_Network);
                readLenLeft = ((T_IPack0_Network *)(readPacket))->pack_len - sizeof(T_IPack0_Network);
                lastActTime = std::time(nullptr);
            } else {
                re = SSL_CLI_ERROR;
                if (res > 0) {
                    std::cerr << "Error: [SSLClient::handleRead()] Only part of T_IPack0_Network header was loaded"
                           << std::endl;
                } else {
                    int errE = SSL_get_error(sslStaff, res);
                    if (SSL_ERROR_WANT_READ != errE ) {
                         std::cerr << "Error: [SSLClient::handleRead()] SSL_read return error: "
                               << errE << std::endl;
                        re = SSL_CLI_ERROR;
                    }
                }
                break;
            }
        }
       re = SSL_CLI_READING;

       /* load packet body */
       while(0<(res = SSL_read(sslStaff,
                                       readCur,
                                       readLenLeft))) {

            readLenLeft -= res;
            readCur += res;
            if (0==readLenLeft) {
                /* all readed */
                readWait = false;
                //Check packet END:
                T_IPack0_Network * pack0 = ((T_IPack0_Network *)(readPacket));
                uint32_t * endMark = (uint32_t *)(readPacket + pack0->pack_len - sizeof(uint32_t));
                if (N_SPEC_MARK_E!=*endMark) {
                    std::cerr << "Error: [SSLClient::handleRead()] N_SPEC_MARK_E!=*endMark "
                                << std::endl;
                    re = SSL_CLI_ERROR;
                    break;
                }
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

void SSLClient::_putPackToSend(char * ptr) {
    writeLenLeft = _NTOHL(((T_IPack0_Network *)(ptr))->pack_len);
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
                    _putPackToSend(ptr);
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

    if (!writePacket) {
            _putPackToSend(ptr);
            re = SSL_CLI_ERROR!= handleWrite();
    } else {
            writeQueue.push(ptr);
            re = true;
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


bool SSLClient::setNONBLOCK(unsigned int sock) {
	bool re = false;
#if defined(Windows)

	//Setup windows socket for nonblocking io.
	//https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-ioctlsocket
	unsigned long iMode = 1;
	if (NO_ERROR == ioctlsocket(sock, FIONBIO, &iMode)) { re = true; }

#else
	int flags = fcntl(servSocks[i], F_GETFL, 0);
	if (flags >= 0) {
		if (0 == fcntl(servSocks[i], F_SETFL, flags | O_NONBLOCK)) {
			re = true;
		}
	}

#endif
	return re;
}


