#include "selectsrv.h"
#include "spec/speccontext.h"
#include "spec/specstatic.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <ctime>
#if !defined(Windows)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#define CLOSE_SOCK(a) (close(a))
#else
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include <io.h>
#include <ws2def.h>
__pragma(warning(push, 3))
//#include <winsock2.h>
#include <ws2tcpip.h>
__pragma(warning(pop))
//#include <WinSock2.h>

#include <mstcpip.h>
#include <ws2def.h>
#define MAKEWORD(a, b)      ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
typedef int ssize_t;
//OPENSSL_MSVC_PRAGMA(comment(lib, "Ws2_32.lib"))
__pragma(comment(lib, "Ws2_32.lib"))
#define CLOSE_SOCK(a) (closesocket(a))
#endif

//
// This code assumes that at the transport level, the system only supports
// one stream protocol (TCP) and one datagram protocol (UDP).  Therefore,
// specifying a socket type of SOCK_STREAM is equivalent to specifying TCP
// and specifying a socket type of SOCK_DGRAM is equivalent to specifying UDP.
//

#define DEFAULT_FAMILY     PF_UNSPEC    // Accept either IPv4 or IPv6
#define DEFAULT_SOCKTYPE   SOCK_STREAM  // TCP


SelectSrv::SelectSrv() {

}

SelectSrv::~SelectSrv() {
    stop();
	cleanup();
}

void SelectSrv::cleanup() {
	//wait for thread before destruction
	if (serverThread.joinable()) {
		serverThread.join();
	}
	for (int i = 0; i < servSockCount; ++i) {
		CLOSE_SOCK(servSocks[i]);
	}
#if defined(Windows)
	WSACleanup();
#endif
}

bool  SelectSrv::start() {
    bool re = false;
    SpecContext & sr = SpecContext::instance();
	p_iEncrypt = sr.iEncrypt;
    iEncrypt = sr.iEncrypt.get();
    p_iLog = sr.iLog;
    iLog = sr.iLog.get();
    p_iAlloc = sr.iAlloc;
    iAlloc = sr.iAlloc.get();
    p_iFileAdapter = sr.iFileAdapter;
    iFileAdapter = sr.iFileAdapter.get();
    p_iDB = sr.iDB;
    iDB = sr.iDB.get();
    if (iFileAdapter && iAlloc && iLog && iEncrypt && iDB &&
            0==srvState.load(std::memory_order_acquire) &&
            create_socket()) {
        srvState.store(1, std::memory_order_release);
        serverThread = std::thread(&SelectSrv::runServThreadLoop, this);
        re = true;
    }
    return re;
}

void  SelectSrv::stop()  {
    keepRun.store(false, std::memory_order_release);
}


std::string SelectSrv::getLastSocketErrorString() {
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

void SelectSrv::printSocketError(const char *function) {
	// On Windows, |perror| and |errno| are part of the C runtime, while sockets
	// are separate, so we must print errors manually.
	const std::string & error = getLastSocketErrorString();
	//fprintf(stderr, "%s: %s\n", function, error.c_str());
	iLog->log("e", "[%s]: %s: %s", TAG, function, error.c_str());
}

bool SelectSrv::create_socket() {
    bool re = false;
	
    //faux loop:
    do {
		if (FD_SETSIZE <= MAX_SERV_SOCK) {
			iLog->log("e", "[%s]: ERROR: FD_SETSIZE <= MAX_SERV_SOCK", TAG);
			break;
		}
        SpecContext & sr = SpecContext::instance();
        logLevel = sr.iConfig.get()->getLongValue("LogLevel");
        maxConnections = sr.iConfig.get()->getLongValue("MaxConnections");

		if (maxConnections > FD_SETSIZE - MAX_SERV_SOCK) {
			maxConnections = FD_SETSIZE - MAX_SERV_SOCK;
			iLog->log("w", "[%s]: maxConnections > FD_SETSIZE - MAX_SERV_SOCK truncated:%d", TAG, maxConnections);
		}

        bufConnections = maxConnections >> 2;
        idleConnLife = sr.iConfig.get()->getLongValue("idleConnLife");
        uint16_t port = sr.iConfig.get()->getLongValue("ServerPort");
        if (0 == port) {
            iLog->log("e","[%s]: FAIL iConfig.get(ServerPort).",TAG);
            break;
        }
		const std::string & port_str = sr.iConfig.get()->getStringValue("ServerPort");

        servPassword = sr.iConfig.get()->getStringValue("ServPassword");
        if (servPassword.empty()) {
            iLog->log("e","[%s]: FAIL iConfig.get()->getStringValue(ServPassword).",TAG);
            break;
        }

        messagesPath =
                iFileAdapter->toFullPath(
                    sr.iConfig.get()->getStringValue(
                        "MessagesPath").c_str());
        if ('/'!=messagesPath[messagesPath.length()-1]) {
            messagesPath.push_back('/');
        }
        avaCertsPath =
                iFileAdapter->toFullPath(
                    sr.iConfig.get()->getStringValue(
                        "AvaCertsPath").c_str());
        if ('/'!=avaCertsPath[avaCertsPath.length()-1]) {
            avaCertsPath.push_back('/');
        }

		//----------------------
		int iResult;
		SOCKADDR_STORAGE From;		
		ADDRINFO Hints, *AddrInfo, *AI;		
		
#if defined(Windows)
		WSADATA wsaData;
		//WSAStartup(0x0201, &wsaData);
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (0!= iResult) {
			iLog->log("e", "[%s]: WSAStartup failed with error %d", TAG, iResult);
			break;
		}
#endif
		// By setting the AI_PASSIVE flag in the hints to getaddrinfo, we're
		// indicating that we intend to use the resulting address(es) to bind
		// to a socket(s) for accepting incoming connections.  This means that
		// when the Address parameter is NULL, getaddrinfo will return one
		// entry per allowed protocol family containing the unspecified address
		// for that family.
		//
		memset(&Hints, 0, sizeof(Hints));
		Hints.ai_family = AF_UNSPEC;
		Hints.ai_socktype = SOCK_STREAM;
		Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
		iResult = getaddrinfo(nullptr, port_str.c_str(), &Hints, &AddrInfo);
		if (iResult != 0) {
			printSocketError("getaddrinfo");
			//fprintf(stderr, "getaddrinfo failed with error %d: %s\n",
			//	RetVal, gai_strerror(RetVal));
			//WSACleanup();
			break;
		}

		// For each address getaddrinfo returned, we create a new socket,
		// bind that address to it, and create a queue to listen on.
		
		int i = 0;
		servSockCount = 0;
		for (AI = AddrInfo; AI != NULL; AI = AI->ai_next) {

			// Highly unlikely, but check anyway.
			if (i == FD_SETSIZE || MAX_SERV_SOCK==i) {
				iLog->log("e", "[%s]: getaddrinfo returned more addresses than we could use:>= %d", TAG, i);				
				break;
			}
			// This example only supports PF_INET and PF_INET6.
			if ((AI->ai_family != AF_INET) && (AI->ai_family != AF_INET6)) {
				continue;
			}

			// Open a socket with the correct address family for this address.
#if defined(Windows)
			servSocks[i] = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol);
			if (servSocks[i] == INVALID_SOCKET) {
				printSocketError("socket");
				//fprintf(stderr, "socket() failed with error %d: %s\n",
				//	WSAGetLastError(), PrintError(WSAGetLastError()));
				continue;
			}
#else
			iResult = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol);
			if (iResult < 0) {
				printSocketError("socket");
				continue;
			}
			servSocks[i] = iResult;
#endif
			
			//if ((AI->ai_family == PF_INET6) &&
			//	IN6_IS_ADDR_LINKLOCAL((IN6_ADDR *)INETADDR_ADDRESS(AI->ai_addr)) &&
			//	(((SOCKADDR_IN6 *)(AI->ai_addr))->sin6_scope_id == 0)
			//	) {
			//	fprintf(stderr,
			//		"IPv6 link local addresses should specify a scope ID!\n");
			//}
			//

			if (!setNONBLOCK(servSocks[i])) {
				iLog->log("e", "[%s]: FAIL setNONBLOCK(servSocks[i])", TAG);
				CLOSE_SOCK(servSocks[i]);
				continue;
			}

			// bind() associates a local address and port combination
			// with the socket just created. This is most useful when
			// the application is a server that has a well-known port
			// that clients know about in advance.
			//
			if (-1 == bind(servSocks[i], AI->ai_addr, (int)AI->ai_addrlen)) {
				printSocketError("bind");
				//fprintf(stderr, "bind() failed with error %d: %s\n",
				//	WSAGetLastError(), PrintError(WSAGetLastError()));
				CLOSE_SOCK(servSocks[i]);
				continue;
			}
					
			if (-1==listen(servSocks[i], EPOLL_WAIT_POOL)) {
				//fprintf(stderr, "listen() failed with error %d: %s\n",
//					WSAGetLastError(), PrintError(WSAGetLastError()));
				printSocketError("listen");
				CLOSE_SOCK(servSocks[i]);
				continue;
			}
			
			iLog->log("i", "[%s]: Listening on port %s, protocol TCP, protocol family %s", TAG,
				port_str.c_str(), (AI->ai_family == AF_INET) ? "AF_INET" : "AF_INET6");		
			++i;
			servSockCount = i;
		}

		freeaddrinfo(AddrInfo);
		
        re = servSockCount > 0;
    } while (false);

    if (!re) {
		stop();
		cleanup();		
    }
    return re;
}

bool SelectSrv::setNONBLOCK(unsigned int sock) {
	bool re = false;
#if defined(Windows)
	
		//Setup windows socket for nonblocking io.
		//https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-ioctlsocket
	unsigned long iMode = 1;
	if (NO_ERROR == ioctlsocket(sock, FIONBIO, &iMode)) { re= true; }
	
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

void* SelectSrv::runServThreadLoop(void* arg){
    SelectSrv* p = reinterpret_cast<SelectSrv*>(arg);
    p->servThreadLoop();
    return 0;
}



SockHolder * SelectSrv::getFreeSocket() {

    SockHolder * re = nullptr;
    if (setFreeSockets.empty()) {
        if (setAllSockets.size()<maxConnections) {
            re = new SockHolder();
            if (re) {           
				re->sock._iServCallback = this;
				re->sock._logLevel = logLevel;
                re->sock.iLog = iLog;
                re->sock.iAlloc = iAlloc;
                re->sock.iEncrypt = iEncrypt;
                re->sock.iFileAdapter = iFileAdapter;
                re->sock.iDB = iDB;
                setAllSockets.insert(re);
            } else {
                ohNoFreeRam();
            }
        }
    } else {
        std::set<SockHolder*>::iterator it = setFreeSockets.begin();
        re = *it;
        setFreeSockets.erase(it);
        re->sock.freeResources();
		if (re->sslStaff) {
			iEncrypt->stopEncryptSocket(re->sslStaff);
			re->sslStaff = nullptr;
		}
    }

    return re;
}


void SelectSrv::ohNoFreeRam() {
    keepRun.store(false, std::memory_order_release);
    iLog->log("e","[SelectSrv]: no free RAM");
}

bool SelectSrv::handleWrite(SockHolder * s){
#ifdef Debug
    iLog->log("i","[SelectSrv::handleWrite]: s=%i", s->cli_socket);
#endif
    bool re = true;
    if (s->writePacket){
        long res = iEncrypt->writeSocket(s->sslStaff, s->writeCur, s->writeLenLeft);
        if (res > 0) {
            s->writeCur+=res;
            s->writeLenLeft -=res;
            if (0==s->writeLenLeft) {
                iAlloc->specFree(s->writePacket);
                s->writePacket = nullptr;
            }
        } else if (ISSL_ERROR_WANT_WRITE!=iEncrypt->getSocketState(s->sslStaff, res)) {
            re = false;//setEncryptWants(s, res);
        }
    }
    return re;
}

void SelectSrv::handleAccept(T_SOCKET server_socket) {

	T_SOCKET client_socket;
#if defined(Windows)	
	SOCKADDR_STORAGE From;
	int FromLen = sizeof(From);
	char Hostname[NI_MAXHOST];
	while ((client_socket = accept(server_socket, (LPSOCKADDR)& From, &FromLen)) != INVALID_SOCKET) {
		if (logLevel > 1) {
			if (getnameinfo((LPSOCKADDR)& From, FromLen, Hostname,
				sizeof(Hostname), NULL, 0, NI_NUMERICHOST) != 0) {
				strcpy_s(Hostname, NI_MAXHOST, "<unknown>");
			}
			//printf("\nAccepted connection from %s\n", Hostname);
			iLog->log("i", "[SelectSrv::handleAccept]: Accepted connection from %s", Hostname);				
		}
#else
	struct sockaddr_in raddr;
	socklen_t rsz = sizeof(raddr);
    while ((client_socket = accept4(server_socket,(struct sockaddr *)&raddr,&rsz, SOCK_CLOEXEC))>=0) {
		if (logLevel > 1) { logConnection((struct sockaddr *)&raddr, rsz, client_socket); }
#endif     

        SockHolder * s = getFreeSocket();
        if (!s) { //can't be that because of check before calling  handleAccept
            close(client_socket);
            break;
        }

        /* set NONBLOCK socket */
		setNONBLOCK(client_socket);        
        s->cli_socket = client_socket;		
		/* start socket thread after handshake */
		s->sock.state.store(ESOCK_GO_SHAKE, std::memory_order_release);
		s->lastActTime = time(nullptr);
		setWorkSockets.insert(s);       
    }
}


void SelectSrv::handleRead(SockHolder * s) {
#ifdef Debug
    iLog->log("i","[SelectSrv::handleRead]: s=%i", s->cli_socket);
#endif
    int res = 0;
    //faux loop
    do {
        if (!s->readPacket) {
            /* loading just header */
            char buf[sizeof(T_IPack0_Network)];
            res = iEncrypt->readSocket(s->sslStaff, buf, sizeof(T_IPack0_Network));
            if (sizeof(T_IPack0_Network) ==res) {
                s->readPacket = IPack0::eatPacket(iAlloc , buf);
                if (!s->readPacket) {
                    //ohNoFreeRam();
                    setFreeSocket3(s);
#ifdef Debug
    iLog->log("e","[SelectSrv::handleRead]: NULL==IPack0::eatPacket(), s=%i", s->cli_socket);
#endif
                    break;
                }
                s->readCur = s->readPacket + sizeof(T_IPack0_Network);
                s->readLenLeft = ((T_IPack0_Network *)(s->readPacket))->pack_len - sizeof(T_IPack0_Network);
                s->lastActTime = time(nullptr);
            } else {
                if (res>0 || ISSL_ERROR_WANT_READ != iEncrypt->getSocketState(s->sslStaff, res)) {
                    setFreeSocket3(s);
                }
                break;
            }
        }   //if (!s->readPacket)

        /* load packet body */
        while(0<(res = iEncrypt->readSocket(s->sslStaff,
                                           s->readCur,
                                           s->readLenLeft))) {
            s->readLenLeft -= res;
            s->readCur += res;
            if (0==s->readLenLeft) { break;}
        }//while

        /* parse packet body */
        if (0==s->readLenLeft) {
            /* all readed */
            //Check packet END:
            T_IPack0_Network * pack0 = ((T_IPack0_Network *)(s->readPacket));
            uint32_t * endMark = (uint32_t *)(s->readPacket + pack0->pack_len - sizeof(uint32_t));
            if (N_SPEC_MARK_E!=*endMark) {
#ifdef Debug
    iLog->log("e","[SelectSrv::handleRead]: N_SPEC_MARK_E!=endMark, s=%i", s->cli_socket);
#endif
                setFreeSocket3(s);
                break;
            }

            switch (pack0->pack_type) {
            case SPEC_PACK_TYPE_2:
                if (3==s->connectState && s->connectedGroup==
                        ((T_IPack1_Network *)(s->readPacket))->groupID) {
                    /* send X509 from file cache */
                    //TODO
                } else  {
                    //Protocol error
                    setFreeSocket3(s);
                }
                break;
            case SPEC_PACK_TYPE_7:
                if (3==s->connectState && s->connectedGroup==
                        ((T_IPack6_Network *)(s->readPacket))->groupID) {
                    /* send X509 from file cache */
                    //TODO
                } else  {
                    //Protocol error
                    setFreeSocket3(s);
                }
                break;
            default:
                /* do long job in the socket thread */
                s->sock.eatPacket(s->readPacket);
                s->readPacket = nullptr;
                break;
            } //switch
            if (s->readPacket) {
                iAlloc->specFree(s->readPacket);
                s->readPacket = nullptr;
            }
            break;
        }

        /* parse errors */
        if (res<=0) {
            if (ISSL_ERROR_WANT_READ != iEncrypt->getSocketState(s->sslStaff, res)) {
                setFreeSocket3(s);
            }
        }
    } while (false);
} //handleRead

void SelectSrv::setFreeSocket3(SockHolder * s) {
    setFreeSocket2(s);    
    std::set<SockHolder*>::iterator it = setWorkSockets.find(s);
    if (setWorkSockets.end()!=it) {
        setWorkSockets.erase(it);
    }
}

void SelectSrv::setFreeSocket2(SockHolder * s) {
    setFreeSocket1(s);    
    setFreeSockets.insert(s);
}

void SelectSrv::setFreeSocket1(SockHolder * s) {
    s->sock.stop();
    s->connectState = 0;

	if (NOT_SOCKET!=s->cli_socket) {
		CLOSE_SOCK(s->cli_socket);
		s->cli_socket = NOT_SOCKET;
	}

    if (s->writePacket) {
         iAlloc->specFree(s->writePacket);
         s->writePacket = nullptr;
    }
    if (s->readPacket) {
         iAlloc->specFree(s->readPacket);
         s->readPacket = nullptr;
    }

}



void SelectSrv::handleHandshake(SockHolder * s) {
//faux loop
    do {        
        if (!s->sslStaff) {
            s->sslStaff = iEncrypt->startEncryptSocket(s->cli_socket);
            if (!s->sslStaff) {
                keepRun.store(false, std::memory_order_release);
                iLog->log("e","[SelectSrv::handleHandshake]: FAIL  iEncrypt->startEncryptSocket()");
                break;
            }
			s->connectState = 1;
        }

        int r = iEncrypt->do_handshakeSocket(s->sslStaff);
        if (r == 1) {
//            s->_connected = true;
            s->connectState = 2;
            if(logLevel>2) {
                iLog->log("i","[SelectSrv::handleHandshake]: ssl connected fd %d",
                                     s->cli_socket);
            }

			/* Start socket thread */
            s->sock.start();            
            break;
        }

//        if (!setEncryptWants(s, r)) {
//            setFreeSocket3(s) ;
//        }
        int errE = iEncrypt->getSocketState(s->sslStaff, r);
        if (ISSL_ERROR_WANT_WRITE != errE
                && ISSL_ERROR_WANT_READ != errE) {
            iLog->log("e","[SelectSrv::setEncryptWants]: socket %d return %d error %d errno %d msg %s",
                                 s->cli_socket, errE, r, errno, strerror(errno));
            iEncrypt->logErrors();
            setFreeSocket3(s) ;
        }

    }while (false);

}


void SelectSrv::setServFD_Set(fd_set &_fd_set) {
	FD_ZERO(&_fd_set);
	for (int i = 0; i < servSockCount; ++i) {
		FD_SET(servSocks[i], &_fd_set);
	}
}

void SelectSrv::servThreadLoop(){ 
	fd_set servSet;	
	fd_set r_servSet;	
	fd_set w_cliSet;
	fd_set r_cliSet;
	//fd_set e_cliSet;
	//std::queue<SockHolder*> queWorkSockets;
	SockHolder* queWorkSockets[FD_SETSIZE];
	int queWorkCur = 0;
	int queWorkLen = 0;
	setServFD_Set(servSet);
	int selCliCnt = 0; //Client events from last call
	int selSrvCnt = 0; //Server's events from last call
	int selecEventCnt = 0;	
	while (keepRun.load(std::memory_order_acquire)) {
		bool goSleep = true;
		//1. Serve all client jobs (select only cli)
		if (setWorkSockets.size() > 0) {
			FD_ZERO(&w_cliSet);
			queWorkCur = 0;
			queWorkLen = 0;				
			for (std::set<SockHolder*>::const_iterator it = setWorkSockets.begin();
						 it != setWorkSockets.end(); ++it) {					
					//queWorkSockets.push(*it);
				queWorkSockets[queWorkLen] = *it;
				++queWorkLen;
				FD_SET((*it)->cli_socket, &w_cliSet);
			}//for
			memcpy(&r_cliSet, &w_cliSet, sizeof(w_cliSet));
				//memcpy(&e_cliSet, &w_cliSet, sizeof(w_cliSet));
			timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 100;
			selecEventCnt = select(queWorkLen,
					&r_cliSet,
					&w_cliSet,
					nullptr,//&e_cliSet,
					&tv);
			if (selecEventCnt < 0) {
				keepRun.store(false, std::memory_order_release);
				printSocketError("servThreadLoop->select()");
				break;
			}
			//Check jobs
			time_t curTime = time(nullptr);
			goSleep = 0==selecEventCnt;
			while (selecEventCnt > 0 
					&& queWorkCur < queWorkLen 
					&& keepRun.load(std::memory_order_acquire)) {
				SockHolder* s = queWorkSockets[queWorkCur];
				++queWorkCur;
				if (ESOCK_GO_SHAKE > s->sock.state.load(std::memory_order_acquire)) {
					/* socket disconnected itself */
					setFreeSocket3(s);
					continue;				
				}

				if (s->connectState < 2) {
					//Not SSL connected
					if (FD_ISSET(s->cli_socket, &r_cliSet)
						|| FD_ISSET(s->cli_socket, &w_cliSet)) {
						--selecEventCnt;
						handleHandshake(s);
					} else {
						//Check timeout
						if ((curTime - s->lastActTime) > idleConnLife) {
							setFreeSocket3(s);							
						}
					}
					continue;
				}

				//Check if read ready
				if (FD_ISSET(s->cli_socket, &r_cliSet)) {
					--selecEventCnt;
					handleRead(s);															
				}//r_cliSet

				//Check timeout
				if ((curTime - s->lastActTime) > idleConnLife) {
					setFreeSocket3(s);
					continue;
				}
				//Check if write ready
				if (FD_ISSET(s->cli_socket, &w_cliSet)) {
					--selecEventCnt;					
					if (!handleWrite(s)) {
						setFreeSocket3(s);						
					}
				}//w_cliSet
			}//while (selecEventCnt > 0
			
			//Check timeouts
			while (queWorkCur < queWorkLen) {
				SockHolder* s = queWorkSockets[queWorkCur];
				++queWorkCur;
				if ((curTime - s->lastActTime) > idleConnLife) {
					setFreeSocket3(s);					
				}
			}
		}

		//2. Accept new connections if can (select only srv)
		memcpy(&r_servSet, &servSet, sizeof(servSet));
		timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 100;
		selecEventCnt = select(servSockCount+1,
			&r_servSet,
			nullptr,
			nullptr,//&e_cliSet,
			&tv);
		if (selecEventCnt < 0) {
			//if error, stop
			keepRun.store(false, std::memory_order_release);
			printSocketError("servThreadLoop->select()");
			break;
		}

		if (selecEventCnt > 0) {
			goSleep = false;
			for (int i = 0; i < servSockCount; ++i) {
				if (FD_ISSET(servSocks[i], &r_servSet)) {
					if (setAllSockets.size() < maxConnections || !setFreeSockets.empty()) {
						handleAccept(servSocks[i]);
					}
					else {
						if (logLevel > 2) {
							iLog->log("w", "[EpolSrv::servThreadLoop]: cant handleAccept() - no free connections in pool");
						}
						break;
					}
				}
			}//for
		}//if

		if (goSleep) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}		
	}//while

    stopServerEpoll();
}

void SelectSrv::stopServerEpoll(){
	for (int i = 0; i < servSockCount; ++i) {
		CLOSE_SOCK(servSocks[i]);
	}
	servSockCount = 0;
	
    /* Say to all that server is going to stopp */
    srvState.store(3, std::memory_order_release);
    iLog->log("i","[%s]: is going to stop.",TAG);
    /* Stop all clients: */
    stopAllSockets();   
    iLog->log("i","[%s]: is stopped.",TAG);
    srvState.store(0, std::memory_order_release);
}

void SelectSrv::handleSockets() {
    std::set<SockHolder*>::iterator it = setWorkSockets.begin();
    time_t lastActTime = std::time(nullptr);
    while (keepRun.load(std::memory_order_acquire) && setWorkSockets.end()!=it) {
        SockHolder * p = *it;
        int state = p->sock.state.load(std::memory_order_acquire);
//#ifdef Debug
//    iLog->log("i","[SelectSrv::handleSockets]: s=%i, state=%i", (*it)->_socket_id, state);
//#endif
        bool isAlive = state > ESOCK_FREE1 && (lastActTime-p->lastActTime)<=idleConnLife;
        if (isAlive && ESOCK_WANT_WRITE==state) {
            /* want write */
                if (!((*it)->writePacket)) {
                    isAlive = goWritePacket(*it);
                }
        }

        if (isAlive)  {
            it++;
        } else {
            setFreeSocket2(*it);
            it = setWorkSockets.erase(it);
        }
    } //while inner
}

bool SelectSrv::goWritePacket(SockHolder * s) {
    bool re = true;
    ++s->sock.state;
    s->writePacket = s->sock.getPacket();
    T_IPack0_Network * pack0 = (T_IPack0_Network *)(s->writePacket);
    if (s->writePacket) {
        if (N_SPEC_PACK_TYPE_6==pack0->pack_type) {
            /* The server checked the certificate and allowed the work */
            s->connectState = 3;
            //groupID in network byte order
            s->connectedGroup = //IPack6::getOutGroupID(s->writePacket);
                    ((T_IPack6_Network *)(s->writePacket))->groupID;
        }
//#ifdef Debug
//    iLog->log("i","[SelectSrv::goWritePacket]: [s=%i]: exist packet", s->_socket_id);
//#endif
        s->writeLenLeft = _NTOHL(pack0->pack_len);
        if (0>=s->writeLenLeft) {
#ifdef Debug
            iLog->log("e","[goWritePacket]: s->writeLenLeft <=0.");
#endif
            s->writePacket = nullptr;
            re = false;
        } else {
            s->writeCur = s->writePacket;         
            re = handleWrite(s);
        }
    }
//    else {
//#ifdef Debug
//    iLog->log("i","[SelectSrv::goWritePacket]: [s=%i]: NOT exist packet", s->_socket_id);
//#endif
//    }
    return re;
}

void SelectSrv::stopAllSockets() {
    if (setWorkSockets.size()>0) {
        std::set<SockHolder*> ::const_iterator it = setWorkSockets.begin();
        while(setWorkSockets.end() != it){
                /* must stop threads */
                (*it)->sock.stop();
                it++;
         }
    }
    setWorkSockets.clear();
    setFreeSockets.clear();
    std::this_thread::yield();
	

    if (setAllSockets.size()>0) {
        std::set<SockHolder*> ::iterator it = setAllSockets.begin();
        while(setAllSockets.end() != it){
            setFreeSocket1(*it);
            /* blocking call - will wait for thread to stop */
			(*it)->sock.freeResources();
            delete (*it);
            it = setAllSockets.erase(it);
        }
    }
}




void SelectSrv::logConnection(sockaddr * remote_addr, unsigned int remote_addr_len, int client_socket) {
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    //SpecContext & sr = SpecContext::instance();
    if (getnameinfo(remote_addr, remote_addr_len, hbuf, sizeof(hbuf), sbuf,
                    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        //sr.iLog.get()->log("i","[%s]: accept host=%s, serv=%s",TAG, hbuf, sbuf);
        iLog->log("i","[SelectSrv::logConnection]: accept host=%s, serv=%s on socket=%i", hbuf, sbuf, client_socket);
    }
}


const char * SelectSrv::getMessagesPath() { return messagesPath.c_str();}
const char * SelectSrv::getAvaCertsPath() { return avaCertsPath.c_str();}
std::string SelectSrv::getServPassword() { return servPassword;}

