#include "epolsrv.h"
#include "spec/speccontext.h"
#include "spec/specstatic.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h> /* Added for the nonblocking socket */
#include <sys/epoll.h>
#include <poll.h>



EpolSrv::EpolSrv() {

}

EpolSrv::~EpolSrv() {
    stop();
    //wait for thread before destruction
    if (serverThread.joinable()) {
        serverThread.join();
    }
}


bool  EpolSrv::start() {
    bool re = false;
    SpecContext & sr = SpecContext::instance();
    iEncrypt = sr.iEncrypt.get();
    iLog = sr.iLog.get();
    iAlloc = sr.iAlloc.get();
    iFileAdapter = sr.iFileAdapter.get();
    iDB = sr.iDB.get();
    if (iFileAdapter && iAlloc && iLog && iEncrypt && iDB &&
            0==srvState.load(std::memory_order_acquire) &&
            create_socket()) {
        srvState.store(1, std::memory_order_release);
        serverThread = std::thread(&EpolSrv::runServThreadLoop, this);
        re = true;
    }
    return re;
}

void  EpolSrv::stop()  {
    //ToDo проверить:
    //socketID.store(-1, std::memory_order_release);
    keepRun.store(false, std::memory_order_release);


}


bool EpolSrv::create_socket() {
    bool re = false;

    //faux loop:
    do {
        SpecContext & sr = SpecContext::instance();
        logLevel = sr.iConfig.get()->getLongValue("LogLevel");
        maxConnections = sr.iConfig.get()->getLongValue("MaxConnections");

        bufConnections = maxConnections >> 2;
        idleConnLife = sr.iConfig.get()->getLongValue("idleConnLife");
        uint16_t port = sr.iConfig.get()->getLongValue("ServerPort");
        if (0 == port) {
            iLog->log("e","[%s]: FAIL iConfig.get(ServerPort).",TAG);
            break;
        }

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


        //int fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
        server_socket = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (server_socket < 0) {
            iLog->log("e","[%s]: FAIL socket(AF_INET, SOCK_STREAM, 0).",TAG);
            break;
        }

        int flags = fcntl(server_socket, F_GETFL, 0);
        if (flags < 0) {
            iLog->log("e","[%s]: 0>create_socket.fcntl(server_socket, F_GETFL, 0)",TAG);
            break;
        }
        fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof (addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (::bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            iLog->log("e","[%s]: FAIL bind(server_socket, (struct sockaddr*)&addr.",TAG);
            break;
        }

        /* set Maximum pending connection to EPOLL_WAIT_POOL */
        if (listen(server_socket, EPOLL_WAIT_POOL) < 0) {
            iLog->log("e","[%s]: FAIL listen(server_socket, EPOLL_WAIT_POOL).",TAG);
            break;
        }

        iLog->log("i","[%s]: now listening on port [%u]",TAG, port);

        re = true;
    } while (false);
    if (!re && server_socket>=0) {
        close(server_socket);
        server_socket = -1;
    }
    return re;
}

void* EpolSrv::runServThreadLoop(void* arg){
    EpolSrv* p = reinterpret_cast<EpolSrv*>(arg);
    p->servThreadLoop();
    return 0;
}



EpolSocket * EpolSrv::getFreeSocket() {

    EpolSocket * re = nullptr;
    if (setFreeSockets.empty()) {
        if (setAllSockets.size()<maxConnections) {
            re = new EpolSocket(this, logLevel);
            if (re) {
                re->sockType = CLI_TYPE;
                re->iLog = iLog;
                re->iAlloc = iAlloc;
                re->iEncrypt = iEncrypt;
                re->iFileAdapter = iFileAdapter;
                re->iDB = iDB;
                setAllSockets.insert(re);
            } else {
                ohNoFreeRam();
            }
        }
    } else {
        std::set<EpolSocket*>::iterator it = setFreeSockets.begin();
        re = *it;
        setFreeSockets.erase(it);
        re->freeResources();
    }

    return re;
}

//bool EpolSrv::addEPollFd(IEpoll* s) {
//    //memset(&(s->_epol_ev), 0, sizeof(_epol_ev));
//    //s->_epol_ev.events = s->_events;
//    s->_epol_ev.data.ptr = s;
//    int res = epoll_ctl(epollfd, EPOLL_CTL_ADD, s->_socket_id, &(s->_epol_ev));
//    if (-1==res) {
//        keepRun.store(false, std::memory_order_release);
//        iLog->log("e","[EpolSrv::addEPollFd]: epoll_ctl(epollfd, EPOLL_CTL_ADD: %d %s",
//                     errno, strerror(errno));
//        return false;
//    }
//    return true;
//}

void EpolSrv::updateEPoll(EpolSocket * s) {
    //memset(&(s->_epol_ev), 0, sizeof(_epol_ev));
    //s->_epol_ev.events = s->_events;
    //s->_epol_ev.data.ptr = s;
//        log("modifying fd %d events read %d write %d\n",
//            fd_, ev.events & EPOLLIN, ev.events & EPOLLOUT);
    //int res = epoll_ctl(epollfd, EPOLL_CTL_MOD, s->_socket_id, &(s->_epol_ev));
    if (-1==epoll_ctl(epollfd, EPOLL_CTL_MOD, s->_socket_id, &(s->_epol_ev))) {
        keepRun.store(false, std::memory_order_release);
        iLog->log("e","[EpolSrv::updateEPoll]: updateEPoll: %d %s",
                     errno, strerror(errno));
    }
}

void EpolSrv::ohNoFreeRam() {
    keepRun.store(false, std::memory_order_release);
    iLog->log("e","[EpolSrv]: no free RAM");
}

bool EpolSrv::handleWrite(EpolSocket * s){
#ifdef Debug
    iLog->log("i","[EpolSrv::handleWrite]: s=%i", s->_socket_id);
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
//                s->_events = EPOLLIN | EPOLLERR;
                if ((EPOLLIN | EPOLLERR)!=s->_epol_ev.events){
                    s->_epol_ev.events = EPOLLIN | EPOLLERR;
                    updateEPoll(s);
                }
            }
        } else if (ISSL_ERROR_WANT_WRITE!=iEncrypt->getSocketState(s->sslStaff, res)) {
            re = false;//setEncryptWants(s, res);
        }
    }
    return re;
}

void EpolSrv::handleAccept() {
    struct sockaddr_in raddr;
    socklen_t rsz = sizeof(raddr);
    int client_socket;
    while ((client_socket = accept4(server_socket,(struct sockaddr *)&raddr,&rsz, SOCK_CLOEXEC))>=0) {
        if (logLevel>1) { logConnection((struct sockaddr *)&raddr, rsz, client_socket);}
    //while ((client_socket = accept4(server_socket,nullptr,nullptr, SOCK_CLOEXEC))>=0) {
//        sockaddr_in peer, local;
//        socklen_t alen = sizeof(peer);
//        int r = getpeername(client_socket, (sockaddr*)&peer, &alen);
//        if (r < 0) {
//            if(logLevel>2) {
//                SpecContext::instance().iLog.get()->
//                        log("w","[EpolSrv::handleAccept]: get peer name failed %d %s",
//                             errno, strerror(errno));
//            }
//            continue;
//        }
//        r = getsockname(client_socket, (sockaddr*)&local, &alen);
//        if (r < 0) {
//            if(logLevel>2) {
//                SpecContext::instance().iLog.get()->
//                        log("w","[EpolSrv::handleAccept]: getsockname failed %d %s",
//                             errno, strerror(errno));
//            }
//            continue;
//        }

        EpolSocket * s = getFreeSocket();
        if (!s) { //can't be that because of check before calling  handleAccept
            close(client_socket);
            break;
        }

        /* set NONBLOCK socket */
        int flags = fcntl(client_socket, F_GETFL, 0);
        if (flags < 0) {
            iLog->log("e","[EpolSrv::handleAccept]: 0>create_socket.fcntl(server_socket, F_GETFL, 0)");
            break;
        }
        fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);

        s->_socket_id = client_socket;
        s->_epol_ev.events = EPOLLIN | EPOLLOUT;
        s->_epol_ev.data.ptr = dynamic_cast<IEpoll *>(s);
        /* start work with epoll */        
        if (-1==epoll_ctl(epollfd, EPOLL_CTL_ADD, s->_socket_id, &(s->_epol_ev))) {
            keepRun.store(false, std::memory_order_release);
            iLog->log("e","[EpolSrv::addEPollFd]: epoll_ctl(epollfd, EPOLL_CTL_ADD: %d %s",
                         errno, strerror(errno));
        } else {
            setWorkSockets.insert(s);
            /* start socket thread after handshake */
            s->state.store(ESOCK_GO_SHAKE, std::memory_order_release);
            s->lastActTime = std::time(nullptr);
        }
    }
}


void EpolSrv::handleRead(EpolSocket * s) {
#ifdef Debug
    iLog->log("i","[EpolSrv::handleRead]: s=%i", s->_socket_id);
#endif
    int res = 0;
    if (!s->readPacket) {
        /* loading just header */
        char buf[SPEC_LEN_HEAD_2];
        res = iEncrypt->readSocket(s->sslStaff, buf, SPEC_LEN_HEAD_2);
//        char buf[1024];
//        res = iEncrypt->readSocket(s->sslStaff, buf, 1024);
        if (res > 0) {
            /* check packet header */
            long len = IPack0::eatPacket(buf, res);
            if (len<=0) {
                setFreeSocket3(s);
                if (logLevel>2) {
                    iLog->log("e","[EpolSrv::handleRead]: IPack0::eatPacket(%i)=%ld",
                          s->_socket_id, len);
                }
                return;
            }
            /* allocate len for packet */
            s->readPacket = (char *)iAlloc->specAlloc(len+SPEC_LEN_HEAD_1);
            if (!s->readPacket) {
                ohNoFreeRam();
                return;
            }
            s->readCur = s->readPacket + SPEC_LEN_HEAD_1;
            s->readLenLeft = len;
            /* fist bytes == len */
            *((uint32_t*)(s->readPacket)) = len;
            s->lastActTime = std::time(nullptr);
        } else {
//            if (setEncryptWants(s, res)) {
//            } else {
//                setFreeSocket3(s);
//            }
            if (ISSL_ERROR_WANT_READ != iEncrypt->getSocketState(s->sslStaff, res)) {
                setFreeSocket3(s);
            }
            return;
        }
    }

    while(0<(res = iEncrypt->readSocket(s->sslStaff,
                                       s->readCur,
                                       s->readLenLeft))) {

        s->readLenLeft -= res;
        s->readCur += res;
        if (0==s->readLenLeft) {
            /* all readed */
//            uint32_t * headers = (uint32_t *)s->readPacket;
//            long size = headers[0];
//            long type = ntohl(headers[1]);
            uint32_t type = IPack0::getTypeIn(s->readPacket);            

            switch (type) {
            case SPEC_PACK_TYPE_2:
            case SPEC_PACK_TYPE_7:
                if (3==s->connectState &&
                        IPack1::getGroupIn(s->readPacket)==s->connectedGroup) {
                    //TODO
                    /* send mail from file cache */
                    /* send X509 from file cache */
                } else {
                    //Protocol error
                    s->stop();
                }
                break;
            default:
                /* do long job in the socket thread */
                s->eatPacket(s->readPacket);
                s->readPacket = nullptr;
                break;
            } //switch
            if (s->readPacket) {
                iAlloc->specFree(s->readPacket);
                s->readPacket = nullptr;
            }


            break;
        }
    }//while

    if (res<=0) {
//        if (!setEncryptWants(s, res)) {
//            setFreeSocket3(s);
//        }
        if (ISSL_ERROR_WANT_READ != iEncrypt->getSocketState(s->sslStaff, res)) {
            setFreeSocket3(s);
        }
    }
}

void EpolSrv::setFreeSocket3(EpolSocket * s) {
    setFreeSocket2(s);    
    std::set<EpolSocket*>::iterator it = setWorkSockets.find(s);
    if (setWorkSockets.end()!=it) {
        setWorkSockets.erase(it);
    }
}

void EpolSrv::setFreeSocket2(EpolSocket * s) {
    setFreeSocket1(s);    
    setFreeSockets.insert(s);
}

void EpolSrv::setFreeSocket1(EpolSocket * s) {
    s->stop();
    s->connectState = 0;

    if (-1!=s->_socket_id) {
        close(s->_socket_id);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, s->_socket_id, NULL);
        s->_socket_id = -1;
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



void EpolSrv::handleHandshake(EpolSocket * s) {
//faux loop
    do {
        if (0==s->connectState) {
            struct pollfd pfd;
            pfd.fd = s->_socket_id;
            pfd.events = POLLOUT | POLLERR;
            int r = poll(&pfd, 1, 0);
            if (r == 1 && pfd.revents == POLLOUT) {
                if(logLevel>2) {
                    iLog->log("i","[EpolSrv::handleHandshake]: tcp connected fd %d",
                                         s->_socket_id);
                }
                //s->_connected = true;
                s->connectState = 1;
                s->_epol_ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
                //s->_epol_ev.data.ptr = s;
                updateEPoll(s);
            } else {
                if(logLevel>2) {
                    iLog->log("w","[EpolSrv::handleHandshake]: poll fd %d return %d revents %d",
                                         s->_socket_id, r, pfd.revents);
                }
                setFreeSocket3(s) ;
                break;
            }
       } //if (!s->_connected

        if (!s->sslStaff) {
            s->sslStaff = iEncrypt->startEncryptSocket(s->_socket_id);
            if (!s->sslStaff) {
                keepRun.store(false, std::memory_order_release);
                iLog->log("e","[EpolSrv::handleHandshake]: FAIL  iEncrypt->startEncryptSocket()");
                break;
            }
        }

        int r = iEncrypt->do_handshakeSocket(s->sslStaff);
        if (r == 1) {
//            s->_connected = true;
            s->connectState = 2;
            if(logLevel>2) {
                iLog->log("i","[EpolSrv::handleHandshake]: ssl connected fd %d",
                                     s->_socket_id);
            }

            s->start();
            //s->_events = EPOLLIN;
            //s->_events = EPOLLIN | EPOLLOUT | EPOLLERR;
//            s->_epol_ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
//            s->_epol_ev.data.ptr = s;
            if ((EPOLLIN | EPOLLOUT | EPOLLERR) !=s->_epol_ev.events) {
                iLog->log("w","[EpolSrv::handleHandshake]: EPOLLIN | EPOLLOUT | EPOLLERR !=s->_epol_ev.events");
                s->_epol_ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
                updateEPoll(s);
            }
            break;
        }

//        if (!setEncryptWants(s, r)) {
//            setFreeSocket3(s) ;
//        }
        int errE = iEncrypt->getSocketState(s->sslStaff, r);
        if (ISSL_ERROR_WANT_WRITE != errE
                && ISSL_ERROR_WANT_READ != errE) {
            iLog->log("e","[EpolSrv::setEncryptWants]: socket %d return %d error %d errno %d msg %s",
                                 s->_socket_id, errE, r, errno, strerror(errno));
            iEncrypt->logErrors();
            setFreeSocket3(s) ;
        }

    }while (false);

}

bool EpolSrv::addServerEpoll() {
    bool re = false;
    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (-1==epollfd) {
        iLog->log("e","[%s]: FAIL epoll_create1(EPOLL_CLOEXEC).",TAG);
    } else {
        srvEpoll._socket_id = server_socket;
        srvEpoll.sockType = SERV_TYPE;
        srvEpoll._epol_ev.data.ptr = &srvEpoll;
        srvEpoll._epol_ev.events = EPOLLIN;
        if (-1==epoll_ctl(epollfd, EPOLL_CTL_ADD, srvEpoll._socket_id, &(srvEpoll._epol_ev))) {
            iLog->log("e","[EpolSrv::addEPollFd]: epoll_ctl(epollfd, EPOLL_CTL_ADD: %d %s",
                         errno, strerror(errno));
        } else {
            re = true;
        }
    }
    if (!re) {
        keepRun.store(false, std::memory_order_release);
        srvState.store(0, std::memory_order_release);
    }
    return re;
}

void EpolSrv::servThreadLoop(){    
    if (!addServerEpoll()){ return;}
    struct epoll_event activeEvs[EPOLL_WAIT_POOL];

    srvState.store(2, std::memory_order_release);
    while (keepRun.load(std::memory_order_acquire)) {
        int n = epoll_wait(epollfd, activeEvs, EPOLL_WAIT_POOL, WAIT_TIME);
        for (int i = n-1; i >= 0; --i) {            
            IEpoll * s = reinterpret_cast<IEpoll*>(activeEvs[i].data.ptr);
            /* check if it alive */
            if (CLI_TYPE == s->sockType) {
                 /* Clients epoll handle */
                EpolSocket * pS = dynamic_cast<EpolSocket*>(s);
                if (ESOCK_GO_SHAKE > pS->state.load(std::memory_order_acquire)) {
                    /* socket disconnected itself */
                    setFreeSocket3(pS);
                    continue;
                } else {
                    int events = activeEvs[i].events;
                    if (events & (EPOLLIN | EPOLLERR)) {
                        if (2==s->connectState){
                            handleRead(pS);
                        } else {
                            handleHandshake(pS);
                        }
                    } else if (events & EPOLLOUT) {
                        if (2==s->connectState) {
                            if (!handleWrite(pS)) {
                                if (CLI_TYPE == s->sockType) {
                                    setFreeSocket3(pS);
                                }
                            }
                        } else {
                            handleHandshake(pS);
                        }
                    }
                }
            } else if (SERV_TYPE == s->sockType) {
            /* Server's epoll handle */
                if (setAllSockets.size()<maxConnections || !setFreeSockets.empty()) {
                    handleAccept();
                } else {
                    if(logLevel>2) {
                       iLog->log("w","[EpolSrv::servThreadLoop]: cant handleAccept() - no free connections in pool");
                    }
                }
            } else  {
                iLog->log("e","[EpolSrv::servThreadLoop]: FAIL check s->sockType.");
                keepRun.store(false, std::memory_order_release);
                break;
            }

//            int events = activeEvs[i].events;
//            if (events & (EPOLLIN | EPOLLERR)) {
//                if (server_socket==s->_socket_id) {
//                    if (setAllSockets.size()<maxConnections || !setFreeSockets.empty()) {
//                        handleAccept();
//                    } else {
//                        if(logLevel>2) {
//                           iLog->log("w","[EpolSrv::servThreadLoop]: cant handleAccept() - no free connections in pool");
//                        }
//                    }
//                } else if (2==s->connectState){
//                    handleRead(s);
//                } else {
//                    handleHandshake(s);
//                }
//            } else if (events & EPOLLOUT) {
//                if (server_socket==s->_socket_id) {
//                    iLog->log("e","[EpolSrv::servThreadLoop]: тут не должен был оказаться");
//                    keepRun.store(false, std::memory_order_release);
//                } else if (2==s->connectState) {
//                    if (!handleWrite(s)) {
//                        if (CLI_TYPE == s->sockType) {
//                            setFreeSocket3(s);
//                        }
//                    }
//                } else {
//                    handleHandshake(s);
//                }
//            } else if(logLevel>2) {
//                iLog->log("w","[EpolSrv::servThreadLoop]: epoll_wait unknown event: %i", events);
//            }

        } //for

        if (setWorkSockets.size()>0) {
            handleSockets();
        } else if (0==n) {
            //nothing to do
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

    } //while

    stopServerEpoll();
}

void EpolSrv::stopServerEpoll(){
    //if (-1!=epollfd) {
    /* remove self from epoll */
        epoll_ctl(epollfd, EPOLL_CTL_DEL, srvEpoll._socket_id, NULL);

    //}
    /* no new connections: */
    close(server_socket);
    /* Say to all that server is going to stopp */
    srvState.store(3, std::memory_order_release);
    iLog->log("i","[%s]: is going to stop.",TAG);
    /* Stop all clients: */
    stopAllSockets();
    /* close Epoll fd */
    ::close(epollfd);
    iLog->log("i","[%s]: is stopped.",TAG);
    srvState.store(0, std::memory_order_release);
}

void EpolSrv::handleSockets() {
    std::set<EpolSocket*>::iterator it = setWorkSockets.begin();
    srvEpoll.lastActTime = std::time(nullptr);
    while (keepRun.load(std::memory_order_acquire) && setWorkSockets.end()!=it) {
        EpolSocket * p = *it;
        int state = p->state.load(std::memory_order_acquire);
//#ifdef Debug
//    iLog->log("i","[EpolSrv::handleSockets]: s=%i, state=%i", (*it)->_socket_id, state);
//#endif
        bool isAlive = state > ESOCK_FREE1 && (srvEpoll.lastActTime-p->lastActTime)<=idleConnLife;
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

bool EpolSrv::goWritePacket(EpolSocket * s) {
    bool re = true;
    ++s->state;
    s->writePacket = s->getPacket();
    if (s->writePacket) {
        if (SPEC_PACK_TYPE_6==IPack0::getTypeOut(s->writePacket)) {
            /* The server checked the certificate and allowed the work */
            s->connectState = 3;
            s->connectedGroup = IPack6::getOutGroupID(s->writePacket);
        }
//#ifdef Debug
//    iLog->log("i","[EpolSrv::goWritePacket]: [s=%i]: exist packet", s->_socket_id);
//#endif
        s->writeLenLeft = IPack0::lenPacket(s->writePacket);
        if (s->writeLenLeft <=0) {
#ifdef Debug
            iLog->log("e","[goWritePacket]: s->writeLenLeft <=0.");
#endif
            s->writePacket = nullptr;
            re = false;
        } else {
#ifdef Debug
    std::string str (s->writePacket+SPEC_LEN_HEAD_3, s->writeLenLeft-SPEC_LEN_HEAD_1);
    iLog->log("i","[EpolSrv::goWritePacket]: [s=%i]: %s", s->_socket_id, str.c_str());
#endif
            s->writeLenLeft+=SPEC_LEN_HEAD_2;
            s->writeCur = s->writePacket;
//            int oldev = s->_events;
            //s->_events  |= EPOLLOUT;
            if ((EPOLLIN | EPOLLOUT | EPOLLERR)!=s->_epol_ev.events) {
                s->_epol_ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
                updateEPoll(s);
            }
            re = handleWrite(s);
        }
    }
//    else {
//#ifdef Debug
//    iLog->log("i","[EpolSrv::goWritePacket]: [s=%i]: NOT exist packet", s->_socket_id);
//#endif
//    }
    return re;
}

void EpolSrv::stopAllSockets() {
    if (setWorkSockets.size()>0) {
        std::set<EpolSocket*> ::const_iterator it = setWorkSockets.begin();
        while(setWorkSockets.end() != it){
                /* must stop threads */
                (*it)->stop();
                it++;
         }
    }
    setWorkSockets.clear();
    setFreeSockets.clear();
    std::this_thread::yield();

    if (setAllSockets.size()>0) {
        std::set<EpolSocket*> ::iterator it = setAllSockets.begin();
        while(setAllSockets.end() != it){
            setFreeSocket1(*it);
            /* blocking call - will wait for thread to stop */
            delete (*it);
            it = setAllSockets.erase(it);
        }
    }
}



//void  EpolSrv::EpolSocketDown(void * ptr)  {
//    std::lock_guard<std::mutex> raiiGuard(freeSockets_mutex);
//    setFreeSockets.insert((EpolSocket*)ptr);
//}

//void  EpolSrv::onSocketDown(void * ptr)  {
//    std::lock_guard<std::mutex> raiiGuard(freeSockets_mutex);
//    setFreeSockets.insert((EpolSocket*)ptr);
//}

//void  EpolSrv::onSocketEvent()  {
//    serverThreadCond.notify_all();
//}

void EpolSrv::logConnection(sockaddr * remote_addr, unsigned int remote_addr_len, int client_socket) {
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    //SpecContext & sr = SpecContext::instance();
    if (getnameinfo(remote_addr, remote_addr_len, hbuf, sizeof(hbuf), sbuf,
                    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        //sr.iLog.get()->log("i","[%s]: accept host=%s, serv=%s",TAG, hbuf, sbuf);
        iLog->log("i","[EpolSrv::logConnection]: accept host=%s, serv=%s on socket=%i", hbuf, sbuf, client_socket);
    }
}

//bool EpolSrv::setEncryptWants(IEpoll * s, int err) {
//    int errE = iEncrypt->getSocketState(s->sslStaff, err);
//    int oldev = s->_events;
//    if (ISSL_ERROR_WANT_WRITE == errE ) {
//        s->_events |= EPOLLOUT;
//        s->_events &= ~EPOLLIN;
//        if(logLevel>3) {
//            iLog->log("i","[EpolSrv::setEncryptWants]: return want write set events %d",
//                                 s->_socket_id);
//        }
//        if (oldev != s->_events) {
//            updateEPoll(s);
//        }
//    } else if (ISSL_ERROR_WANT_READ == errE) {
//        s->_events  |= EPOLLIN;
//        s->_events  &= ~EPOLLOUT;
//        if(logLevel>3) {
//            iLog->log("i","[EpolSrv::setEncryptWants]: return want read set events %d",
//                                 s->_socket_id);
//        }
//        if (oldev != s->_events) {
//            updateEPoll(s);
//        }
//    } else {
//        if(logLevel>1) {
//            iLog->log("e","[EpolSrv::setEncryptWants]: socket %d return %d error %d errno %d msg %s",
//                                 s->_socket_id, errE, err, errno, strerror(errno));
//            iEncrypt->logErrors();
//        }
//        return false;
//    }
//    return true;
//}

const char * EpolSrv::getMessagesPath() { return messagesPath.c_str();}
const char * EpolSrv::getAvaCertsPath() { return avaCertsPath.c_str();}
std::string EpolSrv::getServPassword() { return servPassword;}

