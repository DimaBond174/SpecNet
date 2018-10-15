#include "defserver.h"
#include "spec/speccontext.h"

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
//#include <fcntl.h> /* Added for the nonblocking socket */

DefServer::DefServer() {

}

DefServer::~DefServer() {
    stop();
    //wait for thread before destruction
    if (serverThread.joinable()) {
        serverThread.join();
    }
}

bool  DefServer::start() {
    bool re = false;
    if (create_socket()) {
        serverThread = std::thread(&DefServer::runServThreadLoop, this);
        re = true;
    }
    return re;
}

void  DefServer::stop()  {
    //ToDo проверить:
    //socketID.store(-1, std::memory_order_release);
    keepRun.store(false, std::memory_order_release);
    close_socket();


}

void DefServer::close_socket() {
//    int sID = socketID.load(std::memory_order_acquire);
//    if (sID >= 0) {
//        socketID.store(-1, std::memory_order_release);
//        ::close(sID);
//        //http://beej.us/guide/bgnet/html/single/bgnet.html#accept
//        //Except to remember that if you're using Windows and Winsock that you should call closesocket() instead of close()
//    }
    SpecContext & sr = SpecContext::instance();
    sr.iLog.get()->log("i","[%s]: going to stop server socket ..",TAG);
    //faux loop:
    do {

       // uint16_t port = sr.iConfig.get()->getLongValue("ServerPort");
        const std::string& port = sr.iConfig.get()->getStringValue("ServerPort");
        //if (0 == port) {
        if (port.empty()) {
            sr.iLog.get()->log("e","[%s]: FAIL iConfig.get(ServerPort).",TAG);
            break;
        }

        int sockfd;
        struct addrinfo hints, *servinfo, *p;
        int rv;
        //char s[INET6_ADDRSTRLEN];


        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if ((rv = getaddrinfo("127.0.0.1", port.c_str(), &hints, &servinfo)) != 0) {
            sr.iLog.get()->log("e","[%s]: FAIL getaddrinfo(127.0.0.1",TAG);
            break;
        }

        // loop through all the results and connect to the first we can
        for(p = servinfo; p != NULL; p = p->ai_next) {
            if ((sockfd = socket(p->ai_family, p->ai_socktype,
                    p->ai_protocol)) == -1) {
                continue;
            }

            if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                close(sockfd);
                continue;
            }

            break;
        }
        close(sockfd);
//        break;
//        /* Create the socket. */
//        int sock = socket (PF_INET, SOCK_STREAM, 0);
//        if (sock < 0) {
//            sr.iLog.get()->log("e","[%s]: FAIL cli socket (PF_INET, SOCK_STREAM, 0).",TAG);
//            break;
//          }

//        struct hostent *hostinfo;
//        struct sockaddr_in servername;
//        servername.sin_family = AF_INET;
//        servername.sin_port = htons(port);
//        //addr.sin_addr.s_addr = htonl(INADDR_ANY);

//        hostinfo = gethostbyname ("127.0.0.1");
//        if (!hostinfo) {
//            sr.iLog.get()->log("e","[%s]: FAIL hostinfo = gethostbyname (127.0.0.1).",TAG);
//            break;
//        }
//        servername.sin_addr = *(struct in_addr *) hostinfo->h_addr;

//        connect (sock, (struct sockaddr *) &servername, sizeof (servername));
//        close(sock);

    } while (false);
    sr.iLog.get()->log("i","[%s]: going to wait for stop of the sockets of connected clients..",TAG);
}

bool DefServer::create_socket() {
    bool re = false;
    int server_socket = -1;
    //faux loop:
    do {
        SpecContext & sr = SpecContext::instance();
        logLevel = sr.iConfig.get()->getLongValue("LogLevel");
        freeConnections = sr.iConfig.get()->getLongValue("MaxConnections");
        bufConnections = freeConnections >> 2;
        idleConnLife = sr.iConfig.get()->getLongValue("idleConnLife");
        uint16_t port = sr.iConfig.get()->getLongValue("ServerPort");
        if (0 == port) {
            sr.iLog.get()->log("e","[%s]: FAIL iConfig.get(ServerPort).",TAG);
            break;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        server_socket = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (server_socket < 0) {
            sr.iLog.get()->log("e","[%s]: FAIL socket(AF_INET, SOCK_STREAM, 0).",TAG);
            break;
        }

        if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            sr.iLog.get()->log("e","[%s]: FAIL bind(server_socket, (struct sockaddr*)&addr.",TAG);
            break;
        }

        /* set Maximum pending connection to 5 */
        if (listen(server_socket, 5) < 0) {
            sr.iLog.get()->log("e","[%s]: FAIL listen(server_socket, 5).",TAG);
            break;
        }

        sr.iLog.get()->log("i","[%s]: now listening on port [%u]",TAG, port);
        socketID.store(server_socket, std::memory_order_release);
        re = true;
    } while (false);
    if (!re && server_socket>=0) {
        close(server_socket);
    }
    return re;
}

void* DefServer::runServThreadLoop(void* arg){
    DefServer* p = reinterpret_cast<DefServer*>(arg);
    p->servThreadLoop();
    return 0;
}


SmartSocket * DefServer::getFreeSocketFromSet() {
    SmartSocket * re = nullptr;
    std::lock_guard<std::mutex> raiiGuard(freeSockets_mutex);
    long long freeCount = setFreeSockets.size();
    if (freeCount>0) {
        std::set<SmartSocket*>::iterator it = setFreeSockets.begin();
        re = *it;
        setWorkSockets.insert(re);
        it = setFreeSockets.erase(it);
        if (freeCount > bufConnections) {
            while (freeCount <= bufConnections) {
                delete (*it);
                it = setFreeSockets.erase(it);
                --freeCount;
                ++freeConnections;
            }
        }
    }
    return re;
}

SmartSocket * DefServer::getFreeSocket() {
    SmartSocket * re = nullptr;
    while (keepRun.load(std::memory_order_acquire)) {
        re = getFreeSocketFromSet();
        if (!re && freeConnections>0) {
            --freeConnections;
            re = new SmartSocket(this, logLevel);
            setWorkSockets.insert(re);
            if (logLevel>1) {
                SpecContext::instance().iLog.get()->
                        log("i","[%s]: getFreeSocket->freeConnections=%lld",TAG, freeConnections);
            }
        }
        if (re) { break;}
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return re;
}

void DefServer::servThreadLoop(){

    int server_socket = socketID.load(std::memory_order_acquire);
    if (server_socket < 0) { return; }

    SpecContext & sr = SpecContext::instance();
    struct timeval tv;
    tv.tv_sec = idleConnLife;       /* Timeout in seconds */

    while (keepRun.load(std::memory_order_acquire)) {
        SmartSocket * pSocket = getFreeSocket();
        if (!pSocket) { break; }
        int client_socket = -1;
        client_socket = accept(server_socket,
                               (struct sockaddr*)&(pSocket->remote_addr),
                               &(pSocket->remote_addr_len));
        if (!keepRun.load(std::memory_order_acquire)) { break; }
        if (client_socket < 0) {
            sr.iLog.get()->log("e","[%s]: FAIL accept(server_socket, (struct sockaddr*)&addr.",TAG);
            sr.sendStopSig();
            break;
        }

        setsockopt(socketID, SOL_SOCKET, SO_SNDTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
        setsockopt(socketID, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
        pSocket->start(socketID);

    } //while

    close(server_socket);
    /* Say to all that server is stopped: */
    socketID.store(-1, std::memory_order_release);

    /* Stop all clients: */
    stopAllSmart();
}

void DefServer::stopAllSmart() {
    if (setWorkSockets.size()>0) {
        std::set<SmartSocket*> ::iterator it = setWorkSockets.begin();
        while(setWorkSockets.end() != it){
            if (0==(*it)->state.load(std::memory_order_acquire)) {
                /* not started, can delete */
                delete (*it);
                it = setWorkSockets.erase(it);
            } else {
                /* must stop threads */
                (*it)->stop();
            }
        }
    }
    /* wait for stop all sockets */
    bool (*checkDelSmart) (void * ptr) = [](void * ptr) {
        DefServer * p = reinterpret_cast<DefServer*>(ptr);
        return p->delFreeSmart();
    };
    SpecContext::instance().iSys.get()->
            waitForSUCCESS(checkDelSmart, this, 100, (idleConnLife)*2000);

}


bool DefServer::delFreeSmart() {
    bool re = false;
    std::lock_guard<std::mutex> raii(freeSockets_mutex);
    if (setFreeSockets.size()>0) {
        std::set<SmartSocket*> ::iterator itFree = setFreeSockets.begin();
        while(setFreeSockets.end() != itFree){
            std::set<SmartSocket*> ::iterator itWork = setWorkSockets.find(*itFree);
            if (setWorkSockets.end() != itWork) {
                setWorkSockets.erase(itWork);
            }
            delete (*itFree);
            itFree = setFreeSockets.erase(itFree);
        }
        re = setWorkSockets.size()>0;
    }
    return re;
}


void  DefServer::smartSocketDown(void * ptr)  {
    std::lock_guard<std::mutex> raiiGuard(freeSockets_mutex);
    setFreeSockets.insert((SmartSocket*)ptr);
}



