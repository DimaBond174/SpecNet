#include "smartsocket.h"
#include "spec/speccontext.h"

#define  BUF_SIZE 2048
#define  MAX_CHANK  204800

SmartSocket::SmartSocket(IServCallback * iServCallback, int logLevel):
        _iServCallback(iServCallback), _logLevel(logLevel){
    remote_addr_len = sizeof(remote_addr);
}

SmartSocket::~SmartSocket() {
    keepRun.store(false, std::memory_order_release);
    if (writeThread.joinable()){
        writeThread.join();
    }
}

void SmartSocket::start(int client_socket) {
    socketID.store(client_socket, std::memory_order_release);
    //TODO cleanup socket for new job
    state.store(1, std::memory_order_release);
    writeThread = std::thread(&SmartSocket::runWriteThreadLoop, this);
}

void SmartSocket::stop() {
    keepRun.store(false, std::memory_order_release);
    writeThreadCond.notify_all();
//    int sID = socketID.load(std::memory_order_acquire);
//    if (sID >= 0) {
//        ::close(sID);
//        socketID.store(-1, std::memory_order_release);
//    }
}

void SmartSocket::logConnection() {
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    SpecContext & sr = SpecContext::instance();
    if (getnameinfo((sockaddr *)&remote_addr, remote_addr_len, hbuf, sizeof(hbuf), sbuf,
                    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        sr.iLog.get()->log("i","[%s]: accept host=%s, serv=%s",TAG, hbuf, sbuf);
    }
}


void* SmartSocket::runWriteThreadLoop(void* arg) {
    SmartSocket* p = reinterpret_cast<SmartSocket*>(arg);
    p->writeThreadLoop();
    return 0;
}

void SmartSocket::onSocketDown(){
    keepRun.store(false, std::memory_order_release);
    writeThreadCond.notify_all();
}

void SmartSocket::onStrReady(){
    writeThreadCond.notify_all();
}

void SmartSocket::writeThreadLoop(){
    if (_logLevel > 0) { logConnection(); }
    SpecContext & sr = SpecContext::instance();
    keepRun.store(sr.keepRun.load(std::memory_order_acquire), std::memory_order_release);


    /* Start TLSSocket */
    sslStaf = sr.iEncrypt.get()->startEncryptSocket(socketID.load(std::memory_order_acquire), this);
//            std::bind(&SmartSocket::onSSLDown, this),
//            std::bind(&SmartSocket::onSSLEmail, this) );

    if (!sslStaf) {
        keepRun.store(false, std::memory_order_release);
        _iServCallback->smartSocketDown(this);
        return;
    }

    /* main loop */
    std::unique_lock<std::mutex> lk(writeThreadMutex);
    while (keepRun.load(std::memory_order_acquire)) {
        bool nothingToDo = true;
        const std::string & json = sslStaf->readStr();
        if (!json.empty()) {
            if (_logLevel > 2) {
                sr.iLog.get()->log("i","[%s]:%s",TAG,json.c_str());
            }
            /* work with json */
            sslStaf->writeStr(json);
        }//if (!json.empty())

        if (nothingToDo) {
            writeThreadCond.wait_for(lk, std::chrono::milliseconds(100)); //Таймаут в 0.1 сек
        }
    }//while

    sr.iEncrypt.get()->delEncryptSocket(sslStaf);
    sslStaf = nullptr;
    _iServCallback->smartSocketDown(this);
    state.store(0, std::memory_order_release);
}




