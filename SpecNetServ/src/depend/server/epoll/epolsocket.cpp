#include "epolsocket.h"
#include "spec/speccontext.h"

#include "spec/specstatic.h"
#include "i/ipack.h"


EpolSocket::EpolSocket(IServCallback * iServCallback, int logLevel):
        _iServCallback(iServCallback), _logLevel(logLevel){
    //remote_addr_len = sizeof(remote_addr);

}

//EpolSocket::EpolSocket(int logLevel): _logLevel(logLevel){

//}

EpolSocket::~EpolSocket() {

    freeResources();
}

void EpolSocket::start() {


    keepRun.store(true, std::memory_order_release);
    workThread = std::thread(&EpolSocket::runWorkThreadLoop, this);
}

void EpolSocket::stop() {
    keepRun.store(false, std::memory_order_release);
    workThreadCond.notify_all();
}

/* Use only when read thread has stopped */
void EpolSocket::freeResources() {
    if (workThread.joinable()){
        stop();
        std::this_thread::yield();
        workThread.join();
    }
        if (sslStaff) {
            iEncrypt->stopEncryptSocket(sslStaff);
            sslStaff = nullptr;
        }

        freeResourcesLocal();
//        while (readQueue.size()>0) {
//            char * p = readQueue.front();
//            readQueue.pop();
//            iAlloc->specFree(p);
//        }
//        while (writeQueue.size()>0) {
//            char * p = writeQueue.front();
//            writeQueue.pop();
//            iAlloc->specFree(p);
//        }
}

void EpolSocket::freeResourcesLocal() {
    if (_x509) { iEncrypt->freeX509(_x509); _x509= nullptr;}

    if (_evpX509) {
        iEncrypt->freeEVP(_evpX509);
        _evpX509 = nullptr;
    }
    {
        std::lock_guard<std::mutex> raii(readQueueMutex);
        while (readQueue.size()>0) {
            char * p = readQueue.front();
            readQueue.pop();
            iAlloc->specFree(p);
        }
    }
    {
        std::lock_guard<std::mutex> raii(writeQueueMutex);
        while (writeQueue.size()>0) {
            char * p = writeQueue.front();
            writeQueue.pop();
            iAlloc->specFree(p);
        }
    }
}

void* EpolSocket::runWorkThreadLoop(void* arg) {
    EpolSocket* p = reinterpret_cast<EpolSocket*>(arg);
    p->workThreadLoop();
    return 0;
}


void EpolSocket::eatPacket(char * ptr) {
    {
        std::lock_guard<std::mutex> raiiLock(readQueueMutex);
        readQueue.push(ptr);
    }
    workThreadCond.notify_all();
}

char * EpolSocket::getPacket() {
    char * re = nullptr;
    std::lock_guard<std::mutex> raiiLock(writeQueueMutex);    
    if (!writeQueue.empty()) {
        re = writeQueue.front();
        writeQueue.pop();
    }
    return re;
}

void EpolSocket::workThreadLoop(){
    state.store(ESOCK_START_THREAD, std::memory_order_release);

    std::unique_lock<std::mutex> lk(workThreadMutex);
    while (keepRun.load(std::memory_order_acquire)) {
        char * pack = nullptr;
        readQueueMutex.lock();
        if (!readQueue.empty()) {
            pack = readQueue.front();
            readQueue.pop();
        }
        readQueueMutex.unlock();

        if (pack) {
            if (!parsePack(pack)) {
                keepRun.store(false, std::memory_order_release);
            }
            iAlloc->specFree(pack);
        }

        if (!pack && keepRun.load(std::memory_order_acquire)) {
            workThreadCond.wait_for(lk, std::chrono::milliseconds(100)); //Таймаут в 0.1 сек
        }
    }//while

    state.store(ESOCK_FREE0, std::memory_order_release);
}


bool EpolSocket::parsePack(char * ptr) {
    bool re = false;
    uint32_t type = IPack0::getTypeIn(ptr);
    switch (type) {
    case SPEC_PACK_TYPE_1:
        re = doPack1(ptr);
        break;
    case SPEC_PACK_TYPE_3:
        re = doPack3(ptr);
        break;
    case SPEC_PACK_TYPE_5:
        re = doPack5(ptr);
        break;
    case SPEC_PACK_TYPE_6:
        re = doPack6(ptr);
        break;
    case SPEC_PACK_TYPE_7:
        re = doPack7(ptr);
        break;
    case SPEC_PACK_TYPE_8:
        re = doPack8(ptr);
        break;
    case SPEC_PACK_TYPE_9:
        re = doPack9(ptr);
        break;
    case SPEC_PACK_TYPE_10:
        re = doPack10(ptr);
        break;
    default:
        //keepRun.store(false, std::memory_order_release);
        break;
    }
    return re;
} //parsePack




void EpolSocket::writePack(char * ptr){
//    if (ptr) {
        {
            std::lock_guard<std::mutex> raiiGuard(writeQueueMutex);
            writeQueue.push(ptr);
        }
        state.store(ESOCK_WANT_WRITE, std::memory_order_release);
//    } else {
//        keepRun.store(false, std::memory_order_release);
//    }
}

bool EpolSocket::setCurX509(const void *buf, int num) {
    bool re = false;
    //faux loop
    do {        
        if (_x509) { iEncrypt->freeX509(_x509); _x509= nullptr;}

        if (_evpX509) {
            iEncrypt->freeEVP(_evpX509);
            _evpX509 = nullptr;
        }

        _x509 = iEncrypt->getX509(buf, num);
        if (!_x509) { break; }
        _evpX509 = iEncrypt->getX509evp(_x509);
        if (!_evpX509) { break; }
        re = true;
    } while (false);
    return re;
}

bool EpolSocket::doPack1(char * ptr) {
    bool re = false;

    T_IPack1_struct inPacket1;
    //faux loop
    do {
        if (!IPack1::parsePackI(inPacket1 , ptr)) { break;}
        if (MIN_GUID>inPacket1.groupID || MIN_GUID>inPacket1.avatarID) { break;}
        T_IPack3_struct outPacket4;
        groupID = inPacket1.groupID;
        avatarID = inPacket1.avatarID;

        outPacket4.guid1 = inPacket1.groupID;
        outPacket4.guid2 = inPacket1.avatarID;
        /* Answer that we do not serve that group */
        outPacket4.str = nullptr;
        outPacket4.strLen = 0;
        char * tmp = nullptr;
        if (iEncrypt->groupX509exists(inPacket1.groupID)) {
            char certPath[SMAX_PATH];
            char * certPathSuffix = certPath;
            char * certPathEnd = certPath + SMAX_PATH -1;
            certPathSuffix = printString(_iServCallback->getAvaCertsPath(),certPath,certPathEnd);
            certPathSuffix = printULong(inPacket1.groupID, certPathSuffix, certPathEnd);
            *certPathSuffix='/';++certPathSuffix;
            certPathSuffix = printULong(inPacket1.avatarID, certPathSuffix, certPathEnd);
            const std::string & x509str = iFileAdapter->loadFileF(certPath);
            if (x509str.empty()) {
                /* Ask for cert */
                char * pack2 = IPack1::createPacket(iAlloc, inPacket1.groupID, inPacket1.avatarID, SPEC_PACK_TYPE_2);
                writePack(pack2);
            } else if (!setCurX509(x509str.c_str(), x509str.length())) {
                break;
            }
            /* Prepare test */
            const std::string & servPass = _iServCallback->getServPassword();
            outPacket4.str = servPass.c_str();
            outPacket4.strLen = servPass.length();
            /* warn about servPass scope */
            tmp = IPack3::createPacket(iAlloc, outPacket4, SPEC_PACK_TYPE_4);
        } else {
            tmp = IPack3::createPacket(iAlloc, outPacket4, SPEC_PACK_TYPE_4);
        }

        if (tmp) {
            writePack(tmp);
            re = true;
        }
    } while (false);

    return re;
} //doPack1

//The client sends certificates:
bool EpolSocket::doPack3(char * ptr){
    bool re = false;
    T_IPack3_struct inPacket3;
    //faux loop
    do {
        if (!IPack3::parsePackI(inPacket3 , ptr)) { break;}
        if (MIN_GUID>inPacket3.guid1 || MIN_GUID>inPacket3.guid2 || 0==inPacket3.strLen) { break;}
        if (!iEncrypt->checkX509(inPacket3.guid1, inPacket3.guid2,
                                 inPacket3.str, inPacket3.strLen)) {
                        break;
        }

        if (!setCurX509(inPacket3.str, inPacket3.strLen)) {
                        break;
        }

        /* All fine, need to save */
        char certPath[SMAX_PATH];
        char * certPathSuffix = certPath;
        char * certPathEnd = certPath + SMAX_PATH -1;
        certPathSuffix = printString(_iServCallback->getAvaCertsPath(),certPath,certPathEnd);
        certPathSuffix = printULong(inPacket3.guid1, certPathSuffix, certPathEnd);
        *certPathSuffix='/';++certPathSuffix;
        certPathSuffix = printULong(inPacket3.guid2, certPathSuffix, certPathEnd);
        re =1==iFileAdapter->saveTFile(certPath, inPacket3.str, inPacket3.strLen);
        if (_logLevel>0 && !re) {
            iLog->log("e","[EpolSocket::doPack3]: can't save X509 to: %s",
                                 certPath);
        }
    } while (false);

    return re;
}//doPack3

uint64_t EpolSocket::getCurJavaTime() {
    struct timespec timeout;
    clock_gettime(0, &timeout);
    return (uint64_t)((timeout.tv_sec) * 1000LL + timeout.tv_nsec/1000000);
}


//The client sends answer for the test cryptographic task:
bool EpolSocket::doPack5(char * ptr){
    bool re = false;
    T_IPack3_struct inPacket3;
    //faux loop
    do {
        if (!IPack3::parsePackI(inPacket3 , ptr)) { break;}
        if (0==inPacket3.guid1 || 0==inPacket3.guid2 || 0==inPacket3.strLen) { break;}
        const std::string & servPass = _iServCallback->getServPassword();
        if (!_evpX509 || !iEncrypt->verify_it(servPass.c_str(), servPass.length(),
                                    inPacket3.str, inPacket3.strLen, _evpX509)) {
                        break;
        }
        long long curTime = getCurJavaTime() ;
        grpMailLife = curTime - DAY_MILLISEC * inPacket3.guid1;
        avaMailLife = curTime - DAY_MILLISEC * inPacket3.guid2;
        curTime += DAY_MILLISEC;

        /* All fine, need to send email list */
        uint64_t msgIDs[MAX_SelectRows];
        uint64_t msgDates[MAX_SelectRows];
        uint32_t resRows;
        if (iDB->getNewMessages(groupID, avatarID, curTime,
                                grpMailLife, avaMailLife, msgIDs, msgDates, &resRows)) {
            /* Pack and send data */
            char * pack =  IPack6::createPacket(iAlloc,
                                           resRows,
                                           groupID,
                                           msgIDs,
                                           msgDates,
                                           SPEC_PACK_TYPE_6);
            if (pack) {
                writePack(pack);
                re = true;
            }
        }

    } while (false);

    return re;
}//doPack5

//The list of the new mail from client:
//The server answers with a list of the needed mail :
bool EpolSocket::doPack6(char * ptr){
    bool re = false;
    T_IPack6_struct inPacket6;
    //faux loop
    do {
        //Check if groupID is same with groupID we work with:
        if (!IPack6::parsePackI(inPacket6 , ptr)
                ||groupID!=*(inPacket6.groupID)
                ||0==inPacket6.lenArray) { break;}

        // We need only messages which i have not
        uint64_t msgIDsNEED[MAX_SelectRows];
        uint64_t msgDatesNEED[MAX_SelectRows];
        uint32_t resRowsNEED;
        uint64_t msgIDsNotNEED[MAX_SelectRows];
        uint64_t msgDatesNotNEED[MAX_SelectRows];
        uint32_t resRowsNotNEED;
        if (!iDB->getNeedMessages(groupID, inPacket6.guid1s, inPacket6.guid2s, inPacket6.lenArray,
                                msgIDsNEED, msgDatesNEED, &resRowsNEED,
                                    msgIDsNotNEED, msgDatesNotNEED, &resRowsNotNEED)) { break;}
        if (resRowsNEED > 0) {
        /* Pack and send data */
            char * pack =  IPack6::createPacket(iAlloc,
                                       resRowsNEED,
                                       groupID,
                                       msgIDsNEED,
                                       msgDatesNEED,
                                       SPEC_PACK_TYPE_7);
            if (!pack) {break;}
            writePack(pack);
        }
        if (resRowsNotNEED > 0) {
        /* Pack and send data */
            char * pack =  IPack6::createPacket(iAlloc,
                                       resRowsNotNEED,
                                       groupID,
                                       msgIDsNotNEED,
                                       msgDatesNotNEED,
                                       SPEC_PACK_TYPE_8);
            if (!pack) {break;}
            writePack(pack);
        }
        re = true;
    } while (false);

    return re;
}//doPack6

bool EpolSocket::doPack7(char * ptr){
    bool re = false;
    T_IPack6_struct inPacket7;
    //faux loop
    do {
        if (!IPack6::parsePackI(inPacket7, ptr)
                || groupID!=*(inPacket7.groupID)) {break;}
        if (inPacket7.lenArray>0) {
            /* send msg-s */
            char pathFull[SMAX_PATH];
            char * pathEnd = pathFull+SMAX_PATH-1;
            char * pathSuffix = printString(_iServCallback->getMessagesPath(), pathFull, pathEnd);
            pathSuffix = printULong(groupID, pathSuffix, pathEnd);
            *pathSuffix='/'; ++pathSuffix;

            for (uint32_t i = 0 ; i<inPacket7.lenArray; ++i){
                char * cur = printULong(TO12(inPacket7.guid2s[i]), pathSuffix, pathEnd);
                *cur='/'; ++cur;
                cur = printULong(inPacket7.guid1s[i], cur, pathEnd);
                cur = printULong(inPacket7.guid2s[i], cur, pathEnd);
                const std::string &msg = iFileAdapter->loadFileF(pathFull);
                if (msg.empty()) {
                    iDB->delMsg(groupID, inPacket7.guid1s[i], inPacket7.guid2s[i]);
                } else {
                    T_IPack9_struct outPacket9;
                    if (!iDB->getMsg(groupID, inPacket7.guid1s[i], inPacket7.guid2s[i],
                                     &outPacket9.guid4, &outPacket9.guid5)) { continue;}
                    outPacket9.str = msg.data();
                    outPacket9.strLen = msg.size();
                    outPacket9.guid1 = groupID;
                    outPacket9.guid2 = inPacket7.guid1s[i];
                    outPacket9.guid3 = inPacket7.guid2s[i];
                    char * pack = IPack9::createPacket(iAlloc, outPacket9, SPEC_PACK_TYPE_9);
                    if (!pack) {break;}
                    writePack(pack);
                }
            }
        }//if (inPacket7

        re = true;
    } while(false);
    return re;
} //doPack7

bool EpolSocket::doPack8(char * ptr){
    bool re = false;
    T_IPack6_struct inPacket8;
    //faux loop
    do {
        if (!IPack6::parsePackI(inPacket8, ptr)
                || groupID!=*(inPacket8.groupID)) {break;}
        if (inPacket8.lenArray>0) {
            /* store unwanded */
            if (!iDB->storeNotNeedArray(groupID,
                                           inPacket8.guid1s, inPacket8.guid2s, inPacket8.lenArray, avatarID)){ break;}
        }//if (inPacket8

        re = true;
    } while(false);
    return re;
} //doPack8

bool EpolSocket::doPack9(char * ptr){
    bool re = false;
    T_IPack9_struct inPacket9;
    //faux loop
    do {
        if (!IPack9::parsePackI(inPacket9, ptr)
                || groupID!=inPacket9.guid1) {break;}
        if (inPacket9.strLen>0) {
            /* store Msg */
            char pathFull[SMAX_PATH];
            char * pathEnd = pathFull+SMAX_PATH-1;
            char * cur = printString(_iServCallback->getMessagesPath(), pathFull, pathEnd);
            cur = printULong(groupID, cur, pathEnd);
            *cur='/'; ++cur;
            cur = printULong(TO12(inPacket9.guid3), cur, pathEnd);
            *cur='/'; ++cur;
            cur = printULong(inPacket9.guid2, cur, pathEnd);
            cur = printULong(inPacket9.guid3, cur, pathEnd);
            if (-2==iFileAdapter->saveTFile(pathFull,inPacket9.str,inPacket9.strLen)) {break;}
            if (iDB->storeMessage(groupID, inPacket9.guid4, inPacket9.guid5,
                                      inPacket9.guid2, inPacket9.guid3)) {
                //Send confirmation
                inPacket9.strLen = 0;
                char * pack = IPack9::createPacket(iAlloc, inPacket9, SPEC_PACK_TYPE_10);
                if (!pack) {break;}
                writePack(pack);
            } else { break;}
        }//if (inPacket9

        re = true;
    } while(false);
    return re;
} //doPack9

bool EpolSocket::doPack10(char * ptr){
    bool re = false;
    T_IPack9_struct inPacket9;
    //faux loop
    do {
        if (!IPack9::parsePackI(inPacket9, ptr)
                || groupID!=inPacket9.guid1) {break;}
        if (!iDB->addPath(inPacket9.guid2, inPacket9.guid3, groupID, avatarID)) {break;}

        re = true;
    } while(false);
    return re;
} //doPack10

