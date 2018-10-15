#include <iostream>
#include "i/ilibclass.h"

#include <memory>
#if defined(Linux)
    #include "depend/system/linux/linuxsystem.h"
#elif defined(Windows)
    #include "depend/system/windows/windowssystem.h"
#endif
#include "depend/file/old/cfileadapter.h"
#include "depend/tools/memory/calloc.h"
#include <ctime>
#include <thread>
#include <map>
#include "i/ipack.h"
#include "spec/specstatic.h"
#include "testsql.h"
#include "testssl.h"
#include <time.h>


CAlloc iAlloc;

char * outPack = nullptr;
#define SSL_CLI_ERROR  -1
#define SSL_CLI_NOTHING  0
#define SSL_CLI_CONNECTED  1
#define SSL_CLI_READED  2
#define SSL_CLI_WRITED  3

#define IDLE_MAX_SEC  50
std::shared_ptr <ISystem> iSystem;
std::shared_ptr <IFileAdapter> iFileAdapter;

char pathFull[SMAX_PATH];
char * pathSuffix;
char * pathEnd;

TestSSL * libSSL = nullptr;
TestSQL * libSQL = nullptr;

long long curGroupID = 0;
long long curAvatarID = 0;

int waitForJobResult(){
    time_t lastActTime = std::time(nullptr);
    int res = SSL_CLI_ERROR;
    while ((std::time(nullptr) - lastActTime)<=IDLE_MAX_SEC){
        res=libSSL->getJobResults();
        if (SSL_CLI_ERROR==res ||
                res >= SSL_CLI_READED
              ) { break; }
    }//while
    return res;
}

long long getCurJavaTime() {
    struct timespec timeout;
    clock_gettime(0, &timeout);
    return (long long)((timeout.tv_sec) * 1000LL + timeout.tv_nsec/1000000);
}

bool generateMessage(){
    long long id_msg = libSSL->getGUID09();
    long long date = getCurJavaTime();
    char data[1024];
    char * end  = data + 1023;
    char * cur  = printULong(id_msg, data, end);
    cur = printString(" at ", cur, end);
    cur  = printULong(date, cur, end);
    cur = printString(": my message and some data: bla bla bla ", cur, end);
    return libSQL->storeMessage(curGroupID, 0, curAvatarID, id_msg, date, data, cur-data);

}

/* There is no client certificate on the server. It is necessary to send. */
int doType2(char * answ) {
    int re = -1;
    T_IPack1_struct res;

    if (IPack1::parsePackI(res, answ)) {        
        char * cur = printString("tests/assets/avtr/x509/", pathSuffix, pathEnd);
        cur = printULong(res.groupID, cur, pathEnd);
        *cur='/';++cur;
        cur = printULong(res.avatarID, cur, pathEnd);
        const std::string &cert = iFileAdapter.get()->loadFileF(pathFull);
        if (!cert.empty()) {
            T_IPack3_struct toSend;
            toSend.str = cert.c_str();
            toSend.strLen = cert.length();
            toSend.guid1 = res.groupID;
            toSend.guid2 = res.avatarID;
            char * pack =IPack3::createPacket(&iAlloc, toSend, SPEC_PACK_TYPE_3);
            if (pack && libSSL->putPackToSend(pack)) {
                re = 1;
            }
        }
    }

    return re;
}



int doType4(char * answ) {
    int re = -1;
    T_IPack3_struct res;

    if (IPack3::parsePackI(res, answ)) {
        if (0==res.strLen) {
            //No such group on server, go next group
            re = 0;
        } else {
            //faux loop
            do {
                char * cur = printString("tests/assets/avtr/pkey/", pathSuffix, pathEnd);
                cur = printULong(res.guid1, cur, pathEnd);
                *cur='/';++cur;
                cur = printULong(res.guid2, cur, pathEnd);
                const std::string &pkey = iFileAdapter.get()->loadFileF(pathFull);
                if(!libSSL->setPKEY(pkey.c_str(),pkey.length())) { break; }
                cur = printString("tests/assets/avtr/x509/", pathSuffix, pathEnd);
                cur = printULong(res.guid1, cur, pathEnd);
                *cur='/';++cur;
                cur = printULong(res.guid2, cur, pathEnd);
                const std::string &x509 = iFileAdapter.get()->loadFileF(pathFull);
                if(!libSSL->setX509(x509.c_str(),x509.length())) { break; }

                char signBuf[2048];
                int signLen = 2048;
                if (!libSSL->sign_it(res.str, res.strLen, signBuf, &signLen)) { break; }
                if (!libSSL->checkAvaSign(res.str, res.strLen, signBuf, signLen) ) { break;}
                res.str = signBuf;
                res.strLen = signLen;
                /* You must inform the server of the valid message creation time range. */
                res.guid1 = 5; // days for group chat
                res.guid2 = 365; // days for personal messages
                char * pack =IPack3::createPacket(&iAlloc, res, SPEC_PACK_TYPE_5);
                if (pack && libSSL->putPackToSend(pack)) {
                    re = 1;
                }

            } while (false);
        }
    }
    return re;
}

bool sendMyType6(){
    bool re = false;
    /* All fine, need to send email list */
    uint64_t msgIDs[MAX_SelectRows];
    uint64_t msgDates[MAX_SelectRows];
    uint32_t resRows;
    if (libSQL->getNewMessages(curGroupID, msgIDs, msgDates, &resRows)) {
        /* Pack and send data */
        char * pack =  IPack6::createPacket(&iAlloc,
                                       resRows,
                                       curGroupID,
                                       msgIDs,
                                       msgDates,
                                       SPEC_PACK_TYPE_6);
        if (pack) {
            re = libSSL->putPackToSend(pack);
        }
    }
    return re;
}

int doType6(char * answ) {
    int re = -1;
    T_IPack6_struct inPacket6;
    //faux loop
    do {
        if (!IPack6::parsePackI(inPacket6, answ)
                || curGroupID!=*(inPacket6.groupID)) {break;}
        if (inPacket6.lenArray>0) {
            /* check if i need that mail */
            // We need only messages which i have not
            uint64_t msgIDsNEED[MAX_SelectRows];
            uint64_t msgDatesNEED[MAX_SelectRows];
            uint32_t resRowsNEED;
            uint64_t msgIDsNotNEED[MAX_SelectRows];
            uint64_t msgDatesNotNEED[MAX_SelectRows];
            uint32_t resRowsNotNEED;
            if (libSQL->getNeedMessages(curGroupID, inPacket6.guid1s, inPacket6.guid2s, inPacket6.lenArray,
                                    msgIDsNEED, msgDatesNEED, &resRowsNEED,
                                    msgIDsNotNEED, msgDatesNotNEED, &resRowsNotNEED)) {
                if (resRowsNEED > 0) {
                /* Pack and send data */
                    char * pack =  IPack6::createPacket(&iAlloc,
                                               resRowsNEED,
                                               curGroupID,
                                               msgIDsNEED,
                                               msgDatesNEED,
                                               SPEC_PACK_TYPE_7);
                    if (!pack) {break;}
                    if (!libSSL->putPackToSend(pack)) {break;}
                }
                if (resRowsNotNEED > 0) {
                /* Pack and send data */
                    char * pack =  IPack6::createPacket(&iAlloc,
                                               resRowsNotNEED,
                                               curGroupID,
                                               msgIDsNotNEED,
                                               msgDatesNotNEED,
                                               SPEC_PACK_TYPE_8);
                    if (!pack) {break;}
                    if (!libSSL->putPackToSend(pack)) {break;}
                }
            }
        }

        /* generate new mail */
        if (!generateMessage()) { break;}

        /* send my new mail */
        if (!sendMyType6()) { break;}

        std::this_thread::yield();

        re = 1;
    } while(false);
    return re;
}

int doType7(char * answ) {
    int re = -1;
    T_IPack6_struct inPacket7;
    //faux loop
    do {
        if (!IPack6::parsePackI(inPacket7, answ)
                || curGroupID!=*(inPacket7.groupID)) {break;}
        if (inPacket7.lenArray>0) {
            /* send msg-s */
            for (uint32_t i = 0 ; i<inPacket7.lenArray; ++i){
                char * pack = libSQL->getMsgType9(curGroupID, inPacket7.guid1s[i], inPacket7.guid2s[i]);
                if (pack) {
                    if (!libSSL->putPackToSend(pack)) { break; }
                }
            }
        }//if (inPacket7

        std::this_thread::yield();

        re = 1;
    } while(false);
    return re;
}

int doType8(char * answ) {
    int re = -1;
    T_IPack6_struct inPacket8;
    //faux loop
    do {
        if (!IPack6::parsePackI(inPacket8, answ)
                || curGroupID!=*(inPacket8.groupID)) {break;}
        if (inPacket8.lenArray>0) {
            /* store unwanded */
            if (!libSQL->storeNotNeedArray(curGroupID,
                                           inPacket8.guid1s, inPacket8.guid2s, inPacket8.lenArray)){ break;}
        }//if (inPacket8

        std::this_thread::yield();

        re = 1;
    } while(false);
    return re;
}

//The server and client sends a requested mail:
//Need to save incoming mail:
int doType9(char * answ) {
    int re = -1;
    T_IPack9_struct inPacket9;
    //faux loop
    do {
        if (!IPack9::parsePackI(inPacket9, answ)
                || curGroupID!=inPacket9.guid1) {break;}
        if (inPacket9.strLen>0) {
            /* store Msg */
            if (libSQL->storeMessage(curGroupID, inPacket9.guid4, inPacket9.guid5,
                                      inPacket9.guid2, inPacket9.guid3, inPacket9.str, inPacket9.strLen)) {
                //Send confirmation
                inPacket9.strLen = 0;
                char * pack = IPack9::createPacket(&iAlloc, inPacket9, SPEC_PACK_TYPE_10);
                if (pack) {
                    if (!libSSL->putPackToSend(pack)) { break; }
                }
            } else { break;}
        }//if (inPacket9

        std::this_thread::yield();

        re = 1;
    } while(false);
    return re;
}//doType9


int doType10(char * answ) {
    int re = -1;
    T_IPack9_struct inPacket9;
    //faux loop
    do {
        if (!IPack9::parsePackI(inPacket9, answ)
                || curGroupID!=inPacket9.guid1) {break;}
        if (!libSQL->storeNotNeed(curGroupID, inPacket9.guid2, inPacket9.guid3)) {break;}

        std::this_thread::yield();

        re = 1;
    } while(false);
    return re;
}//doType10

int parsePack() {
    int re = 0;
    char * answ = libSSL->readPack();
    uint32_t type = IPack0::getTypeIn(answ);
    switch (type) {
    case 2:
        //The server  requests unknown certificate X509
        re =doType2(answ);
        break;
    case 4:
        //The server sends a test cryptographic task
        re =doType4(answ);
        break;
    case 6:
        //The server sends OK == list of messages
        re =doType6(answ);
        break;
    case 7:
        //The server and client answers with a list of the needed mail :
        re =doType7(answ);
        break;
    case 8:
        //The server and client answers with a list of the unnecessary mail:
        re =doType8(answ);
        break;
    case 9:
        //The server and client sends a requested mail:
        re =doType9(answ);
        break;
    case 10:
        //The server and client sends a delivery confirmation:
        re =doType10(answ);
        break;
    default:
        std::cerr << "[parsePack] Error: type="<<type << std::endl;
        break;
    }
    libSSL->eraseReadPack();
    return re;
}



bool doTest1(){
    /* state machine -1==error, 0==go Auth, 1==do Work*/
    int state = 1;
    int res = SSL_CLI_NOTHING;
    std::map<uint64_t, uint64_t> myMembership;
#if 1==SPEC_CLI_N
    myMembership.insert(std::make_pair(2000000000000000000, 1395809813882527485));
    myMembership.insert(std::make_pair(1891716358585508223, 1848174035979184476));
#elif 2==SPEC_CLI_N
    myMembership.insert(std::make_pair(2000000000000000000, 1395809813882527485));
    myMembership.insert(std::make_pair(1891716358585508223, 1848174035979184476));
#else
    myMembership.insert(std::make_pair(2000000000000000000, 1395809813882527485));
    myMembership.insert(std::make_pair(1891716358585508223, 1848174035979184476));
#endif
//с помощью CMake сгенерируй 3-х разных тестовых клиентов из однго исходника
//пусть у каждого будут свои подкаталоги с базами сообщений

    time_t lastActTime = std::time(nullptr);
    for (auto it : myMembership) {
        curGroupID = it.first;
        curAvatarID = it.second;
        char * iPack1 = IPack1::createPacket(&iAlloc, curGroupID, curAvatarID, SPEC_PACK_TYPE_1);
        /* Send my membership */
        if (!libSSL->putPackToSend(iPack1)) { break;}
        state = 1;
        while (state>0 && (std::time(nullptr) - lastActTime)<=IDLE_MAX_SEC){
            res=libSSL->getJobResults();
            //exit(0);
            if (SSL_CLI_READED==res) {
                state = parsePack();
                if (state<1){ break; }
                lastActTime = std::time(nullptr);
            } else if (SSL_CLI_NOTHING==res){
                /* generate new mail */
                if (!generateMessage()) { break;}

                /* send my new mail */
                if (!sendMyType6()) { break;}

                std::this_thread::yield();

            //nothing to do
            //    std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else if (SSL_CLI_ERROR== res) {
                break;
                //keepRun = SSL_CLI_ERROR!= res;
            }
        }//while
        if (state<0){ break; }
    }//for

    return true;

}

void doTests(){
    if (!doTest1()) {
        std::cerr << "[doTests] Error: !doTest1(lib)" << std::endl;
        return;
    }

}



int main()
{
    std::cout << "Hello, world!\n";    
//    std::shared_ptr <ISystem> iSystem =
    #if defined(Linux)
        iSystem = std::make_shared<LinuxSystem>();
    #elif defined(Windows)
        iSystem = std::make_shared<WindowsSystem>();
    #endif
    iFileAdapter = std::make_shared<CFileAdapter>();
    iFileAdapter.get()->setExePath(iSystem.get()->getExePath());

    pathEnd = pathFull + SMAX_PATH -1;
    pathSuffix = printString(iSystem.get()->getExePath().c_str(), pathFull, pathEnd);
    pathSuffix = printString("/", pathSuffix, pathEnd);

    //ILibClass<TestLib> testLibLoader(iSystem, "/home/dbond/workspace3/SpecNetDir/libs/libtestlib.so");
    printString("libs/libtestssl.so", pathSuffix, pathEnd);
    ILibClass<TestSSL> testSSL(iSystem, pathFull);
    printString("libs/libtestsql.so", pathSuffix, pathEnd);
    ILibClass<TestSQL> testSQL(iSystem, pathFull);

    //faux loop
    do {
        if (!testSSL.i) {
            std::cerr<<"ERROR: Can't load libs/libtestssl.so"<<std::endl;
            break;
        }
        if (!testSQL.i) {
            std::cerr<<"ERROR: Can't load libs/libtestsql.so"<<std::endl;
            break;
        }

        char * cur = printString("tests/db", pathSuffix, pathEnd);
        cur = printULong(SPEC_CLI_N, cur, pathEnd);
        if (!testSQL.i->start(&iAlloc, "localhost", pathFull, iFileAdapter.get(), testSSL.i->getGUID09())) {
            std::cerr<<"ERROR: testSQL.i->start()"<<std::endl;
            break;
        }

        if (testSSL.i->sslConnect(&iAlloc, "localhost", "1741", IDLE_MAX_SEC)) {
            std::cout << "Cli connected!!!" << std::endl;
            libSSL = testSSL.i;
            libSQL = testSQL.i;
            doTests();
        }


        testSSL.i->stop();
        testSQL.i->stop();
    } while(false);

}
