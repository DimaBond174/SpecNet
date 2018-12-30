/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include <iostream>
#include "i/ilibclass.h"

#include <memory>
#if defined(Linux)
  #include "depend/system/linux/linuxsystem.h"
  #include <signal.h>
  #include <thread>
#elif defined(Windows)
    #include "depend/system/windows/windowssystem.h"
#endif
#include "depend/file/old/cfileadapter.h"

#include <ctime>
#include <thread>
#include <map>
#include "i/ipack.h"
#include "spec/specstatic.h"
#include "testsql.h"
#include "testssl.h"
#include <time.h>


//CAlloc iAlloc;

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

int64_t curGroupID = 0;
int64_t curAvatarID = 0;
bool all_received  =  true;
bool all_sended  =  true;

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


uint64_t getCurJavaTime() {
	int64_t re = std::chrono::duration_cast<std::chrono::milliseconds>
		(std::chrono::system_clock::now().time_since_epoch()).count();
	return re;
}


bool generateMessage(){
    int64_t id_msg = libSSL->getGUID09();
    int64_t date = getCurJavaTime();
    char data[1024];
    char * end  = data + 1023;
    char * cur  = printULong(id_msg, data, end);
    cur = printString(" at ", cur, end);
    cur  = printULong(date, cur, end);
    cur = printString(": my message and some data: bla bla bla ", cur, end);
    return libSQL->storeMessage(curGroupID, 0, curAvatarID, id_msg, date, data, cur-data);

}

/* There is no client certificate on the server. It is necessary to send. */
int doType2(IPack * answ) {
    int re = -1;    

    //if (IPack1::parsePackI(res, answ)) {
        char * cur = printString("tests/assets/avtr/x509/", pathSuffix, pathEnd);
        //cur = printULong(res.groupID, cur, pathEnd);
        cur = printULong(answ->header.key1, cur, pathEnd);
        *cur='/';++cur;
        //cur = printULong(res.avatarID, cur, pathEnd);
        cur = printULong(answ->header.key2, cur, pathEnd);
        const std::string &cert = iFileAdapter.get()->loadFileF(pathFull);
        if (!cert.empty()) {
//            T_IPack3_struct toSend;
//            toSend.str = cert.c_str();
//            toSend.strLen = cert.length();
//            toSend.guid1 = res.groupID;
//            toSend.guid2 = res.avatarID;
//            char * pack =IPack3::createPacket(&iAlloc, toSend, SPEC_PACK_TYPE_3);
//            if (pack && libSSL->putPackToSend(pack)) {
//                re = 1;
//            }
            IPack3::toIPack3(answ,cert.c_str(), cert.length(), SPEC_PACK_TYPE_3);
            if (libSSL->putPackToSend(answ)) {
                re = 1;
            }
            answ = nullptr;
        }
   // }
        if (answ) {
            delete answ;
        }
    return re;
}



int doType4(IPack * answ) {
    int re = -1;
   // T_IPack3_struct res;

   // if (IPack3::parsePackI(res, answ)) {
        //if (0==res.strLen) {
        if (0==answ->header.body_len) {
            //No such group on server, go next group
            re = 0;
        } else {
            //faux loop
            do {
                char * cur = printString("tests/assets/avtr/pkey/", pathSuffix, pathEnd);
                cur = printULong(answ->header.key1, cur, pathEnd);
                *cur='/';++cur;
                cur = printULong(answ->header.key2, cur, pathEnd);
                const std::string &pkey = iFileAdapter.get()->loadFileF(pathFull);
                if(!libSSL->setPKEY(pkey.c_str(),pkey.length())) { break; }
                cur = printString("tests/assets/avtr/x509/", pathSuffix, pathEnd);
                cur = printULong(answ->header.key1, cur, pathEnd);
                *cur='/';++cur;
                cur = printULong(answ->header.key2, cur, pathEnd);
                const std::string &x509 = iFileAdapter.get()->loadFileF(pathFull);
                if(!libSSL->setX509(x509.c_str(),x509.length())) { break; }

                char signBuf[2048];
                int signLen = 2048;
                if (!libSSL->sign_it(answ->body, answ->header.body_len, signBuf, &signLen)) { break; }
                if (!libSSL->checkAvaSign(answ->body, answ->header.body_len, signBuf, signLen) ) { break;}
//                res.str = signBuf;
//                res.strLen = signLen;
//                /* You must inform the server of the valid message creation time range. */
//                res.guid1 = 5; // days for group chat
//                res.guid2 = 365; // days for personal messages
//                char * pack =IPack3::createPacket(&iAlloc, res, SPEC_PACK_TYPE_5);
//                if (pack && libSSL->putPackToSend(pack)) {
//                    re = 1;
//                }
                answ->header.key1 = 5;// days for group chat
                answ->header.key2 = 365; // days for personal messages
                answ->header.key3 = 0;
                IPack3::toIPack3(answ,signBuf, signLen, SPEC_PACK_TYPE_5);
                if (libSSL->putPackToSend(answ)) {
                    re = 1;
                }
                answ = nullptr;
            } while (false);
        }
   // }
    if (answ) { delete answ;}
    return re;
}

bool sendMyType6(){
    bool re = false;
    /* All fine, need to send email list */
    int64_t msgIDs[MAX_SelectRows];
    int64_t msgDates[MAX_SelectRows];
    uint32_t resRows;
    if (libSQL->getNewMessages(curGroupID, msgIDs, msgDates, &resRows)) {
        /* Pack and send data */
        IPack * pack =  IPack6::createPacket(
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

int doType6(IPack * answ) {
    int re = -1;
    //T_IPack6_struct inPacket6;
    //faux loop
    do {
        //Check if groupID is same with groupID we work with:
        T_IPack0_Network * header = &(answ->header);
        if (curGroupID!=header->key1) { break;}
        T_IPack6_struct inPacket6;
        if (!IPack6::parsePackI(inPacket6, answ))  {break;}
        //if (curGroupID!=inPacket6.groupID) {break;}
        if (inPacket6.lenArray>0) {
            /* check if i need that mail */
            // We need only messages which i have not
            int64_t msgIDsNEED[MAX_SelectRows];
            int64_t msgDatesNEED[MAX_SelectRows];
            uint32_t resRowsNEED;
            int64_t msgIDsNotNEED[MAX_SelectRows];
            int64_t msgDatesNotNEED[MAX_SelectRows];
            uint32_t resRowsNotNEED;
            if (libSQL->getNeedMessages(curGroupID, inPacket6.guid1s, inPacket6.guid2s, inPacket6.lenArray,
                                    msgIDsNEED, msgDatesNEED, &resRowsNEED,
                                    msgIDsNotNEED, msgDatesNotNEED, &resRowsNotNEED)) {
                if (resRowsNEED > 0) {
                /* Pack and send data */
//                    char * pack =  IPack6::createPacket(&iAlloc,
//                                               resRowsNEED,
//                                               curGroupID,
//                                               msgIDsNEED,
//                                               msgDatesNEED,
//                                               SPEC_PACK_TYPE_7);
//                    if (!pack) {break;}
//                    if (!libSSL->putPackToSend(pack)) {break;}
                    IPack6::toIPack6(answ,
                                     resRowsNEED,
                                     curGroupID,
                                     msgIDsNEED,
                                     msgDatesNEED,
                                     SPEC_PACK_TYPE_7
                                     );
                     if (!libSSL->putPackToSend(answ)) {
                         answ = nullptr;
                         break;
                     }
                    answ = nullptr;
                }  else  {
                  all_received = true;
                }
                if (resRowsNotNEED > 0) {
                /* Pack and send data */
//                    char * pack =  IPack6::createPacket(&iAlloc,
//                                               resRowsNotNEED,
//                                               curGroupID,
//                                               msgIDsNotNEED,
//                                               msgDatesNotNEED,
//                                               SPEC_PACK_TYPE_8);
//                    if (!pack) {break;}
//                    if (!libSSL->putPackToSend(pack)) {break;}
                    if (!answ) {
                        answ = new IPack();
                    }
                    IPack6::toIPack6(answ,
                                     resRowsNotNEED,
                                     curGroupID,
                                     msgIDsNotNEED,
                                     msgDatesNotNEED,
                                     SPEC_PACK_TYPE_8
                                     );
                    if (!libSSL->putPackToSend(answ)) {
                        answ = nullptr;
                        break;
                    }
                    answ = nullptr;
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
    if (answ) {
        delete answ;
    }
    return re;
}

int  doType7(IPack  *answ)  {
  int  re  =  -1;
    //faux loop
  do  {
    T_IPack0_Network  *header  =  &(answ->header);
    if  (curGroupID!=header->key1)  {  break;  }
    T_IPack6_struct  inPacket7;
    if  (!IPack6::parsePackI(inPacket7, answ))  {  break;  }
        //if (curGroupID!=inPacket7.groupID) {break;}
    if  (inPacket7.lenArray>0)  {
            /* send msg-s */
      for (uint32_t  i  =  0 ;  i<inPacket7.lenArray;  ++i)  {
        IPack  *pack  =  libSQL->getMsgType9(curGroupID,
            inPacket7.guid1s[i],  inPacket7.guid2s[i]);
        if  (pack)  {
          if (!libSSL->putPackToSend(pack)) {  break;  }
          std::this_thread::yield();
        }
      }  //  for
    }  else  {
      all_sended = true;
    }//if (inPacket7
    re = 1;
  } while(false);
  delete answ;
  return re;
}

int doType8(IPack * answ) {
    int re = -1;

    //faux loop
    do {
        T_IPack0_Network * header = &(answ->header);
        if (curGroupID!=header->key1) { break;}
        T_IPack6_struct inPacket8;
        if (!IPack6::parsePackI(inPacket8, answ)) {break;}
        //if (curGroupID!=inPacket8.groupID) {break;}
        if (inPacket8.lenArray>0) {
            /* store unwanded */
            if (!libSQL->storeNotNeedArray(curGroupID,
                                           inPacket8.guid1s, inPacket8.guid2s, inPacket8.lenArray)){ break;}
        }//if (inPacket8

        std::this_thread::yield();

        re = 1;
    } while(false);
    if (answ) { delete answ;}
    return re;
}

//The server and client sends a requested mail:
//Need to save incoming mail:
int doType9(IPack * answ) {
    int re = -1;

    //faux loop
    do {
        T_IPack0_Network * header = &(answ->header);
        if (curGroupID!=header->key1) { break;}
        T_IPack9_struct inPacket9;
        if (!IPack9::parsePackI(inPacket9, answ)) {break;}
        //if (curGroupID!=inPacket9.guids[0]) {break;}
        if (inPacket9.strLen>0) {
            /* store Msg */
            if (libSQL->storeMessage(curGroupID, inPacket9.guid4, inPacket9.guid5,
                                      inPacket9.guid2, inPacket9.guid3, inPacket9.str, inPacket9.strLen)) {
                //Send confirmation

//                inPacket9.strLen = 0;
//                char * pack = IPack9::createPacket(&iAlloc, inPacket9, SPEC_PACK_TYPE_10);
//                if (pack) {
//                    if (!libSSL->putPackToSend(pack)) { break; }
//                }

                inPacket9.strLen = 0;
                IPack9::toIPack9(answ, inPacket9, SPEC_PACK_TYPE_10);
                if (libSSL->putPackToSend(answ)) {
                     re = 1;
                }
                answ = nullptr;
            } else { break;}
        }//if (inPacket9

        std::this_thread::yield();

    } while(false);
    if (answ) { delete answ;}
    return re;
}//doType9


int doType10(IPack * answ) {
    int re = -1;

    //faux loop
    do {
        T_IPack0_Network * header = &(answ->header);
        if (curGroupID!=header->key1) { break;}
        T_IPack9_struct inPacket9;
        if (!IPack9::parsePackI(inPacket9, answ)) {break;}
        //if (curGroupID!=inPacket9.guids[0]) {break;}
        if (!libSQL->storeNotNeed(curGroupID, inPacket9.guid2, inPacket9.guid3)) {break;}

        std::this_thread::yield();

        re = 1;
    } while(false);
    if (answ) { delete answ;}
    return re;
}//doType10

int parsePack() {
    int re = 0;
    IPack * answ = libSSL->readPack();
    //switch  (((T_IPack0_Network *)(answ))->pack_type)  {
    //enshure answ deleted or reused:
    switch  (answ->header.pack_type)  {
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
        re  =  doType6(answ);
        if  (1==re)  {  re = 2;  }
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
        std::cerr << "[parsePack] Error: type" << std::endl;
        delete answ;
        break;
    }    
    //libSSL->eraseReadPack();
    return re;
}



bool  doTest1()  {
    /* state machine -1==error, 0==go next Auth, 1==do Work, 2==authenticated */
  int  state  =  1;
  int  res  =  SSL_CLI_NOTHING;
  std::map<uint64_t,  uint64_t>  myMembership;
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
  time_t  lastActTime  =  std::time(nullptr);
  for  (auto&&  it  :  myMembership)  {
    curGroupID  =  it.first;
    curAvatarID  =  it.second;
    IPack  *pack  =  IPack1::createPacket(curGroupID,  curAvatarID,  SPEC_PACK_TYPE_1);
    //  Send my membership:
    if  (!libSSL->putPackToSend(pack))  {  break;  }
      state  =  1;
      //  generate new mail:
    if  (!generateMessage())  {  break;  }
    bool authenticated = false;
    all_received  =  false;
    all_sended  =  false;
    while  (state>0
        &&  (std::time(nullptr) - lastActTime)<=IDLE_MAX_SEC)  {
      res  =  libSSL->getJobResults();
      if  (SSL_CLI_READED==res)  {
        state  =  parsePack();
        if  (state<1)  {  break;  }
        if  (2==state) {  authenticated=true;  }
        lastActTime = std::time(nullptr);
      }  else if  (SSL_CLI_NOTHING==res)  {
        if  (all_received && all_sended)  {  break;  }

//              if (authenticated)  {
//                /* generate new mail */
//                if (!generateMessage()) { break;}

//                /* send my new mail */
//                if (!sendMyType6()) { break;}
//              }
          //std::this_thread::yield();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      } else if  (SSL_CLI_ERROR== res)  {
        break;
      }
    }//while
    if  (state<0)  {  break;  }
  }//for
  return true;
}

void doTests(){

    if (!doTest1()) {
        std::cerr << "[doTests] Error: !doTest1(lib)" << std::endl;
        return;
    }

}

void setSIGPIPEhandler(){
    sigset_t sigpipe_mask;
    sigemptyset(&sigpipe_mask);
    sigaddset(&sigpipe_mask, SIGPIPE);
    //sigset_t saved_mask;
    //if (pthread_sigmask(SIG_BLOCK, &sigpipe_mask, &saved_mask) == -1) {
    if (pthread_sigmask(SIG_BLOCK, &sigpipe_mask, nullptr) == -1) {
        assert(false);
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
#if defined(Windows)
	pathSuffix = printString("\\", pathSuffix, pathEnd);
	printString("libs\\testssl.dll", pathSuffix, pathEnd);
	ILibClass<TestSSL> testSSL(iSystem, pathFull);
	printString("libs\\testsql.dll", pathSuffix, pathEnd);
	ILibClass<TestSQL> testSQL(iSystem, pathFull);
#else
    pathSuffix = printString("/", pathSuffix, pathEnd);    
    printString("libs/libtestssl.so", pathSuffix, pathEnd);
    ILibClass<TestSSL> testSSL(iSystem, pathFull);
    printString("libs/libtestsql.so", pathSuffix, pathEnd);
    ILibClass<TestSQL> testSQL(iSystem, pathFull);


#endif
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
        if (!testSQL.i->start("localhost", pathFull, iFileAdapter.get(), testSSL.i->getGUID09())) {
            std::cerr<<"ERROR: testSQL.i->start()"<<std::endl;
            break;
        }

        setSIGPIPEhandler();
        //if (testSSL.i->sslConnect(&iAlloc, "localhost", "1741", IDLE_MAX_SEC)) {
        if (testSSL.i->sslConnect("localhost", "1741", IDLE_MAX_SEC)) {
            std::cout << "Cli connected!!!" << std::endl;
            libSSL = testSSL.i;
            libSQL = testSQL.i;
            doTests();
        }


        testSSL.i->stop();
        testSQL.i->stop();
    } while(false);

}
