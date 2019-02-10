/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include "epolworker.h"
#include <time.h>
//#include <chrono>

EpolWorker::EpolWorker(IServCallback  *iServCallback_,  int  logLevel_,
    ILog  *iLog_,  SpecSSL  *specSSL_,  IFileAdapter  *iFileAdapter_,
    Idb  *iDB_)  :  iServCallback(iServCallback_),  logLevel(logLevel_),
      iLog(iLog_),  specSSL(specSSL_),  iFileAdapter(iFileAdapter_),
      iDB(iDB_)  {
}

EpolWorker::~EpolWorker()  {
  if (workThread.joinable())  {
    workThread.join();
  }
}

void  EpolWorker::start()  {
  workThread  =  std::thread(&EpolWorker::runWorkThreadLoop,  this);
}

void  EpolWorker::stop()  {
  keepRun.store(-1,  std::memory_order_release);
}

void  EpolWorker::lazyGoStop()  {
  keepRun.store(0,  std::memory_order_release);
}

void * EpolWorker::runWorkThreadLoop(void  *arg)  {
    //EpolSocket* p = reinterpret_cast<EpolSocket*>(arg);
  EpolWorker  *p  =  static_cast<EpolWorker*>(arg);
  p->workThreadLoop();
  return 0;
}

void  EpolWorker::workThreadLoop()  {
  int  keep  =  1;  
  try  {
    SpecStack<IPack>  readStackWorker;
    IPack  *pack;
    while  ((keep  =  keepRun.load(std::memory_order_acquire))
        >=0)  {
      EpolSocket  *sock  =  stackSockNeedWorker.pop();
      if  (!sock)  {
        if  (keep)  {
          stackSockNeedWorker.swap(iServCallback->getStackSockNeedWorker());
          sock = stackSockNeedWorker.pop();
        } else {
          iServCallback->workerGoneDown(this);
          break;
        }
      }
      if  ( sock )  {
        //doWork
        bool  sockIsOK  =  sock->keepRun.load(std::memory_order_acquire);
        readStackWorker.swap(sock->readStack.getStack());
        while  ((pack  =  readStackWorker.pop())
            && keepRun.load(std::memory_order_acquire)>=0)  {
          if  (sockIsOK)  {
            if  (sock->keepRun.load(std::memory_order_acquire))  {
#ifdef Debug
              uint32_t  pack_type  =  pack->p_body.get()->header.pack_type;
#endif
              sockIsOK  =  eatPack(sock, pack);
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::workThreadLoop]: eatPack(%llu,%llu)[type=%zu]=%d",
              sock, pack, pack_type, sockIsOK);
  }
#endif
            }  else  {
              sockIsOK = false;
            }
          }  else  {            
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::workThreadLoop]: delete IPack:%llu", pack);
  }
#endif
            delete pack;
          }
        }  //  while
        if  (sockIsOK)  {
          iServCallback->returnSocketToWork(sock);
        }  else  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("e","[EpolWorker::workThreadLoop]: NOT sockIsOK returnSocketToFree:%llu", sock);
  }
#endif
          iServCallback->returnSocketToFree(sock);
        }
      } else {
        //no sockets to work with, go sleep:
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }//while keepRun
    // Delete work tail:
    while ((pack = readStackWorker.pop()) ) {
        delete pack;
    }
  } catch (...) {
        iLog->log("e","[EpolWorker::workThreadLoop]: try{}catch (...).");
  }
  freeResources();
}  //  workThreadLoop

void  EpolWorker::freeResources()  {
  EpolSocket  *sock;
  while  ((sock  =  stackSockNeedWorker.pop()))  {
    iServCallback->returnSocketToWork(sock);
  }
}

bool  EpolWorker::eatPack(EpolSocket  *sock,  IPack  *pack)  {
  bool  re  =  false;
  switch  (pack->p_body.get()->header.pack_type)  {
  case  SPEC_PACK_TYPE_1:
    //The client sends a one of their membership in the groups:
    re  =  doPack1(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_2:
    //The client asks for X509:
    re  =  doPack2(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_3:
    //The client sends certificates:
    re  =  doPack3(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_5:
    //The client sends answer for the test cryptographic task:
    re  =  doPack5(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_6:
    //The client sends list of the new mail too:
    re  =  doPack6(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_7:
    //The server and client answers with a list of the needed mail :
    re  =  doPack7(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_8:
    //The server and client answers with a list of the unnecessary mail:
    re  =  doPack8(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_9:
    //The server and client sends a requested mail (messages here):
    re  =  doPack9(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_10:
    //The server and client sends a delivery confirmation:
    re  =  doPack10(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_12:
    //Ask for avatar personal information, picture:
    re  =  doPack12(sock,  pack);
    break;
  case  SPEC_PACK_TYPE_13:
    //Avatar personal information, picture:
    re  =  doPack13(sock,  pack);
    break;
  default:
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::eatPack]: delete IPack:%llu", pack);
  }
#endif
    delete pack;
    break;
  }
  return re;
}  //  parsePack

//The client sends a one of their membership in the groups, parse it:
bool  EpolWorker::doPack1(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network  *header  =  &(b->header);
    //if (MIN_GUID>inPacket1.groupID || MIN_GUID>inPacket1.avatarID) { break;}
    if  (MIN_GUID>header->key1  ||  MIN_GUID>header->key2)  {  break;  }
    if  (specSSL->groupX509exists(header->key1))  {
      sock->next_groupID  =  header->key1;
      sock->next_avatarID  =  header->key2;
      char  certPath[SMAX_PATH];
      char  *certPathSuffix  =  certPath;
      char  *certPathEnd  =  certPath + SMAX_PATH - 1;
      certPathSuffix  =  printString(iServCallback->getAvaCertsPath(),  certPath,  certPathEnd);
      //certPathSuffix = printULong(inPacket1.groupID, certPathSuffix, certPathEnd);
      certPathSuffix  =  printULong(header->key1,  certPathSuffix,  certPathEnd);
      *certPathSuffix  =  '/';  ++certPathSuffix;
      //certPathSuffix = printULong(inPacket1.avatarID, certPathSuffix, certPathEnd);
      certPathSuffix  =  printULong(header->key2,  certPathSuffix,  certPathEnd);
      const  std::string  &x509str  =  iFileAdapter->loadFileF(certPath);

      /*  Check if ava picture exists: */
      certPathSuffix  =  printString(iServCallback->getAvaPicPath(),  certPath,  certPathEnd);
      //certPathSuffix = printULong(inPacket1.groupID, certPathSuffix, certPathEnd);
      certPathSuffix  =  printULong(header->key1,  certPathSuffix,  certPathEnd);
      *certPathSuffix  =  '/';  ++certPathSuffix;
      //certPathSuffix = printULong(inPacket1.avatarID, certPathSuffix, certPathEnd);
      certPathSuffix  =  printULong(header->key2,  certPathSuffix,  certPathEnd);
      if  (!iFileAdapter->file_exists(certPath))  {
        iLog->log("i","[EpolWorker::doPack1]: will send Pack11: no file:%s", certPath);
        sock->writeStack.push(IPack1::createPacket(header->key1,
            header->key2,  SPEC_PACK_TYPE_12));
      }

      if  (x509str.empty())  {
        /* Ask for cert */
        header->pack_type  =  SPEC_PACK_TYPE_2;
        IPack0::toNetwork(*header);
        sock->writeStack.push(pack);
        pack = nullptr;
        break;
      } else if (sock->failSetCurX509(specSSL,
          x509str.c_str(),  x509str.length()))  {
        break;
      }
      /* Prepare test */
      const  std::string  &servPass  =  iServCallback->getServPassword();
      IPack3::toIPack3(b,  servPass.c_str(),  servPass.length(),  SPEC_PACK_TYPE_4);
      sock->writeStack.push(pack);
      pack = nullptr;

    } else {
      header->pack_type = SPEC_PACK_TYPE_4;
      header->body_len = 0;
      IPack0::toNetwork(*header);
      sock->writeStack.push(pack);
      pack = nullptr;
    }

  } while (false);
  if  (pack)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack1]: delete IPack:%llu", pack);
  }
#endif
    delete pack;
    return false;
  }
  return true;
} //doPack1

//Client asks for uknown cert X509:
bool  EpolWorker::doPack2(EpolSocket  *sock,  IPack  *pack)  {
  IPackBody * b  =  pack->p_body.get();
  T_IPack0_Network  *header  =  &(b->header);
  char  certPath[SMAX_PATH];
  char  *certPathSuffix  =  certPath;
  char  *certPathEnd  =  certPath + SMAX_PATH - 1;
  certPathSuffix  =  printString(iServCallback->getAvaCertsPath(),  certPath,  certPathEnd);
  certPathSuffix  =  printULong(header->key1,  certPathSuffix,  certPathEnd);
  *certPathSuffix  =  '/';  ++certPathSuffix;
  certPathSuffix  =  printULong(header->key2,  certPathSuffix,  certPathEnd);
  const std::string &cert = iFileAdapter->loadFileF(certPath);
  if (cert.empty()) {
    delete  pack;
  }  else {
    IPack3::toIPack3(b,  cert.c_str(),  cert.length(),  SPEC_PACK_TYPE_3);
    sock->writeStack.push(pack);
  }
  //TODO send ava personal info also
  return  true;
}  //  doPack2

//Client answers with X509, check it:
bool  EpolWorker::doPack3(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network  *header  =  &(b->header);
        //if (MIN_GUID>inPacket3.guid1 || MIN_GUID>inPacket3.guid2 || 0==inPacket3.strLen) { break;}
    if  (MIN_GUID>header->key1  ||  MIN_GUID>header->key2)  {  break;  }
    if  (!specSSL->checkX509(header->key1,  header->key2,
        b->body,  header->body_len))  {
      break;
    }
    if  (sock->failSetCurX509(specSSL,  b->body,  header->body_len))  {
      break;
    }
        /* All fine, need to save */
    char  certPath[SMAX_PATH];
    char  *certPathSuffix  =  certPath;
    char  *certPathEnd  =  certPath + SMAX_PATH - 1;
    certPathSuffix  =  printString(iServCallback->getAvaCertsPath(),  certPath,  certPathEnd);
    certPathSuffix  =  printULong(header->key1,  certPathSuffix,  certPathEnd);
    *certPathSuffix  =  '/';  ++certPathSuffix;
    certPathSuffix  =  printULong(header->key2,  certPathSuffix,  certPathEnd);
    if  (1!=iFileAdapter->saveTFile(certPath,  b->body,  header->body_len))  {
      if  (logLevel>0)  {
        iLog->log("e","[EpolSocket::doPack3]: can't save X509 to: %s",  certPath);
      }
      break;
    }

        /* Prepare test */
    const  std::string  &servPass  =  iServCallback->getServPassword();
    IPack3::toIPack3(b,  servPass.c_str(),  servPass.length(),  SPEC_PACK_TYPE_4);
    sock->writeStack.push(pack);
    pack  =  nullptr;
  }  while  (false);

  if  (pack)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack3]: delete IPack:%llu", pack);
  }
#endif
    delete  pack;
    return  false;
  }
  return  true;
}  //  doPack3

int64_t  EpolWorker::getCurJavaTime()  {
  struct  timespec  timeout;
  clock_gettime(0,  &timeout);
  return static_cast<int64_t>((timeout.tv_sec) * 1000LL  +  timeout.tv_nsec/1000000);
  //return (int64_t)((timeout.tv_sec) * 1000LL + timeout.tv_nsec/1000000);
    //code above twice faster than
//    return std::chrono::duration_cast< std::chrono::milliseconds >(
//    std::chrono::system_clock::now().time_since_epoch()).count();
}

bool  EpolWorker::doPack5(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network  *header  =  &(b->header);
    if  (0==header->key1  ||  0==header->key2 )  {  break;  }
    const  std::string  &servPass  =  iServCallback->getServPassword();
    if  (!sock->evpX509
        ||  !specSSL->verify_it(servPass.c_str(),  servPass.length(),
            b->body, header->body_len, sock->evpX509))  {
      break;
    }
    //  Passed encrypt test, next_avatarID became current:
    sock->authed_groupID  =  sock->next_groupID;
    sock->authed_avatarID  =  sock->next_avatarID;
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack5]: authed_groupID:%lld, next_avatarID:%lld",
              sock->authed_groupID, sock->authed_avatarID);
  }
#endif
    int64_t  curTime  =  getCurJavaTime() ;
    int64_t  grpMailLife  =  curTime  -  DAY_MILLISEC * header->key1;
    int64_t  avaMailLife  =  curTime  -  DAY_MILLISEC * header->key2;
    curTime  +=  DAY_MILLISEC;

        /* All fine, need to send email list */
    int64_t  msgIDs[MAX_SelectRows];
    int64_t  msgDates[MAX_SelectRows];
    uint32_t  resRows;
    if  (iDB->getNewMessages(sock->authed_groupID,  sock->authed_avatarID,  curTime,
        grpMailLife,  avaMailLife,  msgIDs,  msgDates,  &resRows))  {
            /* Pack and send data */
      IPack6::toIPack6(b,
                             resRows,
                             sock->authed_groupID,
                             msgIDs,
                             msgDates,
                             SPEC_PACK_TYPE_6);
      sock->writeStack.push(pack);
      pack = nullptr;
    }
  }  while  (false);
  if  (pack)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack5]: delete IPack:%llu", pack);
  }
#endif
    delete  pack;
    return false;
  }
  return true;
}//doPack5

//The list of the new mail from client:
bool  EpolWorker::doPack6(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network  *header  =  &(b->header);
    if  (sock->authed_groupID!=header->key1)  {  break;  }
    T_IPack6_struct  inPacket6;
    if  (!IPack6::parsePackI(inPacket6,  b))  {  break;  }
    if  (inPacket6.lenArray>0)  {
           // We need only messages which i have not
      int64_t  msgIDsNEED[MAX_SelectRows];
      int64_t  msgDatesNEED[MAX_SelectRows];
      uint32_t  resRowsNEED;
      int64_t  msgIDsNotNEED[MAX_SelectRows];
      int64_t  msgDatesNotNEED[MAX_SelectRows];
      uint32_t resRowsNotNEED;
      if  (!iDB->getNeedMessages(sock->authed_groupID,
          inPacket6.guid1s,  inPacket6.guid2s,  inPacket6.lenArray,
          msgIDsNEED,  msgDatesNEED,  &resRowsNEED,
          msgIDsNotNEED,  msgDatesNotNEED,  &resRowsNotNEED))  {
        break;
      }
      if  (resRowsNEED  >  0)  {
           /* Pack and send data */
        IPack6::toIPack6(b,
                                resRowsNEED,
                                sock->authed_groupID,
                                msgIDsNEED,
                                msgDatesNEED,
                                SPEC_PACK_TYPE_7);
        sock->writeStack.push(pack);
        pack  =  nullptr;
      }
      if  (resRowsNotNEED  >  0)  {
           /* Pack and send data */
        if  (!pack)  {
          pack  =  new  IPack();
          b  =  pack->p_body.get();
        }
        IPack6::toIPack6(b,
                                resRowsNotNEED,
                                sock->authed_groupID,
                                msgIDsNotNEED,
                                msgDatesNotNEED,
                                SPEC_PACK_TYPE_8);
        sock->writeStack.push(pack);
        pack  =  nullptr;
      }
    } else {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack6]: delete IPack:%llu", pack);
  }
#endif
      delete  pack;
      pack  =  nullptr;
    }
  } while (false);
  if  (pack)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack6]: delete IPack:%llu", pack);
  }
#endif
    delete  pack;
    return  false;
  }
  return true;
}  //  doPack6

bool  EpolWorker::doPack7(EpolSocket  *sock, IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network * header  =  &(b->header);
    if  (sock->authed_groupID!=header->key1)  {  break;  }
    T_IPack6_struct  inPacket7;
    if  (!IPack6::parsePackI(inPacket7, b))  {  break;  }
    if  (inPacket7.lenArray>0)  {
            /* send msg-s */
      char pathFull[SMAX_PATH];
      char  *pathEnd  =  pathFull  +  SMAX_PATH  -  1;
      char  *pathSuffix  =  printString(iServCallback->getMessagesPath(),  pathFull,  pathEnd);
      pathSuffix  =  printULong(sock->authed_groupID,  pathSuffix,  pathEnd);
      *pathSuffix  =  '/';  ++pathSuffix;
      T_IPack9_struct  outPacket9;
      outPacket9.guid1  =  sock->authed_groupID;
      for  (uint32_t  i  =  0 ;  i<inPacket7.lenArray;  ++i)  {
        if  (0==inPacket7.guid1s[i])  {
          continue;
        }
        char  *cur  =  printULong(TO12(inPacket7.guid2s[i]),  pathSuffix,  pathEnd);
        *cur  =  '/';  ++cur;
        cur  =  printULong(inPacket7.guid1s[i],  cur,  pathEnd);
        cur  =  printULong(inPacket7.guid2s[i],  cur,  pathEnd);
        const  std::string  &msg  =  iFileAdapter->loadFileF(pathFull);
        if  (msg.empty())  {
          iDB->delMsg(sock->authed_groupID,  inPacket7.guid1s[i],  inPacket7.guid2s[i]);
        }  else  {
          if  (!iDB->getMsg(sock->authed_groupID,  inPacket7.guid1s[i],  inPacket7.guid2s[i],
              &outPacket9.guid4, &outPacket9.guid5))  {
            continue;
          }
          outPacket9.str  =  msg.data();
          outPacket9.strLen  =  msg.size();
          outPacket9.guid2  =  inPacket7.guid1s[i];
          outPacket9.guid3  =  inPacket7.guid2s[i];
          IPack  *p  =  IPack9::createPacket(outPacket9,  SPEC_PACK_TYPE_9);
          sock->writeStack.push(p);
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack7]: sended %llu:%llu,%llu",
              outPacket9.guid1, outPacket9.guid2, outPacket9.guid3);
  }
#endif
        }  //  if !msg.empty()
      }
    }//if (inPacket7
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack7]: delete IPack:%llu", pack);
  }
#endif
    delete pack;
    pack = nullptr;
  }  while  (false);
  if  (pack)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack7]: delete IPack:%llu", pack);
  }
#endif
    delete  pack;
    return false;
  }
  return true;
}  //  doPack7

bool  EpolWorker::doPack8(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network  *header  =  &(b->header);
    if  (sock->authed_groupID!=header->key1)  {  break;  }
    T_IPack6_struct  inPacket8;
    if  (!IPack6::parsePackI(inPacket8, b))  {  break;  }
    if  (inPacket8.lenArray>0)  {
            /* store unwanded */
      if  (!iDB->storeNotNeedArray(sock->authed_groupID,
          inPacket8.guid1s, inPacket8.guid2s, inPacket8.lenArray,
          sock->authed_avatarID))  {
        break;
      }
    }//if (inPacket8
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack8]: delete IPack:%llu", pack);
  }
#endif
    delete pack;
    pack = nullptr;
  } while(false);
  if  (pack)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack8]: delete IPack:%llu", pack);
  }
#endif
    delete  pack;
    return  false;
  }
  return true;
}  // doPack8

bool  EpolWorker::doPack9(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network  *header  =  &(b->header);
    if  (sock->authed_groupID  !=  header->key1)  {  break;  }
    T_IPack9_struct  inPacket9;
    if  (!IPack9::parsePackI(inPacket9, b))  {  break;  }
    if  (inPacket9.strLen>0)  {
            /* store Msg */
      char  pathFull[SMAX_PATH];
      char  *pathEnd  =  pathFull  +  SMAX_PATH  -  1;
      char  *cur  =  printString(iServCallback->getMessagesPath(),  pathFull,  pathEnd);
      cur  =  printULong(sock->authed_groupID,  cur,  pathEnd);
      *cur  =  '/';  ++cur;
      cur  =  printULong(TO12(inPacket9.guid3),  cur,  pathEnd);
      *cur  =  '/';  ++cur;
      cur  =  printULong(inPacket9.guid2,  cur,  pathEnd);
      cur  =  printULong(inPacket9.guid3,  cur,  pathEnd);
      if  (-2==iFileAdapter->saveTFile(pathFull,  inPacket9.str,  inPacket9.strLen))  {
         break;
      }
      if  (iDB->storeMessage(sock->authed_groupID,
          inPacket9.guid4,  inPacket9.guid5,
          inPacket9.guid2,  inPacket9.guid3))  {
                //Send confirmation
        inPacket9.strLen = 0;
        IPack9::toIPack9(b,  inPacket9,  SPEC_PACK_TYPE_10);
        sock->writeStack.push(pack);
        pack  =  nullptr;
      } else {  break;  }
    }  //if (inPacket9
  }  while  (false);
  if  (pack)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack9]: delete IPack:%llu", pack);
  }
#endif
    delete  pack;
    return false;
  }
  return true;
}  //  doPack9

bool  EpolWorker::doPack10(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network  *header  =  &(b->header);
    if  (sock->authed_groupID!=header->key1)  {  break;  }
      T_IPack9_struct  inPacket9;
      if  (!IPack9::parsePackI(inPacket9, b))  {  break;  }
      if  (!iDB->addPath(inPacket9.guid2,  inPacket9.guid3,
          sock->authed_groupID,  sock->authed_avatarID))  {
        break;
      }
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack10]: delete IPack:%llu", pack);
  }
#endif
      delete  pack;
      pack  =  nullptr;
  }  while  (false);
  if  (pack)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolWorker::doPack10]: delete IPack:%llu", pack);
  }
#endif
    delete  pack;
    return  false;
  }
  return  true;
}  // doPack10

//Ask for avatar personal information, picture:
bool  EpolWorker::doPack12(EpolSocket  *sock,  IPack  *pack) {
  //faux loop
  do  {
      //Check if groupID is same with groupID we work with:
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network * header  =  &(b->header);
    if  (sock->authed_groupID  !=  header->key1
         || 0 == header->key2)  {  break;  }
    char pathFull[SMAX_PATH];
    char  *pathEnd  =  pathFull  +  SMAX_PATH  -  1;
    char  *pathSuffix  =  printString(iServCallback->getAvaPicPath(),  pathFull,  pathEnd);
    pathSuffix  =  printULong(sock->authed_groupID,  pathSuffix,  pathEnd);
    *pathSuffix  =  '/';  ++pathSuffix;
    pathSuffix  =  printULong(header->key2,  pathSuffix,  pathEnd);
    const  std::string  &msg  =  iFileAdapter->loadFileF(pathFull);
    if (msg.empty()) {
      delete  pack;
      pack = nullptr;
    } else {
      T_IPack9_struct  outPacket9;
      outPacket9.guid1  =  sock->authed_groupID;
      outPacket9.guid2  =  header->key2;
      outPacket9.str  =  msg.data();
      outPacket9.strLen  =  msg.size();
      IPack9::toIPack9(b, outPacket9, SPEC_PACK_TYPE_13);
      sock->writeStack.push(pack);
      pack = nullptr;
    }
  }  while  (false);
  if  (pack)  {
#ifdef Debug
    if  (logLevel>4)  {
      iLog->log("i","[EpolWorker::doPack12]: delete IPack:%llu", pack);
    }
#endif
    delete  pack;
    return false;
  }
  return true;
}  //  doPack12

//Avatar personal information, picture:
bool  EpolWorker::doPack13(EpolSocket  *sock,  IPack  *pack) {
  //faux loop
  do  {
      //Check if groupID is same with groupID we work with:
    IPackBody * b  =  pack->p_body.get();
    T_IPack0_Network  *header  =  &(b->header);
    if  (sock->authed_groupID  !=  header->key1
         && sock->next_groupID  !=  header->key1)  {  break;  }
    T_IPack9_struct  inPacket9;
    if  (!IPack9::parsePackI(inPacket9, b))  {  break;  }
    if  (inPacket9.strLen>0)  {
          /* store Msg */
      char  pathFull[SMAX_PATH];
      char  *pathEnd  =  pathFull  +  SMAX_PATH  -  1;
      char  *cur  =  printString(iServCallback->getAvaPicPath(),  pathFull,  pathEnd);
      cur  =  printULong(header->key1,  cur,  pathEnd);
      *cur  =  '/';  ++cur;
      cur  =  printULong(header->key2,  cur,  pathEnd);
      iFileAdapter->saveTFile(pathFull,  inPacket9.str,  inPacket9.strLen);
    }  //if
    delete  pack;
    pack  =  nullptr;
}  while  (false);
  if  (pack)  {
#ifdef Debug
    if  (logLevel>4)  {
      iLog->log("i","[EpolWorker::doPack9]: delete IPack:%llu", pack);
    }
#endif
    delete  pack;
    return false;
  }
  return true;
}
