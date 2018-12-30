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
        IPack  *pack;
        bool  sockIsOK  =  sock->keepRun.load(std::memory_order_acquire);
        sock->readStackWorker.swap(sock->readStack.getStack());
        while  ((pack  =  sock->readStackWorker.pop())
            && keepRun.load(std::memory_order_acquire)>=0)  {
          if  (sockIsOK)  {
            if  (sock->keepRun.load(std::memory_order_acquire))  {
              sockIsOK  =  eatPack(sock, pack);
            }  else  {
              sockIsOK = false;
            }
          }  else  {
            delete pack;
          }
        }  //  while
        if  (sockIsOK)  {
          iServCallback->returnSocketToWork(sock);
        }  else  {
          iServCallback->returnSocketToFree(sock);
        }
      } else {
        //no sockets to work with, go sleep:
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }//while keepRun
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
  switch  (pack->header.pack_type)  {
  case  SPEC_PACK_TYPE_1:
    //The client sends a one of their membership in the groups:
    re  =  doPack1(sock,  pack);
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
  default:
    delete pack;
    break;
  }
  return re;
}  //  parsePack

//The client sends a one of their membership in the groups, parse it:
bool  EpolWorker::doPack1(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
    T_IPack0_Network  *header  =  &(pack->header);
    //if (MIN_GUID>inPacket1.groupID || MIN_GUID>inPacket1.avatarID) { break;}
    if  (MIN_GUID>header->key1  ||  MIN_GUID>header->key2)  {  break;  }
    if  (specSSL->groupX509exists(header->key1))  {
      sock->groupID  =  header->key1;
      sock->avatarID  =  header->key2;
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
      IPack3::toIPack3(pack,  servPass.c_str(),  servPass.length(),  SPEC_PACK_TYPE_4);
    } else {
      header->pack_type = SPEC_PACK_TYPE_4;
      header->body_len = 0;
      IPack0::toNetwork(*header);
    }
    sock->writeStack.push(pack);
    pack = nullptr;
  } while (false);
  if  (pack)  {
    delete pack;
    return false;
  }
  return true;
} //doPack1

//Client answers with X509, check it:
bool  EpolWorker::doPack3(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
    T_IPack0_Network  *header  =  &(pack->header);
        //if (MIN_GUID>inPacket3.guid1 || MIN_GUID>inPacket3.guid2 || 0==inPacket3.strLen) { break;}
    if  (MIN_GUID>header->key1  ||  MIN_GUID>header->key2)  {  break;  }
    if  (!specSSL->checkX509(header->key1,  header->key2,
        pack->body,  header->body_len))  {
      break;
    }
    if  (sock->failSetCurX509(specSSL,  pack->body,  header->body_len))  {
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
    if  (1!=iFileAdapter->saveTFile(certPath,  pack->body,  header->body_len))  {
      if  (logLevel>0)  {
        iLog->log("e","[EpolSocket::doPack3]: can't save X509 to: %s",  certPath);
      }
      break;
    }

        /* Prepare test */
    const  std::string  &servPass  =  iServCallback->getServPassword();
    IPack3::toIPack3(pack,  servPass.c_str(),  servPass.length(),  SPEC_PACK_TYPE_4);
    sock->writeStack.push(pack);
    pack  =  nullptr;
  }  while  (false);

  if  (pack)  {
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
    T_IPack0_Network  *header  =  &(pack->header);
    if  (0==header->key1  ||  0==header->key2 )  {  break;  }
    const  std::string  &servPass  =  iServCallback->getServPassword();
    if  (!sock->evpX509
        ||  !specSSL->verify_it(servPass.c_str(),  servPass.length(),
            pack->body, header->body_len, sock->evpX509))  {
      break;
    }
    int64_t  curTime  =  getCurJavaTime() ;
    sock->grpMailLife  =  curTime  -  DAY_MILLISEC * header->key1;
    sock->avaMailLife  =  curTime  -  DAY_MILLISEC * header->key2;
    curTime  +=  DAY_MILLISEC;

        /* All fine, need to send email list */
    int64_t msgIDs[MAX_SelectRows];
    int64_t msgDates[MAX_SelectRows];
    uint32_t resRows;
    if  (iDB->getNewMessages(sock->groupID,  sock->avatarID,  curTime,
        sock->grpMailLife,  sock->avaMailLife,  msgIDs,  msgDates,  &resRows))  {
            /* Pack and send data */
      IPack6::toIPack6(pack,
                             resRows,
                             sock->groupID,
                             msgIDs,
                             msgDates,
                             SPEC_PACK_TYPE_6);
      sock->writeStack.push(pack);
      pack = nullptr;
    }
  }  while  (false);
  if  (pack)  {
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
    T_IPack0_Network  *header  =  &(pack->header);
    if  (sock->groupID!=header->key1)  {  break;  }
    T_IPack6_struct  inPacket6;
    if  (!IPack6::parsePackI(inPacket6,  pack))  {  break;  }
    if  (inPacket6.lenArray>0)  {
           // We need only messages which i have not
      int64_t  msgIDsNEED[MAX_SelectRows];
      int64_t  msgDatesNEED[MAX_SelectRows];
      uint32_t  resRowsNEED;
      int64_t  msgIDsNotNEED[MAX_SelectRows];
      int64_t  msgDatesNotNEED[MAX_SelectRows];
      uint32_t resRowsNotNEED;
      if  (!iDB->getNeedMessages(sock->groupID,
          inPacket6.guid1s,  inPacket6.guid2s,  inPacket6.lenArray,
          msgIDsNEED,  msgDatesNEED,  &resRowsNEED,
          msgIDsNotNEED,  msgDatesNotNEED,  &resRowsNotNEED))  {
        break;
      }
      if  (resRowsNEED  >  0)  {
           /* Pack and send data */
        IPack6::toIPack6(pack,
                                resRowsNEED,
                                sock->groupID,
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
        }
        IPack6::toIPack6(pack,
                                resRowsNotNEED,
                                sock->groupID,
                                msgIDsNotNEED,
                                msgDatesNotNEED,
                                SPEC_PACK_TYPE_8);
        sock->writeStack.push(pack);
        pack  =  nullptr;
      }
    } else {
      delete  pack;
      pack  =  nullptr;
    }
  } while (false);
  if  (pack)  {
    delete  pack;
    return  false;
  }
  return true;
}  //  doPack6

bool  EpolWorker::doPack7(EpolSocket  *sock, IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    T_IPack0_Network * header  =  &(pack->header);
    if  (sock->groupID!=header->key1)  {  break;  }
    T_IPack6_struct  inPacket7;
    if  (!IPack6::parsePackI(inPacket7, pack))  {  break;  }
    if  (inPacket7.lenArray>0)  {
            /* send msg-s */
      char pathFull[SMAX_PATH];
      char  *pathEnd  =  pathFull  +  SMAX_PATH  -  1;
      char  *pathSuffix  =  printString(iServCallback->getMessagesPath(),  pathFull,  pathEnd);
      pathSuffix  =  printULong(sock->groupID,  pathSuffix,  pathEnd);
      *pathSuffix  =  '/';  ++pathSuffix;
      T_IPack9_struct  outPacket9;
      outPacket9.guid1  =  sock->groupID;
      for  (uint32_t  i  =  0 ;  i<inPacket7.lenArray;  ++i)  {
        char  *cur  =  printULong(TO12(inPacket7.guid2s[i]),  pathSuffix,  pathEnd);
        *cur  =  '/';  ++cur;
        cur  =  printULong(inPacket7.guid1s[i],  cur,  pathEnd);
        cur  =  printULong(inPacket7.guid2s[i],  cur,  pathEnd);
        const  std::string  &msg  =  iFileAdapter->loadFileF(pathFull);
        if  (msg.empty())  {
          iDB->delMsg(sock->groupID,  inPacket7.guid1s[i],  inPacket7.guid2s[i]);
        }  else  {
          if  (!iDB->getMsg(sock->groupID,  inPacket7.guid1s[i],  inPacket7.guid2s[i],
              &outPacket9.guid4, &outPacket9.guid5))  {
            continue;
          }
          outPacket9.str  =  msg.data();
          outPacket9.strLen  =  msg.size();
          outPacket9.guid2  =  inPacket7.guid1s[i];
          outPacket9.guid3  =  inPacket7.guid2s[i];
          IPack  *p  =  IPack9::createPacket(outPacket9,  SPEC_PACK_TYPE_9);
          sock->writeStack.push(p);
        }  //  if !msg.empty()
      }
    }//if (inPacket7
    delete pack;
    pack = nullptr;
  }  while  (false);
  if  (pack)  {
    delete  pack;
    return false;
  }
  return true;
}  //  doPack7

bool  EpolWorker::doPack8(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    T_IPack0_Network  *header  =  &(pack->header);
    if  (sock->groupID!=header->key1)  {  break;  }
    T_IPack6_struct  inPacket8;
    if  (!IPack6::parsePackI(inPacket8, pack))  {  break;  }
    if  (inPacket8.lenArray>0)  {
            /* store unwanded */
      if  (!iDB->storeNotNeedArray(sock->groupID,
          inPacket8.guid1s, inPacket8.guid2s, inPacket8.lenArray,
          sock->avatarID))  {
        break;
      }
    }//if (inPacket8
    delete pack;
    pack = nullptr;
  } while(false);
  if  (pack)  {
    delete  pack;
    return  false;
  }
  return true;
}  // doPack8

bool  EpolWorker::doPack9(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    T_IPack0_Network  *header  =  &(pack->header);
    if  (sock->groupID!=header->key1)  {  break;  }
    T_IPack9_struct  inPacket9;
    if  (!IPack9::parsePackI(inPacket9, pack))  {  break;  }
    if  (inPacket9.strLen>0)  {
            /* store Msg */
      char  pathFull[SMAX_PATH];
      char  *pathEnd  =  pathFull  +  SMAX_PATH  -  1;
      char  *cur  =  printString(iServCallback->getMessagesPath(),  pathFull,  pathEnd);
      cur  =  printULong(sock->groupID,  cur,  pathEnd);
      *cur  =  '/';  ++cur;
      cur  =  printULong(TO12(inPacket9.guid3),  cur,  pathEnd);
      *cur  =  '/';  ++cur;
      cur  =  printULong(inPacket9.guid2,  cur,  pathEnd);
      cur  =  printULong(inPacket9.guid3,  cur,  pathEnd);
      if  (-2==iFileAdapter->saveTFile(pathFull,  inPacket9.str,  inPacket9.strLen))  {
         break;
      }
      if  (iDB->storeMessage(sock->groupID,
          inPacket9.guid4,  inPacket9.guid5,
          inPacket9.guid2,  inPacket9.guid3))  {
                //Send confirmation
        inPacket9.strLen = 0;
        IPack9::toIPack9(pack,  inPacket9,  SPEC_PACK_TYPE_10);
        sock->writeStack.push(pack);
        pack  =  nullptr;
      } else {  break;  }
    }  //if (inPacket9
  }  while  (false);
  if  (pack)  {
    delete  pack;
    return false;
  }
  return true;
}  //  doPack9

bool  EpolWorker::doPack10(EpolSocket  *sock,  IPack  *pack)  {
    //faux loop
  do  {
        //Check if groupID is same with groupID we work with:
    T_IPack0_Network  *header  =  &(pack->header);
    if  (sock->groupID!=header->key1)  {  break;  }
      T_IPack9_struct  inPacket9;
      if  (!IPack9::parsePackI(inPacket9, pack))  {  break;  }
      if  (!iDB->addPath(inPacket9.guid2,  inPacket9.guid3,
          sock->groupID,  sock->avatarID))  {
        break;
      }
      delete  pack;
      pack  =  nullptr;
  }  while  (false);
  if  (pack)  {
    delete  pack;
    return  false;
  }
  return  true;
}  // doPack10


