/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include "epolsocket.h"
#include "spec/speccontext.h"

bool EpolSocket::failSetCurX509(SpecSSL * specSSL, const void *buf, int num) {
    if (x509) {
        X509_free(x509);
        x509= nullptr;
    }

    if (evpX509) {
        EVP_PKEY_free(evpX509);
        evpX509 = nullptr;
    }

    if ((x509 = specSSL->getX509(buf, num))) {
        if ((evpX509 = specSSL->getX509evp(x509))) {
            return false;
        }
    }
    return true;
} //failSetCurX509

void  EpolSocket::clearOnStart()  {
  authed_groupID  =  0;
  authed_avatarID  =  0;
  connectState  =  0;
  connectedGroup  =  0;
  lastActTime  =  0;

  msgs_to_receive  =  2; // type1 + type11
  msgs_to_send  =  0;
  groups_count  =  0;

  readHeaderPending  =  0;
  readLenLeft  =  0;
  readCur  =  nullptr;

  writeHeaderPending   =   0;
  writeLenLeft  =  0;
  writeCur  =  nullptr;

    if (writePacket) {      
         delete(writePacket);      
         writePacket = nullptr;
    }
    if (readPacket) {      
         delete(readPacket);
         readPacket = nullptr;
    }

    SpecStack<IPack> tmpStack;
    IPack * p;
    tmpStack.swap(readStack.getStack());
    while ((p = tmpStack.pop()) ) {
//#ifdef Debug
//    SpecContext::instance().iLog.get()->log("i","[EpolSocket::clearOnStart::readStack]: delete IPack:%llu", p);
//#endif
        delete p;
    }
    tmpStack.swap(writeStack.getStack());
    while ((p = tmpStack.pop()) ) {
//#ifdef Debug
//    SpecContext::instance().iLog.get()->log("i","[EpolSocket::clearOnStart::writeStack]: delete IPack:%llu", p);
//#endif
        delete p;
    }
    while ((p = writeStackServer.pop()) ) {
        delete p;      
    }

    keepRun.store(true, std::memory_order_release);
}//clearOnStart



