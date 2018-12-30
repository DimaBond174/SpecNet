#ifndef EpolSocket_H
#define EpolSocket_H

#include <atomic>
#include <sys/epoll.h>
#include <openssl/base.h>
#include "depend/tools/memory/specstack.h"
#include "i/ipack.h"
#include "depend/encrypt/boringssl/specssl.h"

//class EpolSocket : public IStack {
class EpolSocket  {
 public:
  EpolSocket  *nextIStack; //IStack interface (faster than vtable)
  EpolSocket()  {
    _epol_ev.data.ptr = this;
  }

  std::atomic_bool   keepRun  {  true  };
  SpecSafeStack<IPack>  readStack;
  SpecSafeStack<IPack>  writeStack;

//---------------------------------------------------------
//EpolHolder Server's staff:  
  struct  epoll_event  _epol_ev;
  int  _socket_id   =  -1;
  int  sockType   =  CLI_TYPE;
  SSL  *sslStaff  =  nullptr;
  int  connectState  =  0;  //0=not, 1=TCP, 2=SSL, 3=Authenticated
  uint64_t  connectedGroup  =  0;
  time_t  lastActTime  =  0;
  bool  all_received  =  false;
  int32_t msgs_to_receive  =  0;
  bool  all_sended  =  false;
  int32_t msgs_to_send  =  0;


    /* READ expected packet */
  int  readHeaderPending  =  0; // if need continue to read header
  IPack  *readPacket  =  nullptr;
  int  readLenLeft  =  0;
  char  *readCur  =  nullptr;

    /* WRITE packet */
  SpecStack<IPack>  writeStackServer;
  int  writeHeaderPending  =  0; // if need continue to write header
  IPack  *writePacket  =  nullptr;
  int  writeLenLeft  =  0;
  char  *writeCur  =  nullptr;
  //This call only server when enshure socket not in use:
  void clearOnStart() ;

//---------------------------------------------------------
//EpolSocket Worker's staff:
  SpecStack<IPack>  readStackWorker;
  X509  *x509  =  nullptr;
  EVP_PKEY  *evpX509  =  nullptr;
  int64_t  groupID  =  0;
  int64_t  avatarID  =  0;
  int64_t  grpMailLife  =  0;
  int64_t  avaMailLife  =  0;

  bool  failSetCurX509(SpecSSL * specSSL,  const void *buf,  int num);

};

#endif // EpolSocket_H
