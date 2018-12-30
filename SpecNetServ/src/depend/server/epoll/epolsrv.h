/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef EpolSrv_H
#define EpolSrv_H


#include <thread>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <list>
#include <mutex>
#include "i/iserver.h"
#include "i/ilog.h"
#include "iservcallback.h"
#include "epolsocket.h"
#include "i/ipack.h"
#include "i/ifileadapter.h"
#include "epolworker.h"

class  EpolSrv  :  public IServer,  public IServCallback  {
 public:
  EpolSrv();
  ~EpolSrv();

    /* IServer interfaces */
  bool  start()  override;
  void  stop()  override;

    /* IServCallback interfaces */
  const  char * getMessagesPath()  override;
  const  char * getAvaCertsPath()  override;
  std::string  getServPassword()  override;
  EpolSocket * getStackSockNeedWorker()  override;
  void returnSocketToWork(EpolSocket  *sock)  override;
  void returnSocketToFree(EpolSocket  *sock)  override;
  void workerGoneDown(void  *worker)  override;

 private:
  const  char  *  const  TAG  =  "EpolSrv";
  EpolSocket  srvEpoll;
    /* srvState: 0==not started, 1==starting, 2==works, 3==going to stop */
  //  std::atomic_int srvState {0};
  std::atomic_bool  keepRun  {  true  };
  int  logLevel  =  0;  //How much to write in the log file
  std::thread  serverThread;

    /* worker pool */
  SpecStack<EpolWorker>  stackWorkers;
  SpecSafeStack<EpolWorker>  stoppedWorkers;
  int64_t  curWorkers  =  0;
  int64_t  maxWorkers  = 1;
  int64_t  oneWorkerOnEach  =  10; //check border if need new worker

    /* serverThread staff - thread unsafe */
  int  server_socket  =  -1;
  int  epollfd  =  -1;
  bool tryAcceptConnLater  =  false; //if exists pending connections
  int64_t  maxConnections  = 10;
  int64_t  curConnections  =  0;
  int  idleConnLife  =  5; //seconds

  EpolSocket ** curLeaf_NextPtr  =  nullptr;
  EpolSocket ** headLeaf  =  nullptr;

  /* EpolSocket's not at work
   * WARNING: if workers started with EpolSocket,
   * then only worker can return EpolSocket to stackFreeSockets */
  SpecSafeStack<EpolSocket>  stackFreeSockets;  //sockets to stop
  SpecStack<EpolSocket>  stackFreeSocketsLocal;  //server side pool
  SpecStack<EpolSocket>  stackShakeSockets;  //not SSL connected yet

    /* EpolSocket's workers began working with */
  SpecSafeStack<EpolSocket> stackSockNeedWorker;
  std::list<EpolSocket*> connectedSockets; //sockets under server monitor

  std::string  messagesPath;
  std::string  avaCertsPath;
  std::string  servPassword;
  std::shared_ptr<ILog>  p_iLog;
  ILog  *iLog  =  nullptr;
  std::shared_ptr<IFileAdapter>  p_iFileAdapter;
  IFileAdapter  *iFileAdapter  =  nullptr;
  std::shared_ptr<SpecSSL>  p_specSSL;
  SpecSSL  *specSSL  =  nullptr;
  std::shared_ptr<Idb>  p_iDB;
  Idb  *iDB  =  nullptr;

    /* init */
  bool  create_socket();
  static void * runServThreadLoop(void  *arg);
  void  servThreadLoop();
  void  setSIGPIPEhandler();
  void  newEpolSocketLeaf();
  void  clearSocket(EpolSocket  *p);
    /* work */
  void  logConnection(sockaddr  *remote_addr,
    uint32_t  remote_addr_len,  int client_socket);
  EpolSocket * getFreeSocket();
  void  handleAccept();
  void  handleAcceptWithLog();
  void  handleHandshake(EpolSocket  *s);
  void  updateEPoll(EpolSocket  *s);
  void  freeSocketToLocal(EpolSocket  *s);
  void  freeSocketsToLocal();
  void  startWorker();
  void  stopWorker();
  void  handleSockets();
  void  handleRead(EpolSocket  *s);
  void  handleWrite(EpolSocket  *s);
  void  clearStoppedWorkers();
  void  setFreeSocketID(EpolSocket  *s);
  void  doPack7(EpolSocket  *s,  IPack  *pack);
    /* stop */
  void  delEpolSocketLeaf(EpolSocket  **ptr);
  void  ohNoFreeRam();
  bool  addServerEpoll();
  void  stopServerEpoll();
  void  stopAllSockets();
};

#endif // EpolSrv_H
