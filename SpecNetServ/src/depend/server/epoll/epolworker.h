/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef EPOLWORKER_H
#define EPOLWORKER_H

#include "epolsocket.h"
#include "i/idb.h"
#include <thread>
#include "iservcallback.h"

class EpolWorker  {
 public:
  EpolWorker * nextIStack;  //IStack interface (faster than vtable)

  EpolWorker(IServCallback  *iServCallback_,  int  logLevel_,
      ILog  *iLog_,  SpecSSL  *specSSL_,
      IFileAdapter * iFileAdapter_,  Idb * iDB_);
  ~EpolWorker();
  void  start();
  void  stop();
  void  lazyGoStop();

 private:
  const  int  logLevel;
  IServCallback  *  const  iServCallback;
  ILog  *  const  iLog;
  SpecSSL  *  const  specSSL;
  IFileAdapter  *  const  iFileAdapter;
  Idb  *  const  iDB;
  SpecStack<EpolSocket>  stackSockNeedWorker;

  /*
     * 1 == keepRun == keep run
     * 0 == go lazy to stop
     * -1 == emergency stop
  */
  std::atomic<int>  keepRun  {  1  };
  std::thread  workThread;

  static  void * runWorkThreadLoop(void  *arg);
  void  workThreadLoop();
  void  freeResources();
  bool  eatPack(EpolSocket  *sock,  IPack  *pack);
  bool  doPack1(EpolSocket  *sock,  IPack  *pack);
  bool  doPack3(EpolSocket  *sock,  IPack  *pack);
  bool  doPack5(EpolSocket  *sock,  IPack  *pack);
  bool  doPack6(EpolSocket  *sock,  IPack  *pack);
  bool  doPack7(EpolSocket  *sock,  IPack  *pack);
  bool  doPack8(EpolSocket  *sock,  IPack  *pack);
  bool  doPack9(EpolSocket  *sock,  IPack  *pack);
  bool  doPack10(EpolSocket  *sock,  IPack  *pack);
  int64_t  getCurJavaTime();
};

#endif // EPOLWORKER_H
