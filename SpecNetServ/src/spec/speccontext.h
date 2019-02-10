/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef SPECCONTEXT_H
#define SPECCONTEXT_H

#include <string>
#include <memory>
#include <atomic>
#include "i/idb.h"
#include "i/ilog.h"
#include "i/iconfig.h"
#include "i/ifileadapter.h"
#include "i/isystem.h"
#include "i/iserver.h"
#include "depend/encrypt/boringssl/specssl.h"

class  SpecContext  {
 public:
  static SpecContext& instance()  {
    static SpecContext  s;  //  Single instance
    return  s;
  }

  std::atomic_bool keepRun;  //  Off button total
  //  Injected roots:
  std::shared_ptr<ISystem>  iSys;
  std::shared_ptr<ILog>  iLog;
  std::shared_ptr<IFileAdapter>  iFileAdapter;
  std::shared_ptr<IConfig>  iConfig;
  std::shared_ptr<Idb>  iDB;
  std::shared_ptr<IServer>  iServer;
  std::shared_ptr<SpecSSL>  specSSL;

  void  start(std::shared_ptr<IConfig>  &&_iConfig,
    std::shared_ptr<IFileAdapter>  &&_iFileAdapter,
    std::shared_ptr<ILog>  &&_iLog,
    std::shared_ptr<ISystem>  &&_iSystem,
    std::shared_ptr<Idb>  &&_iDB,
    std::shared_ptr<IServer>  &&_iServer );
  void stop();  //  Stop all
  void onStopSig();  //  Internal stop
  void sendStopSig();  //  External stop

 private:
  const char  *TAG  =  "SpecContext";
  SpecContext();
  ~SpecContext();
  SpecContext(SpecContext const&)  =  delete;
  SpecContext& operator= (SpecContext const&)  =  delete;
};

#endif // SPECCONTEXT_H
