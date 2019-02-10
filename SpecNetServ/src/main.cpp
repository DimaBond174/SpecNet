/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include <iostream>
#include <memory>
#include <functional>

/*  Preparing for the injection of modules according
 * to your preferences. The main work takes place
 * in the server module without RTTI, therefore dependency
 * injection does not affect the performance  */

#if defined(DEpollServer)
    #include "depend/server/epoll/epolsrv.h"
#elif defined(DSelectServer)
    #include "depend/server/select/selectsrv.h"
#endif

#if defined(DFileAdapter)
    #include "depend/file/base/fileadapter.h"
#else
    #include "depend/file/old/cfileadapter.h"
#endif

#if defined(DConfigJson)
    #include "depend/config/json/configjson.h"
#endif

#if defined(DSpecSSL)
    #include "depend/encrypt/boringssl/specssl.h"
#endif

#if defined(DSQLiteDB)
    #include "depend/db/sqlite/sqlitedb.h"
#endif

#if defined(DSpdLog)
    #include "depend/log/spdlog/spdlog.h"
#else
    #include "depend/log/speclog/speclog.h"
#endif

#if defined(Linux)
    #include "depend/system/linux/linuxsystem.h"
    #include "depend/system/linux/linuxservice.h"
#elif defined(Windows)
    #include "depend/system/windows/windowssystem.h"
    #include "depend/system/windows/windowsservice.h"
#endif
#include "spec/speccontext.h"

int  main(int  argc,  char  **argv)  {
    /*
     * TODO Be sure to select the right preference
     * in the CMakeLists.txt
     * Everything is injected here:
     */
  std::function<void()>  f_startContext  =  []()  {
    SpecContext::instance().start(
    //inject config loader:
#if defined(DConfigJson)
      std::make_shared<ConfigJson>(),
#endif
    //inject file adapter:
#if defined(DFileAdapter)
      std::make_shared<FileAdapter>(),
#else
      std::make_shared<CFileAdapter>(),
#endif
    //inject logger:
#if defined(DSpdLog)
      std::make_shared<SpdLog>(),
#else
      std::make_shared<SpecLog>(),
#endif
    //inject os system api adapter:
#if defined(Linux)
      std::make_shared<LinuxSystem>(),
#elif defined(Windows)
      std::make_shared<WindowsSystem>(),
#endif
    //inject database  adapter:
#if defined(DSQLiteDB)
      std::make_shared<SQLiteDB>(),
#endif
    //inject server:
#if defined(DEpollServer)
      std::make_shared<EpolSrv>()
#elif defined(DSelectServer)
      std::make_shared<SelectSrv>()
#endif
    ); //).start(
  }; //[]()

#if defined(Linux)
    LinuxService   srv (f_startContext);
#elif defined(Windows)
    WindowsService srv (f_startContext);
#endif

  srv.onCmd(argc,  argv);
  SpecContext::instance().stop();
  return  0;
}  //  main
