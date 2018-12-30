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

class SpecContext
{    
public:
    static SpecContext& instance() {
        static SpecContext s;
        return s;
    }

    void start(std::shared_ptr <IConfig> && _iConfig,
               std::shared_ptr <IFileAdapter> && _iFileAdapter,
               std::shared_ptr <ILog> && _iLog,
               std::shared_ptr <ISystem> && _iSystem,
               std::shared_ptr <Idb> && _iDB,               
               std::shared_ptr <IServer> && _iServer
                );
    //Stop all:
    void stop();

    //Internal stop:
    void onStopSig();
    //External stop:
    void sendStopSig();


    //Off button total:
    std::atomic_bool keepRun;

    //Injected roots:
    std::shared_ptr <ISystem>       iSys        ;
    std::shared_ptr <ILog>          iLog        ;
    std::shared_ptr <IFileAdapter>  iFileAdapter;
    std::shared_ptr <IConfig>       iConfig     ;
    std::shared_ptr <Idb>           iDB         ;    
    std::shared_ptr <IServer>       iServer     ;    
    std::shared_ptr <SpecSSL>       specSSL     ;

private:
    const char * TAG = "SpecContext";
    SpecContext();
    ~SpecContext();
    SpecContext(SpecContext const&); // реализация не нужна
    SpecContext& operator= (SpecContext const&);  // и тут



};

#endif // SPECCONTEXT_H
