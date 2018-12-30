#include <iostream>
#include "speccontext.h"
#include "specstatic.h"


void SpecContext::start(std::shared_ptr <IConfig> && _iConfig,
                        std::shared_ptr <IFileAdapter> && _iFileAdapter,
                        std::shared_ptr <ILog> && _iLog,
                        std::shared_ptr <ISystem> && _iSystem,
                        std::shared_ptr <Idb> && _iDB,                        
                        std::shared_ptr <IServer> && _iServer
                        ) {
    iConfig      = std::move(_iConfig);
    iFileAdapter = std::move(_iFileAdapter);
    iDB          = std::move(_iDB);
    iLog         = std::move(_iLog);
    iSys         = std::move(_iSystem);    
    iServer      = std::move(_iServer);    

    bool isOk = false;

    //faux loop
    do {
        if (!(iConfig && iFileAdapter && iLog && iSys && iDB)) {
            break;
        }

        if (!iFileAdapter.get()->setExePath(
                    iSys.get()->getExePath())) {
            std::cerr << "Error: SpecContext FAIL iSys->getExePath()" << std::endl;
            break;
        }

        if (!iConfig.get()->loadConfig()) {
            std::cerr << "Error: SpecContext FAIL iConfig->loadConfig()." << std::endl;
            break;
        }

        if (!iLog.get()->start()) {
            std::cerr << "Error: SpecContext FAIL iLog->start()." << std::endl;
            break;
        }

        //Next logs will writes in iLog:

        if (!iDB.get()->start()) {
            iLog.get()->log("e","[%s]: FAIL iDB->start().",TAG);
            break;
        }

//        specSSL   = std::make_shared<SpecSSL>(iLog.get(),
//                                              iFileAdapter.get(), iConfig.get());
//        if (!specSSL.get()->start()) {
//            iLog.get()->log("e","[%s]: FAIL specSSL->start().",TAG);
//            break;
//        }

        keepRun.store(true, std::memory_order_release);


        isOk = true;
    } while (false);

    if (isOk) {
        iLog.get()->log("i","[%s]:STARTED",TAG);
    } else {
        keepRun.store(false, std::memory_order_release);
        std::cerr << "Error: SpecContext FAIL to start." << std::endl;
    }


}

void SpecContext::stop() {
//TODO send STOP to all forks/services
    if (iLog) {
        iLog.get()->stop();
    }
}

void SpecContext::sendStopSig() {
    keepRun.store(false, std::memory_order_release);

    if (iSys) {
        iSys.get()->sendCmd(SPEC_SERVICE, "TERMINATE");
    }

    onStopSig();
}

void SpecContext::onStopSig() {

    keepRun.store(false, std::memory_order_release);

    if (iServer) {
        iServer.get()->stop();
    }

    if (iDB) {
        iDB.get()->stop();
    }

    if (specSSL) {
        specSSL.get()->stop();
    }

    if (iLog) {
        iLog.get()->log("i","[%s]:onStopSig()",TAG);
    }

}

SpecContext::SpecContext() : keepRun(false) {}

SpecContext::~SpecContext() {
    //onStopSig();
}



