#include "testssl.h"
#if defined(DEpollServer)
#include "sslclient.h"
#else
#include "selclient.h"
#endif

#if defined (Windows)
extern "C" __declspec(dllexport) 
#else
extern "C" 
#endif
TestSSL* createInstance() {
    return new SSLClient();
}

#if defined (Windows)
extern "C" __declspec(dllexport)
#else
extern "C"
#endif
void deleteInstance(TestSSL* p) {
    //delete ((SSLClient*)p);
    SSLClient* pD = dynamic_cast<SSLClient *>(p);
    delete pD;
}




