#include "testssl.h"
#include "sslclient.h"

extern "C"
{

TestSSL* createInstance() {
    return new SSLClient();
}

void deleteInstance(TestSSL* p) {
    //delete ((SSLClient*)p);
    SSLClient* pD = dynamic_cast<SSLClient *>(p);
    delete pD;
}

}


