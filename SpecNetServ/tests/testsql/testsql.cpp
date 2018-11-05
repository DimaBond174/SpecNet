#include "testsql.h"
#include "dbclient.h"


#if defined (Windows)
	extern "C" __declspec(dllexport)
#else
	extern "C"
#endif
TestSQL* createInstance() {
    return new DBClient();
}

#if defined (Windows)
	extern "C" __declspec(dllexport)
#else
	extern "C"
#endif
void deleteInstance(TestSQL* p) {
    //delete ((DBClient*)p);
    DBClient* pD = dynamic_cast<DBClient *>(p);
    delete pD;
}




