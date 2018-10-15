#include "testsql.h"
#include "dbclient.h"

extern "C"
{

TestSQL* createInstance() {
    return new DBClient();
}

void deleteInstance(TestSQL* p) {
    //delete ((DBClient*)p);
    DBClient* pD = dynamic_cast<DBClient *>(p);
    delete pD;
}

}


