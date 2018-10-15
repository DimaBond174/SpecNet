#ifndef TestSQL_H
#define TestSQL_H

#include <string>
#include "i/ilib.h"
#include "i/ifileadapter.h"
#include "i/ialloc.h"


class TestSQL: public ILib
{
public:
    TestSQL() {}
    virtual ~TestSQL(){}
    std::string getTAG() {return std::string(TAG);}

    virtual bool  start(IAlloc * iAlloc, const char * serverName, const char * pathBase,
                IFileAdapter * iFileAdapter, long long tmpGUID) = 0;
    virtual void  stop() =0;
    virtual bool storeMessage(uint64_t id_group, uint64_t remote_id_avatar, uint64_t my_id_avatar,
                              uint64_t id_msg, uint64_t date_msg, const char * data, uint32_t len) = 0;
    virtual bool  getNewMessages(uint64_t groupID,
                                 uint64_t * msgIDs, uint64_t * msgDates, uint32_t * resRows
                                 )=0;
    virtual bool getNeedMessages(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN,
                                uint64_t * msgIDsNEED, uint64_t * msgDatesNEED, uint32_t * resRowsNEED,
                                uint64_t * msgIDsNotNEED, uint64_t * msgDatesNotNEED, uint32_t * resRowsNotNEED) = 0;
    virtual bool storeNotNeed(uint64_t groupID, uint64_t msgIDs, uint64_t msgDate) =0;
    virtual bool storeNotNeedArray(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN) = 0;
    virtual char * getMsgType9(uint64_t id_group, uint64_t id_msg, uint64_t date_msg) =0;
private:
    const char * TAG = "TestSQL";
};



#endif // TestSQL_H
