#ifndef IDB_H
#define IDB_H

#include <stdint.h>


class Idb {
public:
    virtual ~Idb() {}
    //Working
    virtual bool  start()  = 0;
    virtual void  stop()   = 0;
    virtual bool  execSQL(const char * sql) = 0;
    virtual bool  getNewMessages(uint64_t groupID, uint64_t avatarID,
                                 uint64_t curTime, uint64_t grpMailLife, uint64_t avaMailLife,
                                 uint64_t * msgIDs, uint64_t * msgDates, uint32_t * resRows
                                 )=0;

    virtual bool getNeedMessages(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN,
                                 uint64_t * msgIDsNEED, uint64_t * msgDatesNEED, uint32_t * resRowsNEED,
                                 uint64_t * msgIDsNotNEED, uint64_t * msgDatesNotNEED, uint32_t * resRowsNotNEED) = 0;
    virtual void delMsg(uint64_t id_group, uint64_t id_msg, uint64_t date_msg) = 0;
    virtual bool getMsg(uint64_t id_group, uint64_t id_msg, uint64_t date_msg,
                        uint64_t * remote_id_avatar, uint64_t * my_id_avatar) = 0;

    virtual bool addPath(uint64_t date_msg, uint64_t id_msg, uint64_t groupID, uint64_t remoteAvatarID) = 0;
    virtual bool storeNotNeedArray(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN, uint64_t remoteAvatarID) = 0;
    virtual bool storeMessage(uint64_t id_group, uint64_t remote_id_avatar, uint64_t my_id_avatar,
                              uint64_t id_msg, uint64_t date_msg) = 0;

};
#endif // IDB_H
