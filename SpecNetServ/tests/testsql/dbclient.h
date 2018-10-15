#ifndef DBClient_H
#define DBClient_H

#include "depend/db/sqlite/sqlite3/sqlite3.h"
#include "i/ifileadapter.h"
#include "testsql.h"

class DBClient :  public TestSQL
{
public:
    /* Current SQLite implementation version: */
    const int DB_VERSION = 1;
    DBClient();
    bool  start(IAlloc * iAlloc, const char * serverName, const char * pathBase ,
                IFileAdapter * iFileAdapter, long long tmpGUID) override;
    void  stop() override;
    bool storeMessage(uint64_t id_group, uint64_t remote_id_avatar, uint64_t my_id_avatar,
                      uint64_t id_msg, uint64_t date_msg, const char * data, uint32_t len) override;
    bool  getNewMessages(uint64_t groupID,
                                     uint64_t * msgIDs, uint64_t * msgDates, uint32_t * resRows
                                     ) override;
    bool getNeedMessages(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN,
                                    uint64_t * msgIDsNEED, uint64_t * msgDatesNEED, uint32_t * resRowsNEED,
                                    uint64_t * msgIDsNotNEED, uint64_t * msgDatesNotNEED, uint32_t * resRowsNotNEED) override;
    bool storeNotNeed(uint64_t groupID, uint64_t msgIDs, uint64_t msgDate)  override;
    bool storeNotNeedArray(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN) override;
    char * getMsgType9(uint64_t id_group, uint64_t id_msg, uint64_t date_msg) override;

private:
    char pathFull[300];
    char * pathSuffix;
    char * pathEnd;
    IFileAdapter * _iFileAdapter;
    IAlloc * _iAlloc;
    sqlite3*    db              = nullptr;
    long long serverID = 0;

    /* prepared SQLs */
    sqlite3_stmt *stmtGetNewMessages = nullptr;
    sqlite3_stmt *stmtGetNeedMessages = nullptr;
    sqlite3_stmt *stmtAddPath = nullptr;
    sqlite3_stmt *stmtInsertMsg = nullptr;
    sqlite3_stmt *stmtInsertPath = nullptr;
    sqlite3_stmt *stmtGetMsgType9 = nullptr;
    sqlite3_stmt *stmtDelMsg = nullptr;

    bool checkDBVersion();
    void dropDB() ;
    bool createDB() ;
    bool updateDB(int curVersion);
    bool setServID(const char * serverName, long long tmpGUID);
    bool _execSQL(const char * sql);
    void delMsg(uint64_t id_group, uint64_t id_msg, uint64_t date_msg);
};

#endif // DBClient_H
