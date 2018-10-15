#ifndef SQLITEDB_H
#define SQLITEDB_H

#include <atomic>
#include <memory>
#include <mutex>

#include "i/idb.h"
#include "i/ilog.h"
#include "depend/db/sqlite/sqlite3/sqlite3.h"

class SQLiteDB : public Idb {
public:
    /* Current SQLite implementation version: */
    const int DB_VERSION = 1;
    SQLiteDB();

    bool  start()  override;
    void  stop()   override;

    bool execSQL(const char * sql) override;
    bool  getNewMessages(uint64_t groupID, uint64_t avatarID,
                         uint64_t curTime, uint64_t grpMailLife, uint64_t avaMailLife,
                         uint64_t * msgIDs, uint64_t * msgDates, uint32_t * resRows
                         ) override;

    bool getNeedMessages(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN,
                                    uint64_t * msgIDsNEED, uint64_t * msgDatesNEED, uint32_t * resRowsNEED,
                                    uint64_t * msgIDsNotNEED, uint64_t * msgDatesNotNEED, uint32_t * resRowsNotNEED) override;
    void delMsg(uint64_t id_group, uint64_t id_msg, uint64_t date_msg) override;
    bool getMsg(uint64_t id_group, uint64_t id_msg, uint64_t date_msg,
                            uint64_t * remote_id_avatar, uint64_t * my_id_avatar) override;

    bool addPath(uint64_t date_msg, uint64_t id_msg, uint64_t groupID, uint64_t remoteAvatarID) override;
    bool storeNotNeedArray(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN, uint64_t remoteAvatarID) override;
    bool storeMessage(uint64_t id_group, uint64_t remote_id_avatar, uint64_t my_id_avatar,
                                  uint64_t id_msg, uint64_t date_msg) override;
private:
    const char * TAG = "SQLiteDB";
    //std::atomic<bool> isStarted ;
    sqlite3*    db              = nullptr;
    ILog * iLog = nullptr;
    std::timed_mutex db_mutex;

    /* prepared SQLs */
    sqlite3_stmt *stmtGetNewMessages = nullptr;
    sqlite3_stmt *stmtAddPath = nullptr;
    sqlite3_stmt *stmtGetNeedMessages = nullptr;
    sqlite3_stmt *stmtDelMsg = nullptr;
    sqlite3_stmt *stmtGetMsgType9 = nullptr;
    sqlite3_stmt *stmtInsertMsg = nullptr;

    bool  templateQuery();
    bool checkDBVersion();
    bool createDB();
    bool updateDB(int curVersion);
    void dropDB();
    bool _execSQL(const char * sql);
    static int callbackSQLite3(void *NotUsed, int argc, char **argv, char **azColName);
};


#endif // SQLITEDB_H
