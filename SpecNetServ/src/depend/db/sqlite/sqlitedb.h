/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

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
    bool  getNewMessages(int64_t groupID, int64_t avatarID,
                         int64_t curTime, int64_t grpMailLife, int64_t avaMailLife,
                         int64_t * msgIDs, int64_t * msgDates, uint32_t * resRows
                         ) override;

    bool getNeedMessages(int64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN,
                                    int64_t * msgIDsNEED, int64_t * msgDatesNEED, uint32_t * resRowsNEED,
                                    int64_t * msgIDsNotNEED, int64_t * msgDatesNotNEED, uint32_t * resRowsNotNEED) override;
    void delMsg(int64_t id_group, int64_t id_msg, int64_t date_msg) override;
    bool getMsg(int64_t id_group, int64_t id_msg, int64_t date_msg,
                            uint64_t * remote_id_avatar, uint64_t * my_id_avatar) override;

    bool addPath(int64_t date_msg, int64_t id_msg, int64_t groupID, int64_t remoteAvatarID) override;
    bool storeNotNeedArray(int64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN, int64_t remoteAvatarID) override;
    bool storeMessage(int64_t id_group, int64_t remote_id_avatar, int64_t my_id_avatar,
                                  int64_t id_msg, int64_t date_msg) override;
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
    sqlite3_stmt *stmtDelPath = nullptr;
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
