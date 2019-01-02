/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef DBClient_H
#define DBClient_H

#include "depend/db/sqlite/sqlite3/sqlite3.h"
#include "i/ifileadapter.h"
#include "testsql.h"
#include "i/ipack.h"

class DBClient :  public TestSQL
{
public:
    /* Current SQLite implementation version: */
    const int DB_VERSION = 1;
    DBClient();
    bool  start(const char * serverName, const char * pathBase ,
                IFileAdapter * iFileAdapter, int64_t tmpGUID) override;
    void  stop() override;
    bool storeMessage(int64_t id_group, int64_t remote_id_avatar, int64_t my_id_avatar,
                      int64_t id_msg, int64_t date_msg, const char * data, uint32_t len) override;
    bool  getNewMessages(int64_t groupID,
                                     int64_t * msgIDs, int64_t * msgDates, uint32_t * resRows
                                     ) override;
    bool getNeedMessages(int64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN,
                                    int64_t * msgIDsNEED, int64_t * msgDatesNEED, uint32_t * resRowsNEED,
                                    int64_t * msgIDsNotNEED, int64_t * msgDatesNotNEED, uint32_t * resRowsNotNEED) override;
    bool storeNotNeed(int64_t groupID, int64_t msgIDs, int64_t msgDate)  override;
    bool storeNotNeedArray(int64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN) override;
    IPack * getMsgType9(int64_t id_group, int64_t id_msg, int64_t date_msg) override;

private:
    char pathFull[300];
    char * pathSuffix;
    char * pathEnd;
    IFileAdapter * _iFileAdapter;
    //IAlloc * _iAlloc;
    sqlite3*    db              = nullptr;
    int64_t serverID = 0;

    /* prepared SQLs */
    sqlite3_stmt *stmtGetNewMessages = nullptr;
    sqlite3_stmt *stmtGetNeedMessages = nullptr;
    sqlite3_stmt *stmtAddPath = nullptr;
    sqlite3_stmt *stmtInsertMsg = nullptr;
    sqlite3_stmt *stmtInsertPath = nullptr;
    sqlite3_stmt *stmtGetMsgType9 = nullptr;
    sqlite3_stmt *stmtDelMsg = nullptr;
    sqlite3_stmt *stmtDelPath = nullptr;

    bool checkDBVersion();
    void dropDB() ;
    bool createDB() ;
    bool updateDB(int curVersion);
    bool setServID(const char * serverName, int64_t tmpGUID);
    bool _execSQL(const char * sql);
    void delMsg(int64_t id_group, int64_t id_msg, int64_t date_msg);
};

#endif // DBClient_H
