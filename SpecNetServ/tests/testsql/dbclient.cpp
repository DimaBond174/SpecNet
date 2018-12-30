/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include "dbclient.h"
#include <iostream>
#include "spec/specstatic.h"
#include "string.h"
#include "i/ipack.h"

DBClient::DBClient()
{

}

void  DBClient::stop() {
    sqlite3_close_v2(db);
    db = nullptr;
}

bool  DBClient::start(const char * serverName, const char * pathBase, IFileAdapter * iFileAdapter, int64_t tmpGUID) {
    bool re = false;
    _iFileAdapter = iFileAdapter;
    //_iAlloc = iAlloc;
    //faux loop:
        do {
            int res = sqlite3_threadsafe();
            std::cout << sqlite3_threadsafe() <<"=sqlite3_threadsafe()"<< std::endl;
            pathEnd = pathFull + 299;
            pathSuffix = printString(pathBase, pathFull, pathEnd);
            pathSuffix = printString("/", pathSuffix, pathEnd);
            char * cur = printString("SQLite", pathSuffix, pathEnd);
            iFileAdapter->mkdirs(pathFull);
            cur = printString("/specnet.db", cur, pathEnd);
            if (SQLITE_OK != sqlite3_open_v2(pathFull, &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, nullptr)) {
                std::cerr<<"[DBClient::start] ERROR: SQLITE_OK != sqlite3_open_v2()"<<std::endl;
                break;
            }

            if (!checkDBVersion()) {
                std::cerr<<"[DBClient::start] ERROR: checkDBVersion()"<<std::endl;
                break;
            }
            //isStarted.store(true, std::memory_order_release);
            if (!setServID(serverName, tmpGUID)) {
                std::cerr<<"[DBClient::start] ERROR: setServID(serverName, tmpGUID)"<<std::endl;
                break;
            }

            re = true;
        } while (false);

    return re;
}

static const char *  sqlGetServID1 =
        "select id_server from t_servers "\
        " where name=?";
static const char *  sqlGetServID2 =
        "select id_server from t_servers "\
        " where id_server=?";
static const char *  sqlSetServID =
        "insert into t_servers (name, id_server) values (?, ?)";
bool DBClient::setServID(const char * serverName, int64_t tmpGUID)  {
    bool re = false;
    sqlite3_stmt *stmtGetServID1 = nullptr;
    sqlite3_stmt *stmtGetServID2 = nullptr;
    sqlite3_stmt *stmtSetServID = nullptr;
    //faux loop:
        do {

            if (SQLITE_OK != sqlite3_prepare_v2(db, sqlGetServID1, strlen(sqlGetServID1),
                                                 &stmtGetServID1, NULL)) {
                break;
            }
            sqlite3_bind_text(stmtGetServID1, 1, serverName, strlen(serverName), NULL);

            if (SQLITE_ROW==sqlite3_step(stmtGetServID1)) {
                serverID = sqlite3_column_int64(stmtGetServID1, 0);
            } else {
                /* new Server Name, must store */
                if (SQLITE_OK != sqlite3_prepare_v2(db, sqlGetServID2, strlen(sqlGetServID2),
                                                     &stmtGetServID2, NULL)) {
                    break;
                }

                do {
                    sqlite3_reset(stmtGetServID2);
                    ++tmpGUID;
                    sqlite3_bind_int64(stmtGetServID2, 1, tmpGUID);
                } while(SQLITE_ROW==sqlite3_step(stmtGetServID2));
                serverID = tmpGUID;
                if (SQLITE_OK != sqlite3_prepare_v2(db, sqlSetServID, strlen(sqlSetServID),
                                                     &stmtSetServID, NULL)) {
                    break;
                }
                sqlite3_bind_text(stmtSetServID, 1, serverName, strlen(serverName), NULL);
                sqlite3_bind_int64(stmtSetServID, 2, serverID);
                sqlite3_step(stmtSetServID);                
            }

            re = true;
        } while (false);

    if (stmtGetServID1) {
        sqlite3_finalize (stmtGetServID1)  ;
    }

    if (stmtGetServID2) {
        sqlite3_finalize (stmtGetServID2)  ;
    }

    if (stmtSetServID) {
        sqlite3_finalize (stmtSetServID)  ;
    }

    return re;
}

void DBClient::dropDB()  {
    const int nsql = 5;
    const char *sql[nsql] = {
        "DROP TABLE IF EXISTS t_version",
        "DROP TABLE IF EXISTS t_servers",
        "DROP TABLE IF EXISTS t_avatars",
        "DROP TABLE IF EXISTS t_messages",
        "DROP TABLE IF EXISTS t_path"
    };
    for(int i = 0; i < nsql; ++i) {
        _execSQL (sql[i]);
//        int rc = sqlite3_exec(db, sql[i], callbackSQLite3, 0, &zErrMsg);
//        if( rc!=SQLITE_OK ) {
//            iLog.get()->log("e", "[%s][%s]:\n %s", TAG, sql[i], sqlite3_errmsg(db));
//            sqlite3_free(zErrMsg);
//            break;
//        }
    }

    return;
}

bool DBClient::_execSQL(const char * sql) {
    bool re = false;
    char *zErrMsg = 0;
    if( SQLITE_OK == sqlite3_exec(db, sql, NULL, 0, &zErrMsg)) {
        re = true;
    } else {
        std::cerr << " FAIL _execSQL:" << sql << std::endl
                  << sqlite3_errmsg(db) << std::endl;
        sqlite3_free(zErrMsg);
    }
    return re;
}

bool DBClient::createDB() {
    bool re = false;
    const int nsql = 7;
    const char *sql[nsql] = {
        "create table IF NOT EXISTS t_version (version integer);",
        "create table IF NOT EXISTS t_servers (name text NOT NULL, "\
                 "id_server integer NOT NULL, PRIMARY KEY (name));",
        "create table IF NOT EXISTS t_avatars (id_group integer NOT NULL, "\
                 "id_avatar integer NOT NULL, "\
                 "status integer, "\
                 "PRIMARY KEY (id_group, id_avatar));",
        "create table IF NOT EXISTS t_messages (date_msg integer NOT NULL, "\
                "id_msg integer NOT NULL, "\
                "id_group integer NOT NULL, "\
                "remote_id_avatar integer NOT NULL, "\
                "my_id_avatar integer NOT NULL, "\
                "PRIMARY KEY (date_msg,id_msg,id_group));",
        "create index IF NOT EXISTS ix_messages1_to ON t_messages (id_group, remote_id_avatar, date_msg);",
        "create table IF NOT EXISTS t_path (date_msg integer NOT NULL, "\
                "id_msg integer NOT NULL, "\
                "id_group integer NOT NULL, "\
                "id_server integer NOT NULL, "\
                "PRIMARY KEY (date_msg,id_msg,id_group, id_server));"
    };
    int i = 0;
    for(; i < nsql; ++i) {
        if (!_execSQL (sql[i])) { break;}
    }
    if (i>=nsql) {
        std::string str("INSERT INTO t_version (version) values(");
        str.append(std::to_string(DB_VERSION)).append(");");
        re = _execSQL(str.c_str());
    }
    return re;
}


bool  DBClient::checkDBVersion() {

    int version = 0;
    bool re = false;

    //dropDB(); //for debug creation

    sqlite3_stmt*   stmt = nullptr;
    int ret = sqlite3_prepare_v2(db, "SELECT version FROM t_version", -1, &stmt, NULL);
    if (SQLITE_OK == ret && SQLITE_ROW==sqlite3_step(stmt)) {
        version = sqlite3_column_int(stmt, 0);
//        for (result = sqlite3_step(stmt); result == SQLITE_ROW; result = sqlite3_step(stmt))
//        {
//            sqlite3_int64 found_time;
//            found_time = sqlite3_column_int64(stmt, 0);
//            printf("Found time: %ld\n", found_time);
//        }

    }
    sqlite3_finalize(stmt);

    if (0==version) {
        re = createDB();
    } else if (version==DB_VERSION) {
        re = true;
    } else {
        re = updateDB(version);
    }
   return re;
}


bool DBClient::updateDB(int curVersion) {

    while (DB_VERSION != curVersion){
        switch (curVersion) {
        case 1:
/* if can update, do update */
         //   break;
        default:
/* if can't update, recreate */
            dropDB();
            if (createDB()) {
                curVersion = DB_VERSION;
            }
            return DB_VERSION == curVersion;
            //break;
        }
    }

    return DB_VERSION == curVersion;
}

static const char *  sqlInsertMsg =
        "insert into t_messages (date_msg,id_msg,id_group,remote_id_avatar,my_id_avatar) values (?,?,?,?,?)";
bool DBClient::storeMessage(int64_t id_group, int64_t remote_id_avatar, int64_t my_id_avatar,
                            int64_t id_msg, int64_t date_msg, const char * data, uint32_t len) {
    /* let's store file */
    bool re = false;
    //faux loop:
    do {
            if (!stmtInsertMsg || SQLITE_OK !=sqlite3_reset(stmtInsertMsg)) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlInsertMsg, strlen(sqlInsertMsg),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtInsertMsg, NULL)) {
                     break;
                 }
            }
            char * cur = printULong(id_group, pathSuffix, pathEnd);
            *cur='/'; ++cur;
            cur = printULong(TO12(date_msg), cur, pathEnd);
            *cur='/'; ++cur;
            cur = printULong(id_msg, cur, pathEnd);
            cur = printULong(date_msg, cur, pathEnd);
            if (1!=_iFileAdapter->saveTFile(pathFull, data, len)){break;}

            sqlite3_bind_int64(stmtInsertMsg, 1, date_msg);
            sqlite3_bind_int64(stmtInsertMsg, 2, id_msg);
            sqlite3_bind_int64(stmtInsertMsg, 3, id_group);
            sqlite3_bind_int64(stmtInsertMsg, 4, remote_id_avatar);
            sqlite3_bind_int64(stmtInsertMsg, 5, my_id_avatar);
            sqlite3_step(stmtInsertMsg);

            re = true;
    } while (false);
    return re;

}//storeMessage



static constexpr ConstString  sqlGetNewMessages  {
  "SELECT t1.date_msg, t1.id_msg FROM t_messages t1"\
  " LEFT OUTER JOIN t_path t2"\
  " ON t1.date_msg=t2.date_msg"\
    " AND t1.id_msg=t2.id_msg"\
    " AND t1.id_group=?1"\
    " AND t1.id_group=t2.id_group"\
    " AND t2.id_server=?2"\
  " WHERE t2.id_server IS NULL"
};

bool  DBClient::getNewMessages(int64_t groupID,
    int64_t * msgIDs, int64_t * msgDates, uint32_t * resRows)  {
  bool re = false;
  //faux loop:
  do {
    if  (!stmtGetNewMessages
         ||  SQLITE_OK  !=  sqlite3_reset(stmtGetNewMessages))  {
      if (SQLITE_OK  !=  sqlite3_prepare_v3(db,  sqlGetNewMessages.c_str,  sqlGetNewMessages.size,
                                            SQLITE_PREPARE_PERSISTENT, &stmtGetNewMessages, NULL)) {
            break;
      }
    }

    sqlite3_bind_int64(stmtGetNewMessages,  1,  groupID);
    sqlite3_bind_int64(stmtGetNewMessages,  2,  serverID);
    uint32_t  i  =  0;
    while  (i<MAX_SelectRows  &&  SQLITE_ROW==sqlite3_step(stmtGetNewMessages))  {
      msgDates[i]  =  sqlite3_column_int64(stmtGetNewMessages,  0);
      msgIDs[i]  =  sqlite3_column_int64(stmtGetNewMessages,  1);
      ++i;
    }
    *resRows  =  i;
    re = true;
  } while (false);
  return re;
}

static const char *  sqlGetNeedMessages =
        "select id_msg from t_messages where date_msg=? and id_msg=? and id_group=?";
bool DBClient::getNeedMessages(int64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN,
                               int64_t * msgIDsNEED, int64_t * msgDatesNEED, uint32_t * resRowsNEED,
                               int64_t * msgIDsNotNEED, int64_t * msgDatesNotNEED, uint32_t * resRowsNotNEED) {
    bool re = false;
    //faux loop:
        do {
            if (!stmtGetNeedMessages ) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlGetNeedMessages, strlen(sqlGetNeedMessages),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtGetNeedMessages, NULL)) {
                     break;
                 }
            }

            uint32_t needN = 0;
            uint32_t notNeedN = 0;
            sqlite3_bind_int64(stmtGetNeedMessages, 3, groupID);
            for (uint32_t i = 0; i<lenArrayIN; ++i ){
                if (SQLITE_OK !=sqlite3_reset(stmtGetNeedMessages)) { break;}
                sqlite3_bind_int64(stmtGetNeedMessages, 1, msgDatesIN[i]);
                sqlite3_bind_int64(stmtGetNeedMessages, 2, msgIDsIN[i]);
                //if not exists:
                if (SQLITE_ROW==sqlite3_step(stmtGetNeedMessages)) {
                    msgDatesNotNEED[notNeedN] = msgIDsIN[i];
                    msgDatesNotNEED[notNeedN] = msgDatesIN[i];
                    ++notNeedN;
                } else {
                    msgIDsNEED[needN] = msgIDsIN[i];
                    msgDatesNEED[needN] = msgDatesIN[i];
                    ++needN;
                }
            }

            *resRowsNEED = needN;
            *resRowsNotNEED = notNeedN;
            re = true;
        } while (false);
    return re;
}

static const char *  sqlInsertPath =
        "insert into t_path (date_msg,id_msg,id_group, id_server) values (?,?,?,?)";
bool DBClient::storeNotNeed(int64_t groupID, int64_t msgIDs, int64_t msgDate) {
    bool re = false;
    //faux loop:
    do {
            if (!stmtInsertPath || SQLITE_OK !=sqlite3_reset(stmtInsertPath)) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlInsertPath, strlen(sqlInsertPath),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtInsertPath, NULL)) {
                     break;
                 }
            }

            sqlite3_bind_int64(stmtInsertPath, 1, msgDate);
            sqlite3_bind_int64(stmtInsertPath, 2, msgIDs);
            sqlite3_bind_int64(stmtInsertPath, 3, groupID);
            sqlite3_bind_int64(stmtInsertPath, 4, serverID);
            sqlite3_step(stmtInsertPath);

            re = true;
    } while (false);
    return re;
}

bool DBClient::storeNotNeedArray(int64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN) {
    bool re = false;
    //faux loop:
    do {
            if (!stmtInsertPath) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlInsertPath, strlen(sqlInsertPath),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtInsertPath, NULL)) {
                     break;
                 }
            }
            sqlite3_bind_int64(stmtInsertPath, 3, groupID);
            sqlite3_bind_int64(stmtInsertPath, 4, serverID);
            for (uint32_t i=0; i<lenArrayIN; ++i){
                if (SQLITE_OK !=sqlite3_reset(stmtInsertPath)){break;}
                sqlite3_bind_int64(stmtInsertPath, 1, msgDatesIN[i]);
                sqlite3_bind_int64(stmtInsertPath, 2, msgIDsIN[i]);
                sqlite3_step(stmtInsertPath);
            }
            re = true;
    } while (false);
    return re;
}

static const char *  sqlGetMsgType9 =
        "select remote_id_avatar, my_id_avatar"\
        " from t_messages where date_msg=? and id_msg=? and id_group=?";
IPack * DBClient::getMsgType9(int64_t id_group, int64_t id_msg, int64_t date_msg) {
    IPack * re = nullptr;
    //faux loop:
    do {
            if (!stmtGetMsgType9 || SQLITE_OK !=sqlite3_reset(stmtGetMsgType9)) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlGetMsgType9, strlen(sqlGetMsgType9),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtGetMsgType9, NULL)) {
                     break;
                 }
            }
            sqlite3_bind_int64(stmtGetMsgType9, 1, date_msg);
            sqlite3_bind_int64(stmtGetMsgType9, 2, id_msg);
            sqlite3_bind_int64(stmtGetMsgType9, 3, id_group);
            if (SQLITE_ROW!=sqlite3_step(stmtGetMsgType9)){break;}
            char * cur = printULong(id_group, pathSuffix, pathEnd);
            *cur='/'; ++cur;
            cur = printULong(TO12(date_msg), cur, pathEnd);
            *cur='/'; ++cur;
            cur = printULong(id_msg, cur, pathEnd);
            cur = printULong(date_msg, cur, pathEnd);
            const std::string &msg = _iFileAdapter->loadFileF(pathFull);
            if (msg.empty()){
                delMsg(id_group, id_msg, date_msg);
                break;
            }
            T_IPack9_struct outPacket9;
            outPacket9.str = msg.data();
            outPacket9.strLen = msg.size();
            outPacket9.guid1 = id_group;
            outPacket9.guid2 = id_msg;
            outPacket9.guid3 = date_msg;
            outPacket9.guid4 = sqlite3_column_int64(stmtGetMsgType9, 0);
            outPacket9.guid5 = sqlite3_column_int64(stmtGetMsgType9, 1);
            re = IPack9::createPacket(outPacket9, SPEC_PACK_TYPE_9);
    } while (false);
    return re;
}

static const char *  sqlDelMsg =
        "delete from "\
        " t_messages where date_msg=? and id_msg=? and id_group=?";
void DBClient::delMsg(int64_t id_group, int64_t id_msg, int64_t date_msg) {
    //faux loop:
    do {
            if (!stmtDelMsg || SQLITE_OK !=sqlite3_reset(stmtDelMsg)) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlDelMsg, strlen(sqlDelMsg),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtDelMsg, NULL)) {
                     break;
                 }
            }
            sqlite3_bind_int64(stmtDelMsg, 1, date_msg);
            sqlite3_bind_int64(stmtDelMsg, 2, id_msg);
            sqlite3_bind_int64(stmtDelMsg, 3, id_group);
            sqlite3_step(stmtDelMsg);
    } while (false);
}
