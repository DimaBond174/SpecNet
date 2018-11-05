#include "sqlitedb.h"
#include "spec/speccontext.h"
#include "spec/specstatic.h"
#include "string.h"

SQLiteDB::SQLiteDB()  {

}

bool  SQLiteDB::start() {
    bool re = false;    
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
    //faux loop:
        do {
            SpecContext & sr = SpecContext::instance();
            iLog = sr.iLog.get();
            int res = sqlite3_threadsafe();
            iLog->log("i","[SQLiteDB::start]: %i==sqlite3_threadsafe()", res);

            const std::string &dbPath =
                    sr.iFileAdapter.get()->toFullPath(
                        sr.iConfig.get()->getStringValue(
                            "SQLitePath").c_str());
            if (dbPath.empty()) { break; }
            sr.iFileAdapter.get()->mkdirs(sr.iFileAdapter.get()->getDir(dbPath));

            if (SQLITE_OK != sqlite3_open_v2(dbPath.c_str(), &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, nullptr)) { break; }

            if (!checkDBVersion()) { break; }
            //isStarted.store(true, std::memory_order_release);
            re = true;
        } while (false);
        db_mutex.unlock();
    }//if

    return re;
}

void  SQLiteDB::stop() {
    //isStarted.store(false, std::memory_order_release);
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
        if (db) {
            if (stmtGetNeedMessages) {
                sqlite3_finalize (stmtGetNeedMessages)  ;
                stmtGetNeedMessages = nullptr;
            }
            if (stmtGetNewMessages) {
                sqlite3_finalize (stmtGetNewMessages)  ;
                stmtGetNewMessages = nullptr;
            }
            if (stmtAddPath) {
                sqlite3_finalize (stmtAddPath)  ;
                stmtAddPath = nullptr;
            }
            sqlite3_close_v2(db);
        }
        db_mutex.unlock();
    }
}

bool  SQLiteDB::checkDBVersion() {

    int version = 0;
    bool re = false;

    dropDB(); //for debug creation

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
    } else if (version!=DB_VERSION) {
        re = updateDB(version);
    }
   return re;
}

bool SQLiteDB::execSQL(const char * sql) {
    //bool re = false;
    //if (isStarted.load(std::memory_order_acquire)) {
    //    re = _execSQL(sql);
    //}
    return _execSQL(sql);
}

bool SQLiteDB::_execSQL(const char * sql) {
    bool re = false;
    char *zErrMsg = 0;
    if( SQLITE_OK == sqlite3_exec(db, sql, callbackSQLite3, 0, &zErrMsg)) {
        re = true;
    } else {
        SpecContext::instance().iLog.get()->log("e", "[%s][%s]:\n %s", TAG, sql, sqlite3_errmsg(db));
        sqlite3_free(zErrMsg);
    }
    return re;
}

bool SQLiteDB::createDB() {
    bool re = false;
    const int nsql = 6;
    const char *sql[nsql] = {
        "create table IF NOT EXISTS t_version (version integer);",
        "create table IF NOT EXISTS t_groups (id_group integer primary key, "\
                                     "name text NOT NULL, "\
                                     "status integer NOT NULL);",
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
                "id_avatar integer NOT NULL, "\
                "PRIMARY KEY (date_msg,id_msg,id_group, id_avatar));"
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

bool SQLiteDB::updateDB(int curVersion) {

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

void SQLiteDB::dropDB()  {
    const int nsql = 5;
    const char *sql[nsql] = {
        "DROP TABLE IF EXISTS t_version",
        "DROP TABLE IF EXISTS t_groups",
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

int SQLiteDB::callbackSQLite3(void *NotUsed, int argc, char **argv, char **azColName)
{
    std::string str;
    for(int i = 0; i<argc; ++i) {
        str.append(azColName[i])
           .append(" = ")
           .append(argv[i] ? argv[i] : "NULL")
           .append("\n");
    }
    str.append("\n");
    SpecContext::instance().iLog.get()->log("i",str.c_str());
    return 0;
}

//TODO передавать только личные сообщения адресату или в группу
//sb.append("select t1.date_msg, t1.id_msg from t_messages t1  left outer join t_path t2  on t1.date_msg=t2.date_msg and t1.id_msg=t2.id_msg and t1.id_group=")
//.append(groupID).append(" and t1.id_group=t2.id_group and t2.id_avatar=")
//.append(avatarID).append(" where t2.id_avatar is null and t1.status<").append(ByteUtils.MsgEndSendL)
//.append(" and (t1.remote_id_avatar=0 and t1.date_msg>").append(grpMailLife)
//.append(" or t1.remote_id_avatar<>0 and t1.date_msg>").append(avaMailLife)
//.append(") and t1.date_msg<").append(curTime);
static const char *  sqlGetNewMessages =
        "select t1.date_msg, t1.id_msg from t_messages t1"\
        " left outer join t_path t2"\
        " on t1.date_msg=t2.date_msg and t1.id_msg=t2.id_msg and t1.id_group=?"\
        " and t1.id_group=t2.id_group and t2.id_avatar=?"\
        " where t2.id_avatar is null "\
        " and (t1.remote_id_avatar=0 and t1.date_msg>?"\
        " or t1.remote_id_avatar=? and t1.date_msg>?"\
        ") and t1.date_msg<?";

bool  SQLiteDB::getNewMessages(uint64_t groupID, uint64_t avatarID,
                                             uint64_t curTime, uint64_t grpMailLife, uint64_t avaMailLife,
                                             uint64_t * msgIDs, uint64_t * msgDates, uint32_t * resRows
                                             ) {

    bool re = false;
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
    //faux loop:
        do {
            if (!stmtGetNewMessages || SQLITE_OK !=sqlite3_reset(stmtGetNewMessages)) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlGetNewMessages, strlen(sqlGetNewMessages),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtGetNewMessages, NULL)) {
                     break;
                 }
            }

            sqlite3_bind_int64(stmtGetNewMessages, 1, groupID);
            sqlite3_bind_int64(stmtGetNewMessages, 2, avatarID);
            sqlite3_bind_int64(stmtGetNewMessages, 3, grpMailLife);
            sqlite3_bind_int64(stmtGetNewMessages, 4, avatarID);
            sqlite3_bind_int64(stmtGetNewMessages, 5, avaMailLife);
            sqlite3_bind_int64(stmtGetNewMessages, 6, curTime);

            unsigned long i=0;
            while (i<MAX_SelectRows && SQLITE_ROW==sqlite3_step(stmtGetNewMessages)) {
                msgDates[i] = sqlite3_column_int64(stmtGetNewMessages, 0);
                msgIDs[i] = sqlite3_column_int64(stmtGetNewMessages, 1);
                ++i;
            }
            *resRows = i;
            re = true;
        } while (false);
        db_mutex.unlock();
    }//if

    return re;   
}

static const char *  sqlAddPath = "insert into t_path (date_msg, id_msg, id_group, id_avatar) values (?,?,?,?)";

bool  SQLiteDB::addPath(uint64_t date_msg, uint64_t id_msg, uint64_t groupID, uint64_t remoteAvatarID){
    bool re = false;
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
    //faux loop:
        do {
            if (!stmtAddPath || SQLITE_OK !=sqlite3_reset(stmtAddPath)) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlAddPath, strlen(sqlAddPath),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtAddPath, NULL)) {
                     break;
                 }
            }

            sqlite3_bind_int64(stmtAddPath, 1, date_msg);
            sqlite3_bind_int64(stmtAddPath, 2, id_msg);
            sqlite3_bind_int64(stmtAddPath, 3, groupID);
            sqlite3_bind_int64(stmtAddPath, 4, remoteAvatarID);

            // commit
            sqlite3_step(stmtAddPath);

            re = true;
        } while (false);
        db_mutex.unlock();
    }//if

    return re;
}

static const char *  sqlGetNeedMessages =
        "select id_msg from t_messages where date_msg=? and id_msg=? and id_group=?";
bool SQLiteDB::getNeedMessages(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN,
                               uint64_t * msgIDsNEED, uint64_t * msgDatesNEED, uint32_t * resRowsNEED,
                               uint64_t * msgIDsNotNEED, uint64_t * msgDatesNotNEED, uint32_t * resRowsNotNEED) {
    bool re = false;
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
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
        db_mutex.unlock();
    }//if

    return re;
}

static const char *  sqlDelMsg =
        "delete from "\
        " t_messages where date_msg=? and id_msg=? and id_group=?";

void  SQLiteDB::delMsg(uint64_t id_group, uint64_t id_msg, uint64_t date_msg){

    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
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
        db_mutex.unlock();
    }//if

}//delMsg

static const char *  sqlGetMsgType9 =
        "select remote_id_avatar, my_id_avatar"\
        " from t_messages where date_msg=? and id_msg=? and id_group=?";
bool SQLiteDB::getMsg(uint64_t id_group, uint64_t id_msg, uint64_t date_msg,
                        uint64_t * remote_id_avatar, uint64_t * my_id_avatar){
    bool re = false;
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
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
            *remote_id_avatar = sqlite3_column_int64(stmtGetMsgType9, 0);
            *my_id_avatar = sqlite3_column_int64(stmtGetMsgType9, 1);

            re = true;
        } while (false);
        db_mutex.unlock();
    }//if

    return re;
}//getMsg


bool  SQLiteDB::storeNotNeedArray(uint64_t groupID, uint64_t * msgIDsIN, uint64_t * msgDatesIN, uint32_t lenArrayIN, uint64_t remoteAvatarID){
    bool re = false;
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
    //faux loop:
        do {
            if (!stmtAddPath ) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlAddPath, strlen(sqlAddPath),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtAddPath, NULL)) {
                     break;
                 }
            }

            sqlite3_bind_int64(stmtAddPath, 3, groupID);
            sqlite3_bind_int64(stmtAddPath, 4, remoteAvatarID);
            for (uint32_t i=0; i<lenArrayIN; ++i){
                if (SQLITE_OK !=sqlite3_reset(stmtAddPath)){break;}
                sqlite3_bind_int64(stmtAddPath, 1, msgDatesIN[i]);
                sqlite3_bind_int64(stmtAddPath, 2, msgIDsIN[i]);
                sqlite3_step(stmtAddPath);
            }

            re = true;
        } while (false);
        db_mutex.unlock();
    }//if

    return re;
}

static const char *  sqlInsertMsg =
        "insert into t_messages (date_msg,id_msg,id_group,remote_id_avatar,my_id_avatar) values (?,?,?,?,?)";
bool SQLiteDB::storeMessage(uint64_t id_group, uint64_t remote_id_avatar, uint64_t my_id_avatar,
                              uint64_t id_msg, uint64_t date_msg){
    bool re = false;
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
    //faux loop:
        do {
            if (!stmtInsertMsg || SQLITE_OK !=sqlite3_reset(stmtInsertMsg)) {
                //const char *pzTest;
                 if (SQLITE_OK != sqlite3_prepare_v3(db, sqlInsertMsg, strlen(sqlInsertMsg),
                                                     SQLITE_PREPARE_PERSISTENT, &stmtInsertMsg, NULL)) {
                     break;
                 }
            }
            sqlite3_bind_int64(stmtInsertMsg, 1, date_msg);
            sqlite3_bind_int64(stmtInsertMsg, 2, id_msg);
            sqlite3_bind_int64(stmtInsertMsg, 3, id_group);
            sqlite3_bind_int64(stmtInsertMsg, 4, remote_id_avatar);
            sqlite3_bind_int64(stmtInsertMsg, 5, my_id_avatar);
            sqlite3_step(stmtInsertMsg);
            re = true;
        } while (false);
        db_mutex.unlock();
    }//if

    return re;
}




bool  SQLiteDB::templateQuery(){
    bool re = false;
    if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
    //faux loop:
        do {


            re = true;
        } while (false);
        db_mutex.unlock();
    }//if

    return re;
}


