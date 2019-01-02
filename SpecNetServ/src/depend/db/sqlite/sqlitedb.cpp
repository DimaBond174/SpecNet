/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include "sqlitedb.h"
#include "spec/speccontext.h"
#include "spec/specstatic.h"
#include "string.h"

SQLiteDB::SQLiteDB()  {

}

bool  SQLiteDB::start()  {
  bool  re  =  false;
  if  (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME)))  {
    //faux loop:
    do  {
      SpecContext  &sr  =  SpecContext::instance();
      iLog  =  sr.iLog.get();
      int  res  =  sqlite3_threadsafe();
      iLog->log("i",  "[SQLiteDB::start]: %i==sqlite3_threadsafe()",  res);
      const  std::string  &dbPath  =
        sr.iFileAdapter.get()->toFullPath(
          sr.iConfig.get()->getStringValue("SQLitePath").c_str());
      if (dbPath.empty())  {  break;  }
      sr.iFileAdapter.get()->mkdirs(sr.iFileAdapter.get()->getDir(dbPath));
      if (SQLITE_OK  !=  sqlite3_open_v2(dbPath.c_str(),  &db,
          SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE,  nullptr))  {
        break;
      }
      if (!checkDBVersion())  {  break;  }
      re = true;
    } while (false);
    db_mutex.unlock();
  }//if
  return re;
}//start()

void  SQLiteDB::stop()  {
  if (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME)))  {
    if  (db)  {
      if  (stmtGetNeedMessages)  {
        sqlite3_finalize(stmtGetNeedMessages);
        stmtGetNeedMessages  =  nullptr;
      }
      if  (stmtGetNewMessages)  {
        sqlite3_finalize(stmtGetNewMessages);
        stmtGetNewMessages  =  nullptr;
      }
      if  (stmtAddPath)  {
        sqlite3_finalize(stmtAddPath);
        stmtAddPath  =  nullptr;
      }
      sqlite3_close_v2(db);
    }
    db_mutex.unlock();
  }
}//stop()

bool  SQLiteDB::checkDBVersion()  {
  int  version  =  0;
  bool  re  =  false;
  //dropDB(); //for debug creation //TODO delete this line
  sqlite3_stmt  *stmt  =  nullptr;
//  int  ret  =  sqlite3_prepare_v2(db,
//    "SELECT version FROM t_version", -1, &stmt, NULL);
  static constexpr  ConstString  sql  {
    "SELECT version FROM t_version"
  };
  int  ret  =  sqlite3_prepare_v2(db,  sql.c_str,  sql.size,  &stmt,  NULL);

  if  (SQLITE_OK==ret  &&  SQLITE_ROW==sqlite3_step(stmt))  {
    version  =  sqlite3_column_int(stmt,  0);
  }
  sqlite3_finalize(stmt);

  if  (0==version)  {
    re  =  createDB();
  }  else if  (version!=DB_VERSION)  {
    re  =  updateDB(version);
  }  else  {
    re  =  true;
  }
  return re;
} //checkDBVersion

bool  SQLiteDB::execSQL(const char  *sql)  {
  return  _execSQL(sql);
}

bool  SQLiteDB::_execSQL(const char  *sql)  {
  bool  re  =  false;
  char  *zErrMsg  =  0;
  if  (SQLITE_OK == sqlite3_exec(db,  sql,  callbackSQLite3,  0,  &zErrMsg))  {
    re  =  true;
  }  else  {
    SpecContext::instance().iLog.get()->
      log("e",  "[SQLiteDB]:[%s]:\n %s",  sql,  sqlite3_errmsg(db));
    sqlite3_free(zErrMsg);
  }
  return re;
}

bool  SQLiteDB::createDB()  {
  bool  re  =  false;
  const  int  nsql  =  6;
  const  char  *sql[nsql]  =  {
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
  int  i  =  0;
  for (  ;  i  <  nsql;  ++i)  {
    if  (!_execSQL (sql[i]))  {  break;  }
  }  //for
  if  (i>=nsql)  {
    std::string str("INSERT INTO t_version (version) values(");
    str.append(std::to_string(DB_VERSION)).append(");");
    re = _execSQL(str.c_str());
  }
  return re;
}

bool  SQLiteDB::updateDB(int  curVersion)  {
  while  (DB_VERSION != curVersion)  {
    switch  (curVersion)  {
    case  1:
/* if can update, do update */
         //   break;
    default:
/* if can't update, recreate */
      dropDB();
      if  (createDB())  {
        curVersion  =  DB_VERSION;
      }
      return DB_VERSION == curVersion;
            //break;
    }//switch
  }//while

  return DB_VERSION == curVersion;
}

void  SQLiteDB::dropDB()  {
  const  int  nsql  =  5;
  const  char  *sql[nsql]  =  {
    "DROP TABLE IF EXISTS t_version",
    "DROP TABLE IF EXISTS t_groups",
    "DROP TABLE IF EXISTS t_avatars",
    "DROP TABLE IF EXISTS t_messages",
    "DROP TABLE IF EXISTS t_path"
  };
  for  (int  i  =  0;  i < nsql;  ++i)  {
    _execSQL(sql[i]);
  }
  return;
}

int  SQLiteDB::callbackSQLite3(void  *NotUsed,  int  argc,  char **argv,
    char **azColName)  {
  std::string str;
  for  (int  i  =  0;  i<argc;  ++i)  {
    str.append(azColName[i])
      .append(" = ")
      .append((argv[i])?  argv[i]  :  "NULL")
      .append("\n");
  }
  str.append("\n");
  SpecContext::instance().iLog.get()->log("i",str.c_str());
  return 0;
}

//TODO передавать только личные сообщения адресату или в группу

//static const char *  sqlGetNewMessages =
//        "select t1.date_msg, t1.id_msg from t_messages t1"\
//        " left outer join t_path t2"\
//        " on t1.date_msg=t2.date_msg and t1.id_msg=t2.id_msg"\
//        " and t1.id_group=?1"\
//        " and t2.id_group=t1.id_group and t2.id_avatar=?2"\
//        " where t2.id_avatar is null "\
//        " and (t1.remote_id_avatar=0 and t1.date_msg>?3"\
//        " or t1.remote_id_avatar=?4 and t1.date_msg>?5"\
//        ") and t1.date_msg<?6";

bool  SQLiteDB::getNewMessages(int64_t  groupID,  int64_t  avatarID,
    int64_t  curTime,  int64_t  grpMailLife,  int64_t  avaMailLife,
    int64_t  *msgIDs,  int64_t  *msgDates,  uint32_t  *resRows)  {

  static constexpr  ConstString  sql  {
    "SELECT t1.date_msg, t1.id_msg FROM t_messages t1"\
    " LEFT OUTER JOIN t_path t2"\
      " ON t1.date_msg=t2.date_msg AND t1.id_msg=t2.id_msg"\        
        " AND t2.id_group=t1.id_group"\
        " AND t2.id_avatar=?1"\
    " WHERE t1.id_group=?2"\
    " AND t2.id_avatar IS NULL"\
      " AND (t1.remote_id_avatar=0 AND t1.date_msg>?3"\
        " OR t1.remote_id_avatar=?4 AND t1.date_msg>?5"\
      ") AND t1.date_msg<?6"
  };

  bool  re  =  false;
  if  (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME)))  {
    //faux loop:
    do  {
      if  (!stmtGetNewMessages  ||  SQLITE_OK != sqlite3_reset(stmtGetNewMessages))  {
        if  (SQLITE_OK  !=  sqlite3_prepare_v3(db,
            sql.c_str,  sql.size,  SQLITE_PREPARE_PERSISTENT,
            &stmtGetNewMessages,  NULL))  {
          break;
        }  //if sqlite3_prepare_v3
      }  //if !stmtGetNewMessages
      sqlite3_bind_int64(stmtGetNewMessages,  1,  avatarID);
      sqlite3_bind_int64(stmtGetNewMessages,  2,  groupID);
      sqlite3_bind_int64(stmtGetNewMessages,  3,  grpMailLife);
      sqlite3_bind_int64(stmtGetNewMessages,  4,  avatarID);
      sqlite3_bind_int64(stmtGetNewMessages,  5,  avaMailLife);
      sqlite3_bind_int64(stmtGetNewMessages,  6,  curTime);
      uint32_t i=0;
      while  (i<MAX_SelectRows  &&  SQLITE_ROW==sqlite3_step(stmtGetNewMessages))  {
        msgDates[i]  =  sqlite3_column_int64(stmtGetNewMessages,  0);
        msgIDs[i]  =  sqlite3_column_int64(stmtGetNewMessages,  1);
        ++i;
      }  //while
      *resRows  =  i;
      re  =  true;
    } while (false);
    db_mutex.unlock();
  }  //if db_mutex
  return  re;
}  //getNewMessages

//static const char *  sqlAddPath = "insert into t_path (date_msg, id_msg, id_group, id_avatar) values (?,?,?,?)";
/*  Remembers who already received mail  */
bool  SQLiteDB::addPath(int64_t  date_msg,  int64_t  id_msg,  int64_t  groupID, int64_t remoteAvatarID)  {
  static constexpr  ConstString  sql  {
    "INSERT INTO t_path (date_msg, id_msg, id_group, id_avatar) VALUES (?,?,?,?)"
  };
  bool  re  =  false;
  if  (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME)))  {
    //faux loop:
    do  {
      if  (!stmtAddPath  ||  SQLITE_OK != sqlite3_reset(stmtAddPath))  {
        if  (SQLITE_OK  !=  sqlite3_prepare_v3(db,
            sql.c_str,  sql.size,  SQLITE_PREPARE_PERSISTENT,
            &stmtAddPath,  NULL))  {
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
  }  //if  db_mutex
  return  re;
} //addPath

//static const char *  sqlGetNeedMessages =
//        "select id_msg from t_messages where date_msg=? and id_msg=? and id_group=?";
bool  SQLiteDB::getNeedMessages(int64_t  groupID,
      uint64_t  *msgIDsIN,  uint64_t  *msgDatesIN,  uint32_t  lenArrayIN,
      int64_t  *msgIDsNEED,  int64_t  *msgDatesNEED,  uint32_t  *resRowsNEED,
      int64_t  *msgIDsNotNEED,  int64_t  *msgDatesNotNEED,  uint32_t  *resRowsNotNEED)  {
  static constexpr  ConstString  sql  {
    "SELECT id_msg FROM t_messages"\
    " WHERE date_msg=?1 AND id_msg=?2 AND id_group=?3"
  };
  bool  re  =  false;
  if  (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME)))  {
    //faux loop:
      do  {
        if  (!stmtGetNeedMessages)  {
          if (SQLITE_OK  !=  sqlite3_prepare_v3(db,  sql.c_str,
              sql.size,  SQLITE_PREPARE_PERSISTENT,
              &stmtGetNeedMessages,  NULL))  {
            break;
          }
        }
        uint32_t  needN  =  0;
        uint32_t  notNeedN  =  0;
        sqlite3_bind_int64(stmtGetNeedMessages,  3,  groupID);
        int64_t  dateIn;
        int64_t  idIn;
        for  (uint32_t  i  =  0;  i<lenArrayIN;  ++i )  {
          if  (SQLITE_OK  !=  sqlite3_reset(stmtGetNeedMessages))  {
            break;
          }
          dateIn  =  static_cast<int64_t>(msgDatesIN[i]);
          idIn  =  static_cast<int64_t>(msgIDsIN[i]);
          sqlite3_bind_int64(stmtGetNeedMessages,  1,  dateIn);
          sqlite3_bind_int64(stmtGetNeedMessages,  2,  idIn);
          //if not exists:
          if  (SQLITE_ROW  ==  sqlite3_step(stmtGetNeedMessages))  {
            msgIDsNotNEED[notNeedN]  =  idIn;
            msgDatesNotNEED[notNeedN]  =  dateIn;
            ++notNeedN;
          }  else  {
            msgIDsNEED[needN]  =  idIn;
            msgDatesNEED[needN]  =  dateIn;
            ++needN;
          }
        }//for

        *resRowsNEED = needN;
        *resRowsNotNEED = notNeedN;
        re = true;
    } while (false);
    db_mutex.unlock();
  }  //if db_mutex
  return re;
}//getNeedMessages


void  SQLiteDB::delMsg(int64_t  id_group,  int64_t  id_msg,  int64_t  date_msg)  {
  static constexpr ConstString  sqlDelMsg  {
    "DELETE FROM t_messages"\
    " WHERE date_msg=?1 AND id_msg=?2 AND id_group=?3"
  };
  static constexpr ConstString  sqlDelPath  {
    "DELETE FROM t_path"\
    " WHERE date_msg=?1 AND id_msg=?2 AND id_group=?3"
  };  
  if  (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME)))  {
    //faux loop:
    do  {
      if (!stmtDelMsg || SQLITE_OK !=sqlite3_reset(stmtDelMsg)) {
        if  (SQLITE_OK  !=  sqlite3_prepare_v3(db,  sqlDelMsg.c_str,  sqlDelMsg.size,
            SQLITE_PREPARE_PERSISTENT,  &stmtDelMsg,  NULL))  {
          break;
        }
      }
      sqlite3_bind_int64(stmtDelMsg, 1, date_msg);
      sqlite3_bind_int64(stmtDelMsg, 2, id_msg);
      sqlite3_bind_int64(stmtDelMsg, 3, id_group);
      sqlite3_step(stmtDelMsg);

      if (!stmtDelPath || SQLITE_OK !=sqlite3_reset(stmtDelPath)) {
        if  (SQLITE_OK  !=  sqlite3_prepare_v3(db,  sqlDelPath.c_str,  sqlDelPath.size,
            SQLITE_PREPARE_PERSISTENT,  &stmtDelPath,  NULL))  {
          break;
        }
      }
      sqlite3_bind_int64(stmtDelPath, 1, date_msg);
      sqlite3_bind_int64(stmtDelPath, 2, id_msg);
      sqlite3_bind_int64(stmtDelPath, 3, id_group);
      sqlite3_step(stmtDelPath);

    } while (false);
    db_mutex.unlock();
  }//if
}//delMsg

static const char *  sqlGetMsgType9 =
        "select remote_id_avatar, my_id_avatar"\
        " from t_messages where date_msg=? and id_msg=? and id_group=?";
bool SQLiteDB::getMsg(int64_t id_group, int64_t id_msg, int64_t date_msg,
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


bool  SQLiteDB::storeNotNeedArray(int64_t  groupID,
    uint64_t  *msgIDsIN,  uint64_t  *msgDatesIN,  uint32_t  lenArrayIN,
    int64_t  remoteAvatarID)  {
  static constexpr  ConstString  sql  {
    "INSERT INTO t_path (date_msg, id_msg, id_group, id_avatar) VALUES (?1,?2,?3,?4)"
  };
  bool  re  =  false;
  if  (db_mutex.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME)))  {
    //faux loop:
    do  {
      if  (!stmtAddPath)  {
        if  (SQLITE_OK  !=  sqlite3_prepare_v3(db,
            sql.c_str, sql.size,  SQLITE_PREPARE_PERSISTENT,
            &stmtAddPath,  NULL))  {
          break;
        }
      }
      sqlite3_bind_int64(stmtAddPath,  3,  groupID);
      sqlite3_bind_int64(stmtAddPath,  4,  remoteAvatarID);
      for  (uint32_t  i  =  0;  i<lenArrayIN;  ++i)  {
        if  (SQLITE_OK  !=  sqlite3_reset(stmtAddPath))  {  break;  }
        sqlite3_bind_int64(stmtAddPath,  1,  static_cast<int64_t>(msgDatesIN[i]));
        sqlite3_bind_int64(stmtAddPath,  2,  static_cast<int64_t>(msgIDsIN[i]));
        sqlite3_step(stmtAddPath);
      }
      re = true;
    } while (false);
    db_mutex.unlock();
  }  //if  db_mutex
  return re;
}  //storeNotNeedArray

static const char *  sqlInsertMsg =
        "insert into t_messages (date_msg,id_msg,id_group,remote_id_avatar,my_id_avatar) values (?,?,?,?,?)";
bool SQLiteDB::storeMessage(int64_t id_group, int64_t remote_id_avatar, int64_t my_id_avatar,
                              int64_t id_msg, int64_t date_msg){
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


