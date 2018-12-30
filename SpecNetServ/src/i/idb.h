/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef IDB_H
#define IDB_H

#include <stdint.h>


class Idb {
 public:
  virtual ~Idb() {}
    //Working
  virtual  bool  start()  =  0;
  virtual  void  stop()  =  0;
  virtual  bool  execSQL(const char * sql)  =  0;
  virtual  bool  getNewMessages(int64_t  groupID,  int64_t  avatarID,
    int64_t  curTime,  int64_t  grpMailLife,  int64_t  avaMailLife,
    int64_t  *msgIDs,  int64_t  *msgDates,  uint32_t  *resRows)  =  0;
  virtual  bool  getNeedMessages(int64_t  groupID,
    uint64_t  *msgIDsIN,  uint64_t  *msgDatesIN,  uint32_t  lenArrayIN,
    int64_t  *msgIDsNEED,  int64_t  *msgDatesNEED,  uint32_t  *resRowsNEED,
    int64_t  *msgIDsNotNEED,  int64_t  *msgDatesNotNEED,
    uint32_t  *resRowsNotNEED)  =  0;
    virtual  void  delMsg(int64_t  id_group,  int64_t  id_msg,  int64_t  date_msg) = 0;
    virtual  bool  getMsg(int64_t  id_group,  int64_t  id_msg,  int64_t date_msg,
      uint64_t  *remote_id_avatar,  uint64_t  *my_id_avatar)  =  0;
    virtual  bool  addPath(int64_t  date_msg,  int64_t  id_msg,
      int64_t  groupID, int64_t remoteAvatarID)  =  0;
    virtual  bool  storeNotNeedArray(int64_t  groupID,
      uint64_t  *msgIDsIN,  uint64_t  *msgDatesIN,
      uint32_t  lenArrayIN,  int64_t  remoteAvatarID)  =  0;
    virtual  bool  storeMessage(int64_t  id_group,
      int64_t  remote_id_avatar,  int64_t  my_id_avatar,
      int64_t  id_msg,  int64_t  date_msg)  =  0;

};
#endif // IDB_H
