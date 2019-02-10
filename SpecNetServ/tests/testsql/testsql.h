/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef TestSQL_H
#define TestSQL_H

#include <string>
#include "i/ilib.h"
#include "i/ifileadapter.h"
#include "i/ipack.h"

class  TestSQL  :  public ILib  {
 public:
  TestSQL()  {  }
  virtual  ~TestSQL()  {  }
  virtual bool  start(const char  *serverName,  const char  *pathBase,
    IFileAdapter  *iFileAdapter,  int64_t  tmpGUID)  =  0;
  virtual void  stop()  =  0;
  virtual bool  storeMessage(int64_t  id_group,  int64_t  remote_id_avatar,
    int64_t  my_id_avatar,  int64_t  id_msg,  int64_t  date_msg,  const char  *data,  uint32_t  len)  =  0;
  virtual bool  getNewMessages(int64_t  groupID,  int64_t  *msgIDs,
    int64_t  *msgDates,  uint32_t  *resRows)  =  0;
  virtual bool  getNeedMessages(int64_t  groupID,  uint64_t  *msgIDsIN,
    uint64_t  *msgDatesIN,  uint32_t  lenArrayIN,  int64_t  *msgIDsNEED,
    int64_t  *msgDatesNEED,  uint32_t  *resRowsNEED,  int64_t  *msgIDsNotNEED,
    int64_t  *msgDatesNotNEED,  uint32_t  *resRowsNotNEED)  =  0;
  virtual bool  storeNotNeed(int64_t  groupID,  int64_t  msgIDs,  int64_t  msgDate)  =  0;
  virtual bool  storeNotNeedArray(int64_t  groupID,  uint64_t  *msgIDsIN, uint64_t * msgDatesIN,
    uint32_t  lenArrayIN)  =  0;
  virtual IPack * getMsgType9(int64_t  id_group,  int64_t  id_msg,  int64_t  date_msg)  =  0;
  virtual void  insertNewAvatar(int64_t  id_group,  int64_t  id_avatar,  int64_t  status)  =  0;
  virtual bool  existAvatar(int64_t  id_group, int64_t  id_avatar)  =  0;
};



#endif // TestSQL_H
