/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef IPACK_H
#define IPACK_H
#if defined(Windows)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include "string.h"
#include <string>
#ifdef Debug
    #include <assert.h>
#endif
#include "spec/specstatic.h"
#include <cmath>
#include <cassert>

#define SPEC_MARK_S 2109201808
//#define SPEC_MARK_E 1510201815
//#define SPEC_LEN_HEAD_1  (sizeof(uint32_t))
//constexpr int SPEC_LEN_HEAD_2 = sizeof(uint32_t)+sizeof(uint32_t);
//constexpr int SPEC_LEN_HEAD_3 = 3 * sizeof(uint32_t);
//constexpr int SPEC_LEN_HEAD_4 = 4 * sizeof(uint32_t);

constexpr uint32_t SIZE_2x_uint64_t = sizeof(uint64_t) * 2;

#define  MAX_CHANK  204800


static const bool NO_NEED_hton = (1==htonl(1));
static const bool NO_NEED_ntoh = (1==ntohl(1));
#define _HTONL(x) (NO_NEED_hton ? (x) : htonl(x))
#define _NTOHL(x) (NO_NEED_ntoh ? (x) : ntohl(x))
#define _HTONLL(x) (NO_NEED_hton ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
#define _NTOHLL(x) (NO_NEED_ntoh ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))
//#define HTONLL(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
//#define NTOHLL(x) ((1==ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))
static const uint32_t N_SPEC_MARK_S = _HTONL(SPEC_MARK_S);
//static uint32_t N_SPEC_MARK_E = _HTONL(SPEC_MARK_E);


/* Conversation protocol between server and client */
//The client sends a list of all the groups in which he is a member:
#define  SPEC_PACK_TYPE_11  11

//The client sends a one of their membership in the groups:
#define  SPEC_PACK_TYPE_1  1

//The server  requests unknown certificate X509 (or not):
#define  SPEC_PACK_TYPE_2  2

//The client sends certificates:
#define  SPEC_PACK_TYPE_3  3

//The server sends a test cryptographic task for certificate to check if PKEY exists:
//If the server does not serve this group, then the job will be empty
#define  SPEC_PACK_TYPE_4  4

//The client sends answer for the test cryptographic task:
#define  SPEC_PACK_TYPE_5  5

//The server send OK to work == list of the new mail:
//The client sends list of the new mail too:
#define  SPEC_PACK_TYPE_6  6
static  const  uint32_t  N_SPEC_PACK_TYPE_6  =  _HTONL(SPEC_PACK_TYPE_6);

//The server and client answers with a list of the needed mail :
#define  SPEC_PACK_TYPE_7  7
static  const  uint32_t  N_SPEC_PACK_TYPE_7  =  _HTONL(SPEC_PACK_TYPE_7);

//The server and client answers with a list of the unnecessary mail:
#define  SPEC_PACK_TYPE_8  8

//The server and client sends a requested mail:
#define  SPEC_PACK_TYPE_9  9
static  const  uint32_t  N_SPEC_PACK_TYPE_9  =  _HTONL(SPEC_PACK_TYPE_9);

//The server and client sends a delivery confirmation:
#define  SPEC_PACK_TYPE_10  10
static  const  uint32_t  N_SPEC_PACK_TYPE_10  =  _HTONL(SPEC_PACK_TYPE_10);

//If the client detects unknown senders in the mail,
//it requests the certificates of these senders with
//SPEC_PACK_TYPE_2 request, and the server responds with SPEC_PACK_TYPE_3

//Any packet starts with header
//and Body next if body_len>0
//struct {
//    uint32_t spec_mark;
//    uint32_t body_len;  //without T_IPack0_Header
//    uint32_t pack_type;
//    uint64_t key1;
//    uint64_t key2;
//    uint64_t key3;
//} typedef T_IPack0_Network;

#define SKIPHEIGHT 5
struct  {
  uint32_t  spec_mark;
  uint32_t  body_len;
  uint32_t  pack_type;
  uint64_t  key1;
  uint64_t  key2;
  uint64_t  key3;
}  typedef  TKey;

using T_IPack0_Network = TKey;

class  IPack  {
 public:
  IPack * nextIStack; //IStack interface (faster than vtable)
  ~IPack()  {
    if  (body)  {  free(body);  }
    guard  =  0;
  }

  bool  delete_after_send  =  true;
//  Common header:
  T_IPack0_Network  header;
//  Common packet:
  char  *  body  =  nullptr;
//  Guard: TODO delete it:
  uint32_t  guard  =  20190101;
};

class IPack0
{
public:
    static bool toHost(T_IPack0_Network * header){
        if (N_SPEC_MARK_S==header->spec_mark){
            header->body_len = _NTOHL(header->body_len);
            if (MAX_CHANK<header->body_len) { return false;}
            header->pack_type = _NTOHL(header->pack_type);
            header->key1 = _NTOHLL(header->key1);
            header->key2 = _NTOHLL(header->key2);
            header->key3 = _NTOHLL(header->key3);
            return true;
        }
        return false;
    }

    static void toNetwork(T_IPack0_Network & header){
        header.spec_mark = N_SPEC_MARK_S;
        header.body_len = _HTONL(header.body_len);
        header.pack_type = _HTONL(header.pack_type);
        header.key1 = _HTONLL(header.key1);
        header.key2 = _HTONLL(header.key2);
        header.key3 = _HTONLL(header.key3);
    }


//    static char * eatPacket(IAlloc * iAlloc, char * packet) {
//        T_IPack0_Network * in = (T_IPack0_Network *)packet;
//        char * re = nullptr;
//        if (N_SPEC_MARK_S==in->spec_mark){
//            uint32_t size = _NTOHL(in->pack_len);
//            if (size>0 && size<MAX_CHANK) {
//                re = (char *)iAlloc->specAlloc(size);
//                if (re) {
//                    T_IPack0_Network * out = (T_IPack0_Network *)re;
//                    out->pack_len = size;
//                    out->spec_mark = SPEC_MARK_S;
//                    out->pack_type = _NTOHL(in->pack_type);
//                }
//            }
//        }

//        return re;
//    }

//    /* for internal trusted use */
//    static uint32_t lenPacket(char * packet) {
//        uint32_t * headers = (uint32_t *)packet;
//        uint32_t re = _NTOHL(headers[1]);
//        if (re>MAX_CHANK) { re = 0;}
//        return re;
//    }

//    /* from packet to send with SPEC_MARK */
//    static uint32_t getTypeOut(char * packet) {
//        uint32_t * headers = (uint32_t *)packet;
//        return _NTOHL(headers[2]);
//    }

//    /* after receiving for header without SPEC_MARK */
//    static uint32_t getTypeIn(char * packet) {
//        uint32_t * headers = (uint32_t *)packet;
//        return _NTOHL(headers[1]);
//    }

    /*
     * Preparing standard headers
     * packet = buf where first bytes for headers
     * len  = meaning data lenght without headers lenght
     * type = type of the packet
     * !!! Packet {lenght} should be without lenHead0 when creating !!! */
//    static void setHeaders(void * packet, uint32_t len, uint32_t type){
//    static void setHeader(T_IPack0_Network &header, uint32_t len, uint32_t type){
//        header.spec_mark = N_SPEC_MARK_S;
//        header.pack_len = _HTONL(len);
//        header.pack_type = _HTONL(type);
//    }

};

//class IPack111
//{
//public:
//    static char * createPacket(IAlloc * iAlloc, const char * str, uint32_t len) {
//        /* alloc for data + headers */
//        char * re = (char *)iAlloc->specAlloc(len+SPEC_LEN_HEAD_3);
//        if (re) {
//            IPack0::setHeaders(re, len, 1);
//            memcpy(re+SPEC_LEN_HEAD_3, str, len);

//            /* headers to see */
////            uint32_t * headers = (uint32_t *)re;
////            long metka = ntohl(headers[0]);
////            long size = ntohl(headers[1]);
////            long type = ntohl(headers[2]);
////            headers = nullptr;
//        }
//        return re;
//    }

//    static std::string parsePack(const char * pack){
//        uint32_t len = *((uint32_t*)(pack));
//        if (len > 0 && len < MAX_CHANK) {
//            return std::string(pack + SPEC_LEN_HEAD_2, len - SPEC_LEN_HEAD_1);
//        }
//        return std::string();
//    }

//};



/*
 * IPack1
 * =Type1 - Client tells about membership
 * =Type2 - Server or client asks for cert X509
*/
//struct {
//    uint64_t groupID;
//    uint64_t avatarID;
//} typedef T_IPack1_struct;

//struct {
//    T_IPack0_Network header;
//    uint64_t groupID;
//    uint64_t avatarID;
//} typedef T_IPack1_Network;



class IPack1
{    
public:

    static  IPack * createPacket(uint64_t groupID, uint64_t avatarID,  uint32_t type) {
        IPack * re = new IPack();
        re->header.body_len = 0;
        re->header.pack_type = type;
        re->header.key1 = groupID;
        re->header.key2 = avatarID;
        re->header.key3 = 0;
        IPack0::toNetwork(re->header);
        return re;
    }
};

/*
 * IPack3
 * =Type3 - Client answers with X509
 * =Type4 - Server's test cryptographic task
 * =Type5 - Client answer with cryptographic result
*/
//struct {
//    uint32_t  strLen;
//    uint64_t  guid1;
//    uint64_t  guid2;
//    const char * str;
//} typedef T_IPack3_struct;

//struct {
//    T_IPack0_Network header;
//    uint32_t  strLen;
//    uint64_t  guid1;
//    uint64_t  guid2;
//} typedef T_IPack3_Network;

class IPack3
{
public:
    static  void toIPack3(IPack * pack,
                                const char * body, uint32_t  bodyLen,
                                uint32_t type) {
        pack->header.body_len = bodyLen;
        pack->header.pack_type = type;
        IPack0::toNetwork(pack->header);
        if (pack->body) { free(pack->body);}
        pack->body = static_cast<char *>(malloc(bodyLen));
        memcpy((void *)(pack->body), body, bodyLen);
    }

    static  IPack * createPacket(uint64_t  guid1, uint64_t  guid2,
                                const char * body, uint32_t  bodyLen,
                                uint32_t type) {
        IPack * re = new IPack();
        re->header.body_len = bodyLen;
        re->header.pack_type = type;
        re->header.key1 = guid1;
        re->header.key2 = guid2;
        re->header.key3 = 0;
        IPack0::toNetwork(re->header);
        re->body = static_cast<char *>(malloc(bodyLen));
        memcpy((void *)(re->body), body, bodyLen);
        return re;
    }

//    static IPack * createPacket(IAlloc * iAlloc, T_IPack3_struct & iStruct, uint32_t type) {
//        /* alloc for data + headers */
//        uint32_t size = sizeof(T_IPack3_Network)
//                + iStruct.strLen
//                + sizeof(uint32_t);//endMark
//        char * re = (char *)iAlloc->specAlloc(size);
//        if (re) {
//        //Mark end of packet:
//            uint32_t * endMark =(uint32_t *)(re + size - sizeof(uint32_t));
//            *endMark = N_SPEC_MARK_E;
//            T_IPack3_Network * pack = (T_IPack3_Network *)re;
//            IPack0::setHeader(pack->header, size, type);
//            pack->strLen = _HTONL(iStruct.strLen);
//            pack->guid1  = _HTONLL(iStruct.guid1);
//            pack->guid2  = _HTONLL(iStruct.guid2);
//            if (iStruct.strLen>0) {
//                memcpy((void *)(re+sizeof(T_IPack3_Network)), iStruct.str, iStruct.strLen);
//            }
//        #ifdef Debug
//        //Template for check overflow:
//                assert(N_SPEC_MARK_E==*endMark);
//        #endif
//        }
//        return re;
//    }


//     static bool parsePackI(T_IPack3_struct & res, const char * pack){
//        bool re = false;
//        //faux loop
//        do {
//            T_IPack3_Network * in = (T_IPack3_Network *)pack;
//            if (sizeof(T_IPack3_Network) > in->header.pack_len) {break;}
//            res.strLen = _NTOHL(in->strLen);
//            if (res.strLen > MAX_CHANK) { break; }
//            res.guid1  = _NTOHLL(in->guid1);
//            res.guid2  = _NTOHLL(in->guid2);
//            if (0==res.strLen) {
//                res.str = nullptr;
//            } else {
//                res.str = (const char *)(pack + sizeof(T_IPack3_Network));
//            }
//            re = true;
//        } while (false);

//        return re;
//    }

}; //IPack3


/*
 * IPack6
 * = Type6 - Server OK to work and new mail array
 * = Type7 - Wanted mail
 * = Type8 - UnWanted mail
*/

struct {
    uint32_t  lenArray;
    uint64_t  groupID;
    uint64_t * guid1s; //msgID
    uint64_t * guid2s; //msgDate
} typedef T_IPack6_struct;

//struct {
//    T_IPack0_Network header;
//    uint32_t  lenArray;
//    uint64_t  groupID;
//} typedef T_IPack6_Network;


class  IPack6  {
 public:
  static  void  toIPack6(IPack  *pack,
      uint32_t  lenArray,
      int64_t  groupID,
      int64_t  *guid1s,
      int64_t  *guid2s,
      uint32_t  type)  {
    pack->header.pack_type  =  type;
    pack->header.key1 = groupID;
    if  (pack->body)  {
      free(pack->body);
      pack->body  =  nullptr;
    }

    if  (0==lenArray)  {
      pack->header.body_len  =  0;
      pack->header.key2  =  0;
      pack->header.key3  =  0;
    }  else if  (1==lenArray)  {
      pack->header.body_len  =  0;
      pack->header.key2  =  guid1s[0];
      pack->header.key3  =  guid2s[0];
    } else {
      uint32_t  size  =  lenArray * SIZE_2x_uint64_t;
      pack->header.body_len  =  size;
      pack->header.key2  =  0;
      pack->header.key3  =  0;
      pack->body  =  static_cast<char *>(malloc(size));
      uint64_t  *guid1sN  =  (uint64_t *)(pack->body);
      uint64_t  *guid2sN  =  guid1sN + lenArray;
      uint64_t tmp;
      for  (uint32_t  i=0;  i<lenArray;  ++i)  {
        tmp  =  guid1s[i];
        guid1sN[i]  =  _HTONLL(tmp);
        tmp  =  guid2s[i];
        guid2sN[i]  =  _HTONLL(tmp);
      }
    }
    IPack0::toNetwork(pack->header);
  } //toIPack6

  static  IPack * createPacket(
      uint32_t lenArray,
      int64_t groupID,
      int64_t * guid1s,
      int64_t * guid2s,
      uint32_t type) {
    IPack * re  =  new  IPack();
    re->header.pack_type  =  type;
    re->header.key1  =  groupID;
    if (0==lenArray)  {
      re->header.body_len  =  0;
      re->header.key2  =  0;
      re->header.key3  =  0;
    } else if  (1==lenArray)  {
      re->header.body_len  =  0;
      re->header.key2  =  guid1s[0];
      re->header.key3  =  guid2s[0];
    } else {
      uint32_t size  =  lenArray * SIZE_2x_uint64_t;
      re->header.body_len  =  size;
      re->header.key2  =  0;
      re->header.key3  =  0;
      re->body  =  static_cast<char *>(malloc(size));
      uint64_t  *guid1sN  =  reinterpret_cast<uint64_t *>(re->body);
      uint64_t  *guid2sN  =  guid1sN + lenArray;
      for  (uint32_t  i  =  0;  i<lenArray;  ++i)  {
        guid1sN[i]  =  _HTONLL(guid1s[i]);
        guid2sN[i]  =  _HTONLL(guid2s[i]);
      }
    }
    IPack0::toNetwork(re->header);
    return re;
  }

  static  bool  parsePackI(T_IPack6_struct  &res,  IPack  *pack)  {
    res.groupID  =  pack->header.key1;
    if  (pack->header.body_len > 0)  {
      uint32_t  len  =  pack->header.body_len / SIZE_2x_uint64_t;
      if  (0==len  ||  !pack->body)  { return false;  }
      if  (len > MAX_SelectRows)  {  len  =  MAX_SelectRows;  }
      res.lenArray  =  len;
      res.guid1s  =  reinterpret_cast<uint64_t *>(pack->body);
      res.guid2s  =  res.guid1s  +  len;
      for  (uint32_t  i  =  0;  i<len;  ++i)  {
        res.guid1s[i]  =  _NTOHLL(res.guid1s[i] );
        res.guid2s[i]  =  _NTOHLL(res.guid2s[i] );
      }
    } else {
      res.guid1s  =  &(pack->header.key2);
      res.guid2s  =  &(pack->header.key3);
      res.lenArray  =  pack->header.key2?  1  :  0;
    }
    return true;
  }
}; //IPack6

/*
 * IPack9
 * =Type9 - Mail
 * =Type10 - Delivery confirmation
*/
struct  {
  uint32_t  strLen;
  uint64_t  guid1; //id_group
  uint64_t  guid2; //id_msg
  uint64_t  guid3; //date_msg
  uint64_t  guid4; //remote_id_avatar
  uint64_t  guid5; //my_id_avatar
  const char  *str;
}  typedef  T_IPack9_struct;


class  IPack9  {
 public:
  static  void  toIPack9(IPack  *pack,  T_IPack9_struct  &iStruct,
      uint32_t  type)  {
    if  (pack->body)  {
      free(pack->body);
      pack->body  =  nullptr;
    }
    pack->header.pack_type  =  type;
    pack->header.key1  =  iStruct.guid1;
    pack->header.key2  =  iStruct.guid2;
    pack->header.key3  =  iStruct.guid3;
    uint32_t  len  =  SIZE_2x_uint64_t  +  iStruct.strLen;
    pack->header.body_len  =  len;
    //HTON header:
    IPack0::toNetwork(pack->header);
    pack->body  =  reinterpret_cast<char *>(malloc(len));
    uint64_t  *guidX  =  reinterpret_cast<uint64_t *>(pack->body);
    *guidX  =  _HTONLL(iStruct.guid4);
    ++guidX;
    *guidX  =  _HTONLL(iStruct.guid5);
    if (iStruct.strLen  >  0)  {
      ++guidX;
      memcpy(reinterpret_cast<void *>(guidX), iStruct.str, iStruct.strLen);
    }
  }//toIPack9

  static  IPack * createPacket(T_IPack9_struct  &iStruct,  uint32_t  type)  {
    IPack  *re  =  new  IPack();
    re->header.pack_type  =  type;
    re->header.key1  =  iStruct.guid1;
    re->header.key2  =  iStruct.guid2;
    re->header.key3  =  iStruct.guid3;
    uint32_t  len  =  SIZE_2x_uint64_t  +  iStruct.strLen;
    re->header.body_len  =  len;
    //HTON header:
    IPack0::toNetwork(re->header);
    re->body  =  reinterpret_cast<char *>(malloc(len));
    uint64_t  *guidX  =  reinterpret_cast<uint64_t *>(re->body);
    *guidX  =  _HTONLL(iStruct.guid4);
    ++guidX;
    *guidX  =  _HTONLL(iStruct.guid5);
    if  (iStruct.strLen  >  0)  {
      ++guidX;
      memcpy(reinterpret_cast<void *>(guidX),  iStruct.str,  iStruct.strLen);
    }
    return re;
  }

  static  bool  parsePackI(T_IPack9_struct  &res,  IPack  *pack)  {
    if  (!pack->body  ||  pack->header.body_len<SIZE_2x_uint64_t)  {
      return false;
    }
    res.guid1  =  pack->header.key1;
    res.guid2  =  pack->header.key2;
    res.guid3  =  pack->header.key3;
    uint64_t  *guidX  =  (uint64_t *)(pack->body);
    res.guid4  =  _NTOHLL(*guidX);
    ++guidX;
    res.guid5  =  _NTOHLL(*guidX);
    res.strLen  =  pack->header.body_len  -  SIZE_2x_uint64_t;
    ++guidX;
    res.str  =  reinterpret_cast<const char *>(guidX);
    return true;
  }
}; //IPack9


class  IPack11  {
 public:
  static  IPack * createPacket(
      uint32_t  lenArray,
      uint64_t  *groupIDs,  //std::vector::data()
      uint32_t  type) {
    IPack  *re  =  new  IPack();
    re->header.pack_type  =  type;
    re->header.key1  =  0;
    re->header.key2  =  0;
    re->header.key3  =  0;
    if  (lenArray < 4)  {
      re->header.body_len  =  0;
      if  (lenArray  >  0)  {
        re->header.key1  =  groupIDs[0];
      }
      if  (lenArray  >  1)  {
        re->header.key2  =  groupIDs[1];
      }
      if  (lenArray  ==  3)  {
        re->header.key2  =  groupIDs[2];
      }
    }  else  {
      uint32_t  size  =  lenArray  *  sizeof(uint64_t);
      re->header.body_len  =  size;
      re->body  =  static_cast<char *>(malloc(size));
      uint64_t  *guid1sN  =  reinterpret_cast<uint64_t *>(re->body);
      for  (uint32_t  i  =  0;  i<lenArray;  ++i)  {
        guid1sN[i]  =  _HTONLL(groupIDs[i]);
      }
    }
    IPack0::toNetwork(re->header);
    return re;
  }


  /*  Used to convert the array only if body_len longer than 0  */
  static  void  parsePackI(IPack  *in_pack, int32_t  *out_size)  {
    int32_t  size  =  in_pack->header.body_len / sizeof(uint64_t);
    uint64_t  *guid1sN  =  reinterpret_cast<uint64_t *>(in_pack->body);
    for  (int32_t  i  =  0;  i<size;  ++i)  {
      guid1sN[i]  =  _NTOHLL(guid1sN[i] );
    }
    *out_size  =  size;
    return;
  }
}; //IPack11

/* OnCache */
class  TONode  {
 public:
  TONode  *fwdPtrs[SKIPHEIGHT];
    //rating queue:
  TONode  *mostUseful;
  TONode  *leastUseful;
  TKey  const  *key;
  IPack  *data;
  unsigned  char  curHeight;// ==SKIPHEIGHT-1 to CPU economy
  uint64_t  hash;
};


class  OnCache  {
 public:
    /*
     * capacity - how many elements can store
     * keyLen - memcmp third parameter
     * Key must be part of the stored Value - will deallocate Value only
    */
  OnCache(uint32_t  capacity)
        :_capacity(capacity),
          _hash_baskets(sqrt(capacity)),
          leafSize((_hash_baskets>256)?  _hash_baskets:  256)  {
    init();
  }

  ~OnCache()  {
    clear();
  }

  uint32_t  size()  {
    return  _size;
  }

  IPack * getData(TKey const  *  key)  {
    TONode  *curFound  =  find(key) ;
    if  (curFound)  {
      toTopUsage(curFound);
      return  curFound->data;
    }
    return nullptr;
  }

  /*  put packet in the cache.
   * WARNING:  data must be marked with: data->delete_after_send  =  false;
 */
  void  insertNode  (TKey  const  *key,  IPack  *data)  {
    data->delete_after_send  =  false;
    assert(data->guard  ==  20190101);
    const  uint64_t  hash  =  getHash(key);//key->hash();
    const  uint32_t  basketID  = hash % _hash_baskets;
    int  cmp  =  setll(hash,  key,  basketID);
    if  (0==cmp)  {
      TONode * cur = updatePathOut[0];
      delete  (cur->data);
      cur->data  =  data;
      cur->key  =  key;
      toTopUsage(cur);
    } else {
            //insert new node:
      allocNode(hash, key, data, basketID, cmp);
    }
  }

 private:
  const  uint32_t  _capacity;
  const uint32_t  _hash_baskets;
  const uint32_t  leafSize;
  uint32_t  _size;
  TONode  *baskets;
  TONode  *updatePathOut[SKIPHEIGHT];

    //Allocations:
  TONode  *curLeaf;
  TONode  **curLeaf_NextPtr;
  TONode  **headLeaf;
  uint32_t  leafAllocCounter;

    //Rating queue:
  TONode  headNode;

    //Landscapes
  unsigned char  landscape_h[256];
  unsigned char  *land_h_p;
  unsigned char  landscape_l[256];
  unsigned char  *land_l_p;


  uint64_t  getHash(TKey const  *key)  const  {
    const  uint64_t  re  =  key->key1  +  key->key2  +  key->key3;
    return  (re<9223372036854775807ll)?  re:  (re>>1);
  }

  int  getCmp(TKey const  *first,  TKey const  *other)  const  {
    if  (first->key2  >  other->key2)  return  1;
    if  (first->key2  <  other->key2)  return  -1;

    if  (first->key1  >  other->key1)  return  1;
    if  (first->key1  <  other->key1)  return  -1;

    if  (first->key3  >  first->key3)  return  1;
    if  (first->key3  <  first->key3)  return  -1;
    return 0;
  }

  void  init()  {
        //init basket lvl counters
    const  size_t  size1  =  _hash_baskets * sizeof(unsigned char);
    land_h_p  =  static_cast<unsigned char *>(malloc(size1));
    land_l_p = static_cast<unsigned char *>(malloc(size1));
    memset(land_h_p,  0,  size1);
    memset(land_l_p,  0,  size1);
    landscape_h[0]  =  4;
    landscape_l[0]  =  1;
    const  uint32_t  lvl2jump  =  (sqrt(_hash_baskets));
    const  uint32_t  lvl1jump  =  (sqrt(lvl2jump));
    int  delLvl2  =  lvl2jump + 1;
    int  delLvl1  =  lvl1jump + 1;
    for  (int  i  =  1;  i<255;  ++i)  {
      if  (i % delLvl2  >=  lvl2jump)  {
        landscape_h[i]  =  4;
        landscape_l[i]  =  0;
      }  else if  (i % delLvl1  >=  lvl1jump)  {
        landscape_h[i]  =  3;
        landscape_l[i]  =  1;
      }  else  {
        landscape_h[i]  =  2;
        landscape_l[i]  =  0;
      }
    }  // for
    landscape_l[255]  =  1;
    landscape_h[255]  =  4;

        //init baskets:
    const  size_t  size2  = _hash_baskets  *  sizeof(TONode);
    baskets  =  static_cast<TONode *>(malloc(size2));
    memset(baskets,  0,  size2);
    for  (int  i  =  0;  i<_hash_baskets;  ++i)  {
      baskets[i].curHeight  =  4;
    }

        //init allocations:
    const  size_t  size3  =  sizeof(TONode * )  +  leafSize * sizeof(TONode);
    headLeaf  =  curLeaf_NextPtr  =  static_cast<TONode **>(malloc(size3));
    memset(curLeaf_NextPtr,  0,  size3);
    curLeaf  =  reinterpret_cast<TONode * >(curLeaf_NextPtr + 1);
    *curLeaf_NextPtr  =  nullptr;
    leafAllocCounter  =  0;
    _size  =  0;

        //init rating queue:
    memset(&headNode,  0,  sizeof(TONode));
    headNode.mostUseful  =  &headNode;
    headNode.leastUseful  =  &headNode;
  }  //  init

  void  clear()  {
    deleteLeaf(headLeaf);
    headLeaf  =  nullptr;
    curLeaf  =  nullptr;
    curLeaf_NextPtr  =  nullptr;
    leafAllocCounter  =  0;
    _size  =  0;
    free(baskets);
    free(land_h_p);
    free(land_l_p);
  }

  void  deleteLeaf(TONode  **ptr)  {
    if  (ptr)  {
      if  (*ptr)  {  deleteLeaf(reinterpret_cast<TONode **>(*ptr));  }
      TONode  *node = reinterpret_cast<TONode *>(ptr+1);
      if  (curLeaf == node)  {
        clearNodes(curLeaf,  leafAllocCounter);
        curLeaf  =  nullptr;
        leafAllocCounter  =  0;
      }  else  {
        clearNodes(node,  leafSize);
      }
      free(ptr);
    }
  }

  void allocNode(const  uint64_t  hash,  TKey const  *key,
      IPack  *data,  const  uint32_t  basketID,  int  cmp)  {
    TONode  *re  =  nullptr;
    TONode  *prevHead  =  updatePathOut[0];
    if  (_capacity  >  _size)  {
      if  (leafSize  ==  leafAllocCounter)  {
        *curLeaf_NextPtr  =  static_cast<TONode *>(malloc(sizeof(TONode * ) + leafSize * sizeof(TONode)));
        if  (*curLeaf_NextPtr)  {
                    //if alloc success
          curLeaf_NextPtr  =  reinterpret_cast<TONode **>(*curLeaf_NextPtr);
          curLeaf  =  reinterpret_cast<TONode * >(curLeaf_NextPtr + 1);
          *curLeaf_NextPtr  =  nullptr;
          leafAllocCounter  =  0;
        }
      } //if  (leafSize  ==
      if  (leafSize  >  leafAllocCounter)  {
        re  =  curLeaf  +  leafAllocCounter;
        ++_size;
        ++leafAllocCounter;
      }
    }  //  if  (_capacity  >  _siz
    // if can't alloc - reuse older one:
    if  (!re)  {
            //reuse an older node
      re  =  headNode.leastUseful;
      headNode.leastUseful  =  re->mostUseful;
      re->mostUseful->leastUseful  =  &headNode;
      if  (hash  ==  re->hash)  {
        if  (re  !=  prevHead)  {
          delInSameBasket(re);
          prevHead  =  updatePathOut[0];
        } //else will replace at place
      }  else if  (basketID  ==  (re->hash % _hash_baskets))  {
        delInSameBasket(re);
        prevHead  =  updatePathOut[0];
      } else {
        delInOtherBacket(re);
      }
      delete (re->data);
    }  //  if  (!re)

    memset(re,  0,  sizeof(TONode));
        //New leader = new:
    re->mostUseful  =  &headNode;
    re->leastUseful  =  headNode.mostUseful;
    headNode.mostUseful->mostUseful  =  re;
    if  (&headNode == headNode.leastUseful)  {
            //The first became last too:
      headNode.leastUseful  =  re;
    }
    headNode.mostUseful  =  re;
    re->hash  =  hash;
    if  (cmp>0)  {
            //using update path
      re->key  =  key;
      re->data  =  data;
      re->curHeight  =  (3==cmp)?
        landscape_h[(land_h_p[basketID])++]
        :  landscape_l[(land_l_p[basketID])++];
      unsigned  char  i  =  0;
      while  (i<=re->curHeight)  {
        re->fwdPtrs[i]  =  updatePathOut[i]->fwdPtrs[i];
        updatePathOut[i]->fwdPtrs[i]  =  re;
        ++i;
      }
      while  (i<=SKIPHEIGHT)  {
        re->fwdPtrs[i]  =  nullptr;
        ++i;
      }
    }  else  {
            //replace at place
      if  (re  ==  prevHead)  {
        re->key  =  key;
        re->data  =  data;
      }  else  {
        re->key  =  prevHead->key;
        re->data  =  prevHead->data;
        re->curHeight  =  landscape_l[(land_l_p[basketID])++];
        re->fwdPtrs[0]  =  prevHead->fwdPtrs[0];
        prevHead->fwdPtrs[0]  =  re;
        if  (1==re->curHeight)  {
          re->fwdPtrs[1]  =  prevHead->fwdPtrs[1];
          prevHead->fwdPtrs[1]  =  re;
        }
        prevHead->key  =  key;
        prevHead->data  =  data;
      }
    }
   return;
  }  //  allocNode

  TONode * find(TKey const  *key)  {
    const  uint64_t  hash  =  getHash(key);
    const  uint32_t  basketID  =  hash  %  _hash_baskets;
    TONode  *cur  =  &(baskets[basketID]);
    int  h  =  4;
    while  (  h>1  )  {
      while  (cur->fwdPtrs[h]  &&  (hash  >  cur->fwdPtrs[h]->hash))  {
        cur  =  cur->fwdPtrs[h]; //step on it
      }
      --h;
    } //while

//same key jumps
        if (cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash) {
            //step on same hash:
             cur = cur->fwdPtrs[2];
            //same hash found, next search for same key
            //cmp = memcmp(key, cur->key, _keyLen);
            int cmp = getCmp(key, cur->key);//key->cmp(cur->key);
            if (cmp < 0) {
                return nullptr; //nothing bigger with same hash
            } else if (0==cmp) {
                return cur;
            }

            while(cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
                //cmp = memcmp(key, cur->fwdPtrs[1]->key, _keyLen);
                cmp = getCmp(key, cur->fwdPtrs[1]->key);// key->cmp(cur->fwdPtrs[1]->key);
                if (cmp < 0) {
                    //found who bigger
                    break;
                }
                if (0==cmp) {
                    return cur->fwdPtrs[1];
                }
                cur = cur->fwdPtrs[1]; //step on it
            }

            while(cur->fwdPtrs[0] && hash==cur->fwdPtrs[0]->hash) {
                cmp = getCmp(key, cur->fwdPtrs[0]->key);// key->cmp(cur->fwdPtrs[0]->key);
                if (cmp < 0) {
                    //found who bigger
                    return nullptr;
                }
                if (0==cmp) {
                    return cur->fwdPtrs[0];
                }
                cur = cur->fwdPtrs[0]; //step on it
            }
        }

        return nullptr;
    } //find


    /*
     * return:
     * 0 ==node with equal key if found
     * 3 == updatePath to insert node with new hash
     * 1 == updatePath to insert node with same hash
     * -N == node with same hash but bigger, to replace at place
   */
    int setll(const uint64_t hash,
                   TKey const * key,
                   const uint32_t basketID) {
        TONode * cur = &(baskets[basketID]);
        //TONode * curBigger = nullptr;
       // int cmp = 1; //not %found
//same hash jumps
//        for(int h = cur->curHeight; h>1; --h){
//            //At first head->fwdPtrs[h] all nullptr, so not pass:
//            while(cmp != 0 && cur->fwdPtrs[h]!=curBigger) {
//                cmp = hash - cur->fwdPtrs[h]->hash;
//                if (cmp < 0) {
//                    //found who bigger
//                    //next iter will shoot on lower level and skip the same..
//                    curBigger = cur->fwdPtrs[h];
//                    break;
//                }
//                cur = cur->fwdPtrs[h]; //step on it
//            }
//            updatePathOut[h] = cur;
//        }

        int h = 4;//cur->curHeight;
        while( h>1 ){
            //updatePathOut[h] = cur;
            while(cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                //updatePathOut[h] = cur;
                cur = cur->fwdPtrs[h]; //step on it
            }
            //Update path always point to node that point to bigger or equal one
            updatePathOut[h] = cur;
            --h;
        } //while


//same key jumps
       // if (0==cmp) {
        if (cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash) {
            //step on same hash:
             cur = cur->fwdPtrs[2];
            //same hash found, next search for same key
            //cmp = memcmp(key, cur->key, _keyLen);
            int cmp = getCmp(key, cur->key);// key->cmp(cur->key);
            if (cmp <= 0) {
                updatePathOut[0] = cur;
                return cmp; //must replace hash head in place
            }

            while(cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
                //cmp = memcmp(key, cur->fwdPtrs[1]->key, _keyLen);
                cmp = getCmp(key, cur->fwdPtrs[1]->key);// key->cmp(cur->fwdPtrs[1]->key);
                if (cmp < 0) {
                    //found who bigger
                    //curBigger = cur->fwdPtrs[1];
                    break;
                }
                if (0==cmp) {
                    updatePathOut[0] = cur->fwdPtrs[1];
                    return 0; //must replace
                }
                //updatePathOut[1] = cur;
                cur = cur->fwdPtrs[1]; //step on it
            }
            updatePathOut[1] = cur;


            while(cur->fwdPtrs[0] && hash==cur->fwdPtrs[0]->hash) {
                //cmp = memcmp(key, cur->fwdPtrs[0]->key, _keyLen);
                cmp = getCmp(key, cur->fwdPtrs[0]->key);// key->cmp(cur->fwdPtrs[0]->key);
                if (cmp < 0) {
                    //found who bigger
                    break;
                }
                if (0==cmp) {
                    updatePathOut[0] = cur->fwdPtrs[0];
                    return 0; //must replace
                }
                cur = cur->fwdPtrs[0]; //step on it
            }
            updatePathOut[0] = cur;
            return 1; //base alhorithm==insert on updatePath
        } else {
            updatePathOut[0] = cur;
            updatePathOut[1] = cur;
            return 3; //base alhorithm==insert on updatePath
        }

        return 3;
    }

//    void clearNode(TONode & node){
//        if (node.data){
//            delete  (node.data);
//        }
//    }

    void clearNodes(TONode * nodes, uint32_t toClear){
         for (uint32_t i=0; i<toClear; ++i) {
             //clearNode(nodes[i]);
             if (nodes[i].data){
                 delete  (nodes[i].data);
             }
         }
    }


    void delInOtherBacket(TONode * nodeToDel) {
        const uint64_t hash = nodeToDel->hash;
        TONode * cur = &(baskets[hash % _hash_baskets]);
        TONode * updatePath[SKIPHEIGHT];
       // TONode * tmpN = nullptr;
       // long long cmp = 1; //not %found
        int h = 4;//cur->curHeight;
//same hash jumps

        while( h>1 ){
            updatePath[h] = cur;
            while(cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                updatePath[h] = cur; //start from head that always smaller
                cur = cur->fwdPtrs[h]; //step on it
            }
            --h;
        } //while

        assert(cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash);
        //Step on head of same hash queue:
        //cur = cur->fwdPtrs[2];

        //same key jumps
        while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
            updatePath[1] = cur; //need in case of null==cur->fwdPtrs[1]
            //if (nodeToDel->key->cmp(cur->fwdPtrs[1]->key) <= 0) {
            if (getCmp(nodeToDel->key, cur->fwdPtrs[1]->key) <= 0) {
                break;
            }
            cur = cur->fwdPtrs[1]; //step on it
        }

        //jumps on lvl 0:
        //if (nodeToDel==updatePath[1]->fwdPtrs[1]) {
//        if (nodeToDel==cur->fwdPtrs[1]) {
//            updatePath[0] = cur;
//        } else {
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }
        while (cur->fwdPtrs[0]!=nodeToDel){
            cur = cur->fwdPtrs[0]; //step on it
        }
        updatePath[0] = cur;

        assert (updatePath[0]->fwdPtrs[0]==nodeToDel);
        if (updatePath[2]->fwdPtrs[2]==nodeToDel) {
            //This is the head of hash queue:
            cur = nodeToDel->fwdPtrs[0]; //new head
            for ( h = nodeToDel->curHeight; h>0; --h) {
                if (h>cur->curHeight) {
                    cur->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                }
                nodeToDel->fwdPtrs[h] = cur;
            }
            cur->curHeight = nodeToDel->curHeight;
        }
        for ( h = nodeToDel->curHeight; h>=0; --h) {
            updatePath[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
        }
        return;

//        //old:
//        tmpN = updatePathOut[h+1] ;
//        while (h>=0){
//            //enshure path filled:
//            updatePathOut[h] = tmpN;
//            --h;
//        }

//        //same key jumps
//        if (0==cmp) {
//            if (nodeToDel == cur) {
//                tmpN = cur->fwdPtrs[0];
//                if (tmpN && tmpN->hash == nodeToDel->hash) {
//                    //replace with same height
//                    assert(tmpN->curHeight<2);
//                    h = nodeToDel->curHeight;
//                    while (h > tmpN->curHeight) {
//                        tmpN->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
//                        --h;
//                    }
//                    //for final update paths cycle:
////                    while (h>=0){
////                        nodeToDel->fwdPtrs[h] = tmpN->fwdPtrs[h];
////                        --h;
////                    }
//                    tmpN->curHeight = nodeToDel->curHeight;
//                }
//            } else {
//                //must find it, first jumps on lvl 1:
//                while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
//                    updatePathOut[1] = cur;
//                    cmp = memcmp(nodeToDel->key, cur->fwdPtrs[1]->key, _keyLen);
//                    if (cmp <= 0) {
//                        break;
//                    }
//                    cur = cur->fwdPtrs[1]; //step on it
//                }
//                //jumps on lvl 0:
//                if (0==cmp) {
//                    updatePathOut[0] = updatePathOut[1];
//                } else {
//                    while (cur->fwdPtrs[0]!=nodeToDel){
//                        updatePathOut[0] = cur;
//                        cur = cur->fwdPtrs[0]; //step on it
//                    }
//                }
//            }
//            //final update paths:
//            assert (updatePathOut[0]->fwdPtrs[0]==nodeToDel);
//            for (int h = nodeToDel->curHeight; h>=0; --h) {
//                updatePathOut[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
//            }
//            return;
//        }
//        assert(false);
//        return;
    } //delInOtherBasket

    void delInSameBasket(TONode * nodeToDel) {
        for (int h = 4; h>=0; --h){
            if (nodeToDel==updatePathOut[h]) {
                //worst case - must do repath
                delInSameBasketPathOut(nodeToDel, h);
                return;
            }
            if (nodeToDel==updatePathOut[h]->fwdPtrs[h]) {
                //best case - know where and how to update
                delInSameBasketSuperFast(nodeToDel, h);
                return;
            }
        }
        //not on path == path not affected
         delInSameBasketFast(nodeToDel);
         return;
    }

    void delInSameBasketPathOut(TONode * nodeToDel, int top_h) {
        //Node to del in updatePathOut[h], need path to it for update
        const uint64_t hash = nodeToDel->hash;
        TONode * updatePath[SKIPHEIGHT];
        int h = 4;
        TONode * cur = &(baskets[hash % _hash_baskets]);
        while(h > top_h){
            cur=updatePath[h] = updatePathOut[h];
            --h;
        }
        //= top_h==4? &(baskets[hash % _hash_baskets]);updatePathOut[top_h];
        while (  h>1 ){
            updatePath[h] = cur;
            while (hash > cur->fwdPtrs[h]->hash) {
                updatePath[h] = cur;
                cur = cur->fwdPtrs[h];
            }
            --h;
        } //while
        assert(1==h);
        assert(cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash);
        //Step on head of same hash queue:
        //cur = cur->fwdPtrs[2];

        //same key jumps
        while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
            updatePath[1] = cur;
            //if (nodeToDel->key->cmp(cur->fwdPtrs[1]->key) <= 0) {
            if (getCmp(nodeToDel->key, cur->fwdPtrs[1]->key) <= 0) {
                break;
            }
            cur = cur->fwdPtrs[1]; //step on it
        }
        //jumps on lvl 0:
//        if (nodeToDel == cur) {
//            updatePath[0] = cur;
//        } else {
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }

        while (cur->fwdPtrs[0]!=nodeToDel){
            cur = cur->fwdPtrs[0]; //step on it
        }
        updatePath[0] = cur;

            //final update paths:
            assert (updatePath[0]->fwdPtrs[0]==nodeToDel);
            if (updatePath[2]->fwdPtrs[2]==nodeToDel) {
                //This is the head of hash queue:
                cur = nodeToDel->fwdPtrs[0]; //new head
                for ( h = nodeToDel->curHeight; h>0; --h) {
                    if (h>cur->curHeight) {
                        cur->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                    }
                    nodeToDel->fwdPtrs[h] = cur;
                }
                cur->curHeight = nodeToDel->curHeight;
            }
            for ( h = top_h; h>=0; --h) {
                updatePath[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                //replace deleted node with previos:
                if (nodeToDel==updatePathOut[h]) {
                    updatePathOut[h] = updatePath[h];
                }
            }
            return;
    }//delInSameBasketPathOut

    void delInSameBasketSuperFast(TONode * nodeToDel, int top_h) {
        //need path before to update pointers
        const uint64_t hash = nodeToDel->hash;
       // long long cmp = 1;
        TONode * updatePath[SKIPHEIGHT];
        updatePath[top_h] = updatePathOut[top_h];
        TONode * cur = updatePathOut[top_h];
        int h = top_h - 1;
        //updatePath[h] = updatePathOut[top_h];
        while (  h>1 ){
            assert(updatePathOut[h]->fwdPtrs[h]->hash<=hash);
            if (cur->hash < updatePathOut[h]->hash) {
                cur = updatePathOut[h];
            }
            updatePath[h] = cur;
            while (cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                updatePath[h] = cur;
                cur = cur->fwdPtrs[h];
            }
            --h;
        } //while
        assert(1==h);
        //lvl[2] always point to the head of same hash queue:
        assert(cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash);
        //Step on head of same hash queue:
       // cur = cur->fwdPtrs[2];

        //Use all known info to narrow jump:
//        if (updatePathOut[1]->fwdPtrs[1]->hash==hash
//                && cur->fwdPtrs[2]->key->cmp(updatePathOut[1]->fwdPtrs[1]->key) < 0) {
//            cur = updatePathOut[1];
//        }

        //same key jumps
        //updatePath[1] = cur;
        while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
            updatePath[1] = cur;
            //cmp = memcmp(nodeToDel->key, cur->fwdPtrs[1]->key, _keyLen);
//            cmp = nodeToDel->key->cmp(cur->fwdPtrs[1]->key);
//            if (cmp <= 0) {
//                break;
//            }
            //if (nodeToDel->key->cmp(cur->fwdPtrs[1]->key) <= 0) {
            if (getCmp(nodeToDel->key, cur->fwdPtrs[1]->key) <= 0) {
                break;
            }
            cur = cur->fwdPtrs[1]; //step on it
        }
        //jumps on lvl 0:
        //if (0==cmp) {
//        if (nodeToDel==cur->fwdPtrs[0]) {
//            updatePath[0] = cur;
//        } else {
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }

        while (cur->fwdPtrs[0]!=nodeToDel){
            cur = cur->fwdPtrs[0]; //step on it
        }
        updatePath[0] = cur;

//        if (nodeToDel==cur->fwdPtrs[0]) {
//            updatePath[0] = cur;
//        } else {
//            //Use all known info to narrow jump:
//            if (updatePathOut[0]->fwdPtrs[0]->hash==hash
//                    && cur->fwdPtrs[0]->key->cmp(updatePathOut[0]->fwdPtrs[0]->key) < 0) {
//                cur = updatePathOut[0];
//            }
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }

            //final update paths:
            assert (updatePath[0]->fwdPtrs[0]==nodeToDel);
            if (updatePath[2]->fwdPtrs[2]==nodeToDel) {
                //This is the head of hash queue:
                cur = nodeToDel->fwdPtrs[0]; //new head
                for ( h = nodeToDel->curHeight; h>0; --h) {
                    if (h>cur->curHeight) {
                        cur->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                    }
                    nodeToDel->fwdPtrs[h] = cur;
                }
                cur->curHeight = nodeToDel->curHeight;
            }
            for ( h = top_h; h>=0; --h) {
                updatePath[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
            }


            return;

    }//delInSameBasketSuperFast

    void delInSameBasketFast(TONode * nodeToDel) {
        const uint64_t hash = nodeToDel->hash;
        //TONode * head = &(baskets[hash % _hash_baskets]);
        //TONode * tmpN = nullptr;
        //long long cmp = 1; //not %found
        TONode * updatePath[SKIPHEIGHT];
        int h = 4;
        //updatePathOut filled with previos setll
        //see if it usefull for this proc:
//        while (h>=0) {
//            updatePath[h] = updatePathOut[h]->hash<=hash?updatePathOut[h]:head;
//            head = updatePath[h];
//            --h;
//        }
//        h = 4;

        TONode * cur = &(baskets[hash % _hash_baskets]);
        //while( 0!=cmp && h>1 ){
        while( h>1 ){
//            while(0!=cmp && cur->fwdPtrs[h]) {
//                updatePath[h] = cur; //start from head that always smaller
//                cmp = hash - cur->fwdPtrs[h]->hash;
//                if (cmp < 0) {
//                //found who bigger
//                //next iter will shoot on lower level and skip the same..
//                //    curBigger = cur->fwdPtrs[h];
//                    break;
//                }
//                cur = cur->fwdPtrs[h]; //step on it
//            }
            //updatePath[h] = cur;
//            if (cur->hash<updatePath[h]->hash) {
//                cur = updatePath[h];
//            }

            //Use all known info to narrow jump:
            if (updatePathOut[h]->hash<=hash
                    && cur->hash < updatePathOut[h]->hash) {
                cur = updatePathOut[h];
            }

            updatePath[h] = cur;
            while (cur->fwdPtrs[h] && hash > cur->fwdPtrs[h]->hash) {
                updatePath[h] = cur;
                cur = cur->fwdPtrs[h];
            }
            //updatePath[h] = cur;
            assert(nodeToDel->curHeight<h || updatePath[h]->fwdPtrs[h]->hash==nodeToDel->hash);
            --h;

        } //while

//        tmpN = updatePath[h+1] ;
//        while (h>=0){
//            //enshure path filled with last jump:
//            updatePath[h] = tmpN;
//            --h;
//        }
        assert(cur->fwdPtrs[2] && hash == cur->fwdPtrs[2]->hash);
        //Step on head of same hash queue:
        //cur = cur->fwdPtrs[2];

        //Use all known info to narrow jump:
//        if (updatePathOut[1]->fwdPtrs[1]->hash==hash
//                && cur->fwdPtrs[2]->key->cmp(updatePathOut[1]->fwdPtrs[1]->key) < 0) {
//            cur = updatePathOut[1];
//        }

        //same key jumps
        updatePath[1] = cur; //need in case of null==cur->fwdPtrs[1]
        while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
            updatePath[1] = cur;
            //if (nodeToDel->key->cmp(cur->fwdPtrs[1]->key) <= 0) {
            if (getCmp(nodeToDel->key, cur->fwdPtrs[1]->key) <= 0) {
                break;
            }
            cur = cur->fwdPtrs[1]; //step on it
        }
        //updatePath[1] = cur;
        //jumps on lvl 0:
        //if (nodeToDel==updatePath[1]->fwdPtrs[1]) {
//        if (nodeToDel==cur->fwdPtrs[0]) {
//            updatePath[0] = cur;
//        } else {
//            //Use all known info to narrow jump:
//            if (updatePathOut[0]->fwdPtrs[0]->hash==hash
//                    && cur->fwdPtrs[0]->key->cmp(updatePathOut[0]->fwdPtrs[0]->key) < 0) {
//                cur = updatePathOut[0];
//            }
//            while (cur->fwdPtrs[0]!=nodeToDel){
//                cur = cur->fwdPtrs[0]; //step on it
//            }
//            updatePath[0] = cur;
//        }

        while (cur->fwdPtrs[0]!=nodeToDel){
            cur = cur->fwdPtrs[0]; //step on it
        }
        updatePath[0] = cur;

//       // if (0==cmp) {
//            if (nodeToDel == cur) {
//                //found what to del, and this is hash head => must create new hash head
//                tmpN = cur->fwdPtrs[0];
//                if (tmpN && tmpN->hash == nodeToDel->hash) {
//                    //replace with same height
//                    assert(tmpN->curHeight<2);
//                    h = nodeToDel->curHeight;
//                    while (h > tmpN->curHeight) {
//                        tmpN->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
//                        --h;
//                    }
//                    //for final update paths cycle:
////                    while (h>=0){
////                        nodeToDel->fwdPtrs[h] = tmpN->fwdPtrs[h];
////                        --h;
////                    }
//                    tmpN->curHeight = nodeToDel->curHeight;
//                }
//            } else {
//                //must find it, first jumps on lvl 1:
//                while (cur->fwdPtrs[1] && hash==cur->fwdPtrs[1]->hash) {
//                    updatePath[1] = cur;
//                    //cmp = memcmp(nodeToDel->key, cur->fwdPtrs[1]->key, _keyLen);
//                    cmp = nodeToDel->key->cmp(cur->fwdPtrs[1]->key);
//                    if (cmp <= 0) {
//                        break;
//                    }
//                    cur = cur->fwdPtrs[1]; //step on it
//                }
//                //jumps on lvl 0:
//                if (0==cmp) {
//                    updatePath[0] = updatePath[1];
//                } else {
//                    while (cur->fwdPtrs[0]!=nodeToDel){
//                        updatePath[0] = cur;
//                        cur = cur->fwdPtrs[0]; //step on it
//                    }
//                }
//            }

            //final update paths:
            assert (updatePath[0]->fwdPtrs[0]==nodeToDel);
            if (updatePath[2]->fwdPtrs[2]==nodeToDel) {
                //This is the head of hash queue:
                cur = nodeToDel->fwdPtrs[0]; //new head
                for ( h = nodeToDel->curHeight; h>0; --h) {
                    if (h>cur->curHeight) {
                        cur->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
                    }
                    nodeToDel->fwdPtrs[h] = cur;
                }
                cur->curHeight = nodeToDel->curHeight;
            }
            for (h = nodeToDel->curHeight; h>=0; --h) {
                updatePath[h]->fwdPtrs[h] = nodeToDel->fwdPtrs[h];
            }
            return;
//        }
//        assert(false);
//        return;
    }//delInSameBasketFast

    void toTopUsage(TONode * node){
        //Exсlude:
        if (node->mostUseful) {
            node->mostUseful->leastUseful = node->leastUseful;
        }
        if (node->leastUseful) {
            node->leastUseful->mostUseful = node->mostUseful;
        }

        //New leader:
        node->mostUseful = &headNode;
        node->leastUseful = headNode.mostUseful;
        headNode.mostUseful->mostUseful = node;
        if (&headNode==headNode.leastUseful) {
            //The first became last too:
            headNode.leastUseful = node;
        }
        headNode.mostUseful = node;
    }

};


#endif // IPACK_H
