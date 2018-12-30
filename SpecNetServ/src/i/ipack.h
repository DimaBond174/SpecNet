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
#include "depend/tools/memory/oncache.h"

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

//The server and client answers with a list of the unnecessary mail:
#define  SPEC_PACK_TYPE_8  8

//The server and client sends a requested mail:
#define  SPEC_PACK_TYPE_9  9

//The server and client sends a delivery confirmation:
#define  SPEC_PACK_TYPE_10  10

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

using T_IPack0_Network = TKey;

class IPack {
public:
    ~IPack(){ if (body) { free(body);}}
//IStack interface (faster than vtable):
    IPack * nextIStack;
//Common header:
    T_IPack0_Network header;
//Common packet:
    //next bytes
    char * body = nullptr;
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


//      static bool parsePackI(T_IPack1_struct & res, const char * pack){
//        bool re = false;
//        //faux loop
//        do {
//            T_IPack1_Network * in = (T_IPack1_Network *)pack;
//            if (sizeof(T_IPack1_Network) > in->header.pack_len) {break;}
//            res.groupID = _NTOHLL(in->groupID);
//            res.avatarID = _NTOHLL(in->avatarID);
//            re = true;
//        } while (false);

//        return re;
//    }
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

#endif // IPACK_H
