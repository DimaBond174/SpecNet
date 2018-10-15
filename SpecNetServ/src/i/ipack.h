#ifndef IPACK_H
#define IPACK_H

#include <arpa/inet.h>
#include "i/ialloc.h"
#include "string.h"
#include <string>
#ifdef Debug
    #include <assert.h>
#endif

#define SPEC_MARK 2109201808
#define SPEC_LEN_HEAD_1  (sizeof(uint32_t))
constexpr int SPEC_LEN_HEAD_2 = sizeof(uint32_t)+sizeof(uint32_t);
constexpr int SPEC_LEN_HEAD_3 = 3 * sizeof(uint32_t);
constexpr int SPEC_LEN_HEAD_4 = 4 * sizeof(uint32_t);

#define  MAX_CHANK  204800


static bool NO_NEED_hton = (1==htonl(1));
static bool NO_NEED_ntoh = (1==ntohl(1));
#define _HTONL(x) (NO_NEED_hton ? (x) : htonl(x))
#define _NTOHL(x) (NO_NEED_ntoh ? (x) : ntohl(x))
#define _HTONLL(x) (NO_NEED_hton ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
#define _NTOHLL(x) (NO_NEED_ntoh ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))
//#define HTONLL(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
//#define NTOHLL(x) ((1==ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))

/* Conversation protocol between server and client */
//The client sends a one of their membership in the groups:
#define SPEC_PACK_TYPE_1 1
//The server  requests unknown certificate X509 (or not):
#define SPEC_PACK_TYPE_2 2
//The client sends certificates:
#define SPEC_PACK_TYPE_3 3
//The server sends a test cryptographic task for certificate to check if PKEY exists:
//If the server does not serve this group, then the job will be empty
#define SPEC_PACK_TYPE_4 4
//The client sends answer for the test cryptographic task:
#define SPEC_PACK_TYPE_5 5
//The server send OK to work == list of the new mail:
//The client sends list of the new mail too:
#define SPEC_PACK_TYPE_6 6

//The server and client answers with a list of the needed mail :
#define SPEC_PACK_TYPE_7 7
//The server and client answers with a list of the unnecessary mail:
#define SPEC_PACK_TYPE_8 8
//The server and client sends a requested mail:
#define SPEC_PACK_TYPE_9 9
//The server and client sends a delivery confirmation:
#define SPEC_PACK_TYPE_10 10
//If the client detects unknown senders in the mail,
//it requests the certificates of these senders with
//SPEC_PACK_TYPE_2 request, and the server responds with SPEC_PACK_TYPE_3

class IPack0
{
public:
    static long eatPacket(char * packet, int len) {
        long re = -1;
        if (len >= SPEC_LEN_HEAD_2) {
            uint32_t * headers = (uint32_t *)packet;            
            if (SPEC_MARK==ntohl(headers[0])) {
                re  = ntohl(headers[1]);
                if (re > MAX_CHANK) { re = -1;}
            }
        }
        return re;
    }

    /* for internal trusted use */
    static uint32_t lenPacket(char * packet) {
        uint32_t * headers = (uint32_t *)packet;
        uint32_t re = ntohl(headers[1]);
        if (re>MAX_CHANK) { re = 0;}
        return re;
    }

    /* from packet to send with SPEC_MARK */
    static uint32_t getTypeOut(char * packet) {
        uint32_t * headers = (uint32_t *)packet;
        return ntohl(headers[2]);
    }

    /* after receiving for header without SPEC_MARK */
    static uint32_t getTypeIn(char * packet) {
        uint32_t * headers = (uint32_t *)packet;
        return ntohl(headers[1]);
    }

    /*
     * Preparing standard headers
     * packet = buf where first bytes for headers
     * len  = meaning data lenght without headers lenght
     * type = type of the packet
     * !!! Packet {lenght} should be without lenHead0 when creating !!! */
    static void setHeaders(char * packet, uint32_t len, uint32_t type){
        uint32_t * headers = (uint32_t *)packet;
        headers[0] = htonl(SPEC_MARK);
    /* len data + len of packet type: */
        headers[1] = htonl(len + SPEC_LEN_HEAD_1);
        headers[2] = htonl(type);        
    }

};

class IPack111
{
public:
    static char * createPacket(IAlloc * iAlloc, const char * str, uint32_t len) {
        /* alloc for data + headers */
        char * re = (char *)iAlloc->specAlloc(len+SPEC_LEN_HEAD_3);
        if (re) {
            IPack0::setHeaders(re, len, 1);
            memcpy(re+SPEC_LEN_HEAD_3, str, len);

            /* headers to see */
//            uint32_t * headers = (uint32_t *)re;
//            long metka = ntohl(headers[0]);
//            long size = ntohl(headers[1]);
//            long type = ntohl(headers[2]);
//            headers = nullptr;
        }
        return re;
    }

    static std::string parsePack(const char * pack){
        uint32_t len = *((uint32_t*)(pack));
        if (len > 0 && len < MAX_CHANK) {
            return std::string(pack + SPEC_LEN_HEAD_2, len - SPEC_LEN_HEAD_1);
        }
        return std::string();
    }

};



/*
 * IPack1
 * =Type1 - Client tells about membership
 * =Type2 - Server asks for cert X509
*/
struct {    
    uint64_t groupID;
    uint64_t avatarID;
} typedef T_IPack1_struct;

constexpr uint32_t LEN_uint64_t_2 =  sizeof(uint64_t) * 2;
constexpr uint32_t MIN_LEN_PACK1 =  SPEC_LEN_HEAD_1 +
         LEN_uint64_t_2;

class IPack1
{    
public:

    static char * createPacket(IAlloc * iAlloc, uint64_t groupID, uint64_t avatarID,  uint32_t type) {
        /* alloc for data + headers */    
        char * re = (char *)iAlloc->specAlloc(SPEC_LEN_HEAD_3
                                              + LEN_uint64_t_2);

        if (re) {
#ifdef Debug
        char *maxRam = re + SPEC_LEN_HEAD_3
                + LEN_uint64_t_2;
#endif
            IPack0::setHeaders(re, LEN_uint64_t_2, type);
            uint64_t * groupIDsN  = (uint64_t *)(re+SPEC_LEN_HEAD_3);
            *groupIDsN = _HTONLL(groupID);
            uint64_t * avatarIDsN = groupIDsN + 1;
            *avatarIDsN = _HTONLL(avatarID);
#ifdef Debug
        char * chk=(char *)(groupIDsN+1);
        assert(re< chk && chk<=maxRam);
        chk=(char *)(avatarIDsN+1);
        assert(re< chk && chk<=maxRam);
#endif
        }
        return re;
    }

    static uint64_t getGroupIn(const char * pack){
        return(_NTOHLL(*((uint64_t *)(pack + SPEC_LEN_HEAD_2))));
    }

      static bool parsePackI(T_IPack1_struct & res, const char * pack){
        bool re = false;
        //faux loop
        do {
            uint32_t len = *((uint32_t*)(pack));
            if (len < MIN_LEN_PACK1 || len >= MAX_CHANK) {  break;  }
            uint64_t * groupIDsN  = (uint64_t *)(pack + SPEC_LEN_HEAD_2);
            uint64_t * avatarIDsN = groupIDsN + 1;

            res.groupID = _NTOHLL(*groupIDsN);
            res.avatarID = _NTOHLL(*avatarIDsN);

            re = true;
        } while (false);

        return re;
    }
};

/*
 * IPack3
 * =Type3 - Client answers with X509
 * =Type4 - Server's test cryptographic task
 * =Type5 - Client answer with cryptographic result
*/
struct {
    uint32_t  strLen;
    uint64_t  guid1;
    uint64_t  guid2;
    const char * str;
} typedef T_IPack3_struct;

constexpr uint32_t MIN_LEN_PACK3 =  SPEC_LEN_HEAD_1 +
         LEN_uint64_t_2 + sizeof(uint32_t) ;

class IPack3
{
public:

    static char * createPacket(IAlloc * iAlloc, T_IPack3_struct & iStruct, uint32_t type) {
        /* alloc for data + headers */
        uint32_t allocLen = sizeof(uint32_t)
                + LEN_uint64_t_2  + iStruct.strLen;
        char * re = (char *)iAlloc->specAlloc(SPEC_LEN_HEAD_3
                                              + allocLen);
#ifdef Debug
        char *maxRam = re + SPEC_LEN_HEAD_3
                + allocLen;
#endif

        if (re) {
            IPack0::setHeaders(re, allocLen, type);
            uint32_t * lenN = (uint32_t *)(re+SPEC_LEN_HEAD_3);
            uint64_t * groupIDsN  = (uint64_t *)(lenN + 1);
            uint64_t * avatarIDsN = groupIDsN + 1;
#ifdef Debug
        char * chk=(char *)lenN;
        assert(re< chk && chk<maxRam);
        chk=(char *)groupIDsN;
        assert(re< chk && chk<maxRam);
        chk=(char *)(avatarIDsN+1);
        assert(re< chk && chk<=maxRam);
#endif
            *lenN = _HTONL(iStruct.strLen);
            *groupIDsN=_HTONLL(iStruct.guid1);
            *avatarIDsN=_HTONLL(iStruct.guid2);
            if (iStruct.strLen>0) {
#ifdef Debug
                chk= (char *)(avatarIDsN+1);
                assert(re<chk && chk<maxRam);
                chk= (char *)(avatarIDsN+1)+iStruct.strLen;
                assert(re<chk && chk<=maxRam);
#endif
                memcpy((void *)(avatarIDsN+1), iStruct.str, iStruct.strLen);
            }
        }
        return re;
    }


     static bool parsePackI(T_IPack3_struct & res, const char * pack){
        bool re = false;
        //faux loop
        do {
            uint32_t len = *((uint32_t*)(pack));
            if (len < MIN_LEN_PACK3 || len >= MAX_CHANK) {  break;  }
            uint32_t * lenN = (uint32_t *)(pack + SPEC_LEN_HEAD_2);
            res.strLen = _NTOHL(*lenN);
            if (res.strLen > MAX_CHANK) {  break;  }

            uint64_t * groupIDsN  = (uint64_t *)(lenN + 1);
            res.guid1 = _NTOHLL(*groupIDsN);
            uint64_t * avatarIDsN = groupIDsN + 1 ;
            res.guid2 = _NTOHLL(*avatarIDsN);
            if (0==res.strLen) {
                res.str = nullptr;
            } else {
                res.str = (const char *)(avatarIDsN + 1);
            }
            re = true;
        } while (false);

        return re;
    }

}; //IPack3


/*
 * IPack6
 * = Type6 - Server OK to work and new mail array
 * = Type7 - Wanted mail
 * = Type8 - UnWanted mail
*/

struct {
    uint32_t  lenArray;
    uint64_t * groupID;
    uint64_t * guid1s; //msgID
    uint64_t * guid2s; //msgDate
} typedef T_IPack6_struct;

constexpr uint32_t MIN_LEN_PACK6 =  SPEC_LEN_HEAD_1 + sizeof(uint32_t) + sizeof(uint64_t);

class IPack6
{
public:

    static char * createPacket(IAlloc * iAlloc,
                               uint32_t lenArray,
                               uint64_t groupID,
                               uint64_t * guid1s,
                               uint64_t * guid2s,
                               uint32_t type) {
        /* alloc for data + headers */
        uint32_t allocLen = sizeof(uint32_t) //lenArray
                + sizeof(uint64_t) //groupID
                + LEN_uint64_t_2 * lenArray; //guid1s and guid2s
        char * re = (char *)iAlloc->specAlloc(SPEC_LEN_HEAD_3
                                              + allocLen);
        if (re) {
            IPack0::setHeaders(re, allocLen, type);
            /* calc adresses */
            uint32_t * lenArrayN = (uint32_t *)(re+SPEC_LEN_HEAD_3);
            uint64_t * groupIDN = (uint64_t *)(lenArrayN + 1);


            /* calc values */
            *lenArrayN = _HTONL(lenArray);
            *groupIDN = _HTONLL(groupID);

            if (lenArray>0) {
                uint64_t * guid1sN = groupIDN+1;
                uint64_t * guid2sN = guid1sN + lenArray;
                for (uint32_t i=0; i<lenArray ;++i) {
                    guid1sN[i]=_HTONLL(guid1s[i]);
                    guid2sN[i]=_HTONLL(guid2s[i]);
                }
            }
        }
        return re;
    }

    /* from packet to send with SPEC_MARK */
    static uint64_t getOutGroupID(char * packet) {
        return _NTOHLL(*((uint64_t *)(packet + SPEC_LEN_HEAD_4)));
    }

     /* pack after receive without SPEC_MARK, first len of pack in host alig*/
      static bool parsePackI(T_IPack6_struct & res, const char * pack){
        bool re = false;
        //faux loop
        do {
            uint32_t len = *((uint32_t*)(pack));
            if (len < MIN_LEN_PACK6 || len >= MAX_CHANK) {  break;  }
            res.lenArray = *((uint32_t *)(pack + SPEC_LEN_HEAD_2));
            res.lenArray = _NTOHL(res.lenArray);
            if (res.lenArray > 1000) {  break;  }
            res.groupID = ((uint64_t *)((uint32_t *)(pack + SPEC_LEN_HEAD_2) + 1));
            *res.groupID = _NTOHLL(*res.groupID);
            if (0==res.lenArray) {
                res.guid1s = nullptr;
                res.guid2s = nullptr;
                re =true;
                break;
            }
            res.guid1s = res.groupID +1;
            res.guid2s = res.guid1s + res.lenArray;
            for (int i=0; i<res.lenArray; ++i) {
                res.guid1s[i] = _NTOHLL(res.guid1s[i] );
                res.guid2s[i] = _NTOHLL(res.guid2s[i] );
            }
            re = true;
        } while (false);

        return re;
    }

}; //IPack6

/*
 * IPack9
 * =Type9 - Mail
 * =Type10 - Delivery confirmation
*/
struct {
    uint32_t  strLen;
    uint64_t  guid1; //id_group
    uint64_t  guid2; //id_msg
    uint64_t  guid3; //date_msg
    uint64_t  guid4; //remote_id_avatar
    uint64_t  guid5; //my_id_avatar
    const char * str;
} typedef T_IPack9_struct;
constexpr uint32_t LEN_uint64_t_5 =  sizeof(uint64_t) * 4;
constexpr uint32_t MIN_LEN_PACK9 =  SPEC_LEN_HEAD_1 +
         LEN_uint64_t_5 + sizeof(uint32_t) ;

class IPack9
{
public:

    static char * createPacket(IAlloc * iAlloc, T_IPack9_struct & iStruct, uint32_t type) {
        /* alloc for data + headers */
        uint32_t allocLen = sizeof(uint32_t)
                + LEN_uint64_t_5  + iStruct.strLen;
        char * re = (char *)iAlloc->specAlloc(SPEC_LEN_HEAD_3
                                              + allocLen);
//#ifdef Debug
//        char *maxRam = re + SPEC_LEN_HEAD_3
//                + allocLen;
//#endif

        if (re) {
            IPack0::setHeaders(re, allocLen, type);
            uint32_t * lenN = (uint32_t *)(re+SPEC_LEN_HEAD_3);
            *lenN = _HTONL(iStruct.strLen);
            uint64_t * guid  = (uint64_t *)(lenN + 1);
            *guid=_HTONLL(iStruct.guid1); ++guid;
            *guid=_HTONLL(iStruct.guid2); ++guid;
            *guid=_HTONLL(iStruct.guid3); ++guid;
            *guid=_HTONLL(iStruct.guid4); ++guid;
            *guid=_HTONLL(iStruct.guid5);

            if (iStruct.strLen>0) {
//#ifdef Debug
//                chk= (char *)(avatarIDsN+1);
//                assert(re<chk && chk<maxRam);
//                chk= (char *)(avatarIDsN+1)+iStruct.strLen;
//                assert(re<chk && chk<=maxRam);
//#endif
                ++guid;
                memcpy((void *)(guid), iStruct.str, iStruct.strLen);
            }
        }
        return re;
    }


     static bool parsePackI(T_IPack9_struct & res, const char * pack){
        bool re = false;
        //faux loop
        do {
            uint32_t len = *((uint32_t*)(pack));
            if (len < MIN_LEN_PACK9 || len >= MAX_CHANK) {  break;  }
            uint32_t * lenN = (uint32_t *)(pack + SPEC_LEN_HEAD_2);
            res.strLen = _NTOHL(*lenN);
            if (res.strLen > MAX_CHANK) {  break;  }

            uint64_t * guid  = (uint64_t *)(lenN + 1);
            res.guid1 = _NTOHLL(*guid); ++guid;
            res.guid2 = _NTOHLL(*guid); ++guid;
            res.guid3 = _NTOHLL(*guid); ++guid;
            res.guid4 = _NTOHLL(*guid); ++guid;
            res.guid5 = _NTOHLL(*guid);
            if (0==res.strLen) {
                res.str = nullptr;
            } else {
                ++guid;
                res.str = (const char *)(guid);
            }
            re = true;
        } while (false);

        return re;
    }

}; //IPack9

#endif // IPACK_H
