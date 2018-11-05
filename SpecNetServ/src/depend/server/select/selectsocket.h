#ifndef SelectSocket_H
#define SelectSocket_H
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>

#include "i/iencrypt.h"
#include "i/ilog.h"
#include "i/ialloc.h"

#include "i/iencrypt.h"
#include "i/ifileadapter.h"
#include <openssl/base.h>
#include "i/idb.h"
#include "i/iservcallback.h"

#if defined(Windows)
#define T_SOCKET UINT_PTR
#define NOT_SOCKET INVALID_SOCKET
#else
#define T_SOCKET int
#define NOT_SOCKET (-1)
#endif

#define ESOCK_FREE0  0
#define ESOCK_FREE1  1
#define ESOCK_GO_SHAKE   2
#define ESOCK_START_THREAD   3
#define ESOCK_WANT_WRITE 4
#define ESOCK_STOPPING   6

class SelectSocket 
{
public:
    SelectSocket();   
    ~SelectSocket();

//    struct sockaddr_in remote_addr;
//    socklen_t remote_addr_len;
    int _logLevel;
    IServCallback * _iServCallback;
    ILog * iLog;
    IAlloc * iAlloc;
    IEncrypt * iEncrypt;
    IFileAdapter * iFileAdapter;
    Idb * iDB;

    /* state: 0=is free, 1=is free, 2=going to handshake
     * 3=thread started
     * 4=wants write
     * 6=stopping
    */
    std::atomic<int> state  {0};

    void start();
    void stop();
    void eatPacket(char * ptr);
    char * getPacket();    
    void writePack(char * ptr);

    /* Common thread unsafe staff */
    void freeResources();
    static uint64_t getCurJavaTime(); //==System.currentTimeMillis()

private:
    //const char * TAG = "SelectSocket";

    std::atomic<bool> keepRun  {true};

    std::queue<char *> readQueue;
    std::mutex readQueueMutex;

    std::queue<char *> writeQueue;
    std::mutex writeQueueMutex;


    std::thread workThread;
    std::condition_variable workThreadCond;
    std::mutex workThreadMutex;

    static void* runWorkThreadLoop(void* arg);
    void workThreadLoop();




    /* Read thread local thread staff */
    X509 * _x509 = nullptr;
    EVP_PKEY * _evpX509 = nullptr;
    long long groupID = 0;
    long long avatarID = 0;
    long long grpMailLife = 0;
    long long avaMailLife = 0;

    bool setCurX509(const void *buf, int num);
    void freeResourcesLocal();
    bool parsePack(char * ptr);
    bool doPack1(char * ptr);
    bool doPack3(char * ptr);
    bool doPack5(char * ptr);
    bool doPack6(char * ptr);
    bool doPack7(char * ptr);
    bool doPack8(char * ptr);
    bool doPack9(char * ptr);
    bool doPack10(char * ptr);
};

#endif // SelectSocket_H
