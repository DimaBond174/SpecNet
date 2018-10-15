#ifndef EpolSrv_H
#define EpolSrv_H


#include <thread>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <set>
#include <queue>
#include <mutex>
#include "i/iserver.h"
#include "i/ilog.h"
#include "i/ialloc.h"
//#include "iservcallback.h"
#include "epolsocket.h"
#include "iepol.h"
#include "i/ipack.h"
#include "i/ifileadapter.h"

class EpolSrv : public IServer,  public IServCallback
{
public:
    EpolSrv();
    ~EpolSrv();

    /* IServer interfaces :*/
    bool  start()   override;
    void  stop()    override;

    /* IServCallback interfaces :*/
    const char * getMessagesPath() override;
    const char * getAvaCertsPath() override;
    std::string getServPassword() override;


    void logConnection(sockaddr * remote_addr, unsigned int remote_addr_len, int client_socket);

private:
    const char * TAG = "EpolSrv";
    IEpoll srvEpoll;
    /* srvState: 0==not started, 1==starting, 2==works, 3==going to stop */
    std::atomic_int srvState {0};
    std::atomic_bool keepRun {true};
    /* How much to write in the log file: */
    int logLevel = 0;

    std::thread serverThread;
    std::condition_variable serverThreadCond;
    std::mutex serverThreadMutex;

    /* pool */
    //long long bufConnections  = 3;
    //std::mutex freeSockets_mutex;



    //std::atomic<int>  socketID {-1};

    bool create_socket();
    static void* runServThreadLoop(void* arg);
    void servThreadLoop();

    /* serverThread staff - thread unsafe*/
    int server_socket =-1; //init before thread starts
    int epollfd =-1;
    std::set<EpolSocket*> setAllSockets;
    std::set<EpolSocket*> setFreeSockets;
    std::set<EpolSocket*> setWorkSockets;
    long long maxConnections =10;
    long long bufConnections =3;
    int idleConnLife = 5; //seconds
    std::string messagesPath;
    std::string avaCertsPath;
    std::string servPassword;

    IEncrypt *iEncrypt = nullptr;
    ILog * iLog = nullptr;
    IAlloc * iAlloc = nullptr;
    IFileAdapter * iFileAdapter = nullptr;
    Idb * iDB = nullptr;

    bool addServerEpoll();
    void stopServerEpoll();
    EpolSocket * getFreeSocket();
    void setFreeSocket1(EpolSocket * s);
    void setFreeSocket2(EpolSocket * s);
    void setFreeSocket3(EpolSocket * s);
    bool goWritePacket(EpolSocket * s);
    void stopAllSockets();    
    void updateEPoll(EpolSocket * s);
    bool handleWrite(EpolSocket * s);
    void handleAccept();
    void handleRead(EpolSocket * s);
    void handleHandshake(EpolSocket * s);
    void handleSockets();
    void ohNoFreeRam();
    //bool setEncryptWants(IEpoll * s, int err);
    /* \ serverThread staff */

};

#endif // EpolSrv_H
