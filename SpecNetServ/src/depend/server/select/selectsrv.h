#ifndef SelectSrv_H
#define SelectSrv_H


#include <thread>
#include <atomic>
//#include <sys/socket.h>
//#include <arpa/inet.h>
//#include <netdb.h>
#include <set>
#include <queue>
#include <mutex>
#include "i/iserver.h"
#include "i/ilog.h"
#include "i/ialloc.h"
#include "i/ipack.h"
#include "i/ifileadapter.h"
#include "i/iservcallback.h"

#define MAX_SERV_SOCK 32
//That will override microsoft WinSock2.h, should be >= 64:
//#define FD_SETSIZE    128

#if defined(Windows)
  #include <WinSock2.h>
#else

#endif

#include "sockholder.h"

class SelectSrv : public IServer,  public IServCallback
{
public:
    SelectSrv();
    ~SelectSrv();

    /* IServer interfaces :*/
    bool  start()   override;
    void  stop()    override;

    /* IServCallback interfaces :*/
    const char * getMessagesPath() override;
    const char * getAvaCertsPath() override;
    std::string getServPassword() override;


    void logConnection(sockaddr * remote_addr, unsigned int remote_addr_len, int client_socket);

private:
    const char * const TAG = "SelectSrv";




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
	T_SOCKET servSocks[MAX_SERV_SOCK];
	int servSockCount = 0;

    int epollfd =-1;
    std::set<SockHolder*> setAllSockets;
    std::set<SockHolder*> setFreeSockets;
    std::set<SockHolder*> setWorkSockets;
    int maxConnections = 10;
    int bufConnections = 3;

    int idleConnLife = 5; //seconds
    std::string messagesPath;
    std::string avaCertsPath;
    std::string servPassword;

	std::shared_ptr <IEncrypt>      p_iEncrypt;
    IEncrypt *iEncrypt = nullptr;

	std::shared_ptr <ILog>          p_iLog;
    ILog * iLog = nullptr;

	std::shared_ptr <IAlloc>       p_iAlloc;
    IAlloc * iAlloc = nullptr;

	std::shared_ptr <IFileAdapter>  p_iFileAdapter;
    IFileAdapter * iFileAdapter = nullptr;

	std::shared_ptr <Idb>           p_iDB;
    Idb * iDB = nullptr;

	void printSocketError(const char *function);
	std::string getLastSocketErrorString();
    
    void stopServerEpoll();
    SockHolder * getFreeSocket();
    void setFreeSocket1(SockHolder * s);
    void setFreeSocket2(SockHolder * s);
    void setFreeSocket3(SockHolder * s);
    bool goWritePacket(SockHolder * s);
    void stopAllSockets();    
    
    bool handleWrite(SockHolder * s);
    void handleAccept(T_SOCKET server_socket);
    void handleRead(SockHolder * s);
    void handleHandshake(SockHolder * s);
    void handleSockets();
    void ohNoFreeRam();
    //bool setEncryptWants(IEpoll * s, int err);
    /* \ serverThread staff */
	bool setNONBLOCK(unsigned int sock);
	void cleanup();
	void setServFD_Set(fd_set &_fd_set);

};

#endif // SelectSrv_H
