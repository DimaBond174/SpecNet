#ifndef DEFSERVER_H
#define DEFSERVER_H

#include "i/iserver.h"
#include "iservcallback.h"
#include <thread>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <set>
#include "smartsocket.h"
#include <mutex>

class DefServer : public IServer, public IServCallback
{
public:
    DefServer();
    ~DefServer();

    bool  start()   override;
    void  stop()    override;

    void  smartSocketDown(void * ptr)  override;
private:
    const char * TAG = "DefServer";
    std::atomic_bool keepRun {true};
    /* How much to write in the log file: */
    int logLevel = 0;

    /* pool */
    long long bufConnections  = 3;
    std::mutex freeSockets_mutex;
    std::set<SmartSocket*> setFreeSockets;

    int idleConnLife = 5; //seconds
    std::atomic<int>  socketID {-1};
    std::thread serverThread;

    /* serverThread staff - thread unsafe*/
    std::set<SmartSocket*> setWorkSockets;
    long long freeConnections = 10;

    SmartSocket * getFreeSocket();
    SmartSocket * getFreeSocketFromSet();
    void stopAllSmart();
    bool delFreeSmart();
    /* \ serverThread staff */


    bool create_socket();
    void close_socket();
    static void* runServThreadLoop(void* arg);
    void servThreadLoop();


};

#endif // DEFSERVER_H
