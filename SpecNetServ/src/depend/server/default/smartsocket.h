#ifndef SMARTSOCKET_H
#define SMARTSOCKET_H
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "iservcallback.h"
#include "i/iencrypt.h"

class SmartSocket : public IEncryptUser
{
public:
    SmartSocket(IServCallback * iServCallback, int logLevel);
    ~SmartSocket();

    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len;
    int _logLevel;
    IServCallback * _iServCallback;

    /*state: 0=is free, 1=starting, 2=stopping */
    std::atomic<int> state  {0};

    void start(int client_socket);
    void stop();

    /* TLS socket callbacks */
    /* Callback on Json String ready - can take mail */
    void onStrReady() override;

    /* Callback on IEncryptSocket down - can delete it */
    void onSocketDown() override;
private:
    const char * TAG = "SmartSocket";
    std::atomic<int>  socketID {-1};
    std::atomic<bool> keepRun  {true};
    std::thread writeThread;
    std::condition_variable writeThreadCond;
    std::mutex writeThreadMutex;

    static void* runWriteThreadLoop(void* arg);
    void writeThreadLoop();

    void logConnection();




    /* Read thread local thread staff */
    IEncryptSocket * sslStaf  {nullptr};
};

#endif // SMARTSOCKET_H
