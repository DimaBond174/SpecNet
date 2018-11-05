#ifndef LINUXSERVICE_H
#define LINUXSERVICE_H

#include <functional>
#include <ctime>

class LinuxService {
public:
    LinuxService(const std::function<void()> & f_startContext);

    void onCmd(int argc, char** argv);    
    bool sendCmdStatus(const char * serviceName, const char * cmd);
private:
    const char * const TAG = "LinuxService";
    std::function<void()> _f_startContext;
    bool startSpecNetServ();
    void printHelp();


    static void* runServThreadLoop(void* arg);
    void serviceThreadLoop();
    std::string getCurStatus(std::time_t t);
    void regSIGhandler();
    void goFork();
    void installService();
    void uninstallService();
};

#endif // LINUXSERVICE_H
