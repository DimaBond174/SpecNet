#ifndef WINDOWSSERVICE_H
#define WINDOWSSERVICE_H

#include <functional>
#include <windows.h>
#include <time.h>

class WindowsService {
public:
    WindowsService(const std::function<void()> & f_startContext);

    void onCmd(int argc, char** argv);
	bool sendCmdStatus(const char * serviceName, const char * cmd);
private:
	const char * const TAG = "WindowsService";
	bool already_hooked_up = false;
    std::function<void()> _f_startContext;
    bool startSpecNetServ();
	void printHelp();


	static void* runServThreadLoop(void* arg);
	void serviceThreadLoop();
	static std::string getCurStatus(time_t t);
	void regSIGhandler();
	void unregSIGhandler();
	void goFork();
	void installService();
	void uninstallService();

};

#endif // WINDOWSSERVICE_H
