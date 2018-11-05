#include "windowsservice.h"
#include <iostream>
#include "spec/speccontext.h"
#include "windowssystem.h"
#include "depend/tools/spectools.h"


#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <thread>
#include <ctime>
#include <csignal>


WindowsService::WindowsService(const std::function<void()> & f_startContext)
        : _f_startContext(f_startContext) {

}

bool WindowsService::startSpecNetServ() {
    bool re = false;
    //faux loop
    do {
        if (_f_startContext) {
            _f_startContext();
        } else {
            std::cerr << "Error: WindowsService::_f_startContext is nullptr" << std::endl;
            break;
        }

        SpecContext & sr = SpecContext::instance();
        if (!sr.keepRun.load(std::memory_order_acquire)) {
            std::cerr << "Error: SpecContext failed to start" << std::endl;
            break;
        }

        re = true;
    } while(false);
    return re;
}


void WindowsService::onCmd(int argc, char** argv) {
	printf("%i arguments was passed .\n", argc);
	if (argc > 1) {
		std::string arg1(argv[1]);
		if (std::string::npos != arg1.find("-i")) {
			//QtServiceController::install(path, account, password) ? "was" : "was not")
			printf("Trying to install service..\n");
			installService();
		}
		else if (std::string::npos != arg1.find("-u")) {
			printf("Trying to uninstall service ..\n");
			uninstallService();
		}
		else if (std::string::npos != arg1.find("-v")) {
			std::cout << "SpecNetServ version:" << SPEC_VERSION << std::endl;
			const std::string &answ = WindowsSystem::sendCmdS(SPEC_SERVICE, "STATUS");
			if (answ.empty()) {
				std::cout << "SpecNetServ is offline." << std::endl;
			}
			else {
				std::cout << answ << std::endl;
			}
		}
		else if (std::string::npos != arg1.find("-s")) {
			printf("Trying to start service..\n");
			if (!sendCmdStatus(SPEC_SERVICE, "STATUS")) {
				//Blocking call:
				serviceThreadLoop();
				//goFork();
			}
			else {
				printHelp();
			}
		}
		else if (std::string::npos != arg1.find("-t")) {
			printf("Trying to terminate service..\n");
			sendCmdStatus(SPEC_SERVICE, "TERMINATE");
		}
		else if (std::string::npos != arg1.find("-d")) {
			printf("Trying to start service detached from current thread..\n");
			if (!sendCmdStatus(SPEC_SERVICE, "STATUS")) {
				goFork();
			}
			else {
				printHelp();
			}
		}
		else {
			printHelp();
		}
	}
	else {
		//  uninstallService();
		printf("Trying to start service at current thread..\n");
		if (!sendCmdStatus(SPEC_SERVICE, "STATUS")) {
			//Blocking call:
			serviceThreadLoop();
			//goFork();
		}
		else {
			printHelp();
		}
	}
}


void WindowsService::printHelp() {
	printf("Usage: sudo SpecNetServ [params]\n"
		"Example: sudo ./SpecNetServ -t \n"
		"[params]:\n"
		"\twithout params\t:\t Start SpecNetServ at current thread\n"
		"\t-d(etached) \t:\t Start SpecNetServ detached from current thread\n"
		"\t-v(ersion)  \t:\t Print status of the service\n"
		"\t-i(nstall)  \t:\t Install the service\n"
		"\t-u(ninstall)\t:\t Uninstall the service\n"
		"\t-s(tart)    \t:\t Start the service\n"
		"\t-t(erminate)\t:\t Stop the service\n"
		"\t-h(elp)     \t:\t Print this help info\n");

}


bool WindowsService::sendCmdStatus(const char * serviceName, const char * cmd) {
	const std::string &answer = WindowsSystem::sendCmdS(serviceName, cmd);
	if (!answer.empty()) {
		printf("The SpecNetServ is online and answered:\n\t %s\n", answer.c_str());
		return true;
	}
	return false;
}



void* WindowsService::runServThreadLoop(void* arg) {
	WindowsService* service = reinterpret_cast<WindowsService*>(arg);
	service->serviceThreadLoop();
	return 0;
}

void WindowsService::serviceThreadLoop() {
	SpecContext & sr = SpecContext::instance();
	const std::string &sock_path = WindowsSystem::getSockPathS(SPEC_SERVICE);	
	//faux loop
	bool allSystemsStarted = false;
	do {
		/* Start context: */
		if (!startSpecNetServ()) { break; }
		time_t startTime = time(nullptr);

		HANDLE hSlot = CreateMailslot(sock_path.c_str(),
			0,                             // no maximum message size 
			MAILSLOT_WAIT_FOREVER,         // no time-out for operations 
			(LPSECURITY_ATTRIBUTES)NULL); // default security

		if (hSlot == INVALID_HANDLE_VALUE) {			
			std::cerr << "CreateMailslot("
				<< sock_path
				<<") failed with error:"
				<< GetLastError()  << std::endl;
			break;
		}

		DWORD cbMessage, cMessage, cbRead;
		BOOL fResult;
		LPTSTR lpszBuffer;
		TCHAR achID[80];
		DWORD cAllMessages;
		HANDLE hEvent;
		OVERLAPPED ov;

		cbMessage = cMessage = cbRead = 0;
		std::string slotName("Slot");
		slotName.append(to_string(hSlot));

		hEvent = CreateEvent(NULL, FALSE, FALSE, slotName.c_str());
		if (NULL == hEvent) {
			std::cerr << "CreateEvent failed with error:"
				<< GetLastError() << std::endl;
			break;
		}		
		ov.Offset = 0;
		ov.OffsetHigh = 0;
		ov.hEvent = hEvent;

		regSIGhandler();

		/* Going to start SERVER: */
		if (!sr.iEncrypt.get()->start()) {
			sr.iLog.get()->log("e", "[%s]: FAIL iEncrypt.get()->start().", TAG);
			break;
		}
		if (!sr.iServer.get()->start()) {
			sr.iLog.get()->log("e", "[%s]: FAIL iServer->start().", TAG);
			break;
		}

		std::cout << "SpecNetServ is started and listening commands on mailslot ["
			<< sock_path << "]" << std::endl;
		allSystemsStarted = true;
		while (sr.keepRun.load(std::memory_order_acquire)) {
			fResult = GetMailslotInfo(hSlot, // mailslot handle 
				(LPDWORD)NULL,               // no maximum message size 
				&cbMessage,                   // size of next message 
				&cMessage,                    // number of messages 
				(LPDWORD)NULL);              // no read time-out 

			if (!fResult) {
				std::cerr << "GetMailslotInfo failed with error:"
					<< GetLastError() << std::endl;				
				break;
			}

			if (cbMessage == MAILSLOT_NO_MESSAGE) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				continue;
			}

			lpszBuffer = (LPTSTR)GlobalAlloc(GPTR,
				lstrlen((LPTSTR)achID) * sizeof(TCHAR) + cbMessage);
			if (NULL == lpszBuffer) {
				std::cerr << "Oh no free RAM, GlobalAlloc==NULL"
					 << std::endl;
				break;
			}			
			lpszBuffer[0] = '\0';
			fResult = ReadFile(hSlot,
				lpszBuffer,
				cbMessage,
				&cbRead,
				&ov);

			if (!fResult) {
				std::cerr << "ReadFile failed with "
					<< GetLastError()  << std::endl;				
				GlobalFree((HGLOBAL)lpszBuffer);
				break;
			}
			std::string str(lpszBuffer);
			const char *cmd = str.c_str();
			int len = 0;
			for (; len < str.length(); ++len, ++cmd) {
				if (*cmd == '$') { break; }
			}
			if (*cmd == '$') {
				++cmd;
				std::string reSlot = str.substr(0, len);
				if (str.length() >= 9 && !strncmp(cmd, "TERMINATE", 9)) {
					sr.onStopSig();
					str = std::string("SpecNetServ is going to stop..");
				}
				else if (str.length() >= 6 && !strncmp(cmd, "STATUS", 6)) {
					str = getCurStatus(startTime);
				}
				WindowsSystem::writeMailSlot(reSlot, str);
			}
						
			GlobalFree((HGLOBAL)lpszBuffer);
		}//while
		unregSIGhandler();
		CloseHandle(hEvent);		

	} while (false);

	if (!allSystemsStarted) {
		std::cerr << "FAIL to start: see SpecNetServ log for details.."
			<< std::endl;
	}
}

std::string WindowsService::getCurStatus(time_t t) {
	std::string strTime;
	char mbstr[100];
	if (std::strftime(mbstr, sizeof(mbstr), "started [%Y-%m-%d %H:%M:%S] and is running..", std::localtime(&t))) {
		strTime = std::string(mbstr);
	}

	return strTime;
}


static void signal_handler(int sig) {
	if (SIGTERM == sig || SIGABRT == sig || SIGINT == sig) {
		printf("SpecNetServ is going to stop on SIGTERM\n");
		SpecContext::instance().onStopSig();
	}
}


void WindowsService::regSIGhandler() {
	if (already_hooked_up) {
		std::cerr << "regSIGhandler called more than once.."
			<< std::endl;
		return;
	}
	already_hooked_up = true;
#if defined(Windows)
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);
#else
	struct sigaction sa;
	// Setup the handler
	sa.sa_handler = &handle_signal;
	// Restart the system call, if at all possible
	sa.sa_flags = SA_RESTART;
	// Block every signal during the handler
	sigfillset(&sa.sa_mask);
	// Intercept SIGHUP and SIGINT
	if (sigaction(SIGHUP, &sa, NULL) == -1) {
		LOG(FATAL) << "Cannot install SIGHUP handler.";
	}
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		LOG(FATAL) << "Cannot install SIGINT handler.";
	}
#endif


}

void WindowsService::unregSIGhandler() {
	if (already_hooked_up) {
#if defined(Windows)
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGABRT, SIG_DFL);
#else
		struct sigaction sa;
		// Setup the sighub handler
		sa.sa_handler = SIG_DFL;
		// Restart the system call, if at all possible
		sa.sa_flags = SA_RESTART;
		// Block every signal during the handler
		sigfillset(&sa.sa_mask);
		// Intercept SIGHUP and SIGINT
		if (sigaction(SIGHUP, &sa, NULL) == -1) {
			LOG(FATAL) << "Cannot uninstall SIGHUP handler.";
		}
		if (sigaction(SIGINT, &sa, NULL) == -1) {
			LOG(FATAL) << "Cannot uninstall SIGINT handler.";
		}
#endif

		already_hooked_up = false;
	}
}

void WindowsService::goFork() {
	//pid_t pid;

	///* Fork off the parent process */
	//pid = fork();

	///* An error occurred */
	//if (pid < 0) { return; }
	////   exit(EXIT_FAILURE);

 //  /* Success: Let the parent terminate */
	//if (pid > 0) { return; }
	////   exit(EXIT_SUCCESS);

 //  /* On success: The child process becomes session leader */
	//if (setsid() < 0) { return; }
	////  exit(EXIT_FAILURE);

 // /* Catch, ignore and handle signals */
 // //TODO: Implement a working signal handler */
	//signal(SIGCHLD, SIG_IGN);
	//signal(SIGHUP, SIG_IGN);
	///* Register SIGTERM listener */
	////regSIGhandler();


	///* Fork off for the second time*/
	//pid = fork();

	///* An error occurred */
	//if (pid < 0) { return; }
	////  exit(EXIT_FAILURE);

 // /* Success: Let the parent terminate */
	//if (pid > 0) { return; }
	////  exit(EXIT_SUCCESS);

 // /* Set new file permissions */
	//umask(0);

	///* Change the working directory to the root directory */
	///* or another appropriated directory */
	//chdir("/");

	///* Close all open file descriptors */
	//int x;
	//for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--)
	//{
	//	close(x);
	//}

	///* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
	//stdin = fopen("/dev/null", "r");
	//stdout = fopen("/dev/null", "w+");
	//stderr = fopen("/dev/null", "w+");


	///* Open the system log file */
	////openlog ("SpecNetServ", LOG_PID, LOG_DAEMON);
	////syslog (LOG_NOTICE, "First daemon started.");
	//if (0 == pid) {
	//	serviceThreadLoop();
	//}
	////syslog (LOG_NOTICE, "First daemon terminated.");
	////closelog();
}

void WindowsService::installService() {
	//faux loop
	do {
		//const std::string &exePath = LinuxSystem::getExeS();
		//const std::string &dirPath = FileAdapter::getDirS(exePath);
		//if (dirPath.empty()) {
		//	std::cerr << "Error: can't get current executive directory in WindowsService::installService(). " << std::endl;
		//	break;
		//}
		////        [Unit]
		////        Description=crash report submission daemon
		////        After=network-online.target
		////        Wants=network-online.target

		////        [Service]
		////        Environment="CRASH_DB_URL=https://daisy.ubuntu.com"
		////        ExecStart=/usr/bin/whoopsie -f
		////        Restart=always

		////        [Install]
		////        WantedBy=multi-user.target
		//std::string iniSrv;
		//iniSrv.append("[Unit]\n");
		//iniSrv.append("Description=SpecNetService\n");
		//iniSrv.append("After=network-online.target\n");
		//iniSrv.append("Wants=network-online.target\n");
		//iniSrv.append("\n");
		//iniSrv.append("[Service]\n");
		//iniSrv.append("ExecStart=")
		//	.append(exePath)
		//	.append(" -s\n");
		////        iniSrv.append("Restart=always\n");
		//iniSrv.append("\n");
		//iniSrv.append("[Install]\n");
		//iniSrv.append("WantedBy=multi-user.target\n");
		//bool isOk = false;
		//std::string fullPath;
		//fullPath.append("/etc/systemd/system/").append(SPEC_SERVICE).append(".service");
		//std::string cmd1("systemctl daemon-reload");
		//std::string cmd2("systemctl enable ");
		//cmd2.append(SPEC_SERVICE).append(".service");
		//std::string cmd3("systemctl start ");
		//cmd3.append(SPEC_SERVICE);

		//if (FileAdapter::saveTFileS(fullPath.c_str(), iniSrv.c_str(), iniSrv.length())) {
		//	//Ok, root access done:
		//	try {
		//		std::cout << LinuxSystem::execCmdS(cmd1.c_str());
		//		std::cout << LinuxSystem::execCmdS(cmd2.c_str());
		//		std::cout << LinuxSystem::execCmdS(cmd3.c_str())
		//			<< std::flush;
		//		if (sendCmdStatus(SPEC_SERVICE, "STATUS")) {
		//			isOk = true;
		//		}
		//	}
		//	catch (...) {}
		//}

		//if (!isOk) {
		//	// must install by hand                      
		//	std::string fullPath2;
		//	fullPath2.append(dirPath).append("/").append(SPEC_SERVICE).append(".service");
		//	if (FileAdapter::saveTFileS(fullPath2.c_str(), iniSrv.c_str(), iniSrv.length())) {
		//		std::cout << "Can't auto install service.." << std::endl
		//			<< "may be there are no root access.." << std::endl
		//			<< "Please execute next commands manually with sudo access:" << std::endl
		//			<< "sudo cp " << fullPath2 << " " << fullPath << std::endl
		//			<< "sudo " << cmd1.c_str() << std::endl
		//			<< "sudo " << cmd2.c_str() << std::endl
		//			<< "sudo " << cmd3.c_str() << std::endl
		//			<< std::flush;
		//	}
		//	else {
		//		std::cerr << "Error: can't create file: "
		//			<< fullPath
		//			<< std::endl;
		//	}
		//}

	} while (false);

}

void WindowsService::uninstallService() {
	//bool isOk = false;
	//std::string cmd1("systemctl stop  ");
	//cmd1.append(SPEC_SERVICE);
	//std::string cmd2("systemctl disable ");
	//cmd2.append(SPEC_SERVICE).append(".service");
	//std::string cmd3("rm /etc/systemd/system/");
	//cmd3.append(SPEC_SERVICE).append(".service");
	//std::string cmd4("systemctl daemon-reload");
	//std::string cmd5("systemctl reset-failed");

	//try {
	//	std::cout << LinuxSystem::execCmdS(cmd1.c_str())
	//		<< LinuxSystem::execCmdS(cmd2.c_str())
	//		<< LinuxSystem::execCmdS(cmd3.c_str())
	//		<< LinuxSystem::execCmdS(cmd4.c_str())
	//		<< LinuxSystem::execCmdS(cmd5.c_str())
	//		<< std::flush;
	//	if (!sendCmdStatus(SPEC_SERVICE, "STATUS")) {
	//		isOk = true;
	//	}
	//}
	//catch (...) {}
	//if (!isOk) {
	//	// must uninstall by hand
	//	std::cout << "Can't auto uninstall service.." << std::endl
	//		<< "may be there are no root access.." << std::endl
	//		<< "Please execute next commands manually with sudo access:" << std::endl
	//		<< "sudo " << cmd1.c_str() << std::endl
	//		<< "sudo " << cmd2.c_str() << std::endl
	//		<< "sudo " << cmd3.c_str() << std::endl
	//		<< "sudo " << cmd4.c_str() << std::endl
	//		<< "sudo " << cmd5.c_str() << std::endl
	//		<< std::flush;
	//}
}
