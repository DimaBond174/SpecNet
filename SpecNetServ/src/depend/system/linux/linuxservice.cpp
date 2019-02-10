/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include "linuxservice.h"
#include "linuxsystem.h"
#include "depend/file/base/fileadapter.h"
#include <iostream>
#include "spec/speccontext.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <algorithm>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>


#define BUFFER_SIZE 256

LinuxService::LinuxService(const std::function<void()> & f_startContext)
    :  _f_startContext(f_startContext)  {

}

bool  LinuxService::startSpecNetServ()  {
  bool  re  =  false;
    //faux loop
  do  {
    if  (_f_startContext)  {
      _f_startContext();
    }  else  {
      std::cerr  <<  "Error: LinuxService::_f_startContext is nullptr"  <<  std::endl;
      break;
    }
    SpecContext  &sr  =  SpecContext::instance();
    if  (!sr.keepRun.load(std::memory_order_acquire))  {
      std::cerr  <<  "Error: SpecContext failed to start"  <<  std::endl;
      break;
    }
    re = true;
  } while(false);
  return re;
}

void  LinuxService::onCmd(int  argc,  char  **argv)  {
  printf("%i arguments was passed .\n",  argc);
  if  (argc  >  1)  {
    std::string  arg1(argv[1]);
    if  (std::string::npos  !=  arg1.find("-i"))  {
      //QtServiceController::install(path, account, password) ? "was" : "was not")
      printf("Trying to install service..\n");
      installService();
    }  else if (std::string::npos  !=  arg1.find("-u"))  {
      printf("Trying to uninstall service ..\n");
      uninstallService();
    }  else if (std::string::npos  !=  arg1.find("-v"))  {
      std::cout  <<  "SpecNetServ version:"  <<  SPEC_VERSION  <<  std::endl;
      const  std::string  &answ  =  LinuxSystem::sendCmdS(SPEC_SERVICE,  "STATUS");
      if  (answ.empty())  {
        std::cout  <<  "SpecNetServ is offline."  <<  std::endl;
      }  else  {
        std::cout  <<  answ  <<  std::endl;
      }
    }  else if  (std::string::npos  !=  arg1.find("-s"))  {
      printf("Trying to start service..\n");
            //Blocking call:
      serviceThreadLoop();
            //goFork();
    }  else if  (std::string::npos  !=  arg1.find("-t"))  {
      printf("Trying to terminate service..\n");
      sendCmdStatus(SPEC_SERVICE,  "TERMINATE");
    }  else if (std::string::npos  !=  arg1.find("-d"))  {
      printf("Trying to start service detached from current thread..\n");
      if  (!sendCmdStatus(SPEC_SERVICE,  "STATUS"))  {
        goFork();
      }  else  {
        printHelp();
      }
    }  else  {
      printHelp();
    }
  }  else  {
      //  in case if  (argc  >  1) :
    printf("Trying to start service at current thread..\n");
    if  (!sendCmdStatus(SPEC_SERVICE, "STATUS"))  {
        //Blocking call:
      serviceThreadLoop();
            //goFork();
    }  else  {
      printHelp();
    }
  }
}  //  onCmd

void  LinuxService::printHelp()  {
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

bool  LinuxService::sendCmdStatus(const char  *serviceName,  const char  *cmd)  {
  const std::string  &answer  =  LinuxSystem::sendCmdS(serviceName,  cmd);
  if  (!answer.empty())  {
    printf("The SpecNetServ is online and answered:\n\t %s\n",  answer.c_str());
    return  true;
  }
  return  false;
}

void * LinuxService::runServThreadLoop(void  *arg)  {
  LinuxService  *service  =  static_cast<LinuxService*>(arg);
  service->serviceThreadLoop();
  return 0;
}

void  LinuxService::serviceThreadLoop()  {
  SpecContext  &sr  =  SpecContext::instance();
  const std::string  &sock_path  =  LinuxSystem::getSockPathS(SPEC_SERVICE);
  int  connection_socket  =  -1;
  bool  allSystemsStarted  =  false;
    //faux loop
  do  {
        /* Start context: */
    if  (!startSpecNetServ())  {  break;  }
    std::time_t  startTime  =  std::time(nullptr);
        /* Unix socket for cmd receiving */
    struct sockaddr_un name;
    int  ret;
    int  data_socket;
    char  buffer[BUFFER_SIZE];
        /* chmode 0777 all files i'll create: */
    umask(0);

    /*  In case the program exited inadvertently on the last run,
        remove the socket:  */
    unlink(sock_path.c_str());
    FileAdapter::removeAllS(sock_path.c_str());

    /* Create local socket. */
    connection_socket  =  socket(AF_UNIX, SOCK_SEQPACKET,  0);
    if  (connection_socket  ==  -1)  {
      std::cerr  <<  "Error: LinuxService::serviceThreadLoop() -1 = socket(AF_UNIX, "
                       <<  std::endl;
      break;
    }

    /* Bind socket to socket name. */
    memset(&name,  0,  sizeof(struct sockaddr_un));
    name.sun_family  =  AF_UNIX;
    ::memcpy(name.sun_path,  sock_path.c_str(),  sock_path.length());
    ret  =  bind(connection_socket,  reinterpret_cast<const struct sockaddr *>(&name),
        sizeof(struct sockaddr_un));
    if  (ret  ==  -1)  {
      std::cerr  <<  "Error: LinuxService::serviceThreadLoop() -1 = bind(connection_socket "
          << sock_path << std::endl;
      break;
    }

        /*
        * Prepare for accepting connections. The backlog size is set
        * to 20. So while one request is being processed other requests
        * can be waiting.
        */
    ret  =  listen(connection_socket,  20);
    if  (ret  ==  -1)  {
        std::cerr  <<  "Error: LinuxService::serviceThreadLoop() -1 = listen(connection_socket "
            <<  sock_path  <<  std::endl;
      break;
    }

        /* chmode 0755 all files i'll create: */
    umask(022);

        /* Register SIGTERM listener */
    regSIGhandler();

        /* Going to start encryption: */
    sr.specSSL  =  std::make_shared<SpecSSL>(sr.iLog.get(),
        sr.iFileAdapter.get(),  sr.iConfig.get());
    if  (!sr.specSSL.get()->start())  {
            sr.iLog.get()->log("e","[%s]: FAIL specSSL->start().",  TAG);
            break;
        }
        /* Going to start SERVER: */
    if  (!sr.iServer.get()->start())  {
      sr.iLog.get()->log("e","[%s]: FAIL iServer->start().",  TAG);
      break;
    }
    std::cout  <<  "SpecNetServ is started and listening commands on unix socket ["
         <<  sock_path  <<  "]"  <<   std::endl;
    allSystemsStarted  =  true;

        /* This is the main loop for handling commands. */
    while  (sr.keepRun.load(std::memory_order_acquire))  {
            /* Wait for incoming connection. */
      data_socket  =  accept(connection_socket,  NULL,  NULL);
      if  (data_socket  ==  -1)  {  continue;  }
            /* Read cmd */
      while  (sr.keepRun.load(std::memory_order_acquire))  {
        ret  =  read(data_socket,  buffer,  BUFFER_SIZE);
        if  (ret  <  0)  {  break;  }
        if  (ret  ==  0)  {  continue;  }
        buffer[ret]  =  0;
        std::string  str(buffer);
        if  (!strncmp(buffer,  "TERMINATE",  9))  {
          sr.onStopSig();
          str  =  std::string("SpecNetServ is going to stop..");
        }  else if  (!strncmp(buffer,  "STATUS",  6))  {
          str  =  getCurStatus(startTime);
        }
        ret  =  write(data_socket,  str.c_str(),  str.length());
        break;
      }  //  read while (sr.keepRun
      close(data_socket);
    } //connection while (sr.keepRun
  } while(false);

  if  (!allSystemsStarted)  {
    std::cerr  <<  "FAIL to start: see SpecNetServ log for details.."
        << std::endl;
  }
  if  (-1  !=  connection_socket)  {
    close(connection_socket);
  }
  /* Unlink the socket. */
  unlink(sock_path.c_str());
  FileAdapter::removeAllS(sock_path.c_str());
}  //  serviceThreadLoop

std::string  LinuxService::getCurStatus(std::time_t t)  {
  std::string  strTime;
  char  mbstr[100];
  if (std::strftime(mbstr,  sizeof(mbstr),
      "started [%Y-%m-%d %H:%M:%S] and is running..",  std::localtime(&t)))  {
    strTime  =  std::string(mbstr);
  }
  return strTime;
}

struct sigaction  act;
static void  signal_handler(int sig)  {
  if  (SIGTERM == sig)  {
    printf("SpecNetServ is going to stop on SIGTERM\n");
    SpecContext::instance().onStopSig();
  }
}

void  LinuxService::regSIGhandler()  {
  memset(&act,  0,  sizeof(act));
  act.sa_handler  =  signal_handler;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGTERM);
  sigaction(SIGTERM, &act, 0);
}

void  LinuxService::goFork()  {
  pid_t  pid;
    /* Fork off the parent process */
  pid  =  fork();
    /* if an error occurred */
  if  (pid  <  0)  {  return;  }
     //   exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
  if  (pid  >  0)  {  return;  }
     //   exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
  if  (setsid()  <  0)  {  return;  }
      //  exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */    
  signal(SIGCHLD,  SIG_IGN);
  signal(SIGHUP,  SIG_IGN);

    /* Register SIGTERM listener */
    //regSIGhandler();

    /* Fork off for the second time*/
  pid  =  fork();

    /* An error occurred */
  if  (pid  <  0)  {  return;  }
      //  exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
  if (pid  >  0)  {  return;  }
      //  exit(EXIT_SUCCESS);

    /* Set new file permissions */
  umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
  chdir("/");

    /* Close all open file descriptors */
  int x;
  for  (x  =  sysconf(_SC_OPEN_MAX);  x  >=  0;  x--)  {
    close (x);
  }

    /* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
  stdin  =  fopen("/dev/null",  "r");
  stdout  =  fopen("/dev/null",  "w+");
  stderr  =  fopen("/dev/null",  "w+");

    /* Open the system log file */
    //openlog ("SpecNetServ", LOG_PID, LOG_DAEMON);
    //syslog (LOG_NOTICE, "First daemon started.");
  if  (0==pid)  {
    serviceThreadLoop();
  }
    //syslog (LOG_NOTICE, "First daemon terminated.");
    //closelog();
}  //  goFork

void  LinuxService::installService()  {
    //faux loop
  do  {
    const std::string  &exePath  =  LinuxSystem::getExeS();
    const std::string  &dirPath  =  FileAdapter::getDirS(exePath);
    if  (dirPath.empty())  {
      std::cerr  <<  "Error: can't get current executive directory in LinuxService::installService(). "
        <<  std::endl;
      break;
    }
//        [Unit]
//        Description=crash report submission daemon
//        After=network-online.target
//        Wants=network-online.target
//        [Service]
//        Environment="CRASH_DB_URL=https://daisy.ubuntu.com"
//        ExecStart=/usr/bin/whoopsie -f
//        Restart=always
//        [Install]
//        WantedBy=multi-user.target
    std::string  iniSrv;
    iniSrv.append("[Unit]\n");
    iniSrv.append("Description=SpecNetService\n");
    iniSrv.append("After=network-online.target\n");
    iniSrv.append("Wants=network-online.target\n");
    iniSrv.append("\n");
    iniSrv.append("[Service]\n");
    iniSrv.append("ExecStart=")
        .append(exePath)
        .append(" -s\n");
//        iniSrv.append("Restart=always\n");
    iniSrv.append("\n");
    iniSrv.append("[Install]\n");
    iniSrv.append("WantedBy=multi-user.target\n");
    bool  isOk  =  false;
    std::string  fullPath;
    fullPath.append("/etc/systemd/system/")
        .append(SPEC_SERVICE).append(".service");
    std::string  cmd1("systemctl daemon-reload");
    std::string  cmd2("systemctl enable ");
    cmd2.append(SPEC_SERVICE).append(".service");
    std::string  cmd3("systemctl start ");
    cmd3.append(SPEC_SERVICE);
    if  (FileAdapter::saveTFileS(fullPath.c_str(),  iniSrv.c_str(),  iniSrv.length()))  {
            //Ok, root access done:
      try  {
        std::cout  <<  LinuxSystem::execCmdS(cmd1.c_str());
        std::cout  <<  LinuxSystem::execCmdS(cmd2.c_str());
        std::cout  <<  LinuxSystem::execCmdS(cmd3.c_str())
            << std::flush;
        if  (sendCmdStatus(SPEC_SERVICE, "STATUS"))  {
          isOk  =  true;
        }
      }  catch(...)  {  }
    }  //  if
    if  (!isOk)  {
            // must install by hand                      
      std::string  fullPath2;
      fullPath2.append(dirPath).append("/").append(SPEC_SERVICE).append(".service");
      if  (FileAdapter::saveTFileS(fullPath2.c_str(),  iniSrv.c_str(),  iniSrv.length()))  {
        std::cout  <<  "Can't auto install service.."  <<  std::endl
            <<  "may be there are no root access.."  <<  std::endl
            <<  "Please execute next commands manually with sudo access:"  <<  std::endl
            <<  "sudo cp "  <<  fullPath2  <<  " "  <<  fullPath  <<std::endl
            <<  "sudo "  <<  cmd1.c_str()  << std::endl
            <<  "sudo "  <<  cmd2.c_str()  << std::endl
            <<  "sudo "  <<  cmd3.c_str()  << std::endl
            <<  std::flush;
      }  else  {
        std::cerr  <<  "Error: can't create file: "
            <<  fullPath  <<  std::endl;
      }
    }  //  if
  }  while  (false);
}  //  installService

void  LinuxService::uninstallService()  {
  bool  isOk  =  false;
  std::string  cmd1("systemctl stop  ");
  cmd1.append(SPEC_SERVICE);
  std::string  cmd2("systemctl disable ");
  cmd2.append(SPEC_SERVICE).append(".service");
  std::string  cmd3("rm /etc/systemd/system/");
  cmd3.append(SPEC_SERVICE).append(".service");
  std::string  cmd4("systemctl daemon-reload");
  std::string  cmd5("systemctl reset-failed");
  try  {
    std::cout  <<  LinuxSystem::execCmdS(cmd1.c_str())
        <<  LinuxSystem::execCmdS(cmd2.c_str())
        <<  LinuxSystem::execCmdS(cmd3.c_str())
        <<  LinuxSystem::execCmdS(cmd4.c_str())
        <<  LinuxSystem::execCmdS(cmd5.c_str())
        <<  std::flush;
    if  (!sendCmdStatus(SPEC_SERVICE, "STATUS"))  {
      isOk  =  true;
    }
  }  catch(...)  { }
  if  (!isOk)  {
        // must uninstall by hand
    std::cout  <<  "Can't auto uninstall service.."  <<  std::endl
        <<  "may be there are no root access.."  <<  std::endl
        <<  "Please execute next commands manually with sudo access:"  <<  std::endl
        <<  "sudo "  <<  cmd1.c_str()  <<  std::endl
        <<  "sudo "  <<  cmd2.c_str()  << std::endl
        <<  "sudo "  <<  cmd3.c_str()  << std::endl
        <<  "sudo "  <<  cmd4.c_str()  << std::endl
        <<  "sudo "  <<  cmd5.c_str()  << std::endl
        <<  std::flush;
  }
}  //  uninstallService
