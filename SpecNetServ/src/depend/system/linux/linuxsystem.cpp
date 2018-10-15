#include "linuxsystem.h"

#include <unistd.h>
#include <limits.h>
#include <linux/limits.h>
#include <dlfcn.h>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <array>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <algorithm>

#define BUFFER_SIZE 256

LinuxSystem::LinuxSystem() {

}

std::string LinuxSystem::getExePath(){
    return getExePathS();
}

std::shared_ptr<ILib> LinuxSystem::openSharedLib(const char * libPath){
    return openSharedLibS(libPath);
}

std::shared_ptr<ILib> LinuxSystem::openSharedLibS(const char * libPath){
    std::shared_ptr<ILib> re;
    //faux loop
    do {
        void * lib_handle = dlopen(libPath, RTLD_LAZY);
        if (!lib_handle) {
            std::cerr << "FAIL dlopenl: " << dlerror() << std::endl;
            break;
        }
        // Reset errors
        dlerror();
        std::shared_ptr<ILib> lib = std::make_shared<ILib>();
        lib.get()->createInstance =
                (TCreateFunc) dlsym(lib_handle, "createInstance");
        const char * err = dlerror();
        if(err) {
            dlclose(lib_handle);
            break;
            //std::cerr << "Failed to load create symbol: " << err << std::endl;
        }
        lib.get()->deleteInstance =
                (TDeleteFunc) dlsym(lib_handle, "deleteInstance");
        err = dlerror();
        if(err) {
            dlclose(lib_handle);
            break;
//            std::cerr << "Failed to load destroy symbol: " << err << std::endl;
        }
        lib.get()->lib_handle = lib_handle;
        re = lib;
    } while (false);
    return re;
}

void LinuxSystem::closeSharedLib(const std::shared_ptr<ILib> &iLib){
    closeSharedLibS(iLib);
}

void LinuxSystem::closeSharedLibS(const std::shared_ptr<ILib> &iLib){
    if (iLib) {
        dlclose(iLib.get()->lib_handle);
        iLib.get()->lib_handle = nullptr;
    }
}


std::string LinuxSystem::getExePathS(){
    std::string _exePath;
#if defined(Linux)
    char buf[PATH_MAX];
    ssize_t len = 0;
    len = readlink("/proc/self/exe", buf, PATH_MAX);
    if (len>0) {
        for(--len; len>0; --len) {
            if ('/'==buf[len]){
                _exePath = std::string(buf, len);
                break;
            }
        }
    }
#endif
    return _exePath;
}

std::string LinuxSystem::getExeS(){
    std::string _exePath;
#if defined(Linux)
    char buf[PATH_MAX];
    ssize_t len = 0;
    len = readlink("/proc/self/exe", buf, PATH_MAX);
    if (len>0) {
        _exePath = std::string(buf, len);
    }
#endif
    return _exePath;
}

std::string LinuxSystem::execCmd(const char * cmd) {
    return execCmdS(cmd);
}

std::string LinuxSystem::execCmdS(const char * cmd){
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    //in deleter of shared_ptr: pclose(pipe);
    return result;
}

std::string LinuxSystem::sendCmd(const char * serviceName, const char * cmd) {
    return sendCmdS(serviceName, cmd);
}


std::string LinuxSystem::sendCmdS(const char * serviceName, const char * cmd) {
    std::string re;
    int sock = -1;
    //faux loop
    do {
        //int sock = ::socket(PF_UNIX, SOCK_STREAM, 0);
        int sock = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (-1 == sock) {
            //std::cerr << "Error: LinuxService::sendCmd  -1 == ::socket(" << std::endl;
            break;
        }
        struct sockaddr_un addr;
        ::memset(&addr, 0, sizeof(struct sockaddr_un));
        addr.sun_family = AF_UNIX;
        const std::string & sock_path = LinuxSystem::getSockPathS(serviceName);
        ::memcpy(addr.sun_path, sock_path.c_str(), sock_path.length());

        int res = ::connect(sock, (struct sockaddr *)&addr, SUN_LEN(&addr));
        if (-1 == res ) {
            //std::cerr << "Error: LinuxService::sendCmd  ::connect(sock to "
            //          << sock_path << std::endl;
            break;
        }

        /* Send. */
        res = write(sock, cmd, strlen(cmd) + 1);
        if (-1 == res ) {
            //std::cerr << "Error: LinuxService::sendCmd  ::write(sock to "
            //          << sock_path << std::endl;
            break;
        }

        char buffer[BUFFER_SIZE];
        /* Receive result. */
        res = read(sock, buffer, BUFFER_SIZE);
        if ( res < 0 ) {
            //std::cerr << "Error: LinuxService::sendCmd  ::read(sock from "
             //         << sock_path << std::endl;
            break;
        }

        //buffer[res] = 0;
        re = std::string(buffer, res);
        //printf("Server answer: %s\n", buffer);

        //re = true;
    } while (false);
    if (-1 != sock) { ::close(sock); }

    return re;
}

std::string LinuxSystem::getSockPath(const char * serviceName) {
    return getSockPathS(serviceName);
}

std::string LinuxSystem::getSockPathS(const char * serviceName) {
   std::string legal (serviceName);
   std::transform(legal.begin(), legal.end(), legal.begin(), [](char ch){
       const char * legal = "abcdefghijklmnopqrstuvwxyz1234567890";
       for (const char *p = legal; *p; ++p) {
           if (*p==ch) { return ch; }
       }
       return 'a'; } );
   std::string re ("/var/tmp/");
   re.append(legal);
   return re;
}

bool LinuxSystem::waitForSUCCESS(TWaitFunc f, void * ptr,
                    int msRepeat,
                    int msTimeout) {
    auto start = std::chrono::system_clock::now();
    while (std::chrono::system_clock::now() - start < std::chrono::milliseconds(msTimeout)) {
        if ((*f)(ptr)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(msRepeat));
    }//while
    return false;
}
