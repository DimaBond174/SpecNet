#include "speclog.h"

#include <sstream>
#include <iomanip>
#include <ctime>
#include <thread>
#include <iostream>

#if defined(Windows)
#define snprintf sprintf_s
#endif

#include "spec/speccontext.h"
#include "spec/specstatic.h"

SpecLog::SpecLog() {

}

bool SpecLog::start() {
    bool re = false;
    SpecContext & sr = SpecContext::instance();
    //faux loop
    do {
        if (!sr.iFileAdapter) { break; }
        IFileAdapter * fileAdapter = sr.iFileAdapter.get();
        const std::string &fullPath = fileAdapter->toFullPath(sr.iConfig.get()->getStringValue("LogPath").c_str());
        auto len = fullPath.length();
        if (len < 5) { break; }

        const std::string &dirPath = fileAdapter->getDir(fullPath);
        fileAdapter->mkdirs(dirPath);


        long long max_file_size = 1024*1024*sr.iConfig.get()->getLongValue("LogSizeMB");
        if (max_file_size <=0) {
            max_file_size = 1048576 * 5;
        }
        long long max_files = sr.iConfig.get()->getLongValue("LogFiles");
        if (max_files <=0) {
            max_files = 3;
        }


        {
            std::lock_guard<std::timed_mutex> raii(loglock);
            logPathDir = dirPath;
            if (fullPath.compare(len-5, 4, ".txt")) {
                    logPathBase = fullPath.substr(0, len-4);
            } else {
                    logPathBase = fullPath;
            }

            logFiles   = max_files;
            maxLogSize = max_file_size;

            openNextLog();
        }
        re = true;
    } while (false);
    return re;
}

void SpecLog::closeLog() {
    try {
        logfs.close();
        curLogSize = 0;
    } catch (...) {}
}

void SpecLog::openNextLog() {
    std::string fileName = logPathBase;
    try {
        closeLog();
        //Delete old files
        SpecContext::instance().iFileAdapter.get()->delOld(logPathDir, logFiles-1);
        //Open new Log file:
        std::string strTime;
        strTime.reserve(24);
        strTime.resize(24);
        std::time_t t = std::time(nullptr);
        auto szTime = std::strftime(&strTime.front(), 24, "%Y-%m-%d_%H-%M-%S", std::localtime(&t));
        strTime.resize(szTime);
        fileName.append(strTime).append(".txt");
        logfs.open (fileName, std::ofstream::out);
    } catch (...) {
        std::cout << "Error SpecLog::openNextLog() opening file:" << fileName;
    }
}


void SpecLog::stop() {
    {
        std::lock_guard<std::timed_mutex> raii(loglock);
        closeLog();
    }
}

void SpecLog::rawLog(const char * lvl, const std::string &str) {
    if (!str.empty()) {
        std::time_t t = std::time(nullptr);
        std::tm tm = *std::localtime(&t);
        std::stringstream ss;
        ss << std::put_time(&tm, "[%Y-%m-%d %H:%M:%S][")
           << lvl
           << "]["
           << std::this_thread::get_id()
           << "]:"
           << str
           << std::endl;
        const std::string &toLog = ss.str();
        auto len = toLog.length();
        if (loglock.try_lock_for(std::chrono::milliseconds(DEADLOCK_TIME))) {
            try {
                curLogSize += len;
                if (curLogSize > maxLogSize) {
                    openNextLog() ;
                }
                if (logfs.is_open()) {
                    logfs << toLog;
#ifdef DDEBUG
                    logfs.flush();
#endif
                }
            } catch(...) {

            }
            loglock.unlock();
        }
    }
}
