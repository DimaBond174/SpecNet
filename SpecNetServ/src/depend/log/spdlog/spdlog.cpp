#include "spdlog.h"
#include "depend/log/spdlog/include/spdlog/sinks/rotating_file_sink.h"
#include "spec/speccontext.h"

SpdLog::SpdLog()
{

}

bool SpdLog::start() {
    bool re = false;
    try {
        //faux loop
        do {
            SpecContext & sr = SpecContext::instance();
            if (!sr.iFileAdapter) { break; }
            IFileAdapter * fileAdapter = sr.iFileAdapter.get();
            const std::string &fullPath = fileAdapter->toFullPath(sr.iConfig.get()->getStringValue("LogPath").c_str());
            if (fullPath.empty()) { break; }
            const std::string &dirPath = fileAdapter->getDir(fullPath);
            fileAdapter->mkdirs(dirPath);

            size_t max_file_size = 1024*1024*sr.iConfig.get()->getLongValue("LogSizeMB");
            if (max_file_size <=0) {
               max_file_size = 1048576 * 5;
            }
            size_t max_files = sr.iConfig.get()->getLongValue("LogFiles");
            if (max_files <=0) {
                max_files = 3;
            }
            pLog = spdlog::rotating_logger_mt("Spec", fullPath, max_file_size, max_files);
//        pLog.get()->error("Test error");
//        pLog.get()->warn("this should appear in both console and file");
//        pLog.get()->info("this message should not appear in the console, only in the file");
            re = true;
        } while (false);
    } catch(...){
    }
    return re;
}

void SpdLog::stop() {

}


void SpdLog::rawLog(const char * lvl, const std::string &str) {
    if (pLog) {
        try {
            switch (*lvl) {
                case 'i':
                    pLog.get()->info(str);
                break;
                case 'w':
                    pLog.get()->warn(str);
                break;
                case 'e':
                    pLog.get()->error(str);
                break;
            }
        } catch(...){
        }
    }
}
