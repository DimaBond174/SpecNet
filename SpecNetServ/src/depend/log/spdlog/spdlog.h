#ifndef SPDLOG_H
#define SPDLOG_H

#include <memory>
#include "i/ilog.h"
#include "depend/log/spdlog/include/spdlog/logger.h"

class SpdLog : public ILog
{
public:
    SpdLog();

    bool start()     override;
    void stop()      override;
    void rawLog(const char * lvl, const std::string &str) override;


private:
    std::shared_ptr<spdlog::logger> pLog;
};

#endif // SPDLOG_H
