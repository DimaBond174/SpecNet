/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include "confighardcode.h"

ConfigHardCode::ConfigHardCode()  {

}

bool  ConfigHardCode::loadConfig()  {
  return  true;
}

long long  ConfigHardCode::getLongValue(const std::string  &key)  {
  long long  re  =  0;
  if  (0==key.compare("LogSizeMB"))  {
    re  =  10;
  } else if (0==key.compare("LogFiles")) {
    re  =  3;
  } else if (0==key.compare("ServerPort")) {
    re  =  443;
  } else if (0==key.compare("MaxConnections")) {
    re  =  100;
  }
    //LogLevel default to 0
    return re;
}

std::string  ConfigHardCode::getStringValue(const std::string  &key)  {
  std::string  re;
  if  (0==key.compare("SQLitePath"))  {
    re  =  std::string("./db/SQLite/specnet.db");
  }  else if (0==key.compare("LogPath"))  {
    re  =  std::string("./log/log.txt");
  }  else if (0==key.compare("SSLcertificate_file"))  {
    re  =  std::string("./assets/ssl_cert.pem");
  }  else if (0==key.compare("SSLPrivateKey_file"))  {
    re  =  std::string("./assets/ssl_pkey.pem");
  }  else if (0==key.compare("MessagesPath"))  {
    re  =  std::string("./db/msg");
  }  else if (0==key.compare("AvaCertsPath"))  {
    re  =  std::string("./db/x509");
  }
  return re;
}
