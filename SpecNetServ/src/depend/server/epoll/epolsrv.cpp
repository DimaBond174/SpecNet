/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#include "epolsrv.h"
#include "spec/speccontext.h"
#include "spec/specstatic.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h> /* Added for the nonblocking socket */
#include <sys/epoll.h>
#include <poll.h>
#include <signal.h>

static constexpr uint32_t EPOL_client_events  =
    EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLHUP | EPOLLET;

static constexpr uint32_t EPOL_client_errors  =
    EPOLLERR | EPOLLHUP | EPOLLRDHUP ;

static constexpr uint32_t EPOL_srv_events  =
    EPOLLIN | EPOLLET;


EpolSrv::EpolSrv() {

}

EpolSrv::~EpolSrv() {
    stop();
    //wait for thread before destruction
    if (serverThread.joinable()) {
        serverThread.join();
    }
    if  (cache)  {
      delete cache;
      cache  =  nullptr;
    }
}


bool  EpolSrv::start() {
    bool re = false;
    SpecContext & sr = SpecContext::instance();
    p_specSSL = sr.specSSL;
    specSSL = p_specSSL.get();

	p_iLog = sr.iLog;
	iLog = sr.iLog.get();
	p_iFileAdapter = sr.iFileAdapter;
	iFileAdapter = sr.iFileAdapter.get();
	p_iDB = sr.iDB;
	iDB = sr.iDB.get();
    if (iFileAdapter && iLog && specSSL && iDB &&
            //0==srvState.load(std::memory_order_acquire) &&
            create_socket()) {
        //srvState.store(1, std::memory_order_release);
        serverThread = std::thread(&EpolSrv::runServThreadLoop, this);
        re = true;
    }
    return re;
}

void  EpolSrv::stop()  {
    //ToDo проверить:
    //socketID.store(-1, std::memory_order_release);
    keepRun.store(false, std::memory_order_release);


}


bool EpolSrv::create_socket() {
    bool re = false;

    //faux loop:
    do {
        SpecContext & sr = SpecContext::instance();
        logLevel = sr.iConfig.get()->getLongValue("LogLevel");
        maxConnections = sr.iConfig.get()->getLongValue("MaxConnections");
        uint32_t  capacity = sr.iConfig.get()->getLongValue("Cache size (msg count)");
        if  (0==capacity  ||  capacity>10000000)  {  capacity  =  10000;  }
        cache = new OnCache(capacity);

        //bufConnections = maxConnections >> 2;
        idleConnLife = sr.iConfig.get()->getLongValue("idleConnLife");
        uint16_t port = sr.iConfig.get()->getLongValue("ServerPort");
        if (0 == port) {
            iLog->log("e","[%s]: FAIL iConfig.get(ServerPort).",TAG);
            break;
        }

        servPassword = sr.iConfig.get()->getStringValue("ServPassword");
        if (servPassword.empty()) {
            iLog->log("e","[%s]: FAIL iConfig.get()->getStringValue(ServPassword).",TAG);
            break;
        }

        messagesPath =
                iFileAdapter->toFullPath(
                    sr.iConfig.get()->getStringValue(
                        "MessagesPath").c_str());
        if ('/'!=messagesPath[messagesPath.length()-1]) {
            messagesPath.push_back('/');
        }
        avaCertsPath =
                iFileAdapter->toFullPath(
                    sr.iConfig.get()->getStringValue(
                        "AvaCertsPath").c_str());
        if ('/'!=avaCertsPath[avaCertsPath.length()-1]) {
            avaCertsPath.push_back('/');
        }


        //int fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
        server_socket = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (server_socket < 0) {
            iLog->log("e","[%s]: FAIL socket(AF_INET, SOCK_STREAM, 0).",TAG);
            break;
        }

        int flags = fcntl(server_socket, F_GETFL, 0);
        if (flags < 0) {
            iLog->log("e","[%s]: 0>create_socket.fcntl(server_socket, F_GETFL, 0)",TAG);
            break;
        }
        fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);

        int reuse = 1;
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)  {
          iLog->log("e","[EpolSrv::create_socket]: setsockopt(SO_REUSEADDR) failed");
          break;
        }

#ifdef SO_REUSEPORT
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
          iLog->log("e","[EpolSrv::create_socket]: setsockopt(SO_REUSEPORT) failed");
          break;
        }
#endif

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof (addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (::bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            iLog->log("e","[%s]: FAIL bind(server_socket, (struct sockaddr*)&addr.",TAG);
            break;
        }

        /* set Maximum pending connection to EPOLL_WAIT_POOL */
        if (listen(server_socket, EPOLL_WAIT_POOL) < 0) {
            iLog->log("e","[%s]: FAIL listen(server_socket, EPOLL_WAIT_POOL).",TAG);
            break;
        }

        iLog->log("i","[%s]: now listening on port [%u]",TAG, port);

        re = true;
    } while (false);
    if (!re && server_socket>=0) {
        close(server_socket);
        server_socket = -1;
    }
    return re;
}

void* EpolSrv::runServThreadLoop(void* arg){
    EpolSrv* p = static_cast<EpolSrv*>(arg);
    p->servThreadLoop();
    return 0;
}

void  EpolSrv::clearSocket(EpolSocket * p)  {
  if  (p->sslStaff)  {
    SSL_free(p->sslStaff);
    p->sslStaff  =  nullptr;
  }
  p->clearOnStart();
  if  (p->x509)  {
    X509_free(p->x509);
    p->x509  =  nullptr;
  }
  if  (p->evpX509)  {
    EVP_PKEY_free(p->evpX509);
    p->evpX509  =  nullptr;
  }

}  //  clearSocket

EpolSocket * EpolSrv::getFreeSocket() {
    EpolSocket * re = stackFreeSocketsLocal.pop();
    if (!re) {
        stackFreeSocketsLocal.swap(stackFreeSockets.getStack());
        re = stackFreeSocketsLocal.pop();
        if (!re) {
            newEpolSocketLeaf();
            re = stackFreeSocketsLocal.pop();
        }
    }

    if (re) {        
        clearSocket(re);
    }

    return re;
}

//bool EpolSrv::addEPollFd(IEpoll* s) {
//    //memset(&(s->_epol_ev), 0, sizeof(_epol_ev));
//    //s->_epol_ev.events = s->_events;
//    s->_epol_ev.data.ptr = s;
//    int res = epoll_ctl(epollfd, EPOLL_CTL_ADD, s->_socket_id, &(s->_epol_ev));
//    if (-1==res) {
//        keepRun.store(false, std::memory_order_release);
//        iLog->log("e","[EpolSrv::addEPollFd]: epoll_ctl(epollfd, EPOLL_CTL_ADD: %d %s",
//                     errno, strerror(errno));
//        return false;
//    }
//    return true;
//}

void  EpolSrv::updateEPoll(EpolSocket  *s)  {
  if  (-1==epoll_ctl(epollfd, EPOLL_CTL_MOD,
      s->_socket_id,  &(s->_epol_ev)))  {
    keepRun.store(false,  std::memory_order_release);
    iLog->log("e","[EpolSrv::updateEPoll]: updateEPoll: %d %s",
                     errno, strerror(errno));
  }
}

void EpolSrv::ohNoFreeRam() {
    keepRun.store(false, std::memory_order_release);
    iLog->log("e","[EpolSrv]: no free RAM");
}

void  EpolSrv::handleWrite(EpolSocket * s)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolSrv::handleWrite]: EpolSocket(%llu):%i",
              s, s->_socket_id);
  }
#endif
    //EPOLLET loop
  do  {
    if  (!s->writePacket)  {
      s->writePacket  =  s->writeStackServer.pop();
      if  (!s->writePacket)  {
        s->writeStackServer.swap(s->writeStack.getStack());
        s->writePacket  =  s->writeStackServer.pop();
        if (!s->writePacket) {  break;  }
      }
      T_IPack0_Network  *header  =  &(s->writePacket->header);
      if  (N_SPEC_PACK_TYPE_6==header->pack_type)  {
          // The server checked the certificate and allowed the work:
          s->connectState = 3;
          // groupID in network byte order to host order:
          s->connectedGroup = _NTOHLL(header->key1);
      }  else if  (N_SPEC_PACK_TYPE_7==header->pack_type)  {
          // Mail waiting:
        int32_t  lenArray  =  _NTOHL(header->body_len) / SIZE_2x_uint64_t;
        s->msgs_to_receive  +=  lenArray;
        s->all_received  =  (s->msgs_to_receive  <=  0);
      }  else if  (N_SPEC_PACK_TYPE_9==header->pack_type)  {
          // Cache mail:        
        if  (s->writePacket->delete_after_send)  {
          cache->insertNode(header,  s->writePacket);
        }
        --s->msgs_to_send;
        s->all_sended  =  (s->msgs_to_send  <=  0);
      }  else if  (N_SPEC_PACK_TYPE_10==header->pack_type)  {
        --s->msgs_to_receive;
        s->all_received  =  (s->msgs_to_receive  <=  0);
      }
      s->writeHeaderPending  =  sizeof(T_IPack0_Network);
      s->writeCur  =  reinterpret_cast<char *>(header);
    } // if  (!s->readPacket
    //  write header:
    if  (s->writeHeaderPending  >  0)  {
      int  res  =  SSL_write(s->sslStaff,  s->writeCur,  s->writeHeaderPending);
      if  (res<=0)  {
        if  (!SSL_ERROR_WANT_WRITE == SSL_get_error(s->sslStaff, res))  {
            setFreeSocketID(s);
        }
        break;
      }
      s->writeCur  +=  res;
      s->writeHeaderPending  -=  res;
      if  (0==s->writeHeaderPending)  {
        s->writeLenLeft = _NTOHL(s->writePacket->header.body_len);
        if  (0  <  s->writeLenLeft)  {
            s->writeCur  =  s->writePacket->body;
        }
      }  else  {  break;  }
    }  //  if  (s->writeHeaderPending

    //  write packet body:
    while  (s->writeLenLeft  >  0)  {
      int  res  =  SSL_write(s->sslStaff,  s->writeCur,  s->writeLenLeft);
      if  (res<=0)  {
        if  (SSL_ERROR_WANT_WRITE  !=  SSL_get_error(s->sslStaff, res))  {
          setFreeSocketID(s);
        }
        return;
      }
      s->writeLenLeft  -=  res;
      s->writeCur  +=  res;
    }//while

    //  if all writed :
    if (0==s->writeLenLeft) {
      if  (s->writePacket->delete_after_send)  {
        delete s->writePacket;
      }
      s->writePacket = nullptr;
    }
  }  while  (true);
  return;
} //handleWrite

void  EpolSrv::handleAcceptWithLog()  {
  struct  sockaddr_in  raddr;
  socklen_t  rsz  =  sizeof(raddr);
  int  client_socket;
  tryAcceptConnLater  =  false;
  //  while ((client_socket = accept4(server_socket,(struct sockaddr *)&raddr,&rsz, SOCK_CLOEXEC))>=0) {
  while  (curConnections<maxConnections)  {
    client_socket  =  accept(server_socket,  (struct sockaddr *)&raddr,  &rsz);
    if  (-1==client_socket)  {
      if  (errno == EWOULDBLOCK)  {
        // we processed all of the connections?
        tryAcceptConnLater  =  true;
      } else {
        keepRun.store(false,  std::memory_order_release);
        iLog->log("e","[EpolSrv::handleAccept]: accept(server_socket) error: %d %s",
                             errno,  strerror(errno));
      }
      break;
    }    

      // set NONBLOCK socket:
    int  flags  =  fcntl(client_socket,  F_GETFL,  0);
    if (flags < 0)  {
      iLog->log("e","[EpolSrv::handleAccept]: 0>create_socket.fcntl(server_socket, F_GETFL, 0)");
      close(client_socket);
      break;
    }

    fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);

    EpolSocket * s = getFreeSocket();
    if  (!s)  { //can't be that because of check before calling  handleAccept
      close(client_socket);
      break;
    }
    logConnection(s, (struct sockaddr *)&raddr,  rsz,  client_socket);
    s->_socket_id  =  client_socket;
    s->_epol_ev.events  =  EPOLLIN | EPOLLOUT;
    if  (-1==epoll_ctl(epollfd,  EPOLL_CTL_ADD,  s->_socket_id,  &(s->_epol_ev)))  {
      keepRun.store(false, std::memory_order_release);
      iLog->log("e","[EpolSrv::addEPollFd]: epoll_ctl(epollfd, EPOLL_CTL_ADD: %d %s",
                         errno, strerror(errno));
    }  else  {
      // start socket handshake:
      s->lastActTime = std::time(nullptr);
      stackShakeSockets.push(s);
    }  // epoll_ctl
  } //while
}  //  handleAcceptWithLog

void  EpolSrv::handleAccept()  {
  tryAcceptConnLater  =  false;
  //  while ((client_socket = accept4(server_socket,(struct sockaddr *)&raddr,&rsz, SOCK_CLOEXEC))>=0) {
  while  (curConnections<maxConnections)  {
    int  client_socket  =  accept(server_socket,  nullptr,  nullptr);
    if  (-1==client_socket)  {
      if  (errno == EWOULDBLOCK)  {
        // we processed all of the connections?
        tryAcceptConnLater  =  true;
      } else {
        keepRun.store(false,  std::memory_order_release);
        iLog->log("e","[EpolSrv::handleAccept]: accept(server_socket) error: %d %s",
                             errno,  strerror(errno));
      }
      break;
    }

      // set NONBLOCK socket:
    int  flags  =  fcntl(client_socket,  F_GETFL,  0);
    if (flags < 0)  {
      iLog->log("e","[EpolSrv::handleAccept]: 0>create_socket.fcntl(server_socket, F_GETFL, 0)");
      close(client_socket);
      break;
    }

    fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);

    EpolSocket * s = getFreeSocket();
    if  (!s)  { //can't be that because of check before calling  handleAccept
      close(client_socket);
      break;
    }

    s->_socket_id  =  client_socket;
    s->_epol_ev.events  =  EPOLLIN | EPOLLOUT;
    if  (-1==epoll_ctl(epollfd,  EPOLL_CTL_ADD,  s->_socket_id,  &(s->_epol_ev)))  {
      keepRun.store(false, std::memory_order_release);
      iLog->log("e","[EpolSrv::addEPollFd]: epoll_ctl(epollfd, EPOLL_CTL_ADD: %d %s",
                         errno, strerror(errno));
    }  else  {
      // start socket handshake:
      s->lastActTime = std::time(nullptr);
      stackShakeSockets.push(s);
    }  //  epoll_ctl
  } //  while
}  //  handleAccept


void  EpolSrv::handleRead(EpolSocket  *s)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolSrv::handleWrite]: EpolSocket(%llu):%i",
              s, s->_socket_id);
  }
#endif
    //EPOLLET loop
  do  {
    if  (!s->readPacket)  {
      s->readPacket  =  new  IPack();
      s->readHeaderPending  =  sizeof(T_IPack0_Network);
      s->readCur  =  reinterpret_cast<char *>(&(s->readPacket->header));
    } // if  (!s->readPacket
    //  read header:
    if  (s->readHeaderPending  >  0)  {
      int  res  =  SSL_read(s->sslStaff,  s->readCur,  s->readHeaderPending);
      if  (res<=0)  {
        if  (!SSL_ERROR_WANT_READ == SSL_get_error(s->sslStaff, res))  {
            setFreeSocketID(s);
        }
        break;
      }
      s->readCur  +=  res;
      s->readHeaderPending  -=  res;
      if  (0==s->readHeaderPending)  {
        T_IPack0_Network  *header  =  &(s->readPacket->header);
        if  (IPack0::toHost(header))  {
          s->readLenLeft  =  header->body_len;
          if  (s->readLenLeft>0)  {
            s->readPacket->body  =  static_cast<char *>(malloc(header->body_len));
            if  (!s->readPacket->body)  {
              setFreeSocketID(s);
              ohNoFreeRam();
              break;
            }
            s->readCur = s->readPacket->body;
          }
          s->lastActTime = std::time(nullptr);
        }  else  {
          setFreeSocketID(s);
#ifdef Debug
iLog->log("e","[EpolSrv::handleRead]: !IPack0::toHost(s->readPacket->header), s=%i", s->_socket_id);
#endif
          break;
        }
      }  else  {  break;  }
    }  //  if  (s->readHeaderPending

    //  load packet body:
    while  (s->readLenLeft  >  0)  {
      int  res  =  SSL_read(s->sslStaff,  s->readCur,  s->readLenLeft);
      if  (res<=0)  {
        if  (SSL_ERROR_WANT_READ  !=  SSL_get_error(s->sslStaff, res))  {
          setFreeSocketID(s);
        }
        return;
      }
      s->readLenLeft  -=  res;
      s->readCur  +=  res;
    }//while

    //  if all readed parse packet body:
    if  (0==s->readLenLeft)  {
      T_IPack0_Network  *header  =  &(s->readPacket->header);
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolSrv::handleRead]:EpolSocket(%llu):header:%llu,%llu,%llu,%llu",
              s , header->pack_type, header->key1, header->key2, header->key3);
  }
#endif
      switch  (header->pack_type)  {
      case SPEC_PACK_TYPE_11:
         doPack11(s,  s->readPacket);
        break;
      case SPEC_PACK_TYPE_1:
        s->all_received  =  false;
        s->all_sended  =  false;
        /*  ABSL_FALLTHROUGH_INTENDED;  */
      case SPEC_PACK_TYPE_3:
      case SPEC_PACK_TYPE_5:
          /* packets without authentication yet */
         s->readStack.push(s->readPacket);
         s->readPacket  =  nullptr;
         break;
      case SPEC_PACK_TYPE_2:
        if  (3==s->connectState
              &&  s->connectedGroup==header->key1)  {
                        //((T_IPack1_Network *)(s->readPacket))->groupID) {
                    /* send X509 from file cache */
                    //TODO
        }  else  {
            //Protocol error
            setFreeSocketID(s);
        }
        break;      
      case SPEC_PACK_TYPE_9:
//        --s->msgs_to_receive;
//        s->all_received  =  (s->msgs_to_receive  <=  0);
        /*  ABSL_FALLTHROUGH_INTENDED;  */
      case SPEC_PACK_TYPE_6:        
      case SPEC_PACK_TYPE_8:
      case SPEC_PACK_TYPE_10:
        if  (3==s->connectState
             &&  s->connectedGroup==header->key1)  {
          s->readStack.push(s->readPacket);
          s->readPacket  =  nullptr;
        }  else  {
          //Protocol error
          setFreeSocketID(s);
        }
        break;
      case SPEC_PACK_TYPE_7:
        if (3==s->connectState
            && s->connectedGroup==header->key1)  {
          /* send mail from file cache and forward tail to worker */
          doPack7(s,  s->readPacket);
          s->readPacket  =  nullptr;
        }  else  {
            //Protocol error
           setFreeSocketID(s);
        }
        break;
      default:
         /* Protocol error */
         setFreeSocketID(s);
         break;
     } //switch

     if  (s->readPacket)  {       
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolSrv::handleRead]: delete IPack:%llu", s->readPacket);
  }
#endif
       delete  s->readPacket;
       s->readPacket  =  nullptr;
     }
    }  //  f (0==s->readLenLeft
  } while (true);
  return;
} //handleRead

void EpolSrv::setFreeSocketID(EpolSocket * s) {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolSrv::setFreeSocketID]:EpolSocket(%llu)", s);
  }
#endif
    if (-1!=s->_socket_id) {
      if (s->sslStaff) {
        SSL_shutdown(s->sslStaff);
      }
        close(s->_socket_id);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, s->_socket_id, NULL);
        s->_socket_id = -1;
    }
    s->keepRun.store(false, std::memory_order_release);
}



//void EpolSrv::setFreeSocket1(EpolSocket * s) {
//    //s->stop();
//    s->connectState = 0;

//    if (-1!=s->_socket_id) {
//        close(s->_socket_id);
//        epoll_ctl(epollfd, EPOLL_CTL_DEL, s->_socket_id, NULL);
//        s->_socket_id = -1;
//    }

//    if (s->writePacket) {
//         delete(s->writePacket);
//         s->writePacket = nullptr;
//    }
//    if (s->readPacket) {
//         delete(s->readPacket);
//         s->readPacket = nullptr;
//    }
//    SpecStack<IPack> tmpStack;
//    IPack * p;
//    tmpStack.swap(s->readStack.getStack());
//    while (p = tmpStack.pop() ) {
//        delete p;
//    }
//    tmpStack.swap(s->writeStack.getStack());
//    while (p = tmpStack.pop() ) {
//        delete p;
//    }

//}



void  EpolSrv::handleHandshake(EpolSocket  *s)  {
//faux loop
  do  {
    if  (0==s->connectState)  {
      struct pollfd pfd;
      pfd.fd = s->_socket_id;
      pfd.events = POLLOUT | POLLERR;
      int  r  =  poll(&pfd,  1,  0);
      if  (r == 1  &&  pfd.revents == POLLOUT)  {
        if  (logLevel>2)  {
          iLog->log("i","[EpolSrv::handleHandshake]:EpolSocket(%llu): tcp connected fd %d",
            s,  s->_socket_id);
        }
        s->connectState  =  1;
        s->_epol_ev.events  =  EPOLLIN | EPOLLOUT | EPOLLERR;
        updateEPoll(s);
      }  else  {
        if  (logLevel>2)  {
          iLog->log("w","[EpolSrv::handleHandshake]:EpolSocket(%llu): poll fd %d return %d revents %d",
            s,  s->_socket_id,  r,  pfd.revents);
        }
        freeSocketToLocal(s);
        break;
      }
    } //if (!s->_connected

    if  (!s->sslStaff)  {
      s->sslStaff = specSSL->startEncryptSocket(s->_socket_id);
      if  (!s->sslStaff)  {
        keepRun.store(false, std::memory_order_release);
        iLog->log("e","[EpolSrv::handleHandshake]:EpolSocket(%llu): FAIL  iEncrypt->startEncryptSocket()",  s);
        break;
      }
    }

    int  r  =  SSL_do_handshake(s->sslStaff);
    if  (r == 1)  {
      s->connectState  =  2;
      if  (logLevel>2)  {
        iLog->log("i","[EpolSrv::handleHandshake]:EpolSocket(%llu): ssl connected fd %d",
          s,  s->_socket_id);
      }
      connectedSockets.emplace_back(s);
      stackSockNeedWorker.push(s);
      s->_epol_ev.events  =  EPOL_client_events;
      updateEPoll(s);
      ++curConnections;
      int64_t  targetWorker  =  1  +  curConnections / oneWorkerOnEach;
      if  (targetWorker  >  maxWorkers)  {  targetWorker  =  maxWorkers;  }
      if  (targetWorker  >  curWorkers)  {
          startWorker();
      }
      break; // Go regular work, hanshake complete
    }  else  {
      int  errE  =  SSL_get_error(s->sslStaff,  r);
      if (SSL_ERROR_WANT_WRITE != errE
                  && SSL_ERROR_WANT_READ != errE)  {
        iLog->log("e","[EpolSrv::setEncryptWants]:EpolSocket(%llu): socket %d return %d error %d errno %d msg %s",
          s,  s->_socket_id, errE, r, errno, strerror(errno));
        specSSL->logErrors();
        freeSocketToLocal(s);
      }
    }  //  if  (r
  }  while  (false);
}  //  handleHandshake

bool EpolSrv::addServerEpoll() {
    bool re = false;
    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (-1==epollfd) {
        iLog->log("e","[%s]: FAIL epoll_create1(EPOLL_CLOEXEC).",TAG);
    } else {
        srvEpoll._socket_id = server_socket;
        srvEpoll.sockType = SERV_TYPE;
        srvEpoll._epol_ev.data.ptr = &srvEpoll;
        srvEpoll._epol_ev.events = EPOLLIN;
        if (-1==epoll_ctl(epollfd, EPOLL_CTL_ADD, srvEpoll._socket_id, &(srvEpoll._epol_ev))) {
            iLog->log("e","[EpolSrv::addEPollFd]: epoll_ctl(epollfd, EPOLL_CTL_ADD: %d %s",
                         errno, strerror(errno));
        } else {
            re = true;
        }
    }
    if (!re) {
        keepRun.store(false, std::memory_order_release);
        //srvState.store(0, std::memory_order_release);
    }
    return re;
}


void EpolSrv::delEpolSocketLeaf(EpolSocket ** ptr) {
    if (ptr) {
        if (*ptr) { delEpolSocketLeaf((EpolSocket **) *ptr);}
        EpolSocket * curLeaf = (EpolSocket *)(ptr+1);
        int leafSize = maxConnections < 256?maxConnections:256;
        for (int i=0; i<leafSize; ++i) {
            curLeaf[i].~EpolSocket();
        }
        free(ptr);
    }
}

void  EpolSrv::newEpolSocketLeaf()  {
  int  leafSize  =  (maxConnections < 256)?  maxConnections:  256;
  const  size_t  size  =  sizeof(EpolSocket * )  +  leafSize * sizeof(EpolSocket);
  EpolSocket  *curLeaf  =  nullptr;
  if  (headLeaf)  {
    *curLeaf_NextPtr  = static_cast<EpolSocket *>(malloc(size));
    if (*curLeaf_NextPtr)  {
      curLeaf_NextPtr  =  reinterpret_cast<EpolSocket **>(*curLeaf_NextPtr);
      curLeaf  =  reinterpret_cast<EpolSocket *>(curLeaf_NextPtr + 1);
      *curLeaf_NextPtr  =  nullptr;
    }
  }  else  {
    headLeaf = curLeaf_NextPtr  = static_cast<EpolSocket **>(malloc(size));
    if  (headLeaf)  {
      curLeaf  =  reinterpret_cast<EpolSocket *>(curLeaf_NextPtr + 1);
      *headLeaf  =  nullptr;
    }  else  {
      keepRun.store(false,  std::memory_order_release);
    }
  }
  if  (curLeaf)  {
    for  (int  i  =  0;  i<leafSize;  ++i)  {
      new  (&curLeaf[i])  EpolSocket();
      stackFreeSocketsLocal.push(&curLeaf[i]);
    }
  } else {
    iLog->log("e","[EpolSrv::newEpolSocketLeaf]: cant malloc - no RAM");
  }
}  //  newEpolSocketLeaf

void EpolSrv::freeSocketToLocal(EpolSocket * s) {
    if (-1!=s->_socket_id) {
        close(s->_socket_id);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, s->_socket_id, NULL);
        s->_socket_id = -1;
    }
    //clearSocket(s);
    stackFreeSocketsLocal.push(s);
}

void EpolSrv::freeSocketsToLocal(){
    EpolSocket * s;
    SpecStack<EpolSocket> tmpFreeSocketsLocal;
    tmpFreeSocketsLocal.swap(stackFreeSockets.getStack());
    while ((s=tmpFreeSocketsLocal.pop())) {
        freeSocketToLocal(s);
    }
}


void  EpolSrv::setSIGPIPEhandler()  {
  sigset_t  sigpipe_mask;
  sigemptyset(&sigpipe_mask);
  sigaddset(&sigpipe_mask,  SIGPIPE);
  //sigset_t saved_mask;
    //if (pthread_sigmask(SIG_BLOCK, &sigpipe_mask, &saved_mask) == -1) {
  int  res  =  pthread_sigmask(SIG_BLOCK,  &sigpipe_mask,  nullptr);
  assert(-1!=res);
  return;
}

void  EpolSrv::servThreadLoop()  {
    //to prevent OpenSSL SIGPIPE
  setSIGPIPEhandler();
  if (!addServerEpoll())  {  return;  }
  struct epoll_event activeEvs[EPOLL_WAIT_POOL];
    //Start worker:
  //srvState.store(2, std::memory_order_release);
  try  {
    while  (keepRun.load(std::memory_order_acquire))  {
      //return sockets to free pool:
      freeSocketsToLocal();
      //accept connections to free slots:
      if  (tryAcceptConnLater  &&  curConnections<maxConnections)  {
        if  (logLevel<2)  {
          handleAccept();
        }  else  {
          handleAcceptWithLog();
        }
      }
      //  ask EPOLL:
      int  n  =  epoll_wait(epollfd,  activeEvs,  EPOLL_WAIT_POOL,  WAIT_TIME);
      for  (int  i  =  n-1;  i >= 0;  --i)  {
        EpolSocket  *s  =  reinterpret_cast<EpolSocket*>(activeEvs[i].data.ptr);
        if  (CLI_TYPE == s->sockType)  {
          //  Clients epoll handle:
          if  (s->connectState  <  2)  {
            //  handshake do not passed yet, keep do handshake:
            handleHandshake(s);
          }  else  {
            uint32_t events  =  activeEvs[i].events;
            if  (events  &  EPOL_client_errors)  {
              setFreeSocketID(s);
            }  else  {
              if  (events  &  EPOLLIN)  {
                handleRead(s);
              }
              if  (events & EPOLLOUT)  {
                  handleWrite(s);
              }
            }
          }  //  if  (s->connectState
        } else if (SERV_TYPE == s->sockType) {
          // Server's epoll handle:
          if  (curConnections<maxConnections)  {
            if  (logLevel<2)  {
              handleAccept();
            }  else  {
              handleAcceptWithLog();
            }
          } else {
            if(logLevel>2) {
                iLog->log("w","[EpolSrv::servThreadLoop]: cant handleAccept() - no free connections in pool");
            }
          }
        }  else  {
          iLog->log("e","[EpolSrv::servThreadLoop]: FAIL check s->sockType.");
          keepRun.store(false, std::memory_order_release);
          break;
        }
      }  //  for
      //  monitor timeouts:
      handleSockets();
      assert(curConnections>=0);
      if  (0==curConnections)  {
        //nothing to do
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        tryAcceptConnLater = true;
      }
      std::this_thread::yield();
      clearStoppedWorkers();
    } //while
  } catch (...) {
        iLog->log("e","[EpolSrv::servThreadLoop]: try{}catch (...).");
  }
  stopServerEpoll();
}  //  servThreadLoop

void  EpolSrv::stopServerEpoll()  {
    //if (-1!=epollfd) {
    /* remove self from epoll */
        epoll_ctl(epollfd, EPOLL_CTL_DEL, srvEpoll._socket_id, NULL);

    //}
    /* no new connections: */
    close(server_socket);
    /* Say to all that server is going to stopp */
    //srvState.store(3, std::memory_order_release);
    iLog->log("i","[%s]: is going to stop.",TAG);
    /* Stop all clients: */
    stopAllSockets();
    /* close Epoll fd */
    ::close(epollfd);
    iLog->log("i","[%s]: is stopped.",TAG);
    //srvState.store(0, std::memory_order_release);
    SpecContext::instance().sendStopSig();
}


void  EpolSrv::handleSockets()  {
  EpolSocket  *s;
  SpecStack<EpolSocket>  tmpShakeSockets;
  tmpShakeSockets.swap(stackShakeSockets);
  time_t  lastActTime  =  std::time(nullptr);
//hourly log:
  if  (hour_maxConnections  <  curConnections)  {
    hour_maxConnections  =  curConnections;
  }
  if  ((lastActTime  -  srvEpoll.lastActTime)  >  60)  {//>  360)  {
    iLog->log("i","[EpolSrv::handleSockets]:hour_maxConnections=%lld", hour_maxConnections);
    srvEpoll.lastActTime  =  lastActTime;
    hour_maxConnections  =  0;
  }

//monitor handshake timeout:
  while  ((s=tmpShakeSockets.pop()))  {
    if  (s->connectState  <  2)  {
      if  ((s->_socket_id  >=  0)
          &&  (lastActTime - s->lastActTime)  <=  idleConnLife)  {
        stackShakeSockets.push(s);
      }  else  {
        freeSocketToLocal(s);
      }
    } //else socket must be moved to free|work already
  }

    //monitor work timeout:
  auto&&  it  =  connectedSockets.begin();
  while  (it!=connectedSockets.end())  {
    s  =  *it;
    if  ((s->all_received  &&  s->all_sended  &&  s->groups_count<=0)
        ||  s->_socket_id  <  0
        ||  (lastActTime - s->lastActTime)  >  idleConnLife)  {
#ifdef Debug
  if  (logLevel>4)  {
    iLog->log("i","[EpolSrv::handleSockets]: setFreeSocketID(%llu):all_received=%d, all_sended=%d, groups_count=%ll",
      s, s->all_received,  s->all_sended,  s->groups_count);
  }
#endif
      setFreeSocketID(s);
      connectedSockets.erase(it++);
      --curConnections;
      if  ((1  +  (curConnections  +  10)/oneWorkerOnEach)
          <  curWorkers)  {
        stopWorker();
      }
    }  else  {
      handleWrite(s);
      ++it;
    }
  }  //  while connectedSockets iter
}  //  handleSockets


void EpolSrv::stopAllSockets() {
    //Stop workers:
    SpecStack<EpolWorker> stopedWorkers;
    EpolWorker * w;
    while ((w=stackWorkers.pop())) {
        w->stop();
        stopedWorkers.push(w);
    }
    std::this_thread::yield();
    clearStoppedWorkers();
    std::this_thread::yield();
    //Delete workers:
    while ((w=stopedWorkers.pop())) {
        delete w;
    }

    //Delete sockets:
    stackFreeSockets.swap(nullptr);
    stackFreeSocketsLocal.swap(nullptr);
    stackSockNeedWorker.swap(nullptr);
    delEpolSocketLeaf(headLeaf);
    headLeaf = nullptr;

}



//void  EpolSrv::EpolSocketDown(void * ptr)  {
//    std::lock_guard<std::mutex> raiiGuard(freeSockets_mutex);
//    setFreeSockets.insert((EpolSocket*)ptr);
//}

//void  EpolSrv::onSocketDown(void * ptr)  {
//    std::lock_guard<std::mutex> raiiGuard(freeSockets_mutex);
//    setFreeSockets.insert((EpolSocket*)ptr);
//}

//void  EpolSrv::onSocketEvent()  {
//    serverThreadCond.notify_all();
//}

void  EpolSrv::logConnection(EpolSocket  *s,  sockaddr  *remote_addr,
    uint32_t  remote_addr_len,  int  client_socket)  {
  char  hbuf[NI_MAXHOST],  sbuf[NI_MAXSERV];
  if  (getnameinfo(remote_addr,  remote_addr_len,  hbuf,  sizeof(hbuf),  sbuf,
      sizeof(sbuf),  NI_NUMERICHOST | NI_NUMERICSERV) == 0)  {
    iLog->log("i","[EpolSrv::logConnection]:EpolSocket(%llu):accept host=%s, serv=%s on socket=%i",
      s,  hbuf,  sbuf,  client_socket);
  }
}

//bool EpolSrv::setEncryptWants(IEpoll * s, int err) {
//    int errE = iEncrypt->getSocketState(s->sslStaff, err);
//    int oldev = s->_events;
//    if (ISSL_ERROR_WANT_WRITE == errE ) {
//        s->_events |= EPOLLOUT;
//        s->_events &= ~EPOLLIN;
//        if(logLevel>3) {
//            iLog->log("i","[EpolSrv::setEncryptWants]: return want write set events %d",
//                                 s->_socket_id);
//        }
//        if (oldev != s->_events) {
//            updateEPoll(s);
//        }
//    } else if (ISSL_ERROR_WANT_READ == errE) {
//        s->_events  |= EPOLLIN;
//        s->_events  &= ~EPOLLOUT;
//        if(logLevel>3) {
//            iLog->log("i","[EpolSrv::setEncryptWants]: return want read set events %d",
//                                 s->_socket_id);
//        }
//        if (oldev != s->_events) {
//            updateEPoll(s);
//        }
//    } else {
//        if(logLevel>1) {
//            iLog->log("e","[EpolSrv::setEncryptWants]: socket %d return %d error %d errno %d msg %s",
//                                 s->_socket_id, errE, err, errno, strerror(errno));
//            iEncrypt->logErrors();
//        }
//        return false;
//    }
//    return true;
//}

const char * EpolSrv::getMessagesPath() { return messagesPath.c_str();}
const char * EpolSrv::getAvaCertsPath() { return avaCertsPath.c_str();}
std::string EpolSrv::getServPassword() { return servPassword;}

EpolSocket * EpolSrv::getStackSockNeedWorker() {
    return stackSockNeedWorker.swap(nullptr);
}

void EpolSrv::returnSocketToWork(EpolSocket * sock){
    stackSockNeedWorker.push(sock);
}

void EpolSrv::returnSocketToFree(EpolSocket * sock) {
    stackFreeSockets.push(sock);
}

void EpolSrv::startWorker() {
    EpolWorker * w = new EpolWorker(this, logLevel,
                                    iLog, specSSL,
                                    iFileAdapter, iDB);
    w->start();
    stackWorkers.push(w);
    ++curWorkers;
}

void EpolSrv::stopWorker() {
    EpolWorker * w = stackWorkers.pop();
    w->lazyGoStop();
    --curWorkers;
    // at workerThread stoppedWorkers.push(w);
}

void EpolSrv::clearStoppedWorkers() {
    SpecStack<EpolWorker> stopedWorkers;
    EpolWorker * w;
    stopedWorkers.swap(stoppedWorkers.swap(nullptr));
    while ((w = stopedWorkers.pop())){
        delete w;
    }
}

void EpolSrv::workerGoneDown(void * worker) {
    stoppedWorkers.push((EpolWorker *)worker);
}

void  EpolSrv::doPack11(EpolSocket  *s,  IPack  *pack)  {
  int32_t  count  =  0;
  T_IPack0_Network * header  =  &(pack->header);
  if  (0==header->body_len)  {
    if  (header->key1  &&  specSSL->groupX509exists(header->key1))  {  ++count;  }
    if  (header->key2  &&  specSSL->groupX509exists(header->key2))  {  ++count;  }
    if  (header->key3  &&  specSSL->groupX509exists(header->key3))  {  ++count;  }
  }  else  {
    IPack11::parsePackI(pack, &count);
    uint64_t  *guid1sN  =  reinterpret_cast<uint64_t *>(pack->body);
    for  (int32_t  i  =  count;  i>=0;  --i)  {
      if (!specSSL->groupX509exists(guid1sN[i]))  {  --count;  }
    }
  }
  if  (count  <=  0)  {
    // There is no client group serviced:
    setFreeSocketID(s);
  }  else  {
    s->groups_count  =  count;
  }
}  //  doPack11

void  EpolSrv::doPack7(EpolSocket  *s,  IPack  *pack)  {
    T_IPack0_Network * header  =  &(pack->header);
    int32_t  lenArray  =  header->body_len / SIZE_2x_uint64_t;
    if  (lenArray>0)  {
      s->msgs_to_send  +=  lenArray;
      uint64_t  *guid1sN  =  reinterpret_cast<uint64_t *>(pack->body);
      uint64_t  *guid2sN  =  guid1sN  +  lenArray;
      TKey key;
      key.key1  =  _HTONLL(header->key1);
      for  (int32_t  i  =  lenArray ;  i>=0;  --i)  {
        key.key2  =  guid1sN[i];
        key.key3  =  guid2sN[i];
        IPack  *cached_pack  =  cache->getData(&key);
        if  (cached_pack)  {
          s->writeStackServer.push(cached_pack);
          guid1sN[i]  =  0ll;  //  mark it sended
          --lenArray;  //  to send work decreased
        }
      }
      if  (lenArray>0)  {
        s->readStack.push(pack);
      }  else  {
        delete pack;
      }
    }  else if (header->key2)  {
      TKey key;
      key.key1  =  _HTONLL(header->key1);
      key.key2  =  _HTONLL(header->key2);
      key.key3  =  _HTONLL(header->key3);
      IPack  *cached_pack  =  cache->getData(&key);
      if  (cached_pack)  {
        s->writeStackServer.push(cached_pack);
        delete pack;
      }  else  {
        s->readStack.push(pack);
        ++s->msgs_to_send;
      }
    }

    s->all_sended  =  (s->msgs_to_send  <=  0);
    --s->groups_count;
  return;
}  //  doPack7
