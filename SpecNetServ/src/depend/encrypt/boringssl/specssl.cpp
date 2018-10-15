#include "specssl.h"
#include "spec/speccontext.h"
#include "spec/specstatic.h"

#define SPEC_LONG_MAX 2147483647

SpecSSL::SpecSSL()
{

}

//bool  SpecSSL::start() {
//    SSL_load_error_strings();
//    OpenSSL_add_ssl_algorithms();
//    SpecContext & sr = SpecContext::instance();
//    bool re = false;
//    //faux loop
//    do {
//        logLevel = sr.iConfig.get()->getLongValue("LogLevel");

//        const SSL_METHOD *method = SSLv23_server_method();
//        ctx = SSL_CTX_new(method);
//        if (!ctx) {
//            sr.iLog.get()->log("e","[%s]: FAIL ctx = SSL_CTX_new(method).",TAG);
//            break;
//        }

//        SSL_CTX_set_ecdh_auto(ctx, 1);

//        const std::string &certPath =
//                sr.iFileAdapter.get()->toFullPath(
//                    sr.iConfig.get()->getStringValue(
//                        "SSLcertificate_file").c_str());
//        const std::string &keyPath =
//                sr.iFileAdapter.get()->toFullPath(
//                    sr.iConfig.get()->getStringValue(
//                        "SSLPrivateKey_file").c_str());

//        /* Set the key and cert */
//        if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
//            sr.iLog.get()->log("e","[%s]: FAIL SSL_CTX_use_certificate_file(ctx, certPath.",TAG);
//            break;
//        }

//        if (SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
//            sr.iLog.get()->log("e","[%s]: FAIL SSL_CTX_use_PrivateKey_file(ctx, keyPath.",TAG);
//            break;
//        }

//        re = true;
//        keepRun.store(true, std::memory_order_release);
//    } while (false);
//    return re;
//}



bool  SpecSSL::start() {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    SpecContext & sr = SpecContext::instance();
    iLog =sr.iLog.get();
    iFileAdapter = sr.iFileAdapter.get();

    bool re = false;
    //faux loop
    do {
        /* for error texts */
        errBIO = BIO_new(BIO_s_mem());
        if (!errBIO) {
            iLog->log("e","[%s]: NULL = BIO_new(BIO_s_mem());.",TAG);
            break;
        }

        /* create the SSL server context */
        ctx = SSL_CTX_new(SSLv23_method());
        if (!ctx) {
            iLog->log("e","[%s]: NULL = SSL_CTX_new(SSLv23_method()).",TAG);
            break;
        }

        logLevel = sr.iConfig.get()->getLongValue("LogLevel");
        idleConnLife = sr.iConfig.get()->getLongValue("idleConnLife");

        const std::string &certPath =
                iFileAdapter->toFullPath(
                    sr.iConfig.get()->getStringValue(
                        "SSLcertificate_file").c_str());
        const std::string &keyPath =
                iFileAdapter->toFullPath(
                    sr.iConfig.get()->getStringValue(
                        "SSLPrivateKey_file").c_str());

        /* Set the key and cert */
        if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
            iLog->log("e","[%s]: FAIL SSL_CTX_use_certificate_file(ctx, certPath.",TAG);
            break;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
            iLog->log("e","[%s]: FAIL SSL_CTX_use_PrivateKey_file(ctx, keyPath.",TAG);
            break;
        }

        /* Make sure the key and certificate file match. */
        if (SSL_CTX_check_private_key(ctx) != 1) {
            iLog->log("e","[%s]: Private Key do not match X509 certificate.",TAG);
        } else {
            iLog->log("i","[%s]: certificate and private key loaded and verified.",TAG);
        }

        /* Recommended to avoid SSLv2 & SSLv3 */
        SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

        /* load SpecGroups encrypt staff */
        re = loadSpecGroups();
//        if (re) {
//            keepRun.store(true, std::memory_order_release);
//        }
    } while (false);
    return re;
}

bool SpecSSL::loadSpecGroups() {
    bool re = false;
    specGroupIDs.clear();
    char jsonName[SMAX_PATH];
    char certPath[SMAX_PATH];
    char * jsonNameSuffix = jsonName;
    char * jsonNameEnd = jsonName + SMAX_PATH -1;
    char * certPathSuffix = certPath;
    char * certPathEnd = certPath + SMAX_PATH -1;
    SpecContext & sr = SpecContext::instance();
//    IConfig * iConfig = sr.iConfig.get();
    //faux loop
    do{
        const std::string &certPath1 = sr.iConfig.get()->getStringValue("GroupsCertsPath");
        if (certPath1.empty()) {break;}
        const std::string &certPath2 =
                iFileAdapter->toFullPath(certPath1.c_str());
        if (certPath2.empty()) {break;}
        certPathSuffix = printString(certPath2.c_str(), certPathSuffix, certPathEnd);
        *certPathSuffix = '/'; ++certPathSuffix;
        jsonNameSuffix= printString("SpecGroupID", jsonNameSuffix, jsonNameEnd);
        unsigned long long groupID =0;
        unsigned long long i =0;
        while(i < SMAX_GROUPS){
            printULong(i, jsonNameSuffix, jsonNameEnd);
            const std::string & groupIDS = sr.iConfig.get()->getStringValue(jsonName);
            if (groupIDS.empty()) { break;  }
            groupID = stoll(groupIDS);
            if (0==groupID){ break;}
            printULong(groupID, certPathSuffix, certPathEnd);
            const std::string & strX509 = iFileAdapter->loadFileF(certPath);

            if (strX509.empty()){
                iLog->log("e","[%s]: Can't read file: %s",TAG, certPath);
                break;
            }

            X509 * pX509 = extractX509(strX509);
            if (!pX509){
                iLog->log("e","[%s]: Can't extractX509 from file: %s",TAG, certPath);
                break;
            }

            specGroupIDs.insert(groupID);
            specGroupX509s.insert(std::make_pair(groupID, pX509));

            ++i;
        }
        if (specGroupIDs.empty()) {
            iLog->log("e","[%s]: There is no group X509 certificate for work.",TAG);
        } else {
            re = true;
        }
    } while(false);
    return re;
}

X509 * SpecSSL::extractX509  (const std::string &inX509) {
    return extractX509  ((void *) inX509.c_str(), inX509.length());
}

X509 * SpecSSL::extractX509  (const void *x509, int len) {
    X509 * cert = nullptr;
    if (x509 && len>0) {        
        BIO *bio = BIO_new_mem_buf(x509, len);
        if (bio) {            
            PEM_read_bio_X509(bio, &cert, NULL, NULL);
            BIO_free(bio);
        }
    }

    return cert;
}

void  SpecSSL::stop()  {
    //keepRun.store(false, std::memory_order_release);
    if (ctx) {
        //SpecContext & sr = SpecContext::instance();
        /* wait for threads who is using SpecSSL */
//        bool (*useCountIs0) (void * ptr) = [](void * ptr) {
//            SpecSSL * p = reinterpret_cast<SpecSSL*>(ptr);
//            return 0==p->useCount.load(std::memory_order_acquire);
//        };
//        sr.iSys.get()->waitForSUCCESS(useCountIs0, this, 100, 10000);
        /* error is better than hung: */
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }

    if (!specGroupX509s.empty()) {
        for (auto it : specGroupX509s) {
            X509_free(it.second);
        }
        specGroupX509s.clear();
    }
    specGroupIDs.clear();

    EVP_cleanup();
}

void   SpecSSL::logErrors() {
    ERR_print_errors(errBIO);
    char buf[1024];
    int n = BIO_read(errBIO, buf, 1024);
    if (n>0) {
        buf[n] = 0;
        SpecContext::instance().iLog.get()
                ->log("e","[SpecSSL]:%s",buf);
    }
    BIO_reset(errBIO);
}

int SpecSSL::printSSLErrors(const char *str, size_t len, void *anyData)
{
    if (str && len > 0) {
        SpecContext & sr = SpecContext::instance();
        std::string str(str, len);
        sr.iLog.get()->log("e","[SpecSSL]:%s",str.c_str());
    }
    return 1;
}


void * SpecSSL::startEncryptSocket(int socket) {
    //SSLstaff * re = nullptr ;
    SSL * re = nullptr ;
    //faux loop:
    do {
        SSL * ssl = SSL_new (ctx);
        if (!ssl) { break; }
        if (1!=SSL_set_fd(ssl, socket)) {
            SSL_free(ssl);
            break;
        }
        SSL_set_accept_state(ssl);
        re = ssl;//new SSLstaff(ssl);
    } while (false);
    return re;
}


int SpecSSL::do_handshakeSocket(void * staff) {
     return SSL_do_handshake((SSL *)staff);
}

void SpecSSL::stopEncryptSocket(void * staff) {
    SSL_free((SSL *)staff);
    //delete ((SSLstaff *)staff);
}

int SpecSSL::getSocketState(void * staff, int code) {
    return SSL_get_error((SSL *)staff, code);
}

int SpecSSL::readSocket(void * staff, void *buf, int num) {
    return SSL_read((SSL *)staff, buf, num);
}

int SpecSSL::writeSocket(void * staff, const void *buf, int num) {
    return SSL_write((SSL *)staff, buf, num);
}

bool SpecSSL::groupX509exists(unsigned long long groupID) {
    return specGroupIDs.end()!=specGroupIDs.find(groupID);
}


X509 * SpecSSL::getX509(const void *buf, int num) {
    X509 * cert = nullptr;
    if (buf && num>0) {
        BIO *bio = BIO_new_mem_buf(buf, num);
        if (bio) {
            PEM_read_bio_X509(bio, &cert, NULL, NULL);
            BIO_free(bio);
        }
    }

    return cert;
}

EVP_PKEY * SpecSSL::getX509evp(X509 * x509) {    
    return X509_get_pubkey(x509);;
}

void SpecSSL::freeX509(X509 * x509) {
    X509_free(x509);
}

void SpecSSL::freeEVP(EVP_PKEY * evp) {
    EVP_PKEY_free(evp);
}

bool SpecSSL::checkX509(unsigned long long groupID, unsigned long long avatarID,
                        const char * strX509, int strX509len){
    bool re = false;
    BIO *bio = nullptr;
    X509 * UScert = nullptr;
    X509_STORE *sto = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    //faux loop
    do {
        std::map<unsigned long long, X509 *>::const_iterator it = specGroupX509s.find(groupID);
        if (specGroupX509s.end()==it) { break; }
        X509 * CAcert = it->second;
        BIO *bio = BIO_new_mem_buf((void*)strX509, strX509len);
        if (!bio) { break; }
        PEM_read_bio_X509(bio, &UScert, NULL, NULL);
        if (!UScert) { break; }
        //int hash = (int)(avatarID % 32767);
        //long hash = (long)((avatarID ^ (avatarID >> 32))%2147483647);
        long hash = avatarID % SPEC_LONG_MAX;
        long serial = ASN1_INTEGER_get(X509_get_serialNumber (UScert));
        if (serial!=hash) { break; }
//        if (ASN1_INTEGER_get(X509_get_serialNumber (UScert))!=hash) { break; }
        time_t t = time(NULL);
        if (ASN1_TIME_to_DWORD(t, X509_get_notAfter(UScert)) - t < 0) { break; }
        sto = X509_STORE_new();
        if (!sto) { break; }
        X509_STORE_add_cert(sto, CAcert);
        ctx = X509_STORE_CTX_new();
        if (!ctx) { break; }
        X509_STORE_CTX_init(ctx, sto, UScert, NULL);
        re = 1==X509_verify_cert(ctx);

    } while (false);

    if (ctx) {X509_STORE_CTX_free(ctx);}
    if (sto) {X509_STORE_free(sto);}
    if (UScert) {X509_free(UScert);}
    if (bio) {BIO_free(bio);}

    return re;
}//checkX509


time_t SpecSSL::ASN1_TIME_to_DWORD(time_t curTime, ASN1_TIME * from)
{
    //time_t re = 0;
    //struct tm t;
    struct tm * timeinfo;
    const char * str = (const char *)from->data;
    int nYear, nMonth, nDay, nHour, nMin, nSec;

    size_t i = 0;
    if (V_ASN1_UTCTIME == from->type)
    {//YYmmddHHMMSS
        //t.tm_year
        nYear = (str[i] - '0') * 10; ++i;
        //t.tm_year
        nYear += (str[i] - '0'); ++i;
        //if (t.tm_year < 70) t.tm_year += 100;
        if (nYear < 70) nYear += 2000;
        else  nYear += 1900;
    }
    else if (V_ASN1_GENERALIZEDTIME == from->type) {
        //t.tm_year
        nYear = (str[i] - '0') * 1000; ++i;
        //t.tm_year
        nYear += (str[i] - '0') * 100; ++i;
        //t.tm_year
        nYear += (str[i] - '0') * 10; ++i;
        //t.tm_year
        nYear += (str[i] - '0'); ++i;
        //t.tm_year -= 1900;
    }
    else return 0;
    //t.tm_mon
    nMonth = (str[i] - '0') * 10; ++i;
    //t.tm_mon
    nMonth += (str[i] - '0'); ++i;

    //t.tm_mday
    nDay = (str[i] - '0') * 10; ++i;
    //t.tm_mday
    nDay += (str[i] - '0'); ++i;

    //t.tm_hour
    nHour = (str[i] - '0') * 10; ++i;
    //t.tm_hour
    nHour += (str[i] - '0'); ++i;

    //t.tm_min
    nMin = (str[i] - '0') * 10; ++i;
    //t.tm_min
    nMin += (str[i] - '0'); ++i;

    //t.tm_sec
    nSec = (str[i] - '0') * 10; ++i;
    //t.tm_sec
    nSec += (str[i] - '0');
    //++i;

    //time_t EndDate = mktime(&t);
    //CString path;
    //path.Format("The time is %s\n", _ctime64(&EndDate));
    //return mktime(&t);// mktime(&t) ÷óäåñíûì îáðàçîì äîáàâëÿåò ËÈØÍÈÉ 1 ãîä è ñð¸ò â äðóãèå ÷àñòè äàòû
    //time_t mktime (struct tm * timeptr);
//    CTime * time = new CTime(nYear, nMonth, nDay, nHour, nMin, nSec);
//    nYear
//    1970–3000
//    nMonth
//    1–12
//    nDay
//    1–31
//    nHour
//    0-23
//    nMin
//    0-59
//    nSec
//    0-59
//    if (time)
//    {
//        re = time->GetTime();
//        delete time;
//    }
//    tm_sec	int	seconds after the minute	0-60*
//                                                   tm_min	int	minutes after the hour	0-59
//    tm_hour	int	hours since midnight	0-23
//    tm_mday	int	day of the month	1-31
//    tm_mon	int	months since January	0-11
//    tm_year	int	years since 1900
//    tm_wday	int	days since Sunday	0-6
//    tm_yday	int	days since January 1	0-365
   // CTime(nYear, nMonth, nDay, nHour, nMin, nSec);

    timeinfo = localtime (&curTime);
    //timeinfo->tm_year = nYear - 1900;
    timeinfo->tm_mon = nMonth - 1;
    timeinfo->tm_mday = nDay;
    timeinfo->tm_hour = nHour;
    timeinfo->tm_min = nMin;
    timeinfo->tm_sec = nSec;
//https://stackoverflow.com/questions/14127013/mktime-returns-1-when-given-a-valid-struct-tm
  //говорят что работает тока в диапазоне ~ 13/12/1901 and 19/1/2038, поэтому:
    if (nYear>=2038) { //Год когда все IT на планете рухнет
        nYear=2037;
    }
    timeinfo->tm_year = nYear - 1900;
    return mktime(timeinfo);

}


bool SpecSSL::verify_it(const void* msg, size_t mlen, const void* sig, size_t slen, EVP_PKEY* evpX509)
{
    bool re = false;

    if(!msg || !mlen || !sig || !slen || !evpX509) {
        return re;
    }

    EVP_MD_CTX* ctx = NULL;

    do
    {
        ctx = EVP_MD_CTX_create();

        if(ctx == NULL) { break;  }

        const EVP_MD* md = EVP_sha256();

        if(md == NULL) { break;  }

        int rc = EVP_DigestInit_ex(ctx, md, NULL);

        if(rc != 1) { break; }

        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, evpX509);

        if(rc != 1) { break; }

        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);

        if(rc != 1) { break;  }

        /* Clear any errors for the call below */
        ERR_clear_error();

        rc = EVP_DigestVerifyFinal(ctx, (const uint8_t *)sig, slen);

        if(rc != 1) { break; }

        re = true;

    } while(0);

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
    }

    return re;

}//verify DigSign



