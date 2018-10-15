#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include <string>
#include <memory>
#if defined(Linux)
    #include "depend/system/linux/linuxsystem.h"
#elif defined(Windows)
    #include "depend/system/windows/windowssystem.h"
#endif

std::shared_ptr <ISystem> iSystem =
#if defined(Linux)
    std::make_shared<LinuxSystem>();
#elif defined(Windows)
    std::make_shared<WindowsSystem>();
#endif

#include "testutils.h"


TEST_CASE( "Start SpecNetServ", "[start]" ) {


    std::string cmd (iSystem.get()->getExePath());
    cmd.append("/").append(SPEC_EXECUTIVE);
    #if defined(Debug)
        cmd.append("d");
    #endif
    cmd.append(" -d");
    std::string str("Going to start SpecNetServ with command:\n");
    str.append(cmd);
    WARN(str.c_str());
    iSystem.get()->execCmd(cmd.c_str());

    bool (*answerSpecNetServ) () = []() {
        const std::string &status = iSystem.get()->sendCmd(SPEC_SERVICE, "STATUS");
        return !status.empty();
        };
    //const std::string &answerSpecNetServ = iSystem.get()->sendCmd(SPEC_SERVICE, "STATUS");
    //REQUIRE( answerSpecNetServ );
    REQUIRE( waitForSUCCESS(answerSpecNetServ, 100, 10000) );

    BENCHMARK ("Get SpecNetServ STATUS answer") {
        iSystem.get()->sendCmd(SPEC_SERVICE, "STATUS");
    }


}


TEST_CASE( "SpecNet client1", "[client1]" ) {



    BENCHMARK ("Get SpecNetServ answer") {

    }

//    REQUIRE( Factorial(1) == 1 );
//    REQUIRE( Factorial(2) == 2 );
//    REQUIRE( Factorial(3) == 6 );
//    REQUIRE( Factorial(10) == 3628800 );
    //REQUIRE( Factorial(0) == 8 );
}


TEST_CASE( "Stop SpecNetServ", "[stop]" ) {


    std::string cmd (iSystem.get()->getExePath());
    cmd.append("/").append(SPEC_EXECUTIVE);
    #if defined(Debug)
        cmd.append("d");
    #endif
    cmd.append(" -t");
    std::string str("Going to stop SpecNetServ with command:\n");
    str.append(cmd);
    WARN(str.c_str());
    iSystem.get()->execCmd(cmd.c_str());
    const std::string &answerSpecNetServ = iSystem.get()->sendCmd(SPEC_SERVICE, "STATUS");
    REQUIRE( answerSpecNetServ.empty() );

}
