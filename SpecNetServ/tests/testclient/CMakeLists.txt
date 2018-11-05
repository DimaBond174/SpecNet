set(CUR_TEST "testclient")

set(CUR_SRC "")
set(CUR_INCLUDES "")
set(CUR_DEFINITIONS "")
set(CUR_LINK_LIBS "")
set(CUR_PROPERTIES "")

file(GLOB_RECURSE CUR_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.h" )
#    "${CMAKE_SOURCE_DIR}/i/*.h")

set (CUR_INCLUDES
    ${CUR_INCLUDES}
    "${CMAKE_SOURCE_DIR}/tests/common"
    "${CMAKE_SOURCE_DIR}/tests/testsql"
    "${CMAKE_SOURCE_DIR}/tests/testssl"
    "${CMAKE_SOURCE_DIR}/src"
)

set(CUR_SRC ${CUR_SRC}
    ${CMAKE_SOURCE_DIR}/src/depend/file/old/cfileadapter.h
    ${CMAKE_SOURCE_DIR}/src/depend/file/old/cfileadapter.cpp
    )

if("${SPEC_ENCRYPT}" STREQUAL "DSpecSSL")
   message(STATUS "SpecSSL was chosen for testclient")
   set(CUR_INCLUDES
       ${CUR_INCLUDES}
       ${CMAKE_SOURCE_DIR}/src/depend/encrypt/boringssl/include
       )
endif()

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
   set(CUR_SRC ${CUR_SRC}
       ${CMAKE_SOURCE_DIR}/src/depend/system/linux/linuxsystem.h
       ${CMAKE_SOURCE_DIR}/src/depend/system/linux/linuxsystem.cpp
       )

elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(CUR_SRC ${CUR_SRC}
        ${CMAKE_SOURCE_DIR}/src/depend/system/windows/windowssystem.h
        ${CMAKE_SOURCE_DIR}/src/depend/system/windows/windowssystem.cpp
        )
endif()

set (CUR_DEFINITIONS
    ${CUR_DEFINITIONS}
#    SPEC_VERSION="${SpecNetServ_VERSION}"
#    SPEC_SERVICE="${SpecNetServ_SERVICE}"
#    SPEC_EXECUTIVE="${PROJECT_NAME}"
#    ${CMAKE_BUILD_TYPE}
	${CMAKE_SYSTEM_NAME}
    ${SPEC_DEFINITIONS}
    )

#custom_add_executable(${CUR_TEST}
#    "${CUR_SRC}"
#    "${CUR_INCLUDES}"
#    "${CUR_DEFINITIONS}"
#    "${CUR_LINK_LIBS}"
#    "${CUR_PROPERTIES}")

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
   message(STATUS "Linux was chosen ")

elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
   message(STATUS "Windows was chosen ")
   
      set(CUR_LINK_LIBS
             ${LIB_LINK_LIBS}
             Ws2_32
         )

   	set(CUR_DEFINITIONS
	${CUR_DEFINITIONS}
	"WIN32_LEAN_AND_MEAN")
endif()

set(CUR_TEST "testclient1")
set (CUR_DEFINITIONS
    SPEC_CLI_N=1
    ${CUR_DEFINITIONS}
    )
custom_add_executable(${CUR_TEST}
    "${CUR_SRC}"
    "${CUR_INCLUDES}"
    "${CUR_DEFINITIONS}"
    "${CUR_LINK_LIBS}"
    "${CUR_PROPERTIES}")

set(CUR_TEST "testclient2")
set (CUR_DEFINITIONS
    SPEC_CLI_N=2
    ${CUR_DEFINITIONS}
    )
custom_add_executable(${CUR_TEST}
    "${CUR_SRC}"
    "${CUR_INCLUDES}"
    "${CUR_DEFINITIONS}"
    "${CUR_LINK_LIBS}"
    "${CUR_PROPERTIES}")

set(CUR_TEST "testclient3")
set (CUR_DEFINITIONS
    SPEC_CLI_N=3
    ${CUR_DEFINITIONS}
    )
custom_add_executable(${CUR_TEST}
    "${CUR_SRC}"
    "${CUR_INCLUDES}"
    "${CUR_DEFINITIONS}"
    "${CUR_LINK_LIBS}"
    "${CUR_PROPERTIES}")
