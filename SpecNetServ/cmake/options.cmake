# Inject Components:
# warn: label name must be differen from class name (Error: declaration of anonymous class must be a definition)

# Config module:
set(SPEC_CONFIG  DConfigJson)

# Logger module:
set(SPEC_LOGGER  DSpecLog)
#set(SPEC_LOGGER  DSpdLog)

# File adapter module:
set(SPEC_FILE  DFileAdapter)

# Database module:
set(SPEC_DB  DSQLiteDB)

# Encryption module:
set(SPEC_ENCRYPT DSpecSSL)

# Server implementation module:
#set(SPEC_SERV DDefServer)
set(SPEC_SERV DEpollServer)
#set(SPEC_SERV DSelectServer)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(SPEC_BUILD DDEBUG)
else()
    set(SPEC_BUILD DRELEASE)
endif ()

# Configuration of the assembly
#   according to the selected components:
set(SPEC_DEFINITIONS
	${SPEC_DEFINITIONS}
    ${CMAKE_SYSTEM_NAME}
    ${SPEC_LOGGER}
    ${SPEC_DB}
    ${SPEC_FILE}
    ${SPEC_ENCRYPT}
    ${SPEC_CONFIG}
    ${SPEC_SERV}
    ${CMAKE_BUILD_TYPE}
    ${SPEC_BUILD}
    SPEC_VERSION="${SpecNetServ_VERSION}"
    SPEC_SERVICE="${SpecNetServ_SERVICE}"
)

set(SPEC_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)

set(SPEC_INCLUDE
    ${CPP_INCLUDES}
#    ${CLANG_INCLUDE}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    )



#link_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs)

if("${SPEC_LOGGER}" STREQUAL "DSpdLog")
   message(STATUS "SpdLog logger was chosen ")
   set(SPEC_INCLUDE
       ${SPEC_INCLUDE}
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/log/spdlog/include
       )
   file(GLOB_RECURSE LOC_SRC
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/log/spdlog/*.h
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/log/spdlog/*.cpp
   )
   set(SPEC_SRC ${SPEC_SRC}  ${LOC_SRC})
else()
   message(STATUS "SpecLog logger was chosen ")
   file(GLOB_RECURSE LOC_SRC
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/log/speclog/*.h
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/log/speclog/*.cpp
   )
   set(SPEC_SRC ${SPEC_SRC}  ${LOC_SRC})
endif()


if("${SPEC_DB}" STREQUAL "DSQLiteDB")
    message(STATUS "SQLiteDB was chosen ")    
    add_library(sqlite3
     STATIC
     ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/db/sqlite/sqlite3/sqlite3.c
     ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/db/sqlite/sqlite3/sqlite3.h
    )

    if (SPEC_TESTS STREQUAL "ON")
        set_target_properties(sqlite3 PROPERTIES COMPILE_FLAGS " -fPIC  ")
    endif()

    set(SPEC_LINK_LIBS
        ${SPEC_LINK_LIBS}
        sqlite3
        #dl
    )
    set(SPEC_SRC ${SPEC_SRC}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/db/sqlite/sqlitedb.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/db/sqlite/sqlitedb.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/db/sqlite/sqlite3/sqlite3.h
        )
endif()


if("${SPEC_ENCRYPT}" STREQUAL "DSpecSSL")
   message(STATUS "SpecSSL was chosen ")
   set(SPEC_INCLUDE
       ${SPEC_INCLUDE}
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/encrypt/boringssl/include
       )
   file(GLOB_RECURSE LOC_SRC
#       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/encrypt/boringssl/*.h 
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/encrypt/boringssl/*.cpp
   )
   set(SPEC_SRC ${SPEC_SRC}  ${LOC_SRC})
   add_library( crypto
                STATIC
                IMPORTED )
   add_library( decrepit
                STATIC
                IMPORTED )
   add_library( ssl
                STATIC
                IMPORTED )

   set(SPEC_LINK_LIBS
                ${SPEC_LINK_LIBS}
                decrepit
                ssl
                crypto
            )
    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
        set_target_properties( # Specifies the target library.
            crypto
            PROPERTIES IMPORTED_LOCATION
            ${CMAKE_CURRENT_SOURCE_DIR}/static/libcrypto.a )
        set_target_properties( # Specifies the target library.
            decrepit
            PROPERTIES IMPORTED_LOCATION
            ${CMAKE_CURRENT_SOURCE_DIR}/static/libdecrepit.a )
        set_target_properties( # Specifies the target library.
            ssl
            PROPERTIES IMPORTED_LOCATION
            ${CMAKE_CURRENT_SOURCE_DIR}/static/libssl.a )
	elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
        set_target_properties( # Specifies the target library.
            crypto
            PROPERTIES IMPORTED_LOCATION
            ${CMAKE_CURRENT_SOURCE_DIR}/static/crypto.lib )
        set_target_properties( # Specifies the target library.
            decrepit
            PROPERTIES IMPORTED_LOCATION
            ${CMAKE_CURRENT_SOURCE_DIR}/static/decrepit.lib )
        set_target_properties( # Specifies the target library.
            ssl
            PROPERTIES IMPORTED_LOCATION
            ${CMAKE_CURRENT_SOURCE_DIR}/static/ssl.lib )
    endif()
endif()


if("${SPEC_SERV}" STREQUAL "DEpollServer")
    message(STATUS "DEpollServer was chosen ")
    file(GLOB_RECURSE LOC_SRC
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/server/epoll/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/server/epoll/*.cpp
    )
    set(SPEC_SRC ${SPEC_SRC}  ${LOC_SRC})
elseif("${SPEC_SERV}" STREQUAL "DSelectServer")
    message(STATUS "DSelectServer was chosen ")
    file(GLOB_RECURSE LOC_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/server/select/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/server/select/*.cpp
    )
    set(SPEC_SRC ${SPEC_SRC}  ${LOC_SRC})
	#https://bugs.freedesktop.org/show_bug.cgi?id=71297
	set(SPEC_DEFINITIONS
	${SPEC_DEFINITIONS}
	FD_SETSIZE=1024)
endif()



if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
   message(STATUS "Linux was chosen ")
   file(GLOB_RECURSE LOC_SRC
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/system/linux/*.h
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/system/linux/*.cpp
   )
   set(SPEC_SRC ${SPEC_SRC}  ${LOC_SRC})

   set(SPEC_LINK_LIBS
             ${SPEC_LINK_LIBS}
             dl
			 pthread
			 stdc++fs
         )
#set(SPEC_LINK_LIBS
#    pthread
#    stdc++fs
##    c++experimental
#    )

#add_library(c++ STATIC IMPORTED)
#add_library(c++abi STATIC IMPORTED)
#set_target_properties(c++ PROPERTIES LINKER_LANGUAGE CXX)
#set_target_properties(c++ PROPERTIES IMPORTED_LOCATION ${CLANG_PATH}/lib/libc++.a)
#set_target_properties(c++abi PROPERTIES LINKER_LANGUAGE CXX)
#set_target_properties(c++abi PROPERTIES IMPORTED_LOCATION ${CLANG_PATH}/lib/libc++abi.a)
#set(SPEC_LINK_LIBS
#             ${SPEC_LINK_LIBS}
#             c++
#             c++abi
#         )

elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
   message(STATUS "Windows was chosen ")
   file(GLOB_RECURSE LOC_SRC
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/system/windows/*.h
       ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/system/windows/*.cpp
   )
   set(SPEC_SRC ${SPEC_SRC}  ${LOC_SRC})
   	set(SPEC_DEFINITIONS
	${SPEC_DEFINITIONS}
	"WIN32_LEAN_AND_MEAN")
endif()

# Sources
#include_directories( ${SPEC_INCLUDE} )

file(GLOB_RECURSE DEF_SRC
#    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.*
    ${CMAKE_CURRENT_SOURCE_DIR}/src/spec/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/spec/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/config/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/config/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/file/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/file/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/tools/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/depend/tools/*.cpp
#    ${CMAKE_CURRENT_SOURCE_DIR}/src/i/*.h
)




set(SPEC_SRC
    ${SPEC_SRC}
    ${DEF_SRC}
    )
message("SPEC_SRC: ${SPEC_SRC}")

# Output folder for binaries
#SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${}/bin)
#SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG  ${CMAKE_CURRENT_SOURCE_DIR}/bin)
# это опирается на каталог откуда был запущен CMAKE:
# https://github.com/OSVR/OSVR-Core/issues/555 :
#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#set(SPEC_BUILD_DIR ${CMAKE_BINARY_DIR}/../bin_toCopy_toInstall)
#set(SPEC_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bin_toCopy_toInstall)
set(SPEC_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${SpecNetServ_INSTALL_FOLDER})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${SPEC_BUILD_DIR}/libs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${SPEC_BUILD_DIR}/libs)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${SPEC_BUILD_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG  ${SPEC_BUILD_DIR})


# Current OS name:
message("CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")


set(SPEC_PROPERTIES
    DEBUG_POSTFIX             "d"
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
