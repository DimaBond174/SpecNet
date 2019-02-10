# This is the source code of SpecNet project
# It is licensed under MIT License.
#
#  Copyright (c) Dmitriy Bondarenko
#  feel free to contact me: specnet.messenger@gmail.com
#
cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(SpecNetServ)
set(SpecNetServ_VERSION  "1.0")
set(SpecNetServ_SERVICE  "specnetserv")
set(SpecNetServ_INSTALL_FOLDER "../SpecNetDir")
#
#           README: how to make
# The project has a modular structure.
# So you can inject another server implementation,
# work with another database, other logging and so on.
# For example: "Epol" networking for Linux,
# "Select" networking for Windows, or blocking sockets..
# Here you can choose your preferences (if something is not, create):

# Creating test programs:
# At the moment, 3 test clients are being created for debugging.
# Clients generate letters and exchange them through the server.
# Also, libraries are created for working with a database and
# cryptography, which test programs connect during execution
# via a universal interface (this can be considered as injection
# of the implementation of work with the database and cryptography)
set(SPEC_TESTS "ON")

# Choosing build system:
if (MSVC)
	message(STATUS "Windows MSVC configure")
	set (CMAKE_BUILD_TYPE "Debug")	
else()
	message(STATUS "Clang configure")
	set(CMAKE_CXX_COMPILER clang++)
	set(CMAKE_C_COMPILER clang)
	set(CLANG_PATH "/usr/local/clang_6.0.1")
endif (MSVC)

# TODO Enshure target build is what you want:
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(SPEC_BUILD DDEBUG)
else()
    set(SPEC_BUILD DRELEASE)
endif()

# Please set project flawors there:
# (What value will be entered into the SPEC_* variable
# affects what module is injected)

# Config module:
# Loads settings for server operation
# (Default from ./SpecNetDir/assets/settings.json
# WARN: Assets copying occurs when you change CMakeLists.txt)
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

include(cmake/options.cmake)
include(cmake/functions.cmake)


# Coping assets (TODO any change&rerun CMake to copy):
FILE(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/assets)
FILE(GLOB_RECURSE SpecAssets
    ${CMAKE_CURRENT_SOURCE_DIR}/assets/*.*
    ${CMAKE_CURRENT_SOURCE_DIR}/assets/*
)
FOREACH(file ${SpecAssets})
    FILE(RELATIVE_PATH
        ITEM_PATH_REL
        ${CMAKE_CURRENT_SOURCE_DIR}/assets
        ${file}
    )
    GET_FILENAME_COMPONENT(dirname ${ITEM_PATH_REL} DIRECTORY)
#    message("File: ${ITEM_PATH_REL}")
#    message("Relative path: ${dirname}")
    FILE(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/assets/${dirname})
#    GET_FILENAME_COMPONENT(filename ${file} NAME)
#    FILE(COPY ${CMAKE_CURRENT_SOURCE_DIR}/assets/${ITEM_PATH_REL} DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/assets/${dirname})
    FILE(COPY ${file} DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/assets/${dirname})
ENDFOREACH()

# Coping custom libs:
FILE(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libs)
FILE(GLOB SpecLibs "libs/*.*")
FOREACH(file ${SpecLibs})
    GET_FILENAME_COMPONENT(filename ${file} NAME)
    FILE(COPY ${CMAKE_CURRENT_SOURCE_DIR}/libs/${filename} DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libs)
ENDFOREACH()


custom_add_executable(${PROJECT_NAME}
    "${SPEC_SRC}"
    "${SPEC_INCLUDE}"
    "${SPEC_DEFINITIONS}"
    "${SPEC_LINK_LIBS}"
    "${SPEC_PROPERTIES}")


message(STATUS "target_link_libraries: ${SPEC_LINK_LIBS}")

# Print CXX compiler information
message (STATUS "CMAKE_CXX_COMPILER '${CMAKE_CXX_COMPILER}' '${CMAKE_CXX_COMPILER_ID}' '${CMAKE_CXX_COMPILER_VERSION}'")

# Print CXX FLAGS
message (STATUS "CMAKE_CXX_FLAGS                '${CMAKE_CXX_FLAGS}'")

# TODO Enshure target build is what you want:
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

if (SPEC_TESTS STREQUAL "ON")
    FILE(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tests/assets)
    FILE(GLOB_RECURSE TestAssets
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/assets/*.*
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/assets/*
    )
    FOREACH(file ${TestAssets})
        FILE(RELATIVE_PATH
            ITEM_PATH_REL
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/assets
            ${file}
        )
        GET_FILENAME_COMPONENT(dirname ${ITEM_PATH_REL} DIRECTORY)
        FILE(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tests/assets/${dirname})
        FILE(COPY ${file} DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tests/assets/${dirname})
    ENDFOREACH()

    enable_testing()
    message(STATUS "Going to do tests..")
    include(cmake/tests.cmake)
    add_subdirectory(tests/testsql)
    add_subdirectory(tests/testssl)
    add_subdirectory(tests/testclient)
#    add_subdirectory(tests/test1)
#    add_test(NAME tests COMMAND ${SPEC_BUILD_DIR}/tests)
endif()
