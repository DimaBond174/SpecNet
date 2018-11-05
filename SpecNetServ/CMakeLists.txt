cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(SpecNetServ) 
set(SpecNetServ_VERSION  "1.0")
set(SpecNetServ_SERVICE  "specnetserv")
set(SpecNetServ_INSTALL_FOLDER "../SpecNetDir")

set(SPEC_TESTS "ON")

if (MSVC)
	message(STATUS "Windows MSVC configure")
	set (CMAKE_BUILD_TYPE "Debug")	
else()
	message(STATUS "Clang configure")
	set(CMAKE_CXX_COMPILER clang++)
	set(CMAKE_C_COMPILER clang)
	set(CLANG_PATH "/usr/local/clang_6.0.1")
endif (MSVC)

# Please set project flawors there:
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
#IF(CMAKE_BUILD_TYPE MATCHES DEBUG)
#    message("debug mode")
#ENDIF(CMAKE_BUILD_TYPE MATCHES DEBUG)


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
