cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(SpecNetServ)
set(SpecNetServ_VERSION  "1.0")
set(SpecNetServ_SERVICE  "specnetserv")
set(SpecNetServ_INSTALL_FOLDER "../SpecNetDir")
set(CLANG_PATH "/usr/local/clang_6.0.1")
set(SPEC_TESTS "ON")

#add_definitions(-std=c++17)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -stdlib=libc++ -nostdinc++")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -stdlib=libc++ -Wall -pedantic")
# так не видит features.h set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -stdlib=libc++ -Wall -pedantic -nostdlib -nostdlibinc")
# так ошибка DSO set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -stdlib=libc++ -Wall -pedantic -nostdlib")
# так не создаёт исполняемых файлов:
# You can call -c on clang to just compile the object for you without linking.
#set(CMAKE_CXX_FLAGS "-std=c++17 -MMD -Wall -pedantic -nostdlib  -fno-omit-frame-pointer -c  ")
#set(CMAKE_C_FLAGS "-MMD -Wall -pedantic -nostdlib  -fno-omit-frame-pointer -c ")
#так :-1: ошибка: /usr/local/clang_6.0.1/lib/libc++.a(locale.cpp.o): undefined reference to symbol 'strtoull_l@@GLIBC_2.3.3'
#set(CMAKE_CXX_FLAGS "-std=c++17 -MMD -Wall -pedantic -nostdlib  -fno-omit-frame-pointer  ")
#set(CMAKE_C_FLAGS "-MMD -Wall -pedantic -nostdlib  -fno-omit-frame-pointer ")
# static понимает но не компилит т.к. sqlite хочет грузить  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -static -stdlib=libc++ -Wall -pedantic")
# так сервис не находит libc++ set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -stdlib=libc++ -Wall -pedantic")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 ")


#set(CMAKE_GENERATOR_CC clang-cl)
# Compiler
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER clang)
#set(CLANG_INCLUDE ${CLANG_PATH}/include/c++/v1)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${CLANG_PATH}/include/c++/v1")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L${CLANG_PATH}/lib/*.*")

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,-rpath,${CLANG_PATH}/lib")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nodefaultlibs -lc++ -lc++abi -lm -lc -lgcc_s -lgcc -lc++experimental -lstdc++fs")

# Please set project flawors there:
include(cmake/options.cmake)
include(cmake/functions.cmake)

# Src files for SpecNetServ:
#add_executable(${PROJECT_NAME}
#    ${SPEC_SRC}
#    )
#set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-std=c++17")
#custom_enable_cxx17(${PROJECT_NAME})


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

#TODO manually copy files for test cases because that don't works:
#set(DIRS_TO_COPY
#    ${CMAKE_CURRENT_SOURCE_DIR}/libs
#    ${CMAKE_CURRENT_SOURCE_DIR}/assets
#    )
#install(DIRECTORY ${DIRS_TO_COPY} DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
#install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/assets
#    DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/assets
#    FILES_MATCHING PATTERN "*.*")
#install(DIRECTORY assets/ DESTINATION assets2
#        FILES_MATCHING PATTERN "*.*")

custom_add_executable(${PROJECT_NAME}
    "${SPEC_SRC}"
    "${SPEC_INCLUDE}"
    "${SPEC_DEFINITIONS}"
    "${SPEC_LINK_LIBS}"
    "${SPEC_PROPERTIES}")

#target_compile_definitions(${PROJECT_NAME}
#    PRIVATE
#    SPEC_VERSION="${SpecNetServ_VERSION}"
#    SPEC_SERVICE="${SpecNetServ_SERVICE}"

#    PUBLIC
#    ${SPEC_DEFINITIONS}

#    INTERFACE
#)

#set_target_properties(${PROJECT_NAME}
#    PROPERTIES
#    ${SPEC_PROPERTIES}
#)

message(STATUS "target_link_libraries: ${SPEC_LINK_LIBS}")
#target_link_libraries(${PROJECT_NAME}
#    ${SPEC_LINK_LIBS}
#    )



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
