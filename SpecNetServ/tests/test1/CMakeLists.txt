#custom_add_test_from_dir(test1)

#file(GLOB_RECURSE TEST_SRC
#    ${CMAKE_CURRENT_SOURCE_DIR}/*.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
#)
set(CUR_TEST "test1")
file(GLOB_RECURSE TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
   set(TEST_SRC ${TEST_SRC}
       ${CMAKE_SOURCE_DIR}/src/depend/system/linux/linuxsystem.h
       ${CMAKE_SOURCE_DIR}/src/depend/system/linux/linuxsystem.cpp
       )

elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(TEST_SRC ${TEST_SRC}
        ${CMAKE_SOURCE_DIR}/src/depend/system/windows/windowssystem.h
        ${CMAKE_SOURCE_DIR}/src/depend/system/windows/windowssystem.cpp
        )
endif()

add_executable(${CUR_TEST}
    ${TEST_SRC}
    )
target_include_directories(${CUR_TEST} PRIVATE
    "${CMAKE_SOURCE_DIR}/tests/common"
    "${CMAKE_SOURCE_DIR}/src"
    )
custom_enable_cxx17(${CUR_TEST})
custom_enable_cxx17libc(${CUR_TEST})





target_compile_definitions(${CUR_TEST}
    PRIVATE
    SPEC_VERSION="${SpecNetServ_VERSION}"
    SPEC_SERVICE="${SpecNetServ_SERVICE}"
    SPEC_EXECUTIVE="${PROJECT_NAME}"
    ${CMAKE_BUILD_TYPE}

    PUBLIC
    ${SPEC_DEFINITIONS}

    INTERFACE
)

