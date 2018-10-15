
function(custom_enable_cxx17 TARGET)   
    if (CMAKE_CXX_COMPILER STREQUAL "clang++")
        if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "-std=c++17 -g -O0 -pthread -Wall -pedantic")
        else()
            set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "-std=c++17 -pthread -Wall -pedantic")
        endif ()

        target_link_libraries(${TARGET}
            dl
            )
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "/std:c++latest")
    endif()
endfunction(custom_enable_cxx17)

function(custom_enable_cxx17libc TARGET)
    if (CMAKE_CXX_COMPILER STREQUAL "clang++")
#        set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "-stdlib=libc++ -pthread")
        set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "-stdlib=libc++ -pthread -Wall -pedantic")
#        set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "-I${CLANGPATH}/include/c++/v1")
        target_include_directories(${TARGET} PRIVATE "${CLANG_PATH}/include/c++/v1")
        target_link_libraries(${TARGET}            
            c++experimental
            c++
            c++abi)
    endif()
endfunction(custom_enable_cxx17libc)


# Add custom sources:
#function(custom_add_library_from_dir TARGET)
#    file(GLOB TARGET_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
#    add_library(${TARGET} ${TARGET_SRC})
#endfunction()

# Add TARGET - library:
function(custom_add_library_from_dir TARGET)
    file(GLOB TARGET_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
    add_library(${TARGET}
        SHARED
        ${TARGET_SRC})
    if (CMAKE_CXX_COMPILER STREQUAL "clang++")
        set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "-std=c++17 -shared -fPIC")
        target_link_libraries(${TARGET}
            dl
            )
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "/std:c++latest")
    endif()
endfunction()


# Add TARGET - executive:
function(custom_add_executable_from_dir TARGET)   
    file(GLOB TARGET_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
    add_executable(${TARGET} ${TARGET_SRC})
endfunction()

#Add TARGET  - executive with all properties
function(custom_add_executable TARGET
        TARGET_SRC
        TARGET_INCLUDES
        TARGET_DEFINITIONS
        TARGET_LINK_LIBS
        TARGET_PROPERTIES
        )
    message(STATUS "custom_add_executable: ${TARGET}")
    add_executable(${TARGET} ${TARGET_SRC})
    custom_enable_cxx17(${TARGET})
    message(STATUS "include_directories: ${TARGET_INCLUDES}")
    target_include_directories(${TARGET} PRIVATE ${TARGET_INCLUDES})
#    target_compile_definitions(${TARGET} PRIVATE ${TARGET_DEFINITIONS})
    message(STATUS "compile_definitions: ${TARGET_DEFINITIONS}")
    target_compile_definitions(${TARGET} PUBLIC ${TARGET_DEFINITIONS})
    message(STATUS "link_libraries: ${TARGET_LINK_LIBS}")
    target_link_libraries(${TARGET}  ${TARGET_LINK_LIBS}  )
    message(STATUS "target_properties: ${TARGET_PROPERTIES}")
    if (NOT("${TARGET_PROPERTIES}" STREQUAL ""))
        set_target_properties(${TARGET}
            PROPERTIES
            ${TARGET_PROPERTIES}
        )
    endif()
endfunction()

#Add TARGET  - lib with all properties
function(custom_add_lib TARGET
        TARGET_SRC
        TARGET_INCLUDES
        TARGET_DEFINITIONS
        TARGET_LINK_LIBS
        )
    message(STATUS "custom_add_lib: ${TARGET}")
    file(GLOB ADD_TARGET_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
    set(ADD_TARGET_SRC ${ADD_TARGET_SRC} ${TARGET_SRC})
    set(ADD_TARGET_INCLUDES ${TARGET_INCLUDES} ${CMAKE_CURRENT_SOURCE_DIR})

    add_library(${TARGET}
        SHARED
        ${ADD_TARGET_SRC}
        )

    if (CMAKE_CXX_COMPILER STREQUAL "clang++")
        if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "-std=c++17 -fPIC -rdynamic -shared -g -O0")
        else()
            set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "-std=c++17 -fPIC -rdynamic -shared ")
        endif ()


        target_link_libraries(${TARGET}
            dl
            )
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "/std:c++latest")
    endif()

#    custom_enable_cxx17(${TARGET})
    message(STATUS "include_directories: ${TARGET_INCLUDES}")
    target_include_directories(${TARGET} PRIVATE ${ADD_TARGET_INCLUDES})
#    target_compile_definitions(${TARGET} PRIVATE ${TARGET_DEFINITIONS})
    message(STATUS "compile_definitions: ${TARGET_DEFINITIONS}")
    target_compile_definitions(${TARGET} PUBLIC ${TARGET_DEFINITIONS})
    message(STATUS "link_libraries: ${TARGET_LINK_LIBS}")
    target_link_libraries(${TARGET}  ${TARGET_LINK_LIBS}  )
    message(STATUS "target_properties: ${TARGET_PROPERTIES}")

endfunction()
