set(CUR_TEST "testssl")
#custom_add_library_from_dir(${CUR_TEST})
set(LIB_SRC "")
set(LIB_INCLUDES     ${CPP_INCLUDES})
set(LIB_DEFINITIONS "")
set(LIB_LINK_LIBS "")

FILE(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libs)
FILE(GLOB TestLibs "libs/*.*")
FOREACH(file ${TestLibs})
    GET_FILENAME_COMPONENT(filename ${file} NAME)
    FILE(COPY ${CMAKE_CURRENT_SOURCE_DIR}/libs/${filename} DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libs)
ENDFOREACH()

set(LIB_INCLUDES
    ${LIB_INCLUDES}
    ${CMAKE_SOURCE_DIR}/src
    )

if("${SPEC_ENCRYPT}" STREQUAL "DSpecSSL")
   message(STATUS "SpecSSL was chosen for testlib")
   set(LIB_INCLUDES
       ${LIB_INCLUDES}
       ${CMAKE_SOURCE_DIR}/src/depend/encrypt/boringssl/include
       )

   set(LIB_LINK_LIBS
                ${LIB_LINK_LIBS}
                decrepit2
                ssl2
                crypto2
            )
        add_library( crypto2
                     SHARED
                     IMPORTED )
        add_library( decrepit2
                     SHARED
                     IMPORTED )
        add_library( ssl2
                     SHARED
                     IMPORTED )


         if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
             set_target_properties( # Specifies the target library.
                 crypto2
                 PROPERTIES IMPORTED_LOCATION
                 ${CMAKE_CURRENT_SOURCE_DIR}/libs/libcrypto.so )
             set_target_properties( # Specifies the target library.
                 decrepit2
                 PROPERTIES IMPORTED_LOCATION
                 ${CMAKE_CURRENT_SOURCE_DIR}/libs/libdecrepit.so )
             set_target_properties( # Specifies the target library.
                 ssl2
                 PROPERTIES IMPORTED_LOCATION
                 ${CMAKE_CURRENT_SOURCE_DIR}/libs/libssl.so )
    endif()
endif()

custom_add_lib(${CUR_TEST}
    "${LIB_SRC}"
    "${LIB_INCLUDES}"
    "${LIB_DEFINITIONS}"
    "${LIB_LINK_LIBS}"

    )
