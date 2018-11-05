set(CUR_TEST "testssl")
#custom_add_library_from_dir(${CUR_TEST})
#set(LIB_SRC "")
set(LIB_INCLUDES     ${CPP_INCLUDES})
set(LIB_DEFINITIONS 
	${CMAKE_SYSTEM_NAME}
    ${SPEC_SERV}
)
set(LIB_LINK_LIBS "")


if("${SPEC_SERV}" STREQUAL "DEpollServer")
    message(STATUS "TestClient: DEpollServer was chosen ")
    set(LIB_SRC ${LIB_SRC}  
	${CMAKE_CURRENT_SOURCE_DIR}/testssl.h
	${CMAKE_CURRENT_SOURCE_DIR}/testssl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/sslclient.h
	${CMAKE_CURRENT_SOURCE_DIR}/sslclient.cpp
	)
elseif("${SPEC_SERV}" STREQUAL "DSelectServer")
    message(STATUS "TestClient: DSelectServer was chosen ")
    set(LIB_SRC ${LIB_SRC}  
	${CMAKE_CURRENT_SOURCE_DIR}/testssl.h
	${CMAKE_CURRENT_SOURCE_DIR}/testssl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/selclient.h
	${CMAKE_CURRENT_SOURCE_DIR}/selclient.cpp
	)
endif()

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


   if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
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
	elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
	#REMEMBER: linking with *.lib, but working with *.dll
		set(LIB_LINK_LIBS
                ${LIB_LINK_LIBS}
                ${CMAKE_CURRENT_SOURCE_DIR}/libs/decrepit.lib
                ${CMAKE_CURRENT_SOURCE_DIR}/libs/ssl.lib
                ${CMAKE_CURRENT_SOURCE_DIR}/libs/crypto.lib
            )
#		set(LIB_LINK_LIBS
#                ${LIB_LINK_LIBS}
#                decrepit2
#                ssl2
#                crypto2
#            )
#        set_target_properties( # Specifies the target library.
#            crypto2
#            PROPERTIES IMPORTED_LOCATION            
#			${CMAKE_CURRENT_SOURCE_DIR}/libs/crypto.lib )
#        set_target_properties( # Specifies the target library.
#            decrepit2
#            PROPERTIES IMPORTED_LOCATION            
#			${CMAKE_CURRENT_SOURCE_DIR}/libs/decrepit.lib )
#        set_target_properties( # Specifies the target library.
#            ssl2
#            PROPERTIES IMPORTED_LOCATION            
#			${CMAKE_CURRENT_SOURCE_DIR}/libs/ssl.lib )
    endif()
endif()

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
   message(STATUS "Linux was chosen ")
   #set(LIB_LINK_LIBS
   #          ${LIB_LINK_LIBS}
   #          dl
   #      )

elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
   message(STATUS "Windows was chosen ")
   
      set(LIB_LINK_LIBS
             ${LIB_LINK_LIBS}
             Ws2_32
         )

   	set(LIB_DEFINITIONS
	${LIB_DEFINITIONS}
	"WIN32_LEAN_AND_MEAN")
endif()

custom_add_lib(${CUR_TEST}
    "${LIB_SRC}"
    "${LIB_INCLUDES}"
    "${LIB_DEFINITIONS}"
    "${LIB_LINK_LIBS}"

    )
