# This is the source code of SpecNet project
# It is licensed under MIT License.
#
#  Copyright (c) Dmitriy Bondarenko
#  feel free to contact me: specnet.messenger@gmail.com
#
set(CUR_TEST "testsql")
#custom_add_library_from_dir(${CUR_TEST})
#set(LIB_SRC "")
set(LIB_INCLUDES     ${CPP_INCLUDES})
set(LIB_DEFINITIONS ${CMAKE_SYSTEM_NAME})
set(LIB_LINK_LIBS "")

file(GLOB LIB_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
#set(ADD_TARGET_SRC ${ADD_TARGET_SRC} ${TARGET_SRC})

#add_library(sqlite3pic
# STATIC
# ${CMAKE_SOURCE_DIR}/src/depend/db/sqlite/sqlite3/sqlite3.c
# ${CMAKE_SOURCE_DIR}/src/depend/db/sqlite/sqlite3/sqlite3.h
#)
#set_target_properties(sqlite3pic PROPERTIES COMPILE_FLAGS "-std=c++17 -fPIC  ")
set(LIB_LINK_LIBS
    ${LIB_LINK_LIBS}
    sqlite3    
)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
   message(STATUS "Linux was chosen ")
   set(LIB_LINK_LIBS
             ${LIB_LINK_LIBS}
             dl
         )

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

set(LIB_INCLUDES
    ${LIB_INCLUDES}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/depend/db/sqlite/sqlite3/
    )


custom_add_lib(${CUR_TEST}
    "${LIB_SRC}"
    "${LIB_INCLUDES}"
    "${LIB_DEFINITIONS}"
    "${LIB_LINK_LIBS}"

    )
