set(CUR_TEST "testsql")
#custom_add_library_from_dir(${CUR_TEST})
set(LIB_SRC "")
set(LIB_INCLUDES     ${CPP_INCLUDES})
set(LIB_DEFINITIONS "")
set(LIB_LINK_LIBS "")

#add_library(sqlite3pic
# STATIC
# ${CMAKE_SOURCE_DIR}/src/depend/db/sqlite/sqlite3/sqlite3.c
# ${CMAKE_SOURCE_DIR}/src/depend/db/sqlite/sqlite3/sqlite3.h
#)
#set_target_properties(sqlite3pic PROPERTIES COMPILE_FLAGS "-std=c++17 -fPIC  ")
set(LIB_LINK_LIBS
    ${LIB_LINK_LIBS}
    sqlite3
    dl
)


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
