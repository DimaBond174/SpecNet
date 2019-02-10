function(custom_add_test_from_dir TARGET)
    custom_add_executable_from_dir(${TARGET})
    # Add the path to the Catch framework header
    target_include_directories(${TARGET} PRIVATE "${CMAKE_SOURCE_DIR}/tests/catch")    
    #target_link_libraries(${TARGET} ${LIBRARY})
    # We register the executable file in CMake as a test suite:
    add_test(${TARGET} ${TARGET})
endfunction()


