function(custom_add_test_from_dir TARGET)
    custom_add_executable_from_dir(${TARGET})
    # Добавляем путь к заголовку фреймворка Catch
    target_include_directories(${TARGET} PRIVATE "${CMAKE_SOURCE_DIR}/tests/catch")
    # Добавляем компоновку с проверяемой библиотекой
    #target_link_libraries(${TARGET} ${LIBRARY})
    # Регистрируем исполняемый файл в CMake как набор тестов.
    add_test(${TARGET} ${TARGET})
endfunction()


