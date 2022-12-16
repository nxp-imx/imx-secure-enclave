#
# Define GCOV Code Coverage compilation flags
#
if(CODE_COVERAGE)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
      set(CMAKE_C_FLAGS_COVERAGE "--coverage")
      set(CMAKE_LINK_FLAGS_COVERAGE "-lgcov --coverage")
    endif()

    # add coverage compile and link option to the target
    target_compile_options(${PROJECT_NAME} PRIVATE ${CMAKE_C_FLAGS_COVERAGE})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_LINK_FLAGS_COVERAGE})
    mark_as_advanced(CMAKE_C_FLAGS_COVERAGE CMAKE_LINK_FLAGS_COVERAGE)
endif()
