cmake_minimum_required(VERSION 3.10)

# set the project name
project(test)

set(CMAKE_BUILD_TYPE Debug)

# add the executable
add_executable(test test.c ../tlv.c)

# compile-time defines
#target_compile_definitions(test PRIVATE DEBUG)

# includes
target_include_directories( test PUBLIC
                            "${PROJECT_BINARY_DIR}"
                            "./"
                            "../"
                            )

