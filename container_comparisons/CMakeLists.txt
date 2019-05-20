cmake_minimum_required(VERSION 3.11)

project(container_compare)

include_directories(include)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_CXX_FLAGS "-O3")

set(INT_KEY_SOURCES src/int_key.cc)
add_executable(int_key_compare ${INT_KEY_SOURCES})
TARGET_LINK_LIBRARIES(int_key_compare pthread)

set(STRING_KEY_SOURCES src/string_key.cc)
add_executable(string_key_compare ${STRING_KEY_SOURCES})
TARGET_LINK_LIBRARIES(string_key_compare pthread)
