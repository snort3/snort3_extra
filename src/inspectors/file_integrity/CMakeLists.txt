cmake_minimum_required(VERSION 3.10)
project(file_integrity LANGUAGES CXX)

add_library(file_integrity MODULE
  file_integrity.cc
  file_integrity_module.cc
)


find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT REQUIRED snort)

target_include_directories(file_integrity PRIVATE ${SNORT_INCLUDE_DIRS})
target_link_libraries(file_integrity PRIVATE ${SNORT_LIBRARIES})

find_package(OpenSSL REQUIRED)
target_link_libraries(file_integrity PRIVATE OpenSSL::Crypto)

target_compile_definitions(file_integrity PRIVATE BUILDING_SO)
set_property(TARGET file_integrity PROPERTY CXX_STANDARD 17)
set_property(TARGET file_integrity PROPERTY CXX_STANDARD_REQUIRED ON)

set_target_properties(file_integrity PROPERTIES PREFIX "" OUTPUT_NAME file_integrity)

if(NOT DEFINED INSPECTOR_INSTALL_PATH)
  set(INSPECTOR_INSTALL_PATH "lib/snort_extra/inspectors")
endif()
install(TARGETS file_integrity LIBRARY DESTINATION ${INSPECTOR_INSTALL_PATH})
