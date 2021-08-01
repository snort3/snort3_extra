cmake_minimum_required ( VERSION 3.4.3 )
project ( mem_test CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    mem_test MODULE
    mem_test.cc
)

if ( APPLE )
    set_target_properties (
        mem_test
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    mem_test
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    mem_test PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS mem_test
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)
