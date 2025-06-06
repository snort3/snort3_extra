cmake_minimum_required ( VERSION 3.5 )
project ( lowmem CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    lowmem MODULE
    lowmem.cc
    sfksearch.cc
    sfksearch.h
)

if ( APPLE )
    set_target_properties (
        lowmem
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    lowmem
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    lowmem PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS lowmem
    LIBRARY
        DESTINATION "${SEARCH_ENGINE_INSTALL_PATH}"
)
