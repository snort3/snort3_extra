cmake_minimum_required ( VERSION 3.4.3 )
project ( domain_filter CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    domain_filter MODULE
    domain_filter.cc
)

if ( APPLE )
    set_target_properties (
        domain_filter
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    domain_filter
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    domain_filter PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS domain_filter
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)

#add_cpputest( domain_filter_test )

