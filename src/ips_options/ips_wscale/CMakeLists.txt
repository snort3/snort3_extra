cmake_minimum_required ( VERSION 3.5 )
project ( ips_wscale CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    ips_wscale MODULE
    ips_wscale.cc
)

if ( APPLE )
    set_target_properties (
        ips_wscale
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    ips_wscale
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    ips_wscale PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS ips_wscale
    LIBRARY
        DESTINATION "${IPS_OPTION_INSTALL_PATH}"
)
