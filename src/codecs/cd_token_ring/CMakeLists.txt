cmake_minimum_required ( VERSION 3.5 )
project ( cd_token_ring CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    cd_token_ring MODULE
    cd_token_ring.cc
)

if ( APPLE )
    set_target_properties (
        cd_token_ring
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    cd_token_ring
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    cd_token_ring PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_token_ring
    LIBRARY
        DESTINATION "${CODEC_INSTALL_PATH}"
)
