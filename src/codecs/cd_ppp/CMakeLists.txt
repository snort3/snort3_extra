cmake_minimum_required ( VERSION 3.5 )
project ( cd_ppp CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    cd_ppp MODULE
    cd_ppp.cc
)

if ( APPLE )
    set_target_properties (
        cd_ppp
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    cd_ppp
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    cd_ppp PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cd_ppp
    LIBRARY
        DESTINATION "${CODEC_INSTALL_PATH}"
)
