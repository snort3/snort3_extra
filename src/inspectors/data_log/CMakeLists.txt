cmake_minimum_required ( VERSION 3.5 )
project ( data_log CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    data_log MODULE
    data_log.cc
)

if ( APPLE )
    set_target_properties (
        data_log
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    data_log
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    data_log PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS data_log
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)
