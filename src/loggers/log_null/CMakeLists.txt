cmake_minimum_required ( VERSION 3.5 )
project ( log_null CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    log_null MODULE
    log_null.cc
)

if ( APPLE )
    set_target_properties (
        log_null
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    log_null
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    log_null PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS log_null
    LIBRARY
        DESTINATION "${LOGGER_INSTALL_PATH}"
)
