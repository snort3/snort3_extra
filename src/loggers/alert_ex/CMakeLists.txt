cmake_minimum_required ( VERSION 3.5 )
project ( alert_ex CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    alert_ex MODULE
    alert_ex.cc
)

if ( APPLE )
    set_target_properties (
        alert_ex
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    alert_ex
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    alert_ex PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS alert_ex
    LIBRARY
        DESTINATION "${LOGGER_INSTALL_PATH}"
)
