cmake_minimum_required ( VERSION 3.4.3 )
project ( appid_listener CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    appid_listener MODULE
    appid_listener.cc
    appid_listener.h
    appid_listener_event_handler.cc
    appid_listener_event_handler.h
)

if ( APPLE )
    set_target_properties (
        appid_listener
            PROPERTIES
                LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    appid_listener
        PROPERTIES
            PREFIX ""
)

target_include_directories (
    appid_listener PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS appid_listener
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)
