cmake_minimum_required ( VERSION 3.4.3 )
project ( rt_packet_inspector CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    rt_packet_inspector MODULE
    rt_packet_inspector.cc
    rt_packet_inspector.h
)

if ( APPLE )
    set_target_properties (
        rt_packet_inspector
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    rt_packet_inspector
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    rt_packet_inspector PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS rt_packet_inspector
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/inspectors"
)
