cmake_minimum_required ( VERSION 3.4.3 )
project ( null_trace_logger CXX )

set ( CMAKE_CXX_STANDARD 14 )
set ( CMAKE_CXX_STANDARD_REQUIRED ON )
set ( CMAKE_CXX_EXTENSIONS OFF )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    null_trace_logger MODULE
    null_trace_logger.cc
)

if ( APPLE )
    set_target_properties (
        null_trace_logger
            PROPERTIES
                LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    null_trace_logger
        PROPERTIES
            PREFIX ""
)

target_include_directories (
    null_trace_logger PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS null_trace_logger
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)

