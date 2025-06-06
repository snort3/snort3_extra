cmake_minimum_required ( VERSION 3.5 )
project ( cpeos_test CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    cpeos_test MODULE
    cpeos_test.cc
)

if ( APPLE )
    set_target_properties (
        cpeos_test
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    cpeos_test
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    cpeos_test PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS cpeos_test
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)
