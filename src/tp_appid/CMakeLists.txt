cmake_minimum_required ( VERSION 3.4.3 )
project ( tp_appid_example CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    tp_appid_example MODULE
    tp_appid_example.cc
)

if ( APPLE )
    set_target_properties (
        tp_appid_example
            PROPERTIES
                LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    tp_appid_example
        PROPERTIES
            PREFIX ""
)

set_property(TARGET tp_appid_example PROPERTY ENABLE_EXPORTS 1)      

target_include_directories (
    tp_appid_example PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS tp_appid_example
    LIBRARY
        DESTINATION "${LIB_INSTALL_PATH}/misc/${CMAKE_PROJECT_NAME}"
)
